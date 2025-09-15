#include "libfilezilla/encode.hpp"
#include "libfilezilla/hash.hpp"
#include "libfilezilla/jws.hpp"
#include "libfilezilla/logger.hpp"
#include "libfilezilla/translate.hpp"
#include "libfilezilla/util.hpp"
#include <nettle/ecdsa.h>
#include <nettle/ecc-curve.h>
#include <nettle/rsa.h>

#if defined(_MSC_VER)
typedef std::make_signed_t<size_t> ssize_t;
#endif

#include <gnutls/x509.h>

#include <memory.h>

namespace fz {
namespace {
extern "C" void rnd(void *, size_t length, uint8_t *dst)
{
	random_bytes(length, dst);
}

std::string to_string(mpz_t n, size_t pad = 0)
{
	std::string ret;
	size_t s = nettle_mpz_sizeinbase_256_u(n);
	if (s) {
		ret.resize(std::max(s, pad));
		size_t offset{};
		if (s < pad) {
			offset = pad - s;
		}
		nettle_mpz_get_str_256(s, reinterpret_cast<unsigned char*>(ret.data() + offset), n);
	}
	return ret;
}

std::pair<json, json> create_jwk_ecdsa()
{
	auto curve = nettle_get_secp_256r1();
	if (!curve) {
		return {};
	}

	ecc_scalar key;
	ecc_point pub;
	nettle_ecc_scalar_init(&key, curve);
	nettle_ecc_point_init(&pub, curve);
	nettle_ecdsa_generate_keypair(&pub, &key, nullptr, &rnd);

	mpz_t d;
	mpz_init(d);
	nettle_ecc_scalar_get(&key, d);

	json jpriv;
	jpriv["kty"] = "EC";
	jpriv["crv"] = "P-256";
	jpriv["d"] = fz::base64_encode(to_string(d), base64_type::url, false);

	mpz_clear(d);

	mpz_t x, y;
	mpz_init(x);
	mpz_init(y);
	nettle_ecc_point_get(&pub, x, y);

	json jpub;
	jpub["kty"] = "EC";
	jpub["crv"] = "P-256";
	jpub["x"] = fz::base64_encode(to_string(x), base64_type::url, false);
	jpub["y"] = fz::base64_encode(to_string(y), base64_type::url, false);

	mpz_clear(x);
	mpz_clear(y);

	nettle_ecc_scalar_clear(&key);
	nettle_ecc_point_clear(&pub);

	return {jpriv, jpub};
}

extern "C" void genramdom(void*, size_t length, uint8_t *dst)
{
	auto ret = fz::random_bytes(length);
	memcpy(dst, ret.data(), length);
}

std::pair<json, json> create_jwk_rsa()
{
	rsa_public_key pub;
	nettle_rsa_public_key_init(&pub);
	mpz_set_ui(pub.e, 65537);

	rsa_private_key priv;
	nettle_rsa_private_key_init(&priv);

	if (!nettle_rsa_generate_keypair(&pub, &priv, nullptr, &genramdom, nullptr, nullptr, 2048, 0)) {
		nettle_rsa_public_key_clear(&pub);
		nettle_rsa_private_key_clear(&priv);
		return {};
	}


	json jpriv;
	jpriv["kty"] = "RSA";
	jpriv["p"] = fz::base64_encode(to_string(priv.p), base64_type::url, false);
	jpriv["q"] = fz::base64_encode(to_string(priv.q), base64_type::url, false);
	jpriv["d"] = fz::base64_encode(to_string(priv.d), base64_type::url, false);
	jpriv["dp"] = fz::base64_encode(to_string(priv.a), base64_type::url, false);
	jpriv["dq"] = fz::base64_encode(to_string(priv.b), base64_type::url, false);
	jpriv["qi"] = fz::base64_encode(to_string(priv.c), base64_type::url, false);
	nettle_rsa_private_key_clear(&priv);

	json jpub;
	jpub["kty"] = "RSA";
	jpub["n"] = fz::base64_encode(to_string(pub.n), base64_type::url, false);
	jpub["e"] = fz::base64_encode(to_string(pub.e), base64_type::url, false);
	nettle_rsa_public_key_clear(&pub);

	return {jpriv, jpub};
}
}

// Private and public key
std::pair<json, json> create_jwk(jwk_type t)
{
	switch (t) {
	case jwk_type::ecdsa:
		return create_jwk_ecdsa();
	case jwk_type::rsa:
		return create_jwk_rsa();
	}
	return {};
}

std::string_view FZ_PRIVATE_SYMBOL to_view(gnutls_datum_t const& d);

std::pair<json, json> jwk_from_x509_privkey(std::string_view const& data, bool pem, logger_interface* logger)
{
	if (!logger) {
		logger = &get_null_logger();
	}

	gnutls_x509_privkey_t pvk;
	gnutls_x509_privkey_init(&pvk);

	gnutls_datum_t d;
	d.data = const_cast<unsigned char *>(reinterpret_cast<unsigned char const *>(data.data()));
	d.size = unsigned(data.size());

	auto res = gnutls_x509_privkey_import2(pvk, &d, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, nullptr, 0);
	if (res < 0) {
		gnutls_x509_privkey_deinit(pvk);
		logger->log(logmsg::error, fztranslate("Could not convert private key to JWK, import failed: %s"), gnutls_strerror(res));
		return {};
	}

	auto alg = gnutls_x509_privkey_get_pk_algorithm(pvk);
	if (alg != GNUTLS_PK_RSA && alg != GNUTLS_PK_ECDSA) {
		gnutls_x509_privkey_deinit(pvk);
		logger->log(logmsg::error, fztranslate("Could not convert private key to JWK, only RSA and ECDSA private keys are supported."));
		return {};
	}

	if (alg == GNUTLS_PK_RSA) {
		gnutls_datum_t n{};
		gnutls_datum_t e{};
		gnutls_datum_t d{};
		gnutls_datum_t p{};
		gnutls_datum_t q{};
		gnutls_datum_t dp{};
		gnutls_datum_t dq{};
		gnutls_datum_t qi{};

		int res = gnutls_x509_privkey_export_rsa_raw2(pvk, &n, &e, &d, &p, &q, &qi, &dp, &dq);
		gnutls_x509_privkey_deinit(pvk);
		if (res < 0) {
			logger->log(logmsg::error, fztranslate("Could not convert private key to JWK, exporting RSA parameters failed: %s"), gnutls_strerror(res));
			return {};
		}

		json jpriv;
		jpriv["kty"] = "RSA";
		jpriv["p"] = fz::base64_encode(to_view(p), base64_type::url, false);
		jpriv["q"] = fz::base64_encode(to_view(q), base64_type::url, false);
		jpriv["d"] = fz::base64_encode(to_view(d), base64_type::url, false);
		jpriv["dp"] = fz::base64_encode(to_view(dp), base64_type::url, false);
		jpriv["dq"] = fz::base64_encode(to_view(dq), base64_type::url, false);
		jpriv["qi"] = fz::base64_encode(to_view(qi), base64_type::url, false);
		gnutls_free(p.data);
		gnutls_free(q.data);
		gnutls_free(d.data);
		gnutls_free(dp.data);
		gnutls_free(dq.data);
		gnutls_free(qi.data);

		json jpub;
		jpub["kty"] = "RSA";
		jpub["n"] = fz::base64_encode(to_view(n), base64_type::url, false);
		jpub["e"] = fz::base64_encode(to_view(e), base64_type::url, false);
		gnutls_free(n.data);
		gnutls_free(e.data);

		return {jpriv, jpub};
	}
	else {
		gnutls_ecc_curve_t curve{};
		gnutls_datum_t x{};
		gnutls_datum_t y{};
		gnutls_datum_t k{};
		int res = gnutls_x509_privkey_export_ecc_raw(pvk, &curve, &x, &y, &k);
		gnutls_x509_privkey_deinit(pvk);
		if (res < 0) {
			logger->log(logmsg::error, fztranslate("Could not convert private key to JWK, exporting ECC parameters failed: %s"), gnutls_strerror(res));
			return {};
		}
		if (curve != GNUTLS_ECC_CURVE_SECP256R1) {
			gnutls_free(k.data);
			gnutls_free(x.data);
			gnutls_free(y.data);
			logger->log(logmsg::error, fztranslate("Could not convert private key to JWK, unsupported elliptic curve, only SECP256R1 is supported."));
			return {};
		}

		json jpriv;
		jpriv["kty"] = "EC";
		jpriv["crv"] = "P-256";
		jpriv["d"] = fz::base64_encode(to_view(k), base64_type::url, false);
		gnutls_free(k.data);

		json jpub;
		jpub["kty"] = "EC";
		jpub["crv"] = "P-256";
		jpub["x"] = fz::base64_encode(to_view(x), base64_type::url, false);
		jpub["y"] = fz::base64_encode(to_view(y), base64_type::url, false);
		gnutls_free(x.data);
		gnutls_free(y.data);

		return {jpriv, jpub};
	}
}

namespace {
std::string jws_sign_ecdsa(json const& priv, std::vector<uint8_t> const& digest)
{
	auto const ds = fz::base64_decode_s(priv["d"].string_value());
	if (priv["kty"].string_value() != "EC" || priv["crv"].string_value() != "P-256"|| ds.empty()) {
		return {};
	}

	auto curve = nettle_get_secp_256r1();
	if (!curve) {
		return {};
	}

	mpz_t d;
	mpz_init(d);
	nettle_mpz_set_str_256_u(d, ds.size(), reinterpret_cast<uint8_t const*>(ds.c_str()));

	ecc_scalar key;
	nettle_ecc_scalar_init(&key, curve);
	if (!nettle_ecc_scalar_set(&key, d)) {
		mpz_clear(d);
		nettle_ecc_scalar_clear(&key);
		return {};
	}
	mpz_clear(d);

	struct dsa_signature sig;
	nettle_dsa_signature_init(&sig);

	nettle_ecdsa_sign(&key, nullptr, rnd, digest.size(), digest.data(), &sig);
	nettle_ecc_scalar_clear(&key);

	std::string ret = fz::base64_encode(to_string(sig.r, 32) + to_string(sig.s, 32), base64_type::url, false);
	nettle_dsa_signature_clear(&sig);
	return ret;
}

std::string jws_sign_rsa(json const& jpriv, std::vector<uint8_t> const& digest)
{
	if (digest.size() != 256/8) {
		return {};
	}

	auto p = fz::base64_decode(jpriv["p"].string_value());
	auto q = fz::base64_decode(jpriv["q"].string_value());
	auto d = fz::base64_decode(jpriv["d"].string_value());
	auto a = fz::base64_decode(jpriv["dp"].string_value());
	auto b = fz::base64_decode(jpriv["dq"].string_value());
	auto c = fz::base64_decode(jpriv["qi"].string_value());
	if (p.empty() || q.empty() || d.empty() || a.empty() || b.empty() || c.empty()) {
		return {};
	}

	rsa_private_key priv;
	nettle_rsa_private_key_init(&priv);
	nettle_mpz_set_str_256_u(priv.p, p.size(), p.data());
	nettle_mpz_set_str_256_u(priv.q, q.size(), q.data());
	nettle_mpz_set_str_256_u(priv.d, d.size(), d.data());
	nettle_mpz_set_str_256_u(priv.a, a.size(), a.data());
	nettle_mpz_set_str_256_u(priv.b, b.size(), b.data());
	nettle_mpz_set_str_256_u(priv.c, c.size(), c.data());

	if (!nettle_rsa_private_key_prepare(&priv)) {
		nettle_rsa_private_key_clear(&priv);
		return {};
	}

	mpz_t signature;
	mpz_init(signature);

	bool res = nettle_rsa_sha256_sign_digest(&priv, digest.data(), signature);
	nettle_rsa_private_key_clear(&priv);
	if (!res) {
		mpz_clear(signature);
		return {};
	}
	auto ret = fz::base64_encode(to_string(signature), fz::base64_type::url, false);
	mpz_clear(signature);
	return ret;
}
}

json jws_sign_flattened(json const& priv, json const& payload, json const& extra_protected)
{
	auto const& kty = priv["kty"].string_value();
	if (kty != "RSA" && (kty != "EC" || priv["crv"].string_value() != "P-256")) {
		return {};
	}

	auto encoded_payload = fz::base64_encode(payload.to_string(), fz::base64_type::url, false);

	json prot;
	if (extra_protected.type() == json_type::object) {
		prot = extra_protected;
	}
	if (kty == "RSA") {
		prot["alg"] = "RS256";
	}
	else {
		prot["alg"] = "ES256";
	}

	auto encoded_prot = base64_encode(prot.to_string(), fz::base64_type::url, false);

	fz::hash_accumulator acc(fz::hash_algorithm::sha256);
	acc << encoded_prot << "." << encoded_payload;
	auto digest = acc.digest();

	auto sig = (kty == "RSA") ? jws_sign_rsa(priv, digest) : jws_sign_ecdsa(priv, digest);
	if (sig.empty()) {
		return {};
	}

	json ret;
	ret["protected"] = std::move(encoded_prot);
	ret["payload"] = std::move(encoded_payload);
	ret["signature"] = std::move(sig);

	return ret;
}

std::string create_jwt(json const& priv, json const& payload, json extra_protected)
{
	if (extra_protected.type() != json_type::none && extra_protected.type() != json_type::object) {
		return {};
	}

	extra_protected["typ"] = "JWT";
	auto sig = jws_sign_flattened(priv, payload, extra_protected);
	if (!sig) {
		return {};
	}

	return sig["protected"].string_value() + "." + sig["payload"].string_value() + "." + sig["signature"].string_value();
}
}
