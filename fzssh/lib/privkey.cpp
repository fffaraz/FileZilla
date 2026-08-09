#include "asn1.hpp"
#include "buffer_util.hpp"
#include "ecc.hpp"
#include "mpz.hpp"
#include "privkey.hpp"

#include <libfilezilla/encode.hpp>
#include <libfilezilla/hash.hpp>
#include <libfilezilla/logger.hpp>

#include <nettle/ecc-curve.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/rsa.h>

#include "string.h"

namespace fz::ssh {

std::string to_openssh_pubkey(std::string_view const& name, std::string_view const& key, std::string const& comment);
std::string to_rfc4716_pubkey(std::string_view const& key, std::string const& comment);

private_key::~private_key()
{
}

void private_key::cancel(event_handler& h)
{
	auto event_filter = [&](event_base& ev) -> bool {
		if (ev.derived_type() == signature_event::type()) {
			return &std::get<0>(static_cast<signature_event const&>(ev).v_) == this;
		}
		return false;
	};
	h.filter_events(event_filter);
}

std::unique_ptr<public_key> private_key::pubkey() const
{
	if (pub_.empty()) {
		return {};
	}
	auto k = create_public_key(name());
	if (!k || !k->parse(pub_.to_view())) {
		return {};
	}
	k->comment_ = comment_;
	return k;
}

std::string private_key::openssh_pubkey() const
{
	return to_openssh_pubkey(name(), pub_.to_view(), comment_);
}

std::string private_key::rfc4716_pubkey() const
{
	return to_rfc4716_pubkey(pub_.to_view(), comment_);
}

std::string fingerprint_from_blob(std::string_view const& data, hash_algorithm alg, bool base64);

std::string private_key::fingerprint(hash_algorithm alg, bool base64) const
{
	return fingerprint_from_blob(pub_.to_view(), alg, base64);
}

bool concrete_private_key_impl::selftest()
{
	auto pub = pubkey();
	if (!pub) {
		pub_.clear();
		return false;
	}
	fz::buffer buf;
	buf.append("Lorem ipsum"sv);
	buf.append(random_bytes(16));
	auto sig = sign(std::basic_string_view<uint8_t>(reinterpret_cast<uint8_t const*>(buf.data()), buf.size()), name());
	bool ret = pub->verify(buf.to_view(), sig.to_view());
	if (!ret) {
		pub_.clear();
	}
	return ret;
}

class private_key_ed25519 final : public concrete_private_key_impl
{
public:
	~private_key_ed25519();

	virtual std::string_view name() const override {
		return "ssh-ed25519"sv;
	}

	virtual bool generate() override;

	virtual buffer sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm) override;

	virtual bool parse_openssh_blob(std::string_view & data) override;
	virtual bool parse_putty_blobs(std::string_view pub, std::string_view priv) override;
	virtual bool parse_der(std::string_view data) override;
	virtual bool parse_inner_pkcs8(std::string_view data, std::string_view opt_pubblob, bool pubblob_constructed) override;

	virtual bool export_pkcs8(std::string & out) const override;

	virtual std::unique_ptr<private_key> clone() const override;
private:
	std::vector<uint8_t> priv_;
};

std::unique_ptr<private_key> private_key_ed25519::clone() const
{
	if (pub_.empty()) {
		return {};
	}

	auto ret = std::make_unique<private_key_ed25519>();
	ret->priv_ = priv_;
	ret->comment_ = comment_;
	ret->pub_ = pub_;
	return ret;
}

private_key_ed25519::~private_key_ed25519()
{
	wipe(priv_);
}

bool private_key_ed25519::generate()
{
	priv_ = random_bytes(32);

	pub_.clear();
	write_string(pub_, name());
	write_uint32(pub_, 32);
	nettle_ed25519_sha512_public_key(pub_.get(32), priv_.data());
	pub_.add(32);

	return selftest();
}

buffer private_key_ed25519::sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm)
{
	if (pub_.empty() || priv_.empty() || data.empty() || signature_algorithm != name()) {
		return {};
	}

	buffer sig;
	write_string(sig, "ssh-ed25519"sv);
	write_uint32(sig, 64);
	nettle_ed25519_sha512_sign(pub_.data() + pub_.size() - 32, priv_.data(), data.size(), data.data(), sig.get(64));
	sig.add(64);
	return sig;
}

bool private_key_ed25519::parse_openssh_blob(std::string_view & data)
{
	pub_.clear();
	wipe(priv_);
	priv_.clear();

	auto pub = extract_blob(data);
	auto priv = extract_blob(data);
	if (!pub || !priv) {
		return false;
	}
	if (pub->size() != 32 || priv->size() != 64) {
		return false;
	}
	if (priv->substr(32) != *pub) {
		return false;
	}
	priv_.assign(priv->begin(), priv->begin() + 32);
	write_string(pub_, name());
	write_string(pub_, *pub);

	return selftest();
}

bool private_key_ed25519::parse_putty_blobs(std::string_view pubblob, std::string_view privblob)
{
	pub_.clear();
	wipe(priv_);
	priv_.clear();

	auto pub = extract_blob(pubblob);
	auto priv = extract_blob(privblob);
	if (!pub || !priv) {
		return false;
	}
	if (pub->size() != 32 || priv->size() != 32) {
		return false;
	}

	priv_.assign(priv->begin(), priv->end());
	write_string(pub_, name());
	write_string(pub_, *pub);

	return selftest();
}

bool private_key_ed25519::parse_inner_pkcs8(std::string_view data, std::string_view opt_pubblob, bool pubblob_constructed)
{
	if (!parse_der(data)) {
		return false;
	}

	if (!opt_pubblob.empty()) {
		// Instead of the raw blob, some programs use a pubblob containing an octet string
		if (pubblob_constructed && opt_pubblob.size() >= 34 && opt_pubblob[0] == '\x04' && static_cast<uint8_t>(opt_pubblob[1]) == opt_pubblob.size() - 2) {
			opt_pubblob.remove_prefix(2);
		}
		if (!opt_pubblob[0]) {
			opt_pubblob.remove_prefix(1);
		}
		if (opt_pubblob != pub_.to_view().substr(19)) {
			pub_.clear();
			wipe(priv_);
			priv_.clear();
			return false;
		}
	}
	return true;
}

bool private_key_ed25519::parse_der(std::string_view data)
{
	pub_.clear();
	wipe(priv_);
	priv_.clear();

	ASN1Value raw = parseDer(data, ASN1Type::OctetString);
	if (raw.data_.size() != 32) {
		return false;
	}

	priv_.assign(raw.data_.begin(), raw.data_.end());

	pub_.clear();
	write_string(pub_, name());
	write_uint32(pub_, 32);
	nettle_ed25519_sha512_public_key(pub_.get(32), priv_.data());
	pub_.add(32);

	return selftest();
}

bool private_key_ed25519::export_pkcs8(std::string & out) const
{
	if (pub_.empty()) {
		return {};
	}

	std::string oid;
	if (!der_encode_oid(oid, "1.3.101.112"sv) ) {
		return {};
	}

	der_encode(out, oid, ASN1Type::Sequence, true);

	std::string inner;
	der_encode(inner, std::string_view(reinterpret_cast<char const*>(priv_.data()), priv_.size()), ASN1Type::OctetString, false);
	der_encode(out, inner, ASN1Type::OctetString, false);

	if (pub_[0]) {
		der_encode(out, pub_.to_view().substr(pub_.size() - 32), ASN1Class::context_specific, 1, false);
	}
	else {
		std::string padded;
		padded += '\0';
		padded += pub_.to_view().substr(pub_.size() - 32);
		der_encode(out, padded, ASN1Class::context_specific, 1, false);
	}

	return true;
}

class private_key_ecdsa_sha2_nistp final : public concrete_private_key_impl
{
public:
	private_key_ecdsa_sha2_nistp(nistp_curve curve);
	virtual ~private_key_ecdsa_sha2_nistp() override;

	virtual std::string_view name() const override {
		return key_name(curve_);
	}

	virtual bool generate() override;

	virtual buffer sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm) override;

	virtual bool parse_openssh_blob(std::string_view & data) override;
	virtual bool parse_putty_blobs(std::string_view pub, std::string_view priv) override;
	virtual bool parse_der(std::string_view data) override;
	virtual bool parse_inner_pkcs8(std::string_view data, std::string_view opt_pubblob, bool pubblob_constructed) override;

	virtual bool export_pkcs8(std::string & out) const override;

	virtual std::unique_ptr<private_key> clone() const override;
private:
	bool parse_raw_blobs(std::string_view const& pub, std::string_view const& priv);

	nistp_curve const curve_;
	curve_scalar priv_;
};

extern "C" void rnd(void *, size_t length, uint8_t *dst)
{
	random_bytes(length, dst);
}

private_key_ecdsa_sha2_nistp::private_key_ecdsa_sha2_nistp(nistp_curve curve)
	: curve_(curve)
	, priv_(curve_)
{
}

private_key_ecdsa_sha2_nistp::~private_key_ecdsa_sha2_nistp()
{
}

std::unique_ptr<private_key> private_key_ecdsa_sha2_nistp::clone() const
{
	if (pub_.empty()) {
		return {};
	}
	auto ret = std::make_unique<private_key_ecdsa_sha2_nistp>(curve_);
	mpz v;
	ecc_scalar_get(priv_, v);
	ecc_scalar_set(ret->priv_, v);
	ret->comment_ = comment_;
	ret->pub_ = pub_;
	return ret;
}

bool private_key_ecdsa_sha2_nistp::generate()
{
	curve_point pub(curve_);

	ecdsa_generate_keypair(pub, priv_, nullptr, &rnd);

	pub_.clear();
	write_string(pub_, name());
	write_string(pub_, curve_name(curve_));
	write_uint32(pub_, curve_bytes(curve_) * 2 + 1);
	pub_.append('\x04');

	mpz x, y;
	ecc_point_get(pub, x, y);

	to_string_append(pub_, x, curve_bytes(curve_));
	to_string_append(pub_, y, curve_bytes(curve_));

	return selftest();
}

buffer private_key_ecdsa_sha2_nistp::sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm)
{
	if (pub_.empty() || data.empty() || signature_algorithm != name()) {
		return {};
	}

	hash_accumulator acc(get_digest(curve_));
	acc.update(data);
	auto digest = acc.digest();

	dsa_signature sig;
	nettle_dsa_signature_init(&sig);

	ecdsa_sign(priv_, nullptr, &rnd, digest.size(), digest.data(), &sig);

	buffer ret;
	write_string(ret, name());
	auto const& p = ret.get(0);
	ret.append(4, 0);
	size_t s = ret.size();

	write_mpint(ret, to_string(sig.r, curve_bytes(curve_)));
	write_mpint(ret, to_string(sig.s, curve_bytes(curve_)));
	write_uint32(p, ret.size() - s);

	nettle_dsa_signature_clear(&sig);

	return ret;
}

bool private_key_ecdsa_sha2_nistp::parse_raw_blobs(std::string_view const& pub, std::string_view const& priv)
{
	pub_.clear();
	if (pub.size() != curve_bytes(curve_) * 2 + 1) {
		return false;
	}

	if (pub[0] != '\x04') {
		return false;
	}

	mpz key;
	mpz_import(key, priv.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(priv.data()));
	if (!ecc_scalar_set(priv_, key)) {
		return false;
	}

	std::string_view x = pub.substr(1, curve_bytes(curve_));
	std::string_view y = pub.substr(1 + curve_bytes(curve_), curve_bytes(curve_));

	mpz xz;
	mpz yz;

	curve_point pubpoint(curve_);

	nettle_mpz_set_str_256_u(xz, x.size(), reinterpret_cast<uint8_t const*>(x.data()));
	nettle_mpz_set_str_256_u(yz, y.size(), reinterpret_cast<uint8_t const*>(y.data()));

	bool ret = nettle_ecc_point_set(pubpoint, xz, yz);

	if (!ret) {
		return false;
	}

	write_string(pub_, name());
	write_string(pub_, curve_name(curve_));
	write_string(pub_, pub);

	return selftest();
}

bool private_key_ecdsa_sha2_nistp::parse_openssh_blob(std::string_view & data)
{
	pub_.clear();

	auto curve = extract_string(data, string_type::ascii, false);
	if (!curve || *curve != curve_name(curve_)) {
		return false;
	}

	auto rawpub = extract_blob(data);
	if (!rawpub) {
		return false;
	}

	auto rawkey = extract_blob(data);
	if (!rawkey) {
		return false;
	}

	return parse_raw_blobs(*rawpub, *rawkey);
}

bool private_key_ecdsa_sha2_nistp::parse_putty_blobs(std::string_view pubblob, std::string_view privblob)
{
	pub_.clear();

	auto curve = extract_string(pubblob, string_type::ascii, false);
	if (!curve || *curve != curve_name(curve_)) {
		return false;
	}

	auto rawpub = extract_blob(pubblob);
	if (!rawpub) {
		return false;
	}

	auto rawkey = extract_blob(privblob);
	if (!rawkey) {
		return {};
	}

	return parse_raw_blobs(*rawpub, *rawkey);
}

bool private_key_ecdsa_sha2_nistp::parse_inner_pkcs8(std::string_view data, std::string_view opt_pubblob, bool /*pubblob_constructed*/)
{
	pub_.clear();

	auto d = data;
	ASN1Value seq = parseDer(d, ASN1Type::Sequence);
	auto version = parseDer(seq.data_, ASN1Type::Integer);
	if (version.data_ != "\x01"sv) {
		return {};
	}
	auto rawkey = parseDer(seq.data_, ASN1Type::OctetString);

	auto rawpub = parseDer(seq.data_, ASN1Class::context_specific, 1);
	rawpub = parseDer(rawpub.data_, ASN1Type::BitString);
	if (rawpub.data_.empty() || rawpub.data_[0]) {
		return {};
	}
	rawpub.data_.remove_prefix(1);
	if (!opt_pubblob.empty()) {
		if (!opt_pubblob[0]) {
			opt_pubblob.remove_prefix(1);
		}
		if (opt_pubblob != rawpub.data_) {
			return {};
		}
	}
	return parse_raw_blobs(rawpub.data_, rawkey.data_);
}

bool private_key_ecdsa_sha2_nistp::export_pkcs8(std::string & out) const
{
	if (pub_.empty()) {
		return {};
	}

	std::string oid;
	if (!der_encode_oid(oid, "1.2.840.10045.2.1"sv) || !der_encode_oid(oid, curve_oid(curve_))) {
		return {};
	}

	der_encode(out, oid, ASN1Type::Sequence, true);

	std::string seq;
	der_encode(seq, 1);

	mpz key;
	ecc_scalar_get(priv_, key);
	der_encode(seq, to_string(key).to_view(), ASN1Type::OctetString, false);

	std::string pubraw;
	pubraw += '\0';
	pubraw += pub_.to_view().substr(pub_.size() - curve_bytes(curve_) * 2 - 1);

	std::string pubbs;
	der_encode(pubbs, pubraw, ASN1Type::BitString, false);
	der_encode(seq, pubbs, ASN1Class::context_specific, 1, true);

	std::string inner;
	der_encode(inner, seq, ASN1Type::Sequence, true);
	der_encode(out, inner, ASN1Type::OctetString, false);

	return true;
}

bool private_key_ecdsa_sha2_nistp::parse_der(std::string_view data)
{
	pub_.clear();

	auto d = data;
	ASN1Value seq = parseDer(d, ASN1Type::Sequence);
	auto version = parseDer(seq.data_, ASN1Type::Integer);
	if (version.data_ != "\x01"sv) {
		return {};
	}
	auto rawkey = parseDer(seq.data_, ASN1Type::OctetString);

	auto choice = parseDer(seq.data_, ASN1Class::context_specific, 0);
	if (parse_oid(parseDer(choice.data_, ASN1Type::ObjectIdentifier)) != curve_oid(curve_)) {
		return {};
	}

	auto rawpub = parseDer(seq.data_, ASN1Class::context_specific, 1);
	rawpub = parseDer(rawpub.data_, ASN1Type::BitString);
	if (rawpub.data_.empty() || rawpub.data_[0]) {
		return {};
	}
	rawpub.data_.remove_prefix(1);
	return parse_raw_blobs(rawpub.data_, rawkey.data_);
}

class private_key_rsa final : public concrete_private_key_impl
{
public:
	private_key_rsa();
	virtual ~private_key_rsa() override;

	virtual std::string_view name() const override;

	virtual bool generate() override {
		return generate(2048);
	}

	bool generate(size_t bits);

	virtual buffer sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm) override;

	virtual bool parse_openssh_blob(std::string_view & data) override;
	virtual bool parse_putty_blobs(std::string_view pub, std::string_view priv) override;
	virtual bool parse_der(std::string_view data) override;
	virtual bool parse_inner_pkcs8(std::string_view data, std::string_view /*opt_pubblob*/, bool /*pubblob_constructed*/) override { return parse_der(data); }

	bool export_pkcs8(std::string & out) const override;

	virtual std::unique_ptr<private_key> clone() const override;

private:
	bool set_values(std::string_view const& n, std::string_view const& e, std::string_view const& d, std::string_view const& p, std::string_view const& q, std::string_view const& iqmp);

	rsa_private_key priv_;
	rsa_public_key rsa_pub_;
};

private_key_rsa::private_key_rsa()
{
	nettle_rsa_private_key_init(&priv_);
	nettle_rsa_public_key_init(&rsa_pub_);
}

private_key_rsa::~private_key_rsa()
{
	nettle_rsa_private_key_clear(&priv_);
	nettle_rsa_public_key_clear(&rsa_pub_);
}

std::unique_ptr<private_key> private_key_rsa::clone() const
{
	if (!pub_) {
		return {};
	}

	auto ret = std::make_unique<private_key_rsa>();
	mpz_set(ret->priv_.a, priv_.a);
	mpz_set(ret->priv_.b, priv_.b);
	mpz_set(ret->priv_.c, priv_.c);
	mpz_set(ret->priv_.d, priv_.d);
	mpz_set(ret->priv_.p, priv_.p);
	mpz_set(ret->priv_.q, priv_.q);
	ret->priv_.size = priv_.size;

	mpz_set(ret->rsa_pub_.n, rsa_pub_.n);
	mpz_set(ret->rsa_pub_.e, rsa_pub_.e);
	ret->rsa_pub_.size = rsa_pub_.size;
	ret->pub_ = pub_;
	ret->comment_ = comment_;
	return ret;
}

std::string_view private_key_rsa::name() const
{
	return "ssh-rsa"sv;
}

bool private_key_rsa::generate(size_t bits)
{
	pub_.clear();

	mpz_set_ui(rsa_pub_.e, 65537);
	if (nettle_rsa_generate_keypair(&rsa_pub_, &priv_, nullptr, &rnd, nullptr, nullptr, bits, 0) != 1) {
		return false;
	}

	write_string(pub_, "ssh-rsa"sv);
	write_mpint(pub_, to_string(rsa_pub_.e));
	write_mpint(pub_, to_string(rsa_pub_.n));

	return selftest();
}

buffer private_key_rsa::sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm)
{
	if (pub_.empty() || data.empty()) {
		return {};
	}

	hash_algorithm a;
	if (signature_algorithm == "ssh-rsa"sv) {
		a = hash_algorithm::sha1;
	}
	else if (signature_algorithm == "rsa-sha2-256"sv) {
		a = hash_algorithm::sha256;
	}
	else if (signature_algorithm == "rsa-sha2-512"sv) {
		a = hash_algorithm::sha512;
	}
	else {
		return {};
	}

	hash_accumulator hash(a);
	hash.update(data);

	buffer ret{};

	mpz sig;

	auto do_sign_rsa = [&]() {
		switch (a) {
		case hash_algorithm::sha1:
			return nettle_rsa_sha1_sign_digest_tr(&rsa_pub_, &priv_, nullptr, &rnd, hash.digest().data(), sig);
		case hash_algorithm::sha256:
			return nettle_rsa_sha256_sign_digest_tr(&rsa_pub_, &priv_, nullptr, &rnd, hash.digest().data(), sig);
		case hash_algorithm::sha512:
			return nettle_rsa_sha512_sign_digest_tr(&rsa_pub_, &priv_, nullptr, &rnd, hash.digest().data(), sig);
		default:
			return 0;
		}
	};

	if (do_sign_rsa()) {
		write_string(ret, signature_algorithm);
		write_string(ret, to_string(sig));
	}

	return ret;
}

bool private_key_rsa::set_values(std::string_view const& n, std::string_view const& e, std::string_view const& d, std::string_view const& p, std::string_view const& q, std::string_view const& iqmp)
{
	pub_.clear();

	if (n.empty() || e.empty() || d.empty() || p.empty() || q.empty() || iqmp.empty()) {
		return false;
	}

	mpz_import(rsa_pub_.e, e.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(e.data()));
	mpz_import(rsa_pub_.n, n.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(n.data()));
	if (mpz_sizeinbase(rsa_pub_.n, 2) < 1024) {
		return false;
	}

	if (nettle_rsa_public_key_prepare(&rsa_pub_) != 1) {
		return false;
	}

	mpz_import(priv_.d, d.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(d.data()));
	mpz_import(priv_.p, p.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(p.data()));
	mpz_import(priv_.q, q.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(q.data()));
	mpz_import(priv_.c, iqmp.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(iqmp.data()));

	mpz p1;
	mpz_sub_ui(p1, priv_.p, 1);
	mpz_fdiv_r(priv_.a, priv_.d, p1);

	mpz q1;
	mpz_sub_ui(q1, priv_.q, 1);
	mpz_fdiv_r(priv_.b, priv_.d, q1);

	if (nettle_rsa_private_key_prepare(&priv_) != 1) {
		return false;
	}

	write_string(pub_, "ssh-rsa"sv);
	write_mpint(pub_, to_string(rsa_pub_.e));
	write_mpint(pub_, to_string(rsa_pub_.n));

	return selftest();
}

bool private_key_rsa::parse_openssh_blob(std::string_view & data)
{
	pub_.clear();

	// Oddly, the order of n and e is swapped compared to ssh-rsa pubkeys
	auto n = extract_blob(data);
	auto e = extract_blob(data);
	auto d = extract_blob(data);
	auto iqmp = extract_blob(data);
	auto p = extract_blob(data);
	auto q = extract_blob(data);

	if (!n || !e || !d || !p || !q || !iqmp) {
		return false;
	}
	return set_values(*n, *e, *d, *p, *q, *iqmp);
}

bool private_key_rsa::parse_putty_blobs(std::string_view pub, std::string_view priv)
{
	pub_.clear();

	// And here, iqmp is in a different position
	auto e = extract_blob(pub);
	auto n = extract_blob(pub);
	auto d = extract_blob(priv);
	auto p = extract_blob(priv);
	auto q = extract_blob(priv);
	auto iqmp = extract_blob(priv);

	if (!n || !e || !d || !p || !q || !iqmp) {
		return false;
	}
	return set_values(*n, *e, *d, *p, *q, *iqmp);
}

bool private_key_rsa::parse_der(std::string_view data)
{
	pub_.clear();

	// RFC 3447 describes contents of the ASN.1 blob

	auto sequence = parseDer(data, ASN1Type::Sequence);

	auto version = parseDer(sequence.data_, ASN1Type::Integer);
	if (!version) {
		return false;
	}
	if (version.data_.size() != 1 || version.data_[0] != 0) {
		return false;
	}

	auto n = parseDer(sequence.data_, ASN1Type::Integer).data_;
	auto e = parseDer(sequence.data_, ASN1Type::Integer).data_;
	auto d = parseDer(sequence.data_, ASN1Type::Integer).data_;
	auto p = parseDer(sequence.data_, ASN1Type::Integer).data_;
	auto q = parseDer(sequence.data_, ASN1Type::Integer).data_;
	parseDer(sequence.data_, ASN1Type::Integer); // we recompute these cheap values
	parseDer(sequence.data_, ASN1Type::Integer); // we recompute these cheap values
	auto iqmp = parseDer(sequence.data_, ASN1Type::Integer).data_;

	return set_values(n, e, d, p, q, iqmp);

}

namespace {
void der_encode(std::string& out, mpz_t const& v)
{
	auto s = to_string(v);
	size_t octets = s.size();
	if (s[0] & 0x80) {
		++octets;
	}

	out += static_cast<char>(ASN1Type::Integer);
	der_encode_length(out, octets);
	if (s[0] & 0x80) {
		out += '\0';
	}
	out += s.to_view();
}
}

bool private_key_rsa::export_pkcs8(std::string & out) const
{
	if (pub_.empty()) {
		return false;
	}

	std::string oid;
	if (!der_encode_oid(oid, "1.2.840.113549.1.1.1"sv)) {
		return false;
	}
	der_encode(oid, {}, ASN1Type::Null, false);

	der_encode(out, oid, ASN1Type::Sequence, true);

	std::string seq;
	der_encode(seq, 0);

	der_encode(seq, rsa_pub_.n);
	der_encode(seq, rsa_pub_.e);
	der_encode(seq, priv_.d);
	der_encode(seq, priv_.p);
	der_encode(seq, priv_.q);
	der_encode(seq, priv_.a);
	der_encode(seq, priv_.b);
	der_encode(seq, priv_.c);

	std::string inner;
	der_encode(inner, seq, ASN1Type::Sequence, true);
	der_encode(out, inner, ASN1Type::OctetString, false);

	return true;
}

std::unique_ptr<concrete_private_key_impl> create_concrete_key(std::string_view const& alg, bool generate)
{
	std::unique_ptr<concrete_private_key_impl> ret;
	if (alg == "ssh-ed25519"sv) {
		ret = std::make_unique<private_key_ed25519>();
	}
	else if (alg == "ecdsa-sha2-nistp256"sv) {
		ret = std::make_unique<private_key_ecdsa_sha2_nistp>(nistp_curve::nistp256);
	}
	else if (alg == "ecdsa-sha2-nistp384"sv) {
		ret = std::make_unique<private_key_ecdsa_sha2_nistp>(nistp_curve::nistp384);
	}
	else if (alg == "ecdsa-sha2-nistp521"sv) {
		ret = std::make_unique<private_key_ecdsa_sha2_nistp>(nistp_curve::nistp521);
	}
	else if (alg == "ssh-rsa"sv) {
		ret = std::make_unique<private_key_rsa>();
	}
	else if (alg == "rsa-sha2-256"sv) {
		ret = std::make_unique<private_key_rsa>();
	}
	else if (alg == "rsa-sha2-512"sv) {
		ret = std::make_unique<private_key_rsa>();
	}
	if (ret && generate && !ret->generate()) {
		ret.reset();
	}
	return ret;
}

std::unique_ptr<private_key> create_private_key(std::string_view const& alg)
{
	return create_concrete_key(alg, true);
}

std::string FZSSH_PUBLIC_SYMBOL export_pkcs8(std::unique_ptr<private_key> const& key, bool pem)
{
	auto concrete = dynamic_cast<concrete_private_key*>(key.get());
	if (!concrete) {
		return {};
	}

	std::string seq;
	der_encode(seq,  0);
	if (!concrete->export_pkcs8(seq)) {
		return {};
	}

	std::string der;
	der_encode(der, seq, ASN1Type::Sequence, true);

	if (!pem) {
		return der;
	}
	else {
		std::string ret{"-----BEGIN PRIVATE KEY-----\n"sv};

		auto append_splitted = [&ret](std::string_view str) {
			for (auto v = str; !v.empty();) {
				auto out = v.substr(0, 72);
				ret += out;
				v.remove_prefix(out.size());
				ret += "\n";
			}
		};

		append_splitted(fz::base64_encode(der));

		ret += "-----END PRIVATE KEY-----"sv;

		return ret;
	}
}

}
