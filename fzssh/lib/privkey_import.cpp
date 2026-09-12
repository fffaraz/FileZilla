#include "asn1.hpp"
#include "buffer_util.hpp"
#include "cipher.hpp"
#include "privkey.hpp"

#include "crypt/bcrypt.hpp"

#include <argon2.h>

#include <libfilezilla/file.hpp>
#include <libfilezilla/hash.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/translate.hpp>
#include <libfilezilla/util.hpp>

#include <nettle/aes.h>
#include <nettle/cbc.h>
#include <nettle/des.h>

#include <string.h>

namespace fz::ssh {

namespace {
void load_openssh_private_key(std::vector<private_key_info> & keys, std::string_view data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	auto constexpr magic = "openssh-key-v1\0"sv;
	if (!fz::starts_with(data, magic)) {
		return;
	}
	logger.log(logmsg::debug_info, "Decoding OpenSSH private key block"sv);

	auto const original_data = data;

	data.remove_prefix(magic.size());

	auto ciphername = extract_string(data, string_type::ascii, false);
	auto kdfname = extract_string(data, string_type::ascii, false);
	auto kdfoptions = extract_string(data, string_type::blob, true);
	uint32_t count{};
	if (!ciphername || !kdfname || !kdfoptions || !extract_uint32(data, count) || !count || count > data.size() / 8) {
		logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
		return;
	}

	std::unique_ptr<cipher_base> cipher;
	if (*ciphername != "none"sv) {
		cipher = create_cipher(*ciphername);
		if (!cipher	) {
			logger.log(logmsg::debug_warning, "Cannot load encrypted OpenSSH private key, cipher %s is not supported"sv, *ciphername);
			return;
		}
		if (*kdfname != "bcrypt"sv) {
			logger.log(logmsg::debug_warning, "Cannot load encrypted OpenSSH private key, key derivation function %s is not supported"sv, *kdfname);
			return;
		}

		auto salt = extract_string(*kdfoptions, string_type::blob, false);
		uint32_t rounds{};
		if (!salt || !extract_uint32(*kdfoptions, rounds) || !rounds) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}

		if (password) {
			auto key = openssh_bcrypt(*password, *salt, rounds, cipher->key_size() + cipher->iv_size());
			cipher->set_key(std::string_view(key).substr(0, cipher->key_size()));
			std::vector<uint8_t> iv(key.data() + cipher->key_size(), key.data() + cipher->key_size() + cipher->iv_size());
			cipher->set_iv(reinterpret_cast<uint8_t const*>(key.data() + cipher->key_size()), cipher->iv_size());
			wipe(key);
		}
	}

	std::vector<std::string_view> rawpubs;
	for (size_t i = 0; i < count; ++i) {
		auto pub = extract_blob(data);
		if (!pub) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		rawpubs.emplace_back(*pub);
	}

	// In case of a AEAD cipher, OpenSSH's PROTOCOL.key omits to mention what to do wrt.
	// authenticated data, and where the tag goes, but this is how it works:
	// - Length is ciphertext length
	// - There is no authenticated data
	// - Auth tag directly follows the ciphertext

	uint32_t privlen{};
	if (!extract_uint32(data, privlen)) {
		logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
		return;
	}
	size_t const authlen = cipher ? cipher->auth_size() : 0;
	if (data.size() < privlen + authlen) {
		logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
		return;
	}

	auto privdata = data.substr(0, privlen + authlen);
	data.remove_prefix(privlen + authlen);

	if (cipher && !password) {
		for (size_t i = 0; i < count; ++i) {
			auto pub = load_public_key(rawpubs[i], get_null_logger());
			if (!pub) {
				logger.log(logmsg::debug_warning, "Skipping encrypted key with invalid or unsupported public key blob"sv);
				continue;
			}

			logger.log(logmsg::debug_info, "Found encrypted OpenSSH key of type %s"sv, pub->name());

			private_key_info info;
			info.pubkey_ = std::move(pub);
			info.ciphertext_ = original_data;
			info.type_ = "OPENSSH PRIVATE KEY"sv;
			keys.emplace_back(std::move(info));
		}
		return;
	}

	std::string decoded;
	fz::scoped_wiper w(decoded);

	bool decrypted{};
	if (cipher) {
		decoded = privdata;
		decrypted = cipher->decrypt(reinterpret_cast<uint8_t*>(decoded.data()), decoded.size());
		privdata = decoded;
		privdata.remove_suffix(authlen);
	}
	else {
		decrypted = true;
	}

	uint32_t checkint1{}, checkint2{};
	// Also look at the length of the key algo of the first key, as just comparing the integers still randomly succeeds with probability of 1/2^32
	if (!decrypted || !extract_uint32(privdata, checkint1) || !extract_uint32(privdata, checkint2) || checkint1 != checkint2 || privdata.size() < 4 || read_uint32(privdata.data()) >= privdata.size() - 4) {
		if (!cipher) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}

		for (size_t i = 0; i < count; ++i) {
			auto pub = load_public_key(rawpubs[i], get_null_logger());
			if (!pub) {
				logger.log(logmsg::debug_warning, "Skipping encrypted key with invalid or unsupported public key blob"sv);
				continue;
			}

			logger.log(logmsg::debug_info, "Found encrypted OpenSSH key of type %s"sv, pub->name());

			private_key_info info;
			info.pubkey_ = std::move(pub);
			info.ciphertext_ = original_data;
			info.type_ = "OPENSSH PRIVATE KEY"sv;
			keys.emplace_back(std::move(info));
		}
		return;
	}

	for (size_t i = 0; i < count; ++i) {
		auto type = extract_string(privdata, string_type::ascii, false);
		if (!type) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		auto key = create_concrete_key(*type, false);
		if (!key) {
			logger.log(logmsg::debug_warning, "Unsupported private key algorithm"sv);
			return;
		}
		if (!key->parse_openssh_blob(privdata)) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		if (key->pubkey_blob() != rawpubs[i]) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		auto comment = extract_string(privdata, string_type::utf8, true);
		if (!comment) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		key->comment_ = *comment;

		logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, key->name());

		private_key_info info;
		info.privkey_ = std::move(key);
		keys.emplace_back(std::move(info));
	}

	return;
}

std::unique_ptr<private_key> load_ec_der_key(std::string_view data, fz::logger_interface & logger)
{
	logger.log(logmsg::debug_verbose, "Decoding key as ECPrivateKey structure"sv);

	// Get the curve identifier.
	// Structure in RFC 5915
	auto d = data;
	ASN1Value seq = parseDer(d, ASN1Type::Sequence);
	auto version = parseDer(seq.data_, ASN1Type::Integer);
	if (!version) {
		logger.log(logmsg::debug_verbose, "Malformed ECPrivateKey structure");
		return {};
	}
	if (version.data_ != "\x01"sv) {
		logger.log(logmsg::debug_verbose, "Unsupported version in ECPrivateKey structure");
		return {};
	}
	parseDer(seq.data_, ASN1Type::OctetString);
	auto choice = parseDer(seq.data_, ASN1Class::context_specific, 0);
	auto oid = parse_oid(parseDer(choice.data_, ASN1Type::ObjectIdentifier));
	if (oid.empty()) {
		logger.log(logmsg::debug_verbose, "Malformed ECPrivateKey structure");
		return {};
	}

	logger.log(logmsg::debug_verbose, "Input looks like a ECPrivateKey structure");

	std::string_view cipher;
	if (oid == "1.2.840.10045.3.1.7"sv) {
		cipher = "ecdsa-sha2-nistp256"sv;
	}
	else if (oid == "1.3.132.0.34"sv) {
		cipher = "ecdsa-sha2-nistp384"sv;
	}
	else if (oid == "1.3.132.0.35"sv) {
		cipher = "ecdsa-sha2-nistp521"sv;
	}
	else {
		logger.log(logmsg::debug_warning, "ECPrivateKey structure with unsupported algorithm %s", oid);
		return {};
	}
	auto key = create_concrete_key(cipher, false);
	if (!key || !key->parse_der(data)) {
		logger.log(logmsg::debug_warning, "Malformed ECPrivateKey, could not parse contained private key");
		return {};
	}

	logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, key->name());
	return key;
}

std::unique_ptr<private_key> load_pkcs8_der_key(std::string_view data, fz::logger_interface & logger)
{
	ASN1Value seq = parseDer(data, ASN1Type::Sequence);
	auto version = toUInt(parseDer(seq.data_, ASN1Type::Integer));
	if (!version || *version > 1) {
		return {};
	}

	// Version 0: RFC5208
	// Version 1: RFC5958

	auto algInfo = parseDer(seq.data_, ASN1Type::Sequence);
	auto oid1 = parse_oid(parseDer(algInfo.data_, ASN1Type::ObjectIdentifier));
	if (oid1.empty()) {
		return {};
	}
	logger.log(logmsg::debug_info, "Decoding private key as PKCS#8"sv);

	auto privblob = parseDer(seq.data_, ASN1Type::OctetString);
	if (privblob.data_.empty()) {
		logger.log(logmsg::debug_warning, "Malformed PKCS#8 structure"sv);
		return {};
	}

	std::string pubblob;
	bool pubblob_constructed{};
	while (auto opt = parseDer(seq.data_)) {
		if (opt.class_ != ASN1Class::context_specific) {
			logger.log(logmsg::debug_warning, "Malformed PKCS#8 structure"sv);
			return {};
		}
		if (!opt.tag_) {
			// Attributes
		}
		else if (opt.tag_ == 1) {
			pubblob = opt.data_;
			pubblob_constructed = opt.constructed_;
		}
	}

	std::string_view cipher;
	if (oid1 == "1.2.840.10045.2.1"sv) {
		auto oid2 = parse_oid(parseDer(algInfo.data_, ASN1Type::ObjectIdentifier));
		if (oid2.empty()) {
			logger.log(logmsg::debug_warning, "Malformed PKCS#8 structure"sv);
			return {};
		}
		else if (oid2 == "1.2.840.10045.3.1.7"sv) {
			cipher = "ecdsa-sha2-nistp256"sv;
		}
		else if (oid2 == "1.3.132.0.34"sv) {
			cipher = "ecdsa-sha2-nistp384"sv;
		}
		else if (oid2 == "1.3.132.0.35"sv) {
			cipher = "ecdsa-sha2-nistp521"sv;
		}
		else {
			logger.log(logmsg::debug_warning, "PKCS#8 structure with unsupported algorithm %s"sv, oid2);
			return {};
		}
	}
	else if (oid1 == "1.2.840.113549.1.1.1"sv) {
		cipher = "ssh-rsa"sv;
	}
	else if (oid1 == "1.3.101.112"sv) {
		cipher = "ssh-ed25519"sv;
	}
	else if (oid1 == "1.3.101.113"sv) {
		cipher = "ssh-ed448"sv;
	}
	else {
		logger.log(logmsg::debug_warning, "PKCS#8 structure with unsupported algorithm %s"sv, oid1);
		return {};
	}
	auto key = create_concrete_key(cipher, false);
	if (!key || !key->parse_inner_pkcs8(privblob.data_, pubblob, pubblob_constructed)) {
		logger.log(logmsg::debug_warning, "Malformed PKCS#8 structure, could not parse contained private key"sv);
		return {};
	}

	logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, key->name());

	return key;
}

namespace {
struct common_kdf_params {
	common_kdf_params(std::string_view salt, uint64_t iterations)
		: salt_(salt)
		, iterations_(iterations)
	{}

	std::string_view salt_;
	uint64_t iterations_{};
};

std::optional<common_kdf_params> get_common_kdf_params(std::string_view & data, fz::logger_interface & logger)
{
	auto salt = parseDer(data, ASN1Type::OctetString).data_;
	if (salt.empty()) {
		logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, could not get salt"sv);
		return {};
	}
	auto iterations = toUInt(parseDer(data, ASN1Type::Integer));
	if (!iterations || !*iterations) {
		logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, could not get iteration count"sv);
		return {};
	}

	return common_kdf_params{salt, *iterations};
}

secure_buffer pbkdf1(hash_algorithm alg, std::string_view const& password, common_kdf_params const& params)
{
	secure_buffer ret;
	hash_accumulator acc(alg);
	ret.resize(acc.digest_size());
	acc.update(password);
	acc.update(params.salt_);
	acc.digest(ret.data(), acc.digest_size());
	for (size_t i = 1; i < params.iterations_; ++i) {
		acc.reinit();
		acc.update(ret);
		acc.digest(ret.data(), acc.digest_size());
	}
	return ret;
}

struct pbkdf2_params : common_kdf_params {
	pbkdf2_params(common_kdf_params const& c, fz::hmac_algorithm h, uint64_t l)
		: common_kdf_params(c)
		, hmac(h)
		, keylen(l)
	{}

	fz::hmac_algorithm hmac{};
	uint64_t keylen{};
};

std::optional<pbkdf2_params> get_pbkdf2_params(std::string_view data, fz::logger_interface & logger)
{
	auto pbkdf2Parameters = parseDer(data, ASN1Type::Sequence).data_;

	auto common = get_common_kdf_params(pbkdf2Parameters, logger);
	if (!common) {
		return {};
	}

	uint64_t keylen{};

	auto next = parseDer(pbkdf2Parameters);
	if (next.is(ASN1Type::Integer)) {
		auto v = toUInt(next);
		if (!v || !*v) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
			return {};
		}
		keylen = *v;
		next = parseDer(pbkdf2Parameters);
	}

	auto alg = fz::hmac_algorithm::sha1;
	if (next.is(ASN1Type::Sequence)) {
		auto func = parse_oid(parseDer(next.data_, ASN1Type::ObjectIdentifier));
		if (func.empty()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
			return {};
		}
		else if (func == "1.2.840.113549.2.7"sv) { // hmacWithSHA1
			alg = fz::hmac_algorithm::sha1;
		}
		else if (func == "1.2.840.113549.2.9"sv) { // hmacWithSHA256
			alg = fz::hmac_algorithm::sha256;
		}
		else if (func == "1.2.840.113549.2.11"sv) { // hmacWithSHA512
			alg = fz::hmac_algorithm::sha512;
		}
		else {
			logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported algorithm %s"sv, func);
			return {};
		}
	}

	return pbkdf2_params{*common, alg, keylen};
}


size_t get_v_by_hash(hash_algorithm alg)
{
	switch (alg) {
	case hash_algorithm::md5:
	case hash_algorithm::sha1:
	case hash_algorithm::sha256:
		return 512/8;
	case hash_algorithm::sha3_256:
	case hash_algorithm::sha384:
	case hash_algorithm::sha3_384:
	case hash_algorithm::sha512:
	case hash_algorithm::sha3_512:
		return 1024/8;
	}
	return {};
}


// Note: password needs to be encoded as BMPString, including terminating null
secure_buffer pkcs12_kdf(fz::hash_algorithm alg, std::string_view const& password, size_t keylen, common_kdf_params const& params, uint8_t id)
{
	// See RFC7292 section B.2. as correccted in errata 4356 how this works.

	if (!keylen) {
		return {};
	}

	hash_accumulator acc(alg);

	size_t const v = get_v_by_hash(alg);

	std::string D(v, static_cast<char>(id));

	auto repeat = [&](secure_buffer& out, std::string_view in, size_t v) {
		size_t len = out.size() + v * ((in.size() + v - 1) / v);
		out.reserve(len);
		while (out.size() < len) {
			out.append(in);
		}
		out.resize(len);
	};

	secure_buffer I;
	repeat(I, params.salt_, v);
	if (!password.empty()) {
		repeat(I, password, v);
	}


	auto const digest_size = get_digest_size(alg);
	size_t c = (keylen + digest_size - 1) / digest_size;

	secure_buffer ret;
	ret.reserve(c * digest_size);

	secure_buffer A;
	A.resize(digest_size);

	while (true) {

		// Step 6.A
		acc.reinit();
		acc.update(D);
		acc.update(I);
		acc.digest(A.data(), digest_size);
		for (size_t j = 1; j < params.iterations_; ++j) {
			acc.reinit();
			acc.update(A.data(), digest_size);
			acc.digest(A.data(), digest_size);
		}

		ret.append(A);

		if (ret.size() >= keylen) {
			break;
		}

		// Step 6.B
		secure_buffer B;
		repeat(B, A.to_view(), v);

		// Step 6.C
		auto pkcs12_adjust = [](uint8_t* block, uint8_t const* b, size_t v)
		{
			unsigned carry = 1; // the "+ 1" in I_j + B + 1

			for (size_t i = v; i-- > 0;) {
				unsigned sum = static_cast<unsigned>(block[i]) + b[i] + carry;
				block[i] = static_cast<uint8_t>(sum);
				carry = sum >> 8;
			}

			// Final carry is discarded: arithmetic is modulo 2^(8*v).
		};

		for (size_t off = 0; off < I.size(); off += v) {
			pkcs12_adjust(I.data() + off, B.data(), v);
		}
	}

	ret.resize(keylen);

	return ret;
}

bool remove_padding(secure_buffer & b, size_t block_size)
{
	if (b.empty()) {
		return false;
	}
	auto pslen = b[b.size() - 1];
	if (!pslen || pslen > block_size) {
		return false;
	}
	for (size_t i = 2; i <= pslen; ++i) {
		if (b[b.size() - i] != pslen) {
			return false;
		}
	}
	b.resize(b.size() - pslen);
	return true;
}
}

std::optional<private_key_info> load_encrypted_pkcs8_der_key(std::string_view data, fz::logger_interface & logger, std::optional<std::string_view> password)
{
	std::string_view d = data;
	ASN1Value seq = parseDer(d, ASN1Type::Sequence);

	auto algInfo = parseDer(seq.data_, ASN1Type::Sequence);
	auto ciphertext = parseDer(seq.data_, ASN1Type::OctetString).data_;
	auto oid = parse_oid(parseDer(algInfo.data_, ASN1Type::ObjectIdentifier));
	if (ciphertext.empty() || oid.empty()) {
		return {};
	}

	logger.log(logmsg::debug_info, "Input looks like an encrypted PKCS#8 structure"sv);

	auto params = parseDer(algInfo.data_, ASN1Type::Sequence);

	secure_buffer decrypted;

	if (oid == "1.2.840.113549.1.5.13"sv) {
		//pkcs5PBES2

		auto pbesInfo = parseDer(params.data_, ASN1Type::Sequence);
		auto pbesOid = parse_oid(parseDer(pbesInfo.data_, ASN1Type::ObjectIdentifier));
		if (pbesOid.empty()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
			return {};
		}

		if (pbesOid != "1.2.840.113549.1.5.12"sv) { // id-PBKDF2
			logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported algorithm %s"sv, pbesOid);
			return {};
		}

		auto kdfparams = get_pbkdf2_params(pbesInfo.data_, logger);
		if (!kdfparams) {
			return {};
		}

		auto encryptionInfo = parseDer(params.data_, ASN1Type::Sequence);
		auto encryption_oid = parse_oid(parseDer(encryptionInfo.data_, ASN1Type::ObjectIdentifier));
		if (encryption_oid.empty()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, no OID for encryption algorithm"sv);
			return {};
		}
		auto iv = parseDer(encryptionInfo.data_, ASN1Type::OctetString).data_;
		std::unique_ptr<cipher_base> cipher;
		if (encryption_oid == "2.16.840.1.101.3.4.1.42"sv) {
			cipher = create_cipher("aes256-cbc"sv);
		}
		else if (encryption_oid == "2.16.840.1.101.3.4.1.22"sv) {
			cipher = create_cipher("aes192-cbc"sv);
		}
		else if (encryption_oid == "2.16.840.1.101.3.4.1.2"sv) {
			cipher = create_cipher("aes128-cbc"sv);
		}
		else {
			logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported OID %s"sv, encryption_oid);
			return {};
		}
		if (!cipher) {
			logger.log(logmsg::debug_warning, "Cipher creation failed");
			return {};
		}

		if (!kdfparams->keylen) {
			kdfparams->keylen = cipher->key_size();
		}
		else if (kdfparams->keylen != cipher->key_size()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, contents of optional KeyLength field don't match cipher requirements"sv);
			return {};
		}

		if (!password) {
			private_key_info ret;
			ret.ciphertext_ = data;
			ret.type_ = "ENCRYPTED PRIVATE KEY"sv;
			return ret;
		}

		auto key = pbkdf2(kdfparams->hmac, *password, kdfparams->salt_, kdfparams->keylen, kdfparams->iterations_);
		if (key.empty()) {
			logger.log(logmsg::debug_warning, "Could not derive key"sv);
			return {};
		}

		if (ciphertext.size() % cipher->block_size()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, ciphertext length does not align with block size"sv);
			return {};
		}
		if (iv.size() != 16) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, wrong iv size"sv);
			return {};
		}

		cipher->set_iv(reinterpret_cast<uint8_t const*>(iv.data()), iv.size());
		cipher->set_key(key);

		decrypted.append(ciphertext);
		if (!cipher->decrypt(decrypted.data(), decrypted.size())) {
			logger.log(logmsg::debug_warning, "Bad ciphertext"sv);
			return {};
		}

		if (!remove_padding(decrypted, cipher->block_size())) {
			logger.log(logmsg::debug_warning, "Wrong password or corrupted private key"sv);
			return {};
		}
	}
	else if (oid == "1.2.840.113549.1.5.3"sv) { // DES+MD5, ses RFC8018
		auto kdfparams = get_common_kdf_params(params.data_, logger);
		if (!kdfparams) {
			return {};
		}

		if (!password) {
			private_key_info ret;
			ret.ciphertext_ = data;
			ret.type_ = "ENCRYPTED PRIVATE KEY"sv;
			return ret;
		}

		auto key = pbkdf1(hash_algorithm::md5, *password, *kdfparams);
		nettle_des_fix_parity(DES_KEY_SIZE, key.data(), key.data());

		if (ciphertext.size() % DES_BLOCK_SIZE) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, ciphertext length does not align with block size"sv);
			return {};
		}

		decrypted.resize(ciphertext.size());

		struct CBC_CTX(des_ctx, DES_BLOCK_SIZE) ctx;
		nettle_des_set_key(&ctx.ctx, key.data());
		CBC_SET_IV(&ctx, key.data() + DES_BLOCK_SIZE);
		CBC_DECRYPT(&ctx, nettle_des_decrypt, ciphertext.size(), decrypted.data(), reinterpret_cast<uint8_t const*>(ciphertext.data()));
		wipe(&ctx, sizeof(ctx));

		if (!remove_padding(decrypted, DES_BLOCK_SIZE)) {
			logger.log(logmsg::debug_warning, "Wrong password or corrupted private key"sv);
			return {};
		}
	}
	else if (oid == "1.2.840.113549.1.12.1.3"sv) {
		// 3DES CBC, rfc7292

		auto kdfparams = get_common_kdf_params(params.data_, logger);
		if (!kdfparams) {
			return {};
		}

		if (!password) {
			private_key_info ret;
			ret.ciphertext_ = data;
			ret.type_ = "ENCRYPTED PRIVATE KEY"sv;
			return ret;
		}

		auto pw = to_bmpstring(*password);
		if (!password->empty() && pw.empty()) {
			logger.log(logmsg::debug_warning, "Password not representable as BMPString"sv);
			return {};
		}
		pw.append(2, '\0');

		auto key = pkcs12_kdf(fz::hash_algorithm::sha1, pw.to_view(), DES3_KEY_SIZE, *kdfparams, 1);
		auto iv = pkcs12_kdf(fz::hash_algorithm::sha1, pw.to_view(), DES3_BLOCK_SIZE, *kdfparams, 2);

		if (ciphertext.size() % DES3_BLOCK_SIZE) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, ciphertext length does not align with block size"sv);
			return {};
		}

		decrypted.resize(ciphertext.size());

		struct CBC_CTX(des3_ctx, DES3_BLOCK_SIZE) ctx;
		nettle_des3_set_key(&ctx.ctx, key.data());
		CBC_SET_IV(&ctx, iv.data());
		CBC_DECRYPT(&ctx, nettle_des3_decrypt, ciphertext.size(), decrypted.data(), reinterpret_cast<uint8_t const*>(ciphertext.data()));
		wipe(&ctx, sizeof(ctx));

		if (!remove_padding(decrypted, DES_BLOCK_SIZE)) {
			logger.log(logmsg::debug_warning, "Wrong password or corrupted private key"sv);
			return {};
		}
	}


	if (decrypted.empty()) {
		return {};
	}

	auto priv = load_pkcs8_der_key(decrypted.to_view(), logger);
	if (!priv) {
		logger.log(logmsg::debug_warning, "Wrong password or corrupted private key"sv);
		return {};
	}

	private_key_info ret;
	logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, priv->name());
	ret.privkey_ = std::move(priv);

	return ret;
}

std::unique_ptr<private_key> load_rsa_der_key(std::string_view data, logger_interface & logger)
{
	auto key = create_concrete_key("ssh-rsa"sv, false);
	if (!key || !key->parse_der(data)) {
		return {};
	}

	logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, key->name());
	return key;
}

std::string_view get_content_info(std::string_view & in, logger_interface & logger)
{
	auto seq = parseDer(in, ASN1Type::Sequence);
	if (!seq) {
		return {};
	}

	auto contentType = parseDer(seq.data_, ASN1Type::ObjectIdentifier);
	if (!contentType) {
		return {};
	}
	auto typeOid = parse_oid(contentType);
	if (typeOid != "1.2.840.113549.1.7.1"sv) {
		logger.log(logmsg::debug_verbose, "Unsupported content type in ContentInfo: %s", typeOid);
		return {};
	}

	auto content = parseDer(seq.data_, ASN1Class::context_specific, 0);
	if (!content || !seq.data_.empty()) {
		return {};
	}

	auto contentData = parseDer(content.data_, ASN1Type::OctetString);
	if (!contentData || !content.data_.empty()) {
		return {};
	}

	if (!seq.data_.empty()) {
		return {};
	}

	return contentData.data_;
}

std::vector<private_key_info> load_pfx(std::string_view data, logger_interface & logger, std::optional<std::string_view> password, std::optional<size_t> index = std::nullopt)
{
	// See RFC 7292 overall, and RFC 2315 for ContentInfo
	auto original_input = data;

	ASN1Value seq = parseDer(data, ASN1Type::Sequence);
	auto version = parseDer(seq.data_, ASN1Type::Integer);
	if (!version) {
		return {};
	}
	if (version.data_ != "\x03"sv) {
		return {};
	}

	auto cdata = get_content_info(seq.data_, logger);
	if (cdata.empty()) {
		return {};
	}

	logger.log(logmsg::debug_verbose, "Input looks like a PKCS#12 structure"sv);

	auto mac_data = parseDer(seq.data_, ASN1Type::Sequence);
	if (mac_data) {
		auto digestInfo = parseDer(mac_data.data_, ASN1Type::Sequence);
		auto alg = parseDer(digestInfo.data_, ASN1Type::Sequence);
		auto oid = parse_oid(parseDer(alg.data_, ASN1Type::ObjectIdentifier));
		auto expected_digest = parseDer(digestInfo.data_, ASN1Type::OctetString);

		auto salt = parseDer(mac_data.data_, ASN1Type::OctetString);
		std::optional<uint64_t> iterations;
		if (mac_data.data_.empty()) {
			iterations = 1;
		}
		else {
			iterations = toUInt(parseDer(mac_data.data_, ASN1Type::Integer));
		}

		if (!expected_digest || !salt || !iterations || oid.empty() || !mac_data.data_.empty()) {
			logger.log(logmsg::debug_warning, "Malformed PKCS#12 structure"sv);
			return {};
		}

		hash_algorithm hash_alg{};
		hmac_algorithm hmac_alg{};
		if (oid == "2.16.840.1.101.3.4.2.1"sv) {
			hash_alg = hash_algorithm::sha256;
			hmac_alg = hmac_algorithm::sha256;
		}
		else if (oid == "2.16.840.1.101.3.4.2.4"sv) {
			hash_alg = hash_algorithm::sha512;
			hmac_alg = hmac_algorithm::sha512;
		}
		else {
			logger.log(logmsg::debug_warning, "PKCS#12 with unsupported digest algorithm %s"sv, oid);
			return {};
		}

		if (password) {
			auto bmppwd = to_bmpstring(*password);
			if (!password->empty() && bmppwd.empty()) {
				logger.log(logmsg::debug_warning, "Password not representable as BMPString"sv);
				return {};
			}
			bmppwd.append(2, '\0');
			auto key = pkcs12_kdf(hash_alg,bmppwd.to_view(), get_digest_size(hash_alg), common_kdf_params(salt.data_, *iterations), 3);

			hash_accumulator acc(hmac_alg, key.to_view());
			acc.update(cdata);
			secure_buffer b;
			b.resize(acc.digest_size());
			acc.digest(b.get(), acc.digest_size());

			if (!equal_consttime(b.to_view(), expected_digest.data_)) {
				logger.log(logmsg::debug_warning, "Wrong password or corrupted PKCS#12 structure"sv);
				return {};
			}
		}
	}

	if (!seq.data_.empty()) {
		logger.log(logmsg::debug_verbose, "Malformed PKCS#12 structure"sv);
		return {};
	}

	auto authSafeContents = parseDer(cdata, ASN1Type::Sequence);
	if (!authSafeContents) {
		logger.log(logmsg::debug_verbose, "Malformed PKCS#12 structure"sv);
		return {};
	}

	std::vector<private_key_info> ret;

	size_t i{};
	while (!authSafeContents.data_.empty()) {
		auto safeContents = get_content_info(authSafeContents.data_, logger);
		auto safeContentSeq = parseDer(safeContents, ASN1Type::Sequence);
		for (; !safeContentSeq.data_.empty(); ++i) {
			auto bagSeq = parseDer(safeContentSeq.data_, ASN1Type::Sequence);

			if (index && i != index) {
				continue;
			}

			auto bagType = parse_oid(parseDer(bagSeq.data_, ASN1Type::ObjectIdentifier));
			auto bagValue = parseDer(bagSeq.data_, ASN1Class::context_specific, 0);

			if (bagType.empty() || !bagValue) {
				logger.log(logmsg::debug_warning, "Malformed PKCS#12 structure"sv);
				return {};
			}

			if (bagType == "1.2.840.113549.1.12.10.1.1"sv) { // keyBag
				auto key = load_pkcs8_der_key(bagValue.data_, logger);
				if (key) {
					if (mac_data && !password) {
						// Mac data hasn't been verified yet.
						private_key_info einfo;
						einfo.ciphertext_.append(original_input);
						einfo.type_ = "PKCS#12"sv;
						einfo.headers_ = to_string(i);
						ret.emplace_back(std::move(einfo));
					}
					else {
						private_key_info info;
						info.pubkey_ = key->pubkey();
						info.privkey_ = std::move(key);
						ret.emplace_back(std::move(info));
					}
				}
			}
			else if (bagType == "1.2.840.113549.1.12.10.1.2"sv) { // pkcs8ShroudedKeyBag
				auto info = load_encrypted_pkcs8_der_key(bagValue.data_, logger, password);
				if (info) {
					if (info->encrypted()) {
						if (password) {
							continue;
						}
						if (mac_data) {
							// Mac data hasn't been verified yet.
							private_key_info einfo;
							einfo.ciphertext_.append(original_input);
							einfo.type_ = "PKCS#12"sv;
							einfo.headers_ = to_string(i);
							ret.emplace_back(std::move(einfo));
						}
						else {
							ret.emplace_back(std::move(*info));
						}
					}
					else {
						ret.emplace_back(std::move(*info));
					}
				}
			}
		}
	}

	return ret;
}

// Single keys, usually PEM encapsulated
std::optional<private_key_info> load_der_key(std::string_view label, std::string_view headers, std::string_view data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	bool encrypted{};
	std::string iv;
	size_t blocksize{};
	size_t keysize{};

	for (auto l : strtokenizer(headers, "\r\n"sv, true)) {
		trim(l);
		auto pos = l.find(':');
		if (pos == l.npos) {
			continue;
		}
		auto name = l.substr(0, pos);
		auto value = l.substr(pos + 1);
		trim(value);
		if (name == "Proc-Type"sv) {
			if (!starts_with(value, "4,"sv)) {
				logger.log(logmsg::debug_warning, "Unsupported encapsulated Proc-Type header found in key"sv);
				return {};
			}
			if (value == "4,ENCRYPTED"sv) {
				encrypted = true;
			}
		}
		else if (name == "DEK-Info"sv) {
			if (starts_with(value, "AES-128-CBC,"sv)) {
				value.remove_prefix(12);
				blocksize = AES_BLOCK_SIZE;
				keysize = AES128_KEY_SIZE;
			}
			else if (starts_with(value, "AES-192-CBC,"sv)) {
				value.remove_prefix(12);
				blocksize = AES_BLOCK_SIZE;
				keysize = AES192_KEY_SIZE;
			}
			else if (starts_with(value, "AES-256-CBC,"sv)) {
				value.remove_prefix(12);
				blocksize = AES_BLOCK_SIZE;
				keysize = AES256_KEY_SIZE;
			}
			else if (starts_with(value, "DES-EDE3-CBC,"sv)) {
				value.remove_prefix(13);
				blocksize = DES3_BLOCK_SIZE;
				keysize = DES3_KEY_SIZE;
			}
			else {
				logger.log(logmsg::debug_warning, "Key is encrypted with unsupported cipher"sv);
				return {};
			}
			iv = fz::hex_decode<std::string>(value);
			if (iv.size() != blocksize) {
				logger.log(logmsg::debug_warning, "Encrypted key has wrong IV size"sv);
				return {};
			}
		}
		// Ignore unknown headers
	}

	if (encrypted) {
		if (!blocksize) {
			logger.log(logmsg::debug_warning, "Encrypted key lacks DEK-Info header"sv);
			return {};
		}
		if (data.size() % blocksize) {
			logger.log(logmsg::debug_warning, "Encrypted key ciphertext doesn't align with blocksize"sv);
			return {};
		}

		if (!password) {
			private_key_info ret;
			ret.type_ = label;
			ret.headers_ = headers;
			ret.ciphertext_ = data;

			logger.log(logmsg::debug_info, "Found encrypted private key"sv);
			return ret;
		}

		// Proc-type: 4,ENCRYPTED
		// DEK-Info: DES-EDE3-CBC/AES-128-CBC,iv
		//
		// A = md5(pw|iv)
		// B = md5(A|pw|iv)
		// key = A|B

		std::string out;
		out.resize(data.size());

		hash_accumulator acc(hash_algorithm::md5);

		size_t c = (keysize + acc.digest_size() - 1) / acc.digest_size();

		secure_buffer key;
		key.resize(c * acc.digest_size());
		for (size_t i = 0; i < c; ++i) {
			acc.reinit();
			acc.update(key.get(), i * acc.digest_size());
			acc.update(*password);
			acc.update((uint8_t const*)iv.data(), 8);
			acc.digest(key.get() + i * acc.digest_size(), acc.digest_size());
		}
		key.resize(keysize);

		if (blocksize == 16) {
			switch (keysize) {
				case 16: {
					aes128_ctx ctx{};
					nettle_aes128_set_decrypt_key(&ctx, key.data());
					nettle_cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&nettle_aes128_decrypt), blocksize, reinterpret_cast<uint8_t*>(iv.data()), data.size(), reinterpret_cast<uint8_t*>(out.data()), reinterpret_cast<uint8_t const*>(data.data()));
					wipe(&ctx, sizeof(ctx));
					break;
				}
				case 24: {
					aes192_ctx ctx{};
					nettle_aes192_set_decrypt_key(&ctx, key.data());
					nettle_cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&nettle_aes192_decrypt), blocksize, reinterpret_cast<uint8_t*>(iv.data()), data.size(), reinterpret_cast<uint8_t*>(out.data()), reinterpret_cast<uint8_t const*>(data.data()));
					wipe(&ctx, sizeof(ctx));
					break;
				}
				case 32: {
					aes256_ctx ctx{};
					nettle_aes256_set_decrypt_key(&ctx, key.data());
					nettle_cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&nettle_aes256_decrypt), blocksize, reinterpret_cast<uint8_t*>(iv.data()), data.size(), reinterpret_cast<uint8_t*>(out.data()), reinterpret_cast<uint8_t const*>(data.data()));
					wipe(&ctx, sizeof(ctx));
					break;
				}
			}
		}
		else {
			des3_ctx ctx{};
			nettle_des3_set_key(&ctx, key.data());
			nettle_cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&nettle_des3_decrypt), blocksize, reinterpret_cast<uint8_t*>(iv.data()), data.size(), reinterpret_cast<uint8_t*>(out.data()), reinterpret_cast<uint8_t const*>(data.data()));
			wipe(&ctx, sizeof(ctx));
		}
		wipe(iv);
		auto ret = load_der_key(label, {}, out, logger, {});
		if (!ret) {
			ret.emplace();
			ret->type_ = label;
			ret->headers_ = headers;
			ret->ciphertext_ = data;
		}
		wipe(out);
		return ret;
	}


	std::optional<private_key_info> ret;
	if (!ret && (label == "ENCRYPTED PRIVATE KEY"sv || label.empty())) {
		ret = load_encrypted_pkcs8_der_key(data, logger, password);
	}
	if (!ret) {
		std::unique_ptr<private_key> key;
		if (label == "PRIVATE KEY"sv || label.empty()) {
			key = load_pkcs8_der_key(data, logger);
		}
		if (!key && (label == "EC PRIVATE KEY"sv || label.empty())) {
			key = load_ec_der_key(data, logger);
		}
		if (!key && (label == "RSA PRIVATE KEY"sv || label.empty())) {
			key = load_rsa_der_key(data, logger);
		}
		if (key) {
			ret.emplace();
			ret->privkey_ = std::move(key);
		}
	}

	return ret;
}

void process_decoded_pem_data(std::vector<private_key_info> & keys, std::string_view const& label, std::string_view headers, std::string_view data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	if (label == "OPENSSH PRIVATE KEY"sv) {
		load_openssh_private_key(keys, data, logger, password);
		return;
	}

	std::optional<private_key_info> key;
	if (label == "RSA PRIVATE KEY"sv) {
		key = load_der_key(label, headers, data, logger, password);
	}
	else if (label == "EC PRIVATE KEY"sv) {
		key = load_der_key(label, headers, data, logger, password);
	}
	else if (label == "PRIVATE KEY"sv) {
		key = load_der_key(label, {}, data, logger, password);
	}
	else if (label == "ENCRYPTED PRIVATE KEY"sv) {
		key = load_der_key(label, {}, data, logger, password);
	}
	if (key) {
		keys.emplace_back(std::move(*key));
	}
}

std::pair<std::string_view, std::string_view> split_key_value(std::string_view line)
{
	size_t pos = line.find(':');
	if (pos == std::string_view::npos) {
		return {};
	}
	auto key = line.substr(0, pos);
	auto value = line.substr(pos + 1);
	fz::trim(key);
	fz::trim(value);
	return {key, value};
}

std::optional<std::string_view> next_value(std::string_view const& expected, fz::strtokenizer<std::string_view const&, std::string_view>::iterator & it, fz::strtokenizer<std::string_view const&, std::string_view>::iterator const& end)
{
	if (it == end) {
		return {};
	}

	auto kv = split_key_value(*it);
	if (kv.first != expected) {
		it = end;
		return {};
	}
	++it;
	return kv.second;
}

size_t next_value_u(std::string_view const& expected, fz::strtokenizer<std::string_view const&, std::string_view>::iterator & it, fz::strtokenizer<std::string_view const&, std::string_view>::iterator const& end)
{
	auto v = next_value(expected, it, end);
	return v ? to_integral<size_t>(*v) : 0;
}

std::string get_blob(std::string_view const& expected, fz::strtokenizer<std::string_view const&, std::string_view>::iterator & it, fz::strtokenizer<std::string_view const&, std::string_view>::iterator const& end)
{
	auto lines = next_value_u(expected, it, end);
	if (!lines || it == end) {
		return {};
	}
	auto start = (*it).data();

	for (; lines && it != end; ++it, --lines) {}

	if (it == end) {
		return {};
	}
	return fz::base64_decode_s(std::string_view(start, (*it).data() - start));
}

std::optional<private_key_info> load_putty_private_key(std::string_view const& data, fz::strtokenizer<std::string_view const&, std::string_view>::iterator it, fz::strtokenizer<std::string_view const&, std::string_view>::iterator const& end, logger_interface & logger, std::optional<std::string_view> password)
{
	auto kv = split_key_value((*it).substr(20));
	++it;
	auto version = fz::to_integral_o<size_t>(kv.first);
	if (!version) {
		logger.log(logmsg::error, "Malformed PuTTY private key, could not read version"sv);
		return {};
	}
	if (*version != 2 && *version != 3) {
		logger.log(logmsg::error, "Cannot load PuTTY private key, unsupported version %u"sv, *version);
		return {};
	}

	auto privkey = create_concrete_key(kv.second, false);
	if (!privkey) {
		logger.log(logmsg::error, "Cannot load PuTTY private key, unsupported private key algorithm"sv);
		return {};
	}

	auto encryption_type = next_value("Encryption"sv, it, end);
	auto comment = next_value("Comment"sv, it, end);
	auto pubblob = get_blob("Public-Lines"sv, it, end);
	if (!encryption_type || !comment || pubblob.empty()) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}

	std::optional<std::string_view> derivation;
	size_t argon2_memory{};
	size_t argon2_passes{};
	size_t argon2_parallelism{};
	std::string argon2_salt;

	if (*encryption_type == "none"sv) {
		password = std::string_view();
	}
	else if (*encryption_type == "aes256-cbc"sv) {
		if (version == 3) {
			derivation = next_value("Key-Derivation"sv, it, end);
			if (!derivation) {
				logger.log(logmsg::error, "Malformed PuTTY private key"sv);
				return {};
			}
			if (*derivation != "Argon2id"sv && *derivation != "Argon2d"sv && *derivation != "Argon2i"sv) {
				logger.log(logmsg::error, "Cannot load PuTTY private key, unsupported key derivation"sv);
				return {};
			}
			argon2_memory = next_value_u("Argon2-Memory"sv, it, end);
			argon2_passes = next_value_u("Argon2-Passes"sv, it, end);
			argon2_parallelism = next_value_u("Argon2-Parallelism"sv, it, end);
			auto salt = next_value("Argon2-Salt"sv, it, end);
			argon2_salt = salt ? hex_decode<std::string>(*salt) : std::string{};
			if (!derivation || !argon2_memory || !argon2_passes || !argon2_parallelism || argon2_salt.empty()) {
				logger.log(logmsg::error, "Malformed PuTTY private key"sv);
				return {};
			}
		}
	}
	else {
		logger.log(logmsg::error, "Cannot load PuTTY private key, unsupported encryption algorithm"sv);
		return {};
	}

	auto privblob = get_blob("Private-Lines"sv, it, end);
	fz::scoped_wiper pw(privblob);
	if (privblob.empty()) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}

	std::vector<uint8_t> mac_key;
	fz::scoped_wiper mw(mac_key);
	if (encryption_type != "none"sv) {
		constexpr size_t blocksize = 16;

		if (privblob.size() % blocksize) {
			logger.log(logmsg::error, "Malformed PuTTY private key"sv);
			return {};
		}

		if (!password) {
			auto pub = load_public_key(pubblob, get_null_logger());
			if (!pub) {
				logger.log(logmsg::error, "PuTTY private key with invalid or unsupported public key blob"sv);
				return {};
			}
			pub->comment_ = *comment;

			private_key_info ret;
			ret.pubkey_ = std::move(pub);
			ret.ciphertext_ = data;
			ret.type_ = "PUTTY"sv;
			return ret;
		}

		if (version == 3) {
			std::string hash;
			fz::scoped_wiper hw(hash);
			hash.resize(32 + 16 + 32);

			auto func = [&]() {
				if (*derivation == "Argon2id"sv) {
					return &argon2id_hash_raw;
				}
				else if (*derivation == "Argon2i"sv) {
					return &argon2i_hash_raw;
				}
				else {
					return &argon2d_hash_raw;
				}
			}();
			if (func(argon2_passes, argon2_memory, argon2_parallelism, password->data(), password->size(), argon2_salt.data(), argon2_salt.size(), hash.data(), hash.size()) != ARGON2_OK) {
				logger.log(logmsg::error, "Argon2 hash failed"sv);
				return {};
			}

			aes256_ctx ctx;
			aes256_set_decrypt_key(&ctx, reinterpret_cast<unsigned char const*>(std::string_view(hash).substr(0, 32).data()));
			std::string iv = hash.substr(32, 16);
			cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&aes256_decrypt), blocksize, reinterpret_cast<unsigned char*>(iv.data()), privblob.size(), reinterpret_cast<unsigned char*>(privblob.data()), reinterpret_cast<unsigned char*>(privblob.data()));
			wipe(&ctx, sizeof(ctx));

			mac_key.resize(32);
			memcpy(mac_key.data(), hash.data() + 32 + 16, 32);
		}
		else {
			std::vector<uint8_t> key;
			key.resize(160/4);

			(hash_accumulator(hash_algorithm::sha1) << 0 << 0 << 0 << 0 << *password).digest(key.data(), 20);
			(hash_accumulator(hash_algorithm::sha1) << 0 << 0 << 0 << 1 << *password).digest(key.data() + 20, 20);

			aes256_ctx ctx;
			aes256_set_decrypt_key(&ctx, reinterpret_cast<unsigned char const*>(key.data()));
			std::string iv;
			iv.resize(16);
			cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&aes256_decrypt), blocksize, reinterpret_cast<unsigned char*>(iv.data()), privblob.size(), reinterpret_cast<unsigned char*>(privblob.data()), reinterpret_cast<unsigned char*>(privblob.data()));

			wipe(key);
			wipe(&ctx, sizeof(ctx));

			mac_key = hash_accumulator(hash_algorithm::sha1) << "putty-private-key-file-mac-key"sv << *password;
		}
	}
	else {
		if (version == 2) {
			mac_key = hash_accumulator(hash_algorithm::sha1) << "putty-private-key-file-mac-key"sv << *password;
		}
	}

	auto mac = next_value("Private-MAC", it, end);
	if (!mac) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}

	auto acc = hash_accumulator(*version == 2 ? hmac_algorithm::sha1 : hmac_algorithm::sha256, mac_key);
	acc.update_with_length(privkey->name());
	acc.update_with_length(*encryption_type);
	acc.update_with_length(*comment);
	acc.update_with_length(pubblob);
	acc.update_with_length(privblob);
	if (fz::hex_encode<std::string>(acc.digest()) != mac) {
		if (*encryption_type == "none"sv) {
			logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		}
		else {
			logger.log(logmsg::error, "Wrong password or corrupted PuTTY private key"sv);
		}
		return {};
	}

	std::string_view pubblob_v(pubblob);
	auto pname = extract_string(pubblob_v, string_type::ascii, false);
	if (!pname || *pname != privkey->name()) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}

	if (!privkey->parse_putty_blobs(pubblob_v, privblob)) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}
	if (pubblob != privkey->pubkey_blob()) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}

	privkey->comment_ = *comment;

	logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, privkey->name());

	private_key_info ret;
	ret.privkey_ = std::move(privkey);
	return ret;
}

std::vector<private_key_info> do_load_private_key_infos(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	std::vector<private_key_info> keys;

	auto d = data;
	if (parseDer(d) && d.empty()) {
		logger.log(logmsg::debug_info, "Input looks like a DER sequence."sv);
		auto key = load_der_key({}, {}, data, logger, password);
		if (key) {
			keys.emplace_back(std::move(*key));
		}
		else {
			keys = load_pfx(data, logger, password);
		}
		return keys;
	}

	auto lines = fz::strtokenizer(data, "\r\n"sv, true);
	auto it = lines.begin();

	if (it != lines.end() && fz::starts_with(*it, "PuTTY-User-Key-File-"sv)) {
		logger.log(logmsg::debug_info, "Input looks like a PuTTY private key"sv);
		auto info = load_putty_private_key(data, it, lines.end(), logger, password);
		if (info) {
			keys.emplace_back(std::move(*info));
		}
		return keys;
	}

	for (;it != lines.end(); ++it) {
		auto label = *it;
		if (!fz::starts_with(label, "-----BEGIN "sv) || !fz::ends_with(label, "-----"sv)) {
			continue;
		}

		label = label.substr(11, label.size() - 16);
		auto valid_label = [&]() {
			for (auto c : label) {
				if ((c < 0x21 && c != ' ') || c > 0x7e || c == '-') {
					return false;
				}
			}
			return true;
		};
		if (!valid_label()) {
			continue;
		}

		// Found valid label, look for end header
		if (++it == lines.end()) {
			logger.log(logmsg::error, "Invalid PEM, could not find end header for label '%s'"sv, label);
			return {};
		}
		auto headers = *it;
		std::string_view begin;
		for (; it != lines.end(); ++it) {
			auto line = *it;
			if (!begin.data() && line.find(':') == std::string_view::npos) {
				begin = line;
			}

			if (!fz::starts_with(line, "-----END "sv) || !fz::ends_with(line, "-----"sv)) {
				continue;
			}
			if (label == line.substr(9, line.size() - 14)) {
				break;
			}
		}
		if (it == lines.end() || !begin.data()) {
			logger.log(logmsg::error, "Invalid PEM, could not find end header for label '%s'"sv, label);
			return {};
		}

		auto size = std::size_t((*it).data() - begin.data());

		std::string_view encapsulated_headers(headers.data(), static_cast<size_t>(begin.data() - headers.data()));
		auto data = std::string_view(begin.data(), size);
		auto decoded = fz::base64_decode_s(data);
		if (decoded.empty()) {
			logger.log(logmsg::error, "Invalid PEM, could not base64-decode data"sv);
			return {};
		}

		process_decoded_pem_data(keys, label, encapsulated_headers, decoded, logger, password);
		wipe(decoded);
	}

	return keys;
}
}

std::vector<private_key_info> load_private_key_infos(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	auto infos = do_load_private_key_infos(data, logger, password);
	for (auto & i : infos) {
		if (i.privkey_ && !i.pubkey_) {
			i.pubkey_ = i.privkey_->pubkey();
		}
	}
	return infos;
}

std::vector<std::unique_ptr<private_key>> load_private_keys(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	std::vector<std::unique_ptr<private_key>> ret;

	auto infos = load_private_key_infos(data, logger, password);
	for (auto const& i : infos) {
		if (i.privkey_) {
			ret.emplace_back(i.privkey_->clone());
		}
	}

	return ret;
}

std::unique_ptr<private_key> load_private_key(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	auto keys = load_private_keys(data, logger, password);
	if (keys.empty()) {
		return {};
	}
	if (keys.size() > 1) {
		logger.log(logmsg::error, "Multiple keys in input detected."sv);
		return {};
	}
	else {
		return std::move(keys.front());
	}
}

bool private_key_info::encrypted() const
{
	return !ciphertext_.empty();
}

bool private_key_info::decrypt(std::string_view const& password, logger_interface *logger)
{
	if (privkey_) {
		return true;
	}

	std::unique_ptr<private_key> ret;
	auto const c = ciphertext_.to_view();
	if (type_ == "PUTTY"sv) {
		auto lines = fz::strtokenizer(c, "\r\n"sv, true);
		auto info = load_putty_private_key(c, lines.begin(), lines.end(), logger ? *logger : get_null_logger(), password);
		if (info) {
			*this = std::move(*info);
		}
	}
	else if (type_ == "PKCS#12"sv) {
		size_t index = to_integral<size_t>(headers_);
		auto infos = load_pfx(c, logger ? *logger : get_null_logger(), password, index);
		if (infos.size() == 1) {
			*this = std::move(infos[0]);
		}
	}
	else {
		std::vector<private_key_info> infos;
		process_decoded_pem_data(infos, type_, headers_, c, logger ? *logger : get_null_logger(), password);
		if (infos.size() == 1) {
			*this = std::move(infos[0]);
		}
	}

	if (privkey_ && !pubkey_) {
		pubkey_ = privkey_->pubkey();
	}

	return privkey_ != nullptr;
}

std::vector<private_key_info> load_private_key_file(native_string const& filename, logger_interface & logger, std::optional<std::string_view> const& password)
{
	secure_buffer b;
	if (!fz::read_file(filename, b, 256*1024)) {
		logger.log(logmsg::error, fztranslate("Could not read key file '%s'."), filename);
		return {};
	}

	auto ret =  load_private_key_infos(b.to_view(), logger, password);
	for (auto & i : ret) {
		i.name_ = fz::to_utf8(filename);
	}
	return ret;
}

}
