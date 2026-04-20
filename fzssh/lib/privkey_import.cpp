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
			cipher->set_iv(std::move(iv));
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

	auto privdata = extract_blob(data);
	if (!privdata) {
		logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
		return;
	}

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

	std::string decoded(*privdata);
	if (cipher) {
		cipher->decrypt(reinterpret_cast<uint8_t*>(decoded.data()), decoded.size(), nullptr, 0);
		privdata = decoded;
	}

	uint32_t checkint1{}, checkint2{};
	// Also look at the length of the key algo of the first key, as just comparing the integers still randomly succeeds with probability of 1/2^32
	if (!extract_uint32(*privdata, checkint1) || !extract_uint32(*privdata, checkint2) || checkint1 != checkint2 || privdata->size() < 4 || read_uint32(privdata->data()) >= privdata->size() - 4) {
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
		auto type = extract_string(*privdata, string_type::ascii, false);
		if (!type) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		auto key = create_concrete_key(*type, false);
		if (!key) {
			logger.log(logmsg::debug_warning, "Unsupported private key algorithm"sv);
			return;
		}
		if (!key->parse_openssh_blob(*privdata)) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		if (key->pubkey_blob() != rawpubs[i]) {
			logger.log(logmsg::debug_warning, "Malformed OpenSSH private key block"sv);
			return;
		}
		auto comment = extract_string(*privdata, string_type::utf8, true);
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
	logger.log(logmsg::debug_info, "Decoding key as ECPrivateKey structure"sv);

	// Get the curve identifier.
	// Structure in RFC 5915
	auto d = data;
	ASN1Value seq = parseDer(d, ASN1Type::Sequence);
	auto version = parseDer(seq.data_, ASN1Type::Integer);
	if (!version) {
		logger.log(logmsg::debug_warning, "Malformed ECPrivateKey structure");
		return {};
	}
	if (version.data_ != "\x01"sv) {
		logger.log(logmsg::debug_warning, "Unsupported version in ECPrivateKey structure");
		return {};
	}
	parseDer(seq.data_, ASN1Type::OctetString);
	auto choice = parseDer(seq.data_, ASN1Class::context_specific, 0);
	auto oid = parse_oid(parseDer(choice.data_, ASN1Type::ObjectIdentifier));
	if (oid.empty()) {
		logger.log(logmsg::debug_warning, "Malformed ECPrivateKey structure");
		return {};
	}

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


std::optional<private_key_info> load_encrypted_pkcs8_der_key(std::string_view data, fz::logger_interface & logger, std::optional<std::string_view> password)
{
	std::string_view d = data;
	ASN1Value seq = parseDer(d, ASN1Type::Sequence);

	auto algInfo = parseDer(seq.data_, ASN1Type::Sequence);
	auto ciphertext = parseDer(seq.data_, ASN1Type::OctetString).data_;
	auto oid = parse_oid(parseDer(algInfo.data_, ASN1Type::ObjectIdentifier));
	if (oid.empty()) {
		return {};
	}

	logger.log(logmsg::debug_info, "Inpput looks like an encrypted PKCS#8 structure"sv);

	if (oid == "1.2.840.113549.1.5.13"sv) {
		//pkcs5PBES2
		auto params = parseDer(algInfo.data_, ASN1Type::Sequence);

		auto pbesInfo = parseDer(params.data_, ASN1Type::Sequence);
		auto pbesOid = parse_oid(parseDer(pbesInfo.data_, ASN1Type::ObjectIdentifier));
		if (pbesOid.empty()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
			return {};
		}

		std::vector<uint8_t> key;
		if (pbesOid == "1.2.840.113549.1.5.12"sv) { // id-PBKDF2
			auto pbkdf2Parameters = parseDer(pbesInfo.data_, ASN1Type::Sequence);
			auto salt = parseDer(pbkdf2Parameters.data_, ASN1Type::OctetString).data_;
			if (salt.empty()) {
				logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
				return {};
			}
			auto iterations = toUInt(parseDer(pbkdf2Parameters.data_, ASN1Type::Integer));
			if (!iterations || !*iterations) {
				logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
				return {};
			}
			auto kdfSeq = parseDer(pbkdf2Parameters.data_, ASN1Type::Sequence);
			auto func = parse_oid(parseDer(kdfSeq.data_, ASN1Type::ObjectIdentifier));
			if (func.empty()) {
				logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
				return {};
			}
			else if (func == "1.2.840.113549.2.9"sv) { // hmacWithSHA256
				if (password) {
					key = pbkdf2_hmac_sha256(*password, salt, 32, *iterations);
				}
			}
			else {
				logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported algorithm %s"sv, func);
				return {};
			}
		}
		else {
			logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported algorithm %s"sv, pbesOid);
			return {};
		}

		if (!password) {
			private_key_info ret;
			ret.ciphertext_ = data;
			ret.type_ = "ENCRYPTED PRIVATE KEY"sv;
			return ret;
		}

		if (key.empty()) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure"sv);
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
		else if (encryption_oid == "2.16.840.1.101.3.4.1.2"sv) {
			cipher = create_cipher("aes128-cbc"sv);
		}

		if (!cipher || key.size() < cipher->key_size()) {
			logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported OID %s"sv, encryption_oid);
			return {};
		}

		key.resize(cipher->key_size());

		if (ciphertext.size() % 16) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, ciphertext length does not align with block size"sv);
			return {};
		}
		if (iv.size() != 16) {
			logger.log(logmsg::debug_warning, "Malformed encrypted PKCS#8 structure, wrong iv size"sv);
			return {};
		}

		std::vector<uint8_t> tmp;
		tmp.assign((uint8_t const*)iv.data(), (uint8_t const*)iv.data() + iv.size());
		cipher->set_iv(std::move(tmp));
		cipher->set_key(key);

		std::vector<uint8_t> buf;
		buf.assign((uint8_t const*)ciphertext.data(), (uint8_t const*)ciphertext.data() + ciphertext.size());
		cipher->decrypt(buf.data(), buf.size(), nullptr, 0);

		auto data = std::string_view(reinterpret_cast<char const*>(buf.data()), buf.size());

		auto priv = load_pkcs8_der_key(data, logger);
		if (!priv) {
			logger.log(logmsg::debug_warning, "Wrong password or corrupted private key"sv);
			return {};
		}

		private_key_info ret;
		logger.log(logmsg::debug_info, "Loaded private key of type %s"sv, priv->name());
		ret.privkey_ = std::move(priv);

		return ret;
	}
	else {
		logger.log(logmsg::debug_warning, "Encrypted PKCS#8 structure with unsupported algorithm %s"sv, oid);
	}

	return {};
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

std::optional<private_key_info> load_der_key(std::string_view label, std::string_view headers, std::string_view data, logger_interface & logger, std::optional<std::string_view> const& password)
{
	bool encrypted{};
	std::string iv;
	size_t blocksize{};

	for (auto l : strtokenizer(headers, "\r\n", true)) {
		trim(l);
		auto pos = l.find(':');
		if (pos == l.npos) {
			continue;
		}
		auto name = l.substr(0, pos);
		auto value = l.substr(pos + 1);
		trim(value);
		if (name == "Proc-Type") {
			if (!starts_with(value, "4,"sv)) {
				logger.log(logmsg::debug_warning, "Unsupported encapsulated Proc-Type header found in key"sv);
				return {};
			}
			if (value == "4,ENCRYPTED"sv) {
				encrypted = true;
			}
		}
		else if (name == "DEK-Info") {
			if (starts_with(value, "AES-128-CBC,"sv)) {
				value.remove_prefix(12);
				blocksize = 16;
			}
			else if (starts_with(value, "DES-EDE3-CBC,"sv)) {
				value.remove_prefix(13);
				blocksize = 8;
			}
			else {
				logger.log(logmsg::debug_warning, "Key is encrypted with unsupported cipher"sv);
				return {};
			}
			iv = fz::hex_decode<std::string>(value);
			if (iv.size() != blocksize) {
				logger.log(logmsg::debug_warning, "Encrypted  key has wrong IV size"sv);
				return {};
			}
		}
		// Ignore unknown headers
	}

	if (encrypted) {
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

		uint8_t key[32];
		hash_accumulator acc(hash_algorithm::md5);
		acc.update(*password);
		acc.update((uint8_t const*)iv.data(), 8);
		acc.digest(key, 16);

		acc.reinit();
		acc.update(key, 16);
		acc.update(*password);
		acc.update((uint8_t const*)iv.data(), 8);
		acc.digest(key + 16, 16);

		if (blocksize == 16) {
			aes128_ctx ctx{};
			nettle_aes128_set_decrypt_key(&ctx, key);
			nettle_cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&nettle_aes128_decrypt), blocksize, reinterpret_cast<uint8_t*>(iv.data()), data.size(), reinterpret_cast<uint8_t*>(out.data()), reinterpret_cast<uint8_t const*>(data.data()));
		}
		else {
			des3_ctx ctx{};
			nettle_des3_set_key(&ctx, key);
			nettle_cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&nettle_des3_decrypt), blocksize, reinterpret_cast<uint8_t*>(iv.data()), data.size(), reinterpret_cast<uint8_t*>(out.data()), reinterpret_cast<uint8_t const*>(data.data()));
		}
		wipe(iv);
		wipe(key, 32);
		auto ret = load_der_key(label, {}, out, logger, {});
		if (!ret) {
			ret.emplace();
			ret->type_ = label;
			ret->headers_ = headers;
			ret->ciphertext_ = data;
		}
		wipe (out);
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
	if (privblob.empty()) {
		logger.log(logmsg::error, "Malformed PuTTY private key"sv);
		return {};
	}

	std::vector<uint8_t> mac_key;
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

		std::string hash;

		if (version == 3) {
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

			mac_key.resize(32);
			memcpy(mac_key.data(), hash.data() + 32 + 16, 32);
		}
		else {
			auto k1 = (hash_accumulator(hash_algorithm::sha1) << 0 << 0 << 0 << 0 << *password).digest();
			auto k2 = (hash_accumulator(hash_algorithm::sha1) << 0 << 0 << 0 << 1 << *password).digest();
			k1.insert(k1.end(), k2.begin(), k2.begin() + 12);

			aes256_ctx ctx;
			aes256_set_decrypt_key(&ctx, reinterpret_cast<unsigned char const*>(k1.data()));
			std::string iv;
			iv.resize(16);
			cbc_decrypt(&ctx, reinterpret_cast<nettle_cipher_func*>(&aes256_decrypt), blocksize, reinterpret_cast<unsigned char*>(iv.data()), privblob.size(), reinterpret_cast<unsigned char*>(privblob.data()), reinterpret_cast<unsigned char*>(privblob.data()));

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

		auto headers = *++it;
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
	if (type_ == "PUTTY"sv) {
		auto const c = std::string_view(ciphertext_);
		auto lines = fz::strtokenizer(c, "\r\n"sv, true);
		auto info = load_putty_private_key(ciphertext_, lines.begin(), lines.end(), logger ? *logger : get_null_logger(), password);
		if (info) {
			*this = std::move(*info);
		}
	}
	else {
		std::vector<private_key_info> infos;
		process_decoded_pem_data(infos, type_, headers_, ciphertext_, logger ? *logger : get_null_logger(), password);
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
	fz::buffer b;
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
