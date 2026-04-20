#include "fzssh/pubkey.hpp"

#include "buffer_util.hpp"
#include "mpz.hpp"
#include "ecc.hpp"

#include <libfilezilla/encode.hpp>
#include <libfilezilla/hash.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/util.hpp>

#include <nettle/ecc-curve.h>
#include <nettle/ecdsa.h>
#include <nettle/eddsa.h>
#include <nettle/rsa.h>

namespace fz::ssh {

std::string to_openssh_pubkey(std::string_view const& name, std::string_view const& key, std::string const& comment)
{
	if (key.empty()) {
		return {};
	}

	std::string ret{name};
	ret += ' ';
	base64_encode_append(ret, key, base64_type::standard, false);
	if (!comment.empty()) {
		ret += ' ';
		ret += comment;
	}
	return ret;
}

std::string to_rfc4716_pubkey(std::string_view const& key, std::string const& comment)
{
	if (key.empty()) {
		return {};
	}

	std::string ret{"---- BEGIN SSH2 PUBLIC KEY ----\n"sv};

	auto append_splitted = [&ret](std::string_view str, std::string_view eol = {}) {
		for (auto v = str; !v.empty();) {
			auto out = v.substr(0, 72 - eol.size());
			ret += out;
			v.remove_prefix(out.size());
			if (!v.empty()) {
				ret += eol;
			}
			ret += "\n";
		}
	};

	if (!comment.empty()) {
		append_splitted("comment: \"" + comment + "\"", "\\"sv);
	}

	append_splitted(fz::base64_encode(key));

	ret += "---- END SSH2 PUBLIC KEY ----"sv;

	return ret;
}

std::string public_key::openssh_pubkey() const
{
	return to_openssh_pubkey(name(), key_, comment_);
}

std::string public_key::rfc4716_pubkey() const
{
	return to_rfc4716_pubkey(key_, comment_);
}


namespace {
std::string prefix(hash_algorithm alg)
{
	switch (alg)
	{
	case hash_algorithm::md5:
		return "MD5:";
	case hash_algorithm::sha1:
		return "SHA1:";
	case hash_algorithm::sha256:
		return "SHA256:";
	case hash_algorithm::sha384:
		return "SHA384:";
	case hash_algorithm::sha512:
		return "SHA512:";
	default:
		return {};
	}
}
}

std::string fingerprint_from_blob(std::string_view const& blob, hash_algorithm alg, bool base64)
{
	if (blob.empty()) {
		return {};
	}

	hash_accumulator acc(alg);
	acc.update(blob);
	if (base64) {
		return prefix(alg) + base64_encode(acc.digest(), base64_type::standard, false);
	}
	else {
		auto h = hex_encode<std::string>(acc.digest());
		std::string ret;
		for (size_t i = 0; i < h.size(); i += 2) {
			ret += h[i] + h[i];
			ret += ':';
		}
		ret.pop_back();
		return ret;
	}
}

std::string public_key::fingerprint(hash_algorithm alg, bool base64) const
{
	return fingerprint_from_blob(key_, alg, base64);
}

class public_key_ed25519 final : public public_key
{
public:
	virtual std::string_view name() const override {
		return "ssh-ed25519"sv;
	}

	virtual std::unique_ptr<public_key> clone() const override {
		if (key_.empty()) {
			return {};
		}
		auto ret = std::make_unique<public_key_ed25519>();
		ret->key_ = key_;
		ret->comment_ = comment_;
		return ret;
	}

	virtual bool parse(std::string_view key) override;
	virtual bool parse_putty(std::string_view key) override;
	virtual bool verify(std::string_view const& data, std::string_view sig) const override;
};

bool public_key_ed25519::parse(std::string_view key)
{
	key_.clear();

	auto const inkey = key;

	auto n = extract_blob(key);
	if (!n || *n != name()) {
		return false;
	}

	auto k = extract_blob(key);
	if (!k || k->size() != 32) {
		return false;
	}

	if (!key.empty()) {
		return false;
	}
	key_ = inkey;

	return true;
}

namespace {
std::string putty_hex_decode(std::string_view data, bool reverse, size_t pad)
{
	if (!starts_with(data, "0x"sv)) {
		return {};
	}
	data.remove_prefix(2);

	std::string ret;
	size_t expected = (data.size() + 1) / 2;
	if (data.size() % 2) {
		ret += static_cast<char>(fz::hex_char_to_int(data.front()));
		data.remove_prefix(1);
	}
	ret += fz::hex_decode<std::string>(data);
	if (ret.size() != expected) {
		return {};
	}
	if (reverse) {
		std::reverse(ret.begin(), ret.end());
		if (ret.size() < pad) {
			ret.append(pad - ret.size(), '\0');
		}
	}
	else {
		if (ret.size() < pad) {
			ret = std::string(pad - ret.size(), '\0') + ret;
		}
	}
	return ret;
}
}

bool public_key_ed25519::parse_putty(std::string_view key)
{
	key_.clear();

	auto tokens = strtok(key, ',', false);
	if (tokens.size() != 2) {
		return false;
	}

	auto x = putty_hex_decode(tokens[0], true, 32);
	auto y = putty_hex_decode(tokens[1], true, 32);
	if (x.size() != 32 || y.size() != 32) {
		return false;
	}

	// Point compression, set sign of x coordinate to y
	auto c = static_cast<unsigned char>(y.back());
	c &= 0x7fu;
	c |= (static_cast<unsigned char>(x.front()) & 0x1u) << 7u;
	y.back() = static_cast<char>(c);

	fz::buffer buf;
	write_string(buf, name());
	write_string(buf, y);
	key_ = buf.to_view();

	return true;
}

bool public_key_ed25519::verify(std::string_view const& data, std::string_view sig) const
{
	if (key_.empty() || data.empty()) {
		return false;
	}
	auto n = extract_string(sig, string_type::ascii, false);
	if (!n || *n != name()) {
		return false;
	}
	auto s = extract_blob(sig);
	if (!s || s->size() != 64) {
		return false;
	}

	return nettle_ed25519_sha512_verify(reinterpret_cast<uint8_t const*>(key_.data() + key_.size() - 32), data.size(), reinterpret_cast<uint8_t const*>(data.data()), reinterpret_cast<uint8_t const*>(s->data()));
}

class public_key_ecdsa_sha2_nistp final : public public_key
{
public:
	public_key_ecdsa_sha2_nistp(nistp_curve curve)
		: curve_(curve)
		, point_(curve_)
	{
	}

	virtual ~public_key_ecdsa_sha2_nistp() override
	{
	}

	virtual std::string_view name() const override {
		return key_name(curve_);
	}

	virtual std::unique_ptr<public_key> clone() const override {
		if (key_.empty()) {
			return {};
		}
		auto ret = std::make_unique<public_key_ecdsa_sha2_nistp>(curve_);
		ret->parse(key_);
		ret->comment_ = comment_;
		return ret;
	}

	virtual bool parse(std::string_view key) override;
	virtual bool parse_putty(std::string_view key) override;
	virtual bool verify(std::string_view const& data, std::string_view sig) const override;

private:
	nistp_curve const curve_;
	curve_point point_;
};


bool public_key_ecdsa_sha2_nistp::parse(std::string_view key)
{
	key_.clear();

	auto const inkey = key;

	auto n = extract_string(key, string_type::ascii, false);
	if (!n || *n != name()) {
		return {};
	}

	auto s = extract_string(key, string_type::ascii, false);
	if (s != curve_name(curve_)) {
		return {};
	}

	auto raw = extract_blob(key);
	if (!raw || raw->size() != curve_bytes(curve_) * 2 + 1) {
		return {};
	}
	if ((*raw)[0] != '\x04') {
		return {};
	}
	if (!key.empty()) {
		return false;
	}

	std::string_view x = raw->substr(1, curve_bytes(curve_));
	std::string_view y = raw->substr(1 + curve_bytes(curve_), curve_bytes(curve_));

	mpz xz;
	mpz yz;

	nettle_mpz_set_str_256_u(xz, x.size(), reinterpret_cast<uint8_t const*>(x.data()));
	nettle_mpz_set_str_256_u(yz, y.size(), reinterpret_cast<uint8_t const*>(y.data()));

	if (!nettle_ecc_point_set(point_, xz, yz)) {
		return false;
	}

	key_ = inkey;
	return true;
}

bool public_key_ecdsa_sha2_nistp::parse_putty(std::string_view key)
{
	key_.clear();

	auto tokens = strtok(key, ',', false);
	if (tokens.size() != 3) {
		return false;
	}

	if (tokens[0] != curve_name(curve_)) {
		return false;
	}

	size_t bytes = curve_bytes(curve_);

	auto x = putty_hex_decode(tokens[1], false, bytes);
	auto y = putty_hex_decode(tokens[2], false, bytes);
	if (x.size() != bytes || y.size() != bytes) {
		return false;
	}

	fz::buffer buf;
	write_string(buf, name());
	write_string(buf, tokens[0]);
	write_uint32(buf, bytes * 2 + 1);
	buf.append('\x04');
	buf.append(x);
	buf.append(y);
	return parse(buf.to_view());
}

bool public_key_ecdsa_sha2_nistp::verify(std::string_view const& data, std::string_view sig) const
{
	if (key_.empty() || data.empty()) {
		return false;
	}

	fz::hash_accumulator acc(get_digest(curve_));
	acc.update(data);
	auto digest = acc.digest();

	auto n = extract_string(sig, string_type::ascii, false);
	if (!n || *n != name()) {
		return false;
	}
	auto raw_sig = extract_blob(sig);
	if (!raw_sig) {
		return false;
	}

	auto r = extract_blob(*raw_sig);
	auto s = extract_blob(*raw_sig);
	if (!r || !s) {
		return false;
	}

	if (!raw_sig->empty() || !sig.empty()) {
		return false;
	}

	dsa_signature dsa_sig;
	dsa_signature_init(&dsa_sig);
	mpz_import(dsa_sig.r, r->size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(r->data()));
	mpz_import(dsa_sig.s, s->size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(s->data()));

	bool ret = nettle_ecdsa_verify(point_, digest.size(), digest.data(), &dsa_sig);

	dsa_signature_clear(&dsa_sig);

	return ret;
}

class public_key_rsa final : public public_key
{
public:
	public_key_rsa()
	{
		nettle_rsa_public_key_init(&pub_);
	}

	virtual ~public_key_rsa() override
	{
		nettle_rsa_public_key_clear(&pub_);
	}

	virtual std::string_view name() const override {
		return "ssh-rsa"sv;
	}

	virtual std::unique_ptr<public_key> clone() const override {
		if (key_.empty()) {
			return {};
		}
		auto ret = std::make_unique<public_key_rsa>();
		ret->key_ = key_;
		ret->comment_ = comment_;
		mpz_set(ret->pub_.n, pub_.n);
		mpz_set(ret->pub_.e, pub_.e);
		ret->pub_.size = pub_.size;

		return ret;
	}

	virtual bool parse(std::string_view key) override;
	virtual bool parse_putty(std::string_view key) override;
	virtual bool verify(std::string_view const& data, std::string_view sig) const override;

private:
	rsa_public_key pub_;
};

bool public_key_rsa::parse(std::string_view key)
{
	key_.clear();

	auto const inkey = key;

	auto alg = extract_string(key, string_type::ascii, false);
	if (!alg || *alg != "ssh-rsa"sv) {
		return false;
	}

	auto e = extract_blob(key);
	if (!e || e->empty()) {
		return false;
	}

	auto n = extract_blob(key);
	if (!n || n->empty()) {
		return false;
	}

	mpz_import(pub_.e, e->size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(e->data()));
	mpz_import(pub_.n, n->size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(n->data()));
	if (mpz_sizeinbase(pub_.n, 2) < 1024) {
		return false;
	}

	if (nettle_rsa_public_key_prepare(&pub_) != 1) {
		return false;
	}

	if (!key.empty()) {
		return false;
	}
	key_ = inkey;

	return true;
}

bool public_key_rsa::parse_putty(std::string_view key)
{
	key_.clear();

	auto tokens = strtok(key, ',', false);
	if (tokens.size() != 2) {
		return false;
	}

	auto e = putty_hex_decode(tokens[0], false, 0);
	auto n = putty_hex_decode(tokens[1], false, 0);
	if (e.empty() || n.empty()) {
		return false;
	}

	fz::buffer buf;
	write_string(buf, name());
	write_mpint(buf, e);
	write_mpint(buf, n);
	return parse(buf.to_view());
}


bool public_key_rsa::verify(std::string_view const& data, std::string_view sig) const
{
	auto alg = extract_string(sig, string_type::ascii, false);
	if (!alg) {
		return false;
	}

	hash_algorithm a;
	if (*alg == "ssh-rsa"sv) {
		a = hash_algorithm::sha1;
	}
	else if (*alg == "rsa-sha2-256"sv) {
		a = hash_algorithm::sha256;
	}
	else if (*alg == "rsa-sha2-512"sv) {
		a = hash_algorithm::sha512;
	}
	else {
		return false;
	}

	auto raw_sig = extract_blob(sig);
	if (!raw_sig || raw_sig->empty()) {
		return false;
	}

	mpz mpsig;
	mpz_import(mpsig, raw_sig->size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(raw_sig->data()));

	hash_accumulator h(a);
	h.update(data);
	auto do_verify = [&]() {
		switch (a) {
			case hash_algorithm::sha1:
				return nettle_rsa_sha1_verify_digest(&pub_, h.digest().data(), mpsig);
			case hash_algorithm::sha256:
				return nettle_rsa_sha256_verify_digest(&pub_, h.digest().data(), mpsig);
			case hash_algorithm::sha512:
				return nettle_rsa_sha512_verify_digest(&pub_, h.digest().data(), mpsig);
			default:
				return 0;
		}
	};

	bool ret = do_verify() == 1;

	return ret;
}


std::unique_ptr<public_key> create_public_key(std::string_view const& alg)
{
	std::unique_ptr<public_key> ret;
	if (alg == "ssh-ed25519"sv) {
		ret = std::make_unique<public_key_ed25519>();
	}
	else if (alg == "ecdsa-sha2-nistp256"sv) {
		ret = std::make_unique<public_key_ecdsa_sha2_nistp>(nistp_curve::nistp256);
	}
	else if (alg == "ecdsa-sha2-nistp384"sv) {
		ret = std::make_unique<public_key_ecdsa_sha2_nistp>(nistp_curve::nistp384);
	}
	else if (alg == "ecdsa-sha2-nistp521"sv) {
		ret = std::make_unique<public_key_ecdsa_sha2_nistp>(nistp_curve::nistp521);
	}
	else if (alg == "ssh-rsa"sv) {
		ret = std::make_unique<public_key_rsa>();
	}
	else if (alg == "rsa-sha2-256"sv) {
		ret = std::make_unique<public_key_rsa>();
	}
	else if (alg == "rsa-sha2-512"sv) {
		ret = std::make_unique<public_key_rsa>();
	}
	if (!ret) {
		ret.reset();
	}
	return ret;
}

std::string_view get_known_pubkey_signature_algorithms()
{
	return "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa"sv;
}

bool supports_signature_algorithm(std::string_view key_alg, std::string_view sig_alg)
{
	if (sig_alg == "ssh-ed25519"sv) {
		return key_alg == sig_alg;
	}
	else if (sig_alg == "ecdsa-sha2-nistp256"sv) {
		return key_alg == sig_alg;
	}
	else if (sig_alg == "ecdsa-sha2-nistp384"sv) {
		return key_alg == sig_alg;
	}
	else if (sig_alg == "ecdsa-sha2-nistp521"sv) {
		return key_alg == sig_alg;
	}
	else if (sig_alg == "ssh-rsa"sv) {
		return key_alg == "ssh-rsa"sv;
	}
	else if (sig_alg == "rsa-sha2-256"sv) {
		return key_alg == "ssh-rsa"sv;
	}
	else if (sig_alg == "rsa-sha2-512"sv) {
		return key_alg == "ssh-rsa"sv;
	}
	return false;
}

namespace {
std::unique_ptr<public_key> load_public_key_blob(std::string_view data, logger_interface & logger)
{
	auto tmp = data;
	auto t = extract_string(tmp, string_type::ascii, false);
	if (!t) {
		return {};
	}

	logger.log(logmsg::debug_info, "Input looks like a public key blob"sv);

	auto k = create_public_key(*t);
	if (!k) {
		logger.log(logmsg::debug_warning, "Unsupported public key blob of type %s"sv, *t);
		return {};
	}
	else if (!k->parse(data)) {
		logger.log(logmsg::debug_warning, "Malformed public key blob of type %s"sv, *t);
		return {};
	}

	logger.log(logmsg::debug_info, "Loaded public key of type %s"sv, *t);

	return k;
}

std::vector<std::unique_ptr<public_key>> load_public_keys_4716(fz::strtokenizer<std::string_view const&, std::string_view>::iterator it, fz::strtokenizer<std::string_view const&, std::string_view>::iterator const& end, fz::logger_interface & logger)
{
	std::vector<std::unique_ptr<public_key>> ret;

	for (;it != end; ++it) {
		if (*it != "---- BEGIN SSH2 PUBLIC KEY ----"sv) {
			continue;
		}

		std::string_view begin;

		std::string comment;
		for (++it; it != end; ++it) {
			auto line = *it;

			if (!begin.data()) {
				if (size_t pos = line.find(':') != std::string_view::npos) {
					bool const is_comment = equal_insensitive_ascii(line.substr(0, pos), "comment"sv);
					line = line.substr(pos + 1);
					if (is_comment) {
						comment += line;
					}
					while ((*it).back() == '\\' && ++it != end) {
						if (is_comment) {
							comment += line;
						}
					}
					continue;
				}
				else {
					begin = line;
				}
			}

			if (line == "---- END SSH2 PUBLIC KEY ----"sv) {
				break;
			}
		}
		if (it == end || !begin.data()) {
			logger.log(logmsg::error, "Invalid SSH2 public key, could not find end header"sv);
			return {};
		}
		if (!is_valid_utf8(comment)) {
			logger.log(logmsg::debug_warning, "Invalid SSH2 public key, comment not in UTF-8"sv);
			continue;
		}

		auto size = std::size_t((*it).data() - begin.data());
		auto data = std::string_view(begin.data(), size);
		auto decoded = fz::base64_decode_s(data);

		auto k = load_public_key_blob(decoded, logger);
		std::string_view tmp = decoded;
		auto type = extract_string(tmp, string_type::ascii, false);
		if (!type) {
			logger.log(logmsg::debug_warning, "Invalid SSH2 public key, could not get key type"sv);
		}
		else {
			k->comment_ = comment;
			ret.emplace_back(std::move(k));
		}
	}

	return ret;
}

void process_putty_hostkey(std::vector<std::unique_ptr<public_key>> & ret, logger_interface & logger, std::string_view name, std::string_view data)
{
	if (!str_is_ascii(name)) {
		return;
	}

	size_t pos = name.find('@');
	if (pos == std::string::npos || !pos) {
		return;
	}
	std::string_view type = name.substr(0, pos);
	name.remove_prefix(pos + 1);

	pos = name.find(':');
	if (pos == std::string::npos) {
		return;
	}
	auto port = to_integral<uint16_t>(name.substr(0, pos), 0);
	if (!port) {
		return;
	}

	name.remove_prefix(pos + 1);
	if (name.empty()) {
		return;
	}

	// Reasonably sure this is a saved PuTTY hostkey

	if (type == "rsa2"sv) {
		type = "ssh-rsa"sv;
	}

	auto key = create_public_key(type);
	if (!key) {
		logger.log(logmsg::debug_warning, "Unsupported public key of type %s"sv, type);
		return;
	}

	if (!key->parse_putty(data)) {
		logger.log(logmsg::debug_warning, "Malformed public key of type %s"sv, type);
		return;
	}

	key->comment_ = fz::sprintf("%s:%u", name, port);

	logger.log(logmsg::debug_info, "Loaded public key of type %s"sv, type);
	ret.emplace_back(std::move(key));
}

}

std::vector<std::unique_ptr<public_key>> load_public_keys(std::string_view const& data, logger_interface & logger)
{
	std::vector<std::unique_ptr<public_key>> ret;

	auto key = load_public_key_blob(data, logger);
	if (key) {
		ret.emplace_back(std::move(key));
		return ret;
	}

	auto lines = strtokenizer(data, "\r\n"sv, true);
	auto it = lines.begin();
	if (it != lines.end() && *it == "---- BEGIN SSH2 PUBLIC KEY ----"sv) {
		return load_public_keys_4716(it, lines.end(), logger);
	}
	else {
		for (;it != lines.end(); ++it) {
			for (auto const& c : *it) {
				if (static_cast<unsigned char>(c) < 32 && c != '\t') {
					continue;
				}
			}
			auto tokens = strtok_view(*it, ' ', true);
			if (tokens.size() < 2) {
				continue;
			}
			if (!str_is_ascii(tokens[0])) {
				continue;
			}

			if (tokens.size() == 2 && tokens[0].find('@') != std::string::npos && tokens[0].find(':') != std::string::npos) {
				process_putty_hostkey(ret, logger, tokens[0], tokens[1]);
				continue;
			}

			auto key = create_public_key(tokens[0]);
			if (!key) {
				logger.log(logmsg::debug_warning, "Unsupported public key of type %s"sv, tokens[0]);
			}
			else if (!key->parse(fz::base64_decode_s(tokens[1]))) {
				logger.log(logmsg::debug_warning, "Malformed public key of type %s"sv, tokens[0]);
			}
			else {
				if (tokens.size() >= 3) {
					auto c = (*it).substr(std::size_t(tokens[2].data() - (*it).data()));
					if (is_valid_utf8(c)) {
						key->comment_ = c;
					}
					else {
						key->comment_ = fz::to_utf8(c);
						if (key->comment_.empty()) {
							logger.log(logmsg::debug_warning, "Could not convert key comment to UTF-8"sv);
						}
					}
				}
				logger.log(logmsg::debug_info, "Loaded public key of type %s"sv, tokens[0]);
				ret.emplace_back(std::move(key));
			}
		}
	}
	return ret;
}

std::unique_ptr<public_key> load_public_key(std::string_view const& data, logger_interface & logger)
{
	auto keys = load_public_keys(data, logger);
	if (keys.size() != 1) {
		return {};
	}
	return std::move(keys.front());
}

}
