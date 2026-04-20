#include "fzssh/pubkey.hpp"
#include "fzssh/ssh.hpp"
#include "transport.hpp"

using namespace std::literals;

namespace fz::ssh {

parameters::operator bool() const
{
	return !kex_.empty() && !cipher_.empty() && !mac_.empty() && !hostkey_signatures_.empty();
}

parameters get_insecure_algorithms()
{
	return parameters{
		"diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"s,
		"aes256-cbc,aes192-cbc,aes128-cbc"s,
		"hmac-sha1-96"s,
		"ssh-rsa"s,
		""s
	};
}

parameters get_parameters_with_all_algorithms()
{
	return parameters{
		"mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group15-sha512,diffie-hellman-group16-sha512,diffie-hellman-group17-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"s,
		"aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc"s,
		"hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96"s,
		std::string(get_known_pubkey_signature_algorithms()),
		""s
	};
}

namespace {
constexpr auto separators = ", \r\n\t"sv;

std::string remove(std::string_view const& in, std::string_view const& to_remove)
{
	std::string ret;
	for (auto const& alg : fz::strtokenizer(in, separators, true)) {
		bool remove{};
		for (auto const& rem : fz::strtokenizer(to_remove, separators, true)) {
			if (alg == rem) {
				remove = true;
				break;
			}
		}
		if (!remove) {
			if (!ret.empty()) {
				ret += ","sv;
			}
			ret += alg;
		}
	}
	return ret;
}
}

void add_algorithm(std::string& algs, std::string_view const& to_add)
{
	for (auto const& alg : fz::strtokenizer(algs, separators, true)) {
		if (alg == to_add) {
			return;
		}
	}
	if (!algs.empty()) {
		algs += ","sv;
	}
	algs += to_add;
}

bool known_algorithm(std::string_view const& in, std::string_view const& algs)
{
	for (auto const& alg : fz::strtokenizer(algs, separators, true)) {
		if (in == alg) {
			return true;
		}
	}
	return false;
}

std::string FZSSH_PUBLIC_SYMBOL resolve(std::string_view in, std::string_view all, std::string_view def, std::string_view insecure, bool keep_unknown)
{
	std::string ret;
	for (auto alg : fz::strtokenizer(in, separators, true)) {
		if (alg == "ALL"sv) {
			for (auto const& a : fz::strtokenizer(all, separators, true)) {
				add_algorithm(ret, a);
			}
		}
		else if (alg == "DEFAULT"sv) {
			for (auto const& a : fz::strtokenizer(def, separators, true)) {
				add_algorithm(ret, a);
			}
		}
		else if (alg == "INSECURE"sv) {
			for (auto const& a : fz::strtokenizer(insecure, separators, true)) {
				add_algorithm(ret, a);
			}
		}
		else if (alg == "-ALL"sv) {
			ret = remove(ret, all);
		}
		else if (alg == "-DEFAULT"sv) {
			ret = remove(ret, def);
		}
		else if (alg == "-INSECURE"sv) {
			ret = remove(ret, insecure);
		}
		else if (alg[0] == '-') {
			ret = remove(ret, alg.substr(1));
		}
		else {
			if (keep_unknown || known_algorithm(alg, all)) {
				add_algorithm(ret, alg);
			}
		}
	}

	return ret;
}

parameters resolve(parameters const& in, bool keep_unknown)
{
	parameters ret;
	static auto const all = get_parameters_with_all_algorithms();
	static auto const def = get_default_parameters();
	static auto const insecure = get_insecure_algorithms();
	ret.kex_ = resolve(in.kex_, all.kex_, def.kex_, insecure.kex_, keep_unknown);
	ret.cipher_ = resolve(in.cipher_, all.cipher_, def.cipher_, insecure.cipher_, keep_unknown);
	ret.mac_ = resolve(in.mac_, all.mac_, def.mac_, insecure.mac_, keep_unknown);
	ret.hostkey_signatures_ = resolve(in.hostkey_signatures_, all.hostkey_signatures_, def.hostkey_signatures_, insecure.hostkey_signatures_, keep_unknown);
	ret.softwareversion_ = in.softwareversion_;
	ret.compatibility_flags_ = in.compatibility_flags_;
	return ret;
}

parameters get_default_parameters()
{
	static const parameters def = []{
		auto def = get_parameters_with_all_algorithms();
		auto insecure = get_insecure_algorithms();
		def.kex_ = remove(def.kex_, insecure.kex_);
		def.cipher_ = remove(def.cipher_, insecure.cipher_);
		def.mac_ = remove(def.mac_, insecure.mac_);
		def.hostkey_signatures_ = remove(def.hostkey_signatures_, insecure.hostkey_signatures_);
		return def;
	}();
	return def;
}

bool operator==(algorithm_info const& lhs, algorithm_info const& rhs)
{
	return std::tie(lhs.kex_, lhs.cipher_c2s_, lhs.cipher_s2c_, lhs.mac_c2s_, lhs.mac_s2c_, lhs.hostkey_signature_) == std::tie(rhs.kex_, rhs.cipher_c2s_, rhs.cipher_s2c_, rhs.mac_c2s_, rhs.mac_s2c_, rhs.hostkey_signature_);
}

session::~session()
{
}

algorithm_info session::current_algorithms()
{
	if (impl_) {
		return impl_->algorithms_;
	}
	return {};
}

std::string session::peer_identification()
{
	return impl_ ? impl_->peer_version() : std::string{};
}

}
