#ifndef FZSSH_PUBKEY_HEADER
#define FZSSH_PUBKEY_HEADER

#include "visibility.hpp"

#include <libfilezilla/hash.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

using namespace std::literals;

namespace fz {
class logger_interface;
}

namespace fz::ssh {

bool FZSSH_PUBLIC_SYMBOL supports_signature_algorithm(std::string_view key_alg, std::string_view sig_alg);

class FZSSH_PUBLIC_SYMBOL public_key
{
public:
	virtual ~public_key() = default;

	public_key(public_key const&) = delete;
	public_key& operator=(public_key const&) = delete;

	virtual std::unique_ptr<public_key> clone() const = 0;

	virtual std::string_view name() const = 0;
	bool supports_signature_algorithm(std::string_view alg) const { return fz::ssh::supports_signature_algorithm(name(), alg); }

	explicit operator bool() const { return !key_.empty(); }
	virtual bool parse(std::string_view key) = 0;
	virtual bool parse_putty(std::string_view key) = 0;
	std::string_view pubkey_blob() const { return key_; }
	std::string openssh_pubkey() const;
	std::string rfc4716_pubkey() const;

	std::string fingerprint(hash_algorithm alg = hash_algorithm::sha256, bool base64 = true) const;

	bool verify(std::vector<uint8_t> const& data, std::string_view const& sig) const {
		return verify(std::string_view(reinterpret_cast<char const*>(data.data()), data.size()), sig);
	}
	virtual bool verify(std::string_view const& data, std::string_view sig) const = 0;

	std::string comment_;

protected:
	public_key() = default;
	std::string key_;
};

std::unique_ptr<public_key> FZSSH_PUBLIC_SYMBOL create_public_key(std::string_view const& alg);
std::string_view FZSSH_PUBLIC_SYMBOL get_known_pubkey_signature_algorithms();

std::vector<std::unique_ptr<public_key>> FZSSH_PUBLIC_SYMBOL load_public_keys(std::string_view const& data, logger_interface & logger);
std::unique_ptr<public_key> FZSSH_PUBLIC_SYMBOL load_public_key(std::string_view const& data, logger_interface & logger);

}

#endif
