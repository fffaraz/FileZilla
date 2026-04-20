#ifndef FZSSH_PRIVKEY_HEADER
#define FZSSH_PRIVKEY_HEADER

#include "pubkey.hpp"

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>

#include <memory>
#include <vector>

using namespace std::literals;

namespace fz {
class logger_interface;
}

namespace fz::ssh {

class FZSSH_PUBLIC_SYMBOL private_key {
public:
	virtual ~private_key();

	private_key(private_key const&) = delete;
	private_key& operator=(private_key const&) = delete;

	virtual std::unique_ptr<private_key> clone() const = 0;

	virtual std::string_view name() const = 0;
	bool supports_signature_algorithm(std::string_view alg) const { return fz::ssh::supports_signature_algorithm(name(), alg); }

	std::unique_ptr<public_key> pubkey() const;
	std::string_view pubkey_blob() const { return pub_.to_view(); }
	std::string openssh_pubkey() const;
	std::string rfc4716_pubkey() const;

	std::string fingerprint(hash_algorithm alg = hash_algorithm::sha256, bool base64 = true) const;

	virtual bool sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm, event_handler& h) = 0;
	virtual void cancel(event_handler& h);

	template <typename Data,
	          std::enable_if_t<sizeof(typename Data::value_type) == sizeof(uint8_t)>* = nullptr>
	bool sign(Data const& data, std::string_view signature_algorithm, event_handler& h) {
		if (data.empty()) {
			return false;
		}
		return sign(std::basic_string_view<uint8_t>(reinterpret_cast<uint8_t const*>(data.data()), data.size()), signature_algorithm, h);
	}

	std::string comment_;

protected:
	private_key() = default;
	buffer pub_;
};

class FZSSH_PUBLIC_SYMBOL concrete_private_key : public private_key
{
public:
	using private_key::sign;
	virtual buffer sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm) = 0;
	virtual bool export_pkcs8(std::string & out) const = 0;
};

struct signature_event_type;
typedef simple_event<signature_event_type, private_key const&, buffer> signature_event;

std::unique_ptr<private_key> FZSSH_PUBLIC_SYMBOL create_private_key(std::string_view const& alg);
std::vector<std::unique_ptr<private_key>> FZSSH_PUBLIC_SYMBOL load_private_keys(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password = {});
std::unique_ptr<private_key> FZSSH_PUBLIC_SYMBOL load_private_key(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password = {});

class FZSSH_PUBLIC_SYMBOL private_key_info final
{
public:
	std::unique_ptr<private_key> privkey_;

	// If the key is encrypted, pubkey_ may not be available depending on key type
	std::unique_ptr<public_key> pubkey_;

	bool encrypted() const;

	bool decrypt(std::string_view const& password, logger_interface* logger);

	std::string name_;

	///\private
	std::string type_;
	std::string headers_;
	std::string ciphertext_;
};

std::vector<private_key_info> FZSSH_PUBLIC_SYMBOL load_private_key_infos(std::string_view const& data, logger_interface & logger, std::optional<std::string_view> const& password = {});
std::vector<private_key_info> FZSSH_PUBLIC_SYMBOL load_private_key_file(std::string_view const& filename, logger_interface & logger, std::optional<std::string_view> const& password = {});

std::string FZSSH_PUBLIC_SYMBOL export_pkcs8(std::unique_ptr<private_key> const& key, bool pem);

}

#endif
