#ifndef FZSSH_PRIVKEY_IMPL_HEADER
#define FZSSH_PRIVKEY_IMPL_HEADER

#include "fzssh/privkey.hpp"

namespace fz::ssh {
class concrete_private_key_impl : public concrete_private_key
{
public:
	virtual bool generate() = 0;

	using concrete_private_key::sign;
	virtual bool sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm, event_handler& h) override {
		auto sig = sign(data, signature_algorithm);
		if (sig.empty()) {
			return false;
		}

		h.send_event<signature_event>(*this, std::move(sig));
		return true;
	}

	bool selftest();

	virtual bool parse_openssh_blob(std::string_view & /*data*/) = 0;
	virtual bool parse_putty_blobs(std::string_view /*pub*/, std::string_view /*priv*/) = 0;
	virtual bool parse_der(std::string_view /*data*/) = 0;
	virtual bool parse_inner_pkcs8(std::string_view data, std::string_view opt_pubblob, bool pubblob_constructed) = 0;
};

std::unique_ptr<concrete_private_key_impl> create_concrete_key(std::string_view const& alg, bool generate);
}

#endif
