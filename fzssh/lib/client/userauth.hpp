#ifndef FZSSH_CLIENT_USERAUTH_HEADER
#define FZSSH_CLIENT_USERAUTH_HEADER

#include "../userauth.hpp"

namespace fz::ssh {

class client_userauth final : public userauth, public event_handler
{
public:
	client_userauth(transport& t, std::string_view username);
	~client_userauth();

	virtual continuation process_auth_banner(std::string_view packet) override;
	virtual continuation process_auth_success(std::string_view packet) override;
	virtual continuation process_auth_failure(std::string_view packet) override;
	virtual continuation process_auth_pubkey_ok(std::string_view packet) override;
	virtual continuation process_auth_info_request(std::string_view packet) override;

	continuation auth_none();
	void auth_with_password(std::string_view const& pw);
	void auth_with_key(std::unique_ptr<private_key> const& key, bool with_signature, std::string_view signature_algorithm);
	void auth_with_key(std::unique_ptr<public_key> const& key, std::string_view signature_algorithm);
	void auth_keyboard_interactive();
	void auth_keyboard_interactive_response(std::vector<std::string> const& responses);

private:
	friend class client_transport;

	void auth_with_key(std::string_view const& pubblob, std::string_view const& signature_algorithm);

	virtual void operator()(event_base const& ev) override;
	void on_signature(private_key const& k, fz::buffer const& sig);

	virtual message_id get_method_flag() override;

	std::string signature_algorithm_;
	std::unique_ptr<private_key> privkey_;

	struct pending_auth
	{
		pending_auth(std::string_view name, bool request_only)
			: name_(name)
			, request_only_(request_only)
		{}

		std::string_view name_{};
		size_t flags_{};
		bool request_only_{};
	};

	std::list<pending_auth> pending_auths_;
	bool hostbound_pubkey_auth_{};
};

}

#endif
