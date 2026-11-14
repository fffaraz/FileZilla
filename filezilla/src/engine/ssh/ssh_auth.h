#ifndef FILEZILLA_ENGINE_SSH_SSH_AUTH_HEADER
#define FILEZILLA_ENGINE_SSH_SSH_AUTH_HEADER

#include "../controlsocket.h"

#include <fzssh/agent.hpp>
#include <fzssh/client.hpp>
#include <fzssh/privkey.hpp>

#include <functional>
#include <set>

class SshAuth final : public fz::event_handler
{
public:
	using SuccessHandler = std::function<void()>;
	using FailureHandler = std::function<void(int)>;

	SshAuth(
		fz::event_handler& parent,
		CControlSocket& controlSocket,
		CServer server,
		ServerHandle handle,
		Credentials credentials,
		std::unique_ptr<fz::ssh::client> & ssh,
		SuccessHandler success,
		FailureHandler failure);
	~SshAuth();

	void operator()(fz::event_base const& ev) override;

private:
	template<typename...Args>
	void log(Args&& ...args) const {
		controlSocket_.log(std::forward<Args>(args)...);
	}

	void on_auth_requested(fz::ssh::client*, std::string const& methods, bool is_continuation);
	void on_auth_done(fz::ssh::client*);
	void on_auth_pubkey_ok(fz::ssh::client*);
	void on_auth_signature_failed(fz::ssh::client*);
	void on_auth_keyboard_interactive_prompt(fz::ssh::client*, std::string const&, std::string const&, std::vector<fz::ssh::keyboard_interactive_prompt>& prompts);
	void on_auth_password_change_requested(fz::ssh::client*);

	void on_agent_keys(fz::ssh::agent_connection* conn, std::vector<std::unique_ptr<fz::ssh::private_key>>& keys);

	void next_auth();
	bool load_keys();
	bool auth_with_key();
	void set_keys_loaded();
	void ask_key_password(bool repeated);
	void set_keyfile_password(std::string const& password);
	void set_password(std::string const& password);
	void set_interactive_responses(std::vector<std::string> const& responses);
	bool interactive_prompt_asks_for_password(std::string_view prompt) const;

	void send_async_request(std::unique_ptr<CAsyncRequestNotification>&& notification);
	void set_async_request_reply(CAsyncRequestNotification* notification);
	void fail(int result);

	CControlSocket& controlSocket_;
	CServer const server_;
	ServerHandle const handle_;
	Credentials const credentials_;
	std::unique_ptr<fz::ssh::client> & ssh_;
	std::shared_ptr<AsyncRequestHandle> pending_request_;

	SuccessHandler const success_;
	FailureHandler const failure_;

	std::vector<fz::ssh::private_key_info> keys_;
	std::unique_ptr<fz::ssh::agent_connection> agent_;

	std::string methods_;
	std::string_view method_;
	std::set<std::string> used_keys_;

	uint8_t retry_counter_{};
	bool keys_loaded_{};
	bool tried_pw_{};
	enum class interactive_state {
		unused,
		requested,
		tried
	};
	interactive_state tried_interactive_{};
	bool tried_key_{};
};

#endif
