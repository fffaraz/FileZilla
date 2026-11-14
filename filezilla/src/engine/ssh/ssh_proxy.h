#ifndef FILEZILLA_ENGINE_SSH_SSH_PROXY_HEADER
#define FILEZILLA_ENGINE_SSH_SSH_PROXY_HEADER

#include "../proxy.h"

namespace fz::ssh {
class client;
}

class SshAuth;
class SSHProxy final : public ProxyBase
{
public:
	SSHProxy(fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, CControlSocket* pOwner,
			  ProxyType t, fz::native_string const& proxy_host, unsigned int proxy_port, std::wstring const& user, std::wstring const& pass, SSHProxy* parent_proxy, bool sharable);
	virtual ~SSHProxy();

	virtual int connect(fz::native_string const& host, unsigned int port, fz::address_type family = fz::address_type::unknown) override;
	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;
	virtual int shutdown() override;
	virtual void set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block) override;

	fz::socket_state get_state() const override;

private:
	virtual void operator()(fz::event_base const& ev) override;
	void OnSocketEvent(socket_event_source* s, fz::socket_event_flag t, int error);
	void on_hostkey_verification(fz::ssh::session*, std::unique_ptr<fz::ssh::public_key> & key, fz::ssh::algorithm_info & algs);
	void on_session_done(fz::ssh::session*);
	void on_authenticated();
	void on_auth_failed(int result);

	std::unique_ptr<fz::ssh::client> ssh_;
	std::unique_ptr<fz::socket_interface> channel_;

	std::shared_ptr<AsyncRequestHandle> pending_hostkey_request_;
	std::shared_ptr<SSHProxy*> self_handle_;
	std::weak_ptr<SSHProxy*> parent_handle_;
	std::unique_ptr<SshAuth> auth_;

	bool sharable_{};
};

#endif
