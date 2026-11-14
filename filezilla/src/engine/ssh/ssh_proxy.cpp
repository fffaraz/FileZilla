#include "../controlsocket.h"
#include "../filezilla.h"
#include "../proxy.h"
#include "ssh_proxy.h"
#include "ssh_auth.h"

#include <libfilezilla/iputils.hpp>

#include <fzssh/client.hpp>

#include <algorithm>

#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

SSHProxy::SSHProxy(fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, CControlSocket* pOwner,
		ProxyType t, fz::native_string const& proxy_host, unsigned int proxy_port, std::wstring const& user,
		std::wstring const& pass, SSHProxy* parent_proxy, bool sharable)
	: ProxyBase(pEvtHandler, next_layer, pOwner, t, proxy_host, proxy_port, user, pass)
	, sharable_(sharable && !parent_proxy)
{
	self_handle_ = std::make_shared<SSHProxy*>(this);

	if (parent_proxy && parent_proxy->sharable_) {
		parent_handle_ = parent_proxy->self_handle_;
	}
}

SSHProxy::~SSHProxy()
{
	auth_.reset();
	pending_hostkey_request_.reset();
	remove_handler();
	channel_.reset();
	ssh_.reset();
}

fz::socket_state SSHProxy::get_state() const
{
	return (channel_ && state_ == fz::socket_state::connected) ? channel_->get_state() : state_;
}

int SSHProxy::connect(fz::native_string const& host, unsigned int port, fz::address_type family)
{
	if (auto parent = parent_handle_.lock(); parent && (*parent)->ssh_) {
		state_ = fz::socket_state::connected;
		channel_ = (*parent)->ssh_->open_channel(fz::ssh::channel_type::direct_tcpip, fz::sprintf("%s,%u"sv, host, port), fz::ssh::channel_flags::huge_window);
		if (channel_) {
			channel_->set_event_handler(event_handler_);
			return 0;
		}
	}

	if (next_layer_.get_state() == fz::socket_state::none) {
		int ret = next_layer_.connect(proxy_host_, proxy_port_);
		if (ret) {
			state_ = fz::socket_state::failed;
			return ret;
		}
	}

	state_ = fz::socket_state::connecting;

	host_ = host;
	port_ = port;
	family_ = family;

	fz::ssh::client_parameters params;
	params.single_channel_ = !sharable_;
	params.softwareversion_ = "FileZilla"sv;
	params.softwareversion_ += ' ';
	params.softwareversion_ += PACKAGE_VERSION;
	for (auto & c : params.softwareversion_) {
		if (c == ' ' || c == '-') {
			c = '_';
		}
	}

	ssh_ = std::make_unique<fz::ssh::client>(params, user_, next_layer_, *this, m_pOwner->logger());

	CServer server(SSH, UNIX, fz::to_wstring(proxy_host_), proxy_port_);
	server.SetUser(fz::to_wstring_from_utf8(user_));
	Credentials credentials;
	credentials.logonType_ = LogonType::normal;
	credentials.SetPass(fz::to_wstring_from_utf8(pass_));
	auth_ = std::make_unique<SshAuth>(
		*this,
		*m_pOwner,
		std::move(server),
		ServerHandle{},
		std::move(credentials),
		ssh_,
		[this] { on_authenticated(); },
		[this](int result) { on_auth_failed(result); });

	channel_ = ssh_->open_channel(fz::ssh::channel_type::direct_tcpip, fz::sprintf("%s,%u"sv, host, port), fz::ssh::channel_flags::huge_window);
	if (!channel_) {
		state_ = fz::socket_state::failed;
		auth_.reset();
		ssh_.reset();
		return EINVAL;
	}

	channel_->set_event_handler(event_handler_);
	return 0;
}

int SSHProxy::read(void *buffer, unsigned int size, int& error)
{
	if (!channel_) {
		error = EINVAL;
		return -1;
	}

	return channel_->read(buffer, size, error);
}

int SSHProxy::write(void const* buffer, unsigned int size, int& error)
{
	if (!channel_) {
		error = EINVAL;
		return -1;
	}

	return channel_->write(buffer, size, error);
}

int SSHProxy::shutdown()
{
	if (!channel_) {
		return EINVAL;
	}

	return channel_->shutdown();
}

void SSHProxy::operator()(fz::event_base const& ev)
{
	if (auth_) {
		(*auth_)(ev);
	}

	fz::dispatch<
		fz::socket_event,
		fz::ssh::hostkey_verification_event,
		fz::ssh::session_done_event
	>(
		ev, this,
		&SSHProxy::OnSocketEvent,
		&SSHProxy::on_hostkey_verification,
		&SSHProxy::on_session_done
	);
}

void SSHProxy::OnSocketEvent(socket_event_source* s, fz::socket_event_flag t, int error)
{
	forward_socket_event(s, t, error);
}

void SSHProxy::on_hostkey_verification(fz::ssh::session*, std::unique_ptr<fz::ssh::public_key> & key, fz::ssh::algorithm_info & algs)
{
	if (ssh_) {
		auto reply = [&](CAsyncRequestNotification* req) {
			pending_hostkey_request_.reset();

			auto hkreq = dynamic_cast<CHostKeyNotification*>(req);
			if (hkreq && ssh_) {
				ssh_->hostkey_decision(hkreq->trust_);
			}
		};

		CServer server(SSH, UNIX, fz::to_wstring(proxy_host_), proxy_port_);
		pending_hostkey_request_ = m_pOwner->SendAsyncRequest(std::make_unique<CHostKeyNotification>(server, ServerHandle{}, std::move(key), std::move(algs)), async_request_type::parallel, reply);
	}
}

void SSHProxy::on_authenticated()
{
	state_ = fz::socket_state::connected;
}

void SSHProxy::on_auth_failed(int)
{
	state_ = fz::socket_state::failed;
	pending_hostkey_request_.reset();
	ssh_.reset();
}

void SSHProxy::set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block)
{
	event_handler_ = handler;
	if (channel_) {
		channel_->set_event_handler(handler, retrigger_block);
	}
}

void SSHProxy::on_session_done(fz::ssh::session*)
{
	auth_.reset();
	pending_hostkey_request_.reset();
	ssh_.reset();
}
