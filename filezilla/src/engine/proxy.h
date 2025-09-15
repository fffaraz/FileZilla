#ifndef FILEZILLA_ENGINE_PROXY_HEADER
#define FILEZILLA_ENGINE_PROXY_HEADER

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/socket.hpp>

enum class ProxyType {
	NONE,
	HTTP,
	SOCKS5,
	SOCKS4,

	count
};

class CControlSocket;
class CProxySocket final : protected fz::event_handler, public fz::socket_layer
{
public:
	CProxySocket(fz::event_handler* pEvtHandler, fz::socket_interface & next_layer, CControlSocket* pOwner,
		ProxyType t, fz::native_string const& proxy_host, unsigned int proxy_port, std::wstring const& user, std::wstring const& pass);
	virtual ~CProxySocket();

	static std::wstring Name(ProxyType t);

	virtual int connect(fz::native_string const& host, unsigned int port, fz::address_type family = fz::address_type::unknown) override;

	fz::socket_state get_state() const override { return state_; }

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	ProxyType GetProxyType() const { return type_; }
	std::wstring GetUser() const;
	std::wstring GetPass() const;

	virtual fz::native_string peer_host() const override;
	virtual int peer_port(int& error)  const override;

	virtual int shutdown() override;

protected:
	CControlSocket* m_pOwner;

	ProxyType type_{};
	fz::native_string proxy_host_;
	unsigned int proxy_port_{};
	std::string user_;
	std::string pass_;

	fz::native_string host_;
	unsigned int port_{};
	fz::address_type family_{};

	fz::socket_state state_{};

	int m_handshakeState{};

	fz::buffer sendBuffer_;
	fz::buffer receiveBuffer_;

	virtual void operator()(fz::event_base const& ev) override;
	void OnSocketEvent(socket_event_source* source, fz::socket_event_flag t, int error);

	void OnReceive();
	void OnSend();

	bool m_can_write{};
	bool m_can_read{};
};

#endif
