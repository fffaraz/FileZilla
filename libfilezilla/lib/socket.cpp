#include "libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS
  #include "libfilezilla/glue/windows.hpp"
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mstcpip.h>

  #include "windows/poller.hpp"
#endif

#include "libfilezilla/socket.hpp"

#include "libfilezilla/mutex.hpp"
#include "libfilezilla/thread_pool.hpp"

#ifndef FZ_WINDOWS
  #include "libfilezilla/glue/unix.hpp"
  #include "libfilezilla/process.hpp"
  #include "unix/poller.hpp"

  #define mutex mutex_override // Sadly on some platforms system headers include conflicting names
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/un.h>
  #include <netdb.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #if !defined(MSG_NOSIGNAL) && !defined(SO_NOSIGPIPE)
	#include <signal.h>
  #endif
  #undef mutex
  #if HAVE_TCP_INFO
	#include <atomic>
  #endif
#endif

#include <assert.h>
#include <string.h>

// Fixups needed on FreeBSD
#if !defined(EAI_ADDRFAMILY) && defined(EAI_FAMILY)
  #define EAI_ADDRFAMILY EAI_FAMILY
#endif

#ifndef AI_NUMERICSERV
// Some systems like Windows or OS X don't know AI_NUMERICSERV.
#define AI_NUMERICSERV 0
#endif

#define WAIT_CONNECT 0x01
#define WAIT_READ	 0x02
#define WAIT_WRITE	 0x04
#define WAIT_ACCEPT  0x08
#define WAIT_EVENTCOUNT 4

namespace fz {

namespace {
// Union for strict aliasing-safe casting between
// the different address types
union sockaddr_u
{
	sockaddr_storage storage;
	sockaddr sockaddr_;
	sockaddr_in in4;
	sockaddr_in6 in6;
#ifndef FZ_WINDOWS
	sockaddr_un un;
#endif
};

#if HAVE_TCP_INFO
// Attempting to set a high SND_RCVBUF can actually result in a smaller
// TCP receive window scale factor.
// Through TCP_INFO it is possible to detect this, and if it is the case,
// avoid setting TCP_RCVBUF
std::atomic<int> unmodified_rcv_wscale{};
std::atomic<int> modified_rcv_wscale{};

int get_rcv_wscale(int fd) {
	tcp_info i{};
	socklen_t len = sizeof(tcp_info);
	int res = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &i, &len);
	if (res) {
		return 0;
	}
	return i.tcpi_rcv_wscale;
}

#endif
}

void remove_socket_events(event_handler * handler, socket_event_source const* const source)
{
	if (!handler) {
		return;
	}

	auto socket_event_filter = [&](event_base const& ev) -> bool {
		if (ev.derived_type() == socket_event::type()) {
			return std::get<0>(static_cast<socket_event const&>(ev).v_) == source;
		}
		else if (ev.derived_type() == hostaddress_event::type()) {
			return std::get<0>(static_cast<hostaddress_event const&>(ev).v_) == source;
		}
		return false;
	};

	handler->filter_events(socket_event_filter);
}

socket_event_flag change_socket_event_handler(event_handler * old_handler, event_handler * new_handler, socket_event_source const* const source, socket_event_flag remove)
{
	if (!old_handler) {
		return socket_event_flag{};
	}

	if (!new_handler) {
		remove_socket_events(old_handler, source);
		return socket_event_flag{};
	}

	// Don't check for old == new as we need to remove the events in remove and report the pending ones.

#if DEBUG_SOCKETEVENTS
	socket_event_flag seen = socket_event_flag{};
#endif

	socket_event_flag ret = socket_event_flag{};
	auto socket_event_filter = [&](event_handler*& h, event_base const& ev) -> bool {
		if (h == old_handler) {
			if (ev.derived_type() == socket_event::type()) {
				auto & sev = static_cast<socket_event const&>(ev);
				if (std::get<0>(sev.v_) == source) {
					auto const flag = std::get<1>(sev.v_);
#if DEBUG_SOCKETEVENTS
					assert(!(flag & seen));
					seen |= flag;
#endif
					if (flag & remove) {
						return true;
					}
					ret |= flag;
					h = new_handler;
				}
			}
			else if (ev.derived_type() == hostaddress_event::type()) {
				if (std::get<0>(static_cast<hostaddress_event const&>(ev).v_) == source) {
					h = new_handler;
				}
			}
		}
		return false;
	};

	old_handler->event_loop_.filter_events(socket_event_filter);
	return ret;
}

#if DEBUG_SOCKETEVENTS
bool FZ_PRIVATE_SYMBOL has_pending_event(event_handler * handler, socket_event_source const* const source, socket_event_flag event)
{
	if (!handler) {
		return false;
	}

	bool ret = false;

	auto socket_event_filter = [&](event_base const& ev) -> bool {
		if (ev.derived_type() == socket_event::type()) {
			auto const& socket_ev = static_cast<socket_event const&>(ev).v_;
			if (std::get<0>(socket_ev) == source && std::get<1>(socket_ev) & event) {
				ret = true;
			}
		}
		return false;
	};

	handler->filter_events(socket_event_filter);

	return ret;
}
#endif

#ifdef FZ_WINDOWS
int convert_msw_error_code(int error)
{
	// Takes an MSW socket error and converts it into an equivalent POSIX error code.
	switch (error)
	{
	case WSAECONNREFUSED:
		return ECONNREFUSED;
	case WSAECONNABORTED:
		return ECONNABORTED;
	case WSAEINVAL:
		return EAI_BADFLAGS;
	case WSANO_RECOVERY:
		return EAI_FAIL;
	case WSAEAFNOSUPPORT:
		return EAI_FAMILY;
	case WSA_NOT_ENOUGH_MEMORY:
		return EAI_MEMORY;
	case WSANO_DATA:
		return EAI_NODATA;
	case WSAHOST_NOT_FOUND:
		return EAI_NONAME;
	case WSATYPE_NOT_FOUND:
		return EAI_SERVICE;
	case WSAESOCKTNOSUPPORT:
		return EAI_SOCKTYPE;
	case WSAEWOULDBLOCK:
		return EAGAIN;
	case WSAEMFILE:
		return EMFILE;
	case WSAEINTR:
		return EINTR;
	case WSAEFAULT:
		return EFAULT;
	case WSAEACCES:
		return EACCES;
	case WSAETIMEDOUT:
		return ETIMEDOUT;
	case WSAECONNRESET:
		return ECONNRESET;
	case WSAEHOSTDOWN:
		return EHOSTDOWN;
	case WSAENETUNREACH:
		return ENETUNREACH;
	case WSAEADDRINUSE:
		return EADDRINUSE;
	default:
		return error;
	}
}
#endif

namespace {
#ifdef FZ_WINDOWS
int last_socket_error()
{
	return convert_msw_error_code(WSAGetLastError());
}
#else
int last_socket_error()
{
	int err = errno;
#if EWOULDBLOCK != EAGAIN
	if (err == EWOULDBLOCK) {
		err = EAGAIN;
	}
#endif
	return err;
}
#endif

#ifdef FZ_WINDOWS
int set_nonblocking(socket::socket_t fd)
{
	// Set socket to non-blocking.
	unsigned long nonblock = 1;
	int res = ioctlsocket(fd, FIONBIO, &nonblock);
	if (!res) {
		return 0;
	}
	else {
		return convert_msw_error_code(WSAGetLastError());
	}
}
#endif

int do_set_flags(socket::socket_t fd, int flags, int flags_mask, duration const& keepalive_interval)
{
	if (flags_mask & socket::flag_nodelay) {
		const int value = (flags & socket::flag_nodelay) ? 1 : 0;
		int res = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&value, sizeof(value));
		if (res != 0) {
			return last_socket_error();
		}
	}
	if (flags_mask & socket::flag_keepalive) {
#if FZ_WINDOWS
		tcp_keepalive v{};
		v.onoff = (flags & socket::flag_keepalive) ? 1 : 0;
		v.keepalivetime = static_cast<ULONG>(keepalive_interval.get_milliseconds());
		v.keepaliveinterval = 1000;
		DWORD tmp{};
		int res = WSAIoctl(fd, SIO_KEEPALIVE_VALS, &v, sizeof(v), nullptr, 0, &tmp, nullptr, nullptr);
		if (res != 0) {
			return last_socket_error();
		}
#else
		const int value = (flags & socket::flag_keepalive) ? 1 : 0;
		int res = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&value, sizeof(value));
		if (res != 0) {
			return last_socket_error();
		}
#ifdef TCP_KEEPIDLE
		int const idle = keepalive_interval.get_seconds();
		res = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (const char*)&idle, sizeof(idle));
		if (res != 0) {
			return last_socket_error();
		}
#else
		(void)keepalive_interval;
#endif
#endif
	}

	return 0;
}

int do_set_buffer_sizes(socket::socket_t fd, int size_read, int size_write)
{
	int ret = 0;
	if (size_read >= 0) {
#if HAVE_TCP_INFO
		// Check if setting the buffer size shrinks the window scale factor
		int const mws = modified_rcv_wscale;
		if (!mws || mws >= unmodified_rcv_wscale)
#endif
		{
			int res = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&size_read, sizeof(size_read));
			if (res != 0) {
				ret = last_socket_error();
			}
		}
	}

	if (size_write >= 0) {
		int res = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&size_write, sizeof(size_write));
		if (res != 0) {
			ret = last_socket_error();
		}
	}

	return ret;
}

void close_socket_fds(std::vector<socket::socket_t> & fds_to_close)
{
	for (auto fd : fds_to_close) {
#ifdef FZ_WINDOWS
		closesocket(fd);
#else
		close(fd);
#endif
	}
	fds_to_close.clear();
}

void close_socket_fd(socket::socket_t& fd)
{
	if (fd != -1) {
#ifdef FZ_WINDOWS
		closesocket(fd);
#else
		close(fd);
#endif
		fd = -1;
	}
}
}

#ifdef FZ_WINDOWS
winsock_initializer::winsock_initializer()
{
	WSADATA d{};
	initialized_ = WSAStartup((2 << 8) | 8, &d) == 0;
}

winsock_initializer::~winsock_initializer()
{
	if (initialized_) {
		WSACleanup();
	}
}
#endif

class socket_thread final
{
	friend class socket_base;
	friend class socket;
	friend class listen_socket;
public:
	explicit socket_thread(socket_base* base)
		: socket_(base)
		, mutex_(false)
	{
#ifdef FZ_WINDOWS
		static winsock_initializer init;
#endif
		for (int i = 0; i < WAIT_EVENTCOUNT; ++i) {
			triggered_errors_[i] = 0;
		}
	}

	~socket_thread()
	{
		thread_.join();
		close_socket_fds(fds_to_close_);
	}

	int create_sync()
	{
		return poller_.init();
	}


	void set_socket(socket_base* pSocket)
	{
		scoped_lock l(mutex_);
		set_socket(pSocket, l);
	}

	void set_socket(socket_base* pSocket, scoped_lock const&)
	{
		socket_ = pSocket;

		host_.clear();
		port_.clear();

		waiting_ = 0;
	}

	int connect(std::string const& host, unsigned int port)
	{
		assert(socket_);
		if (!socket_) {
			return EINVAL;
		}

		host_ = host;
		if (host_.empty()) {
			return EINVAL;
		}

		// Connect method of socket ensures port is in range
		port_ = fz::to_string(port);

		return start();
	}

	int start()
	{
		if (thread_) {
			scoped_lock l(mutex_);
			waiting_ = 0;
			wakeup_thread(l);
			return 0;
		}

		int res = create_sync();
		if (res) {
			return res;
		}

		thread_ = socket_->thread_pool_.spawn([this]() { entry(); });

		if (!thread_) {
			return EMFILE;
		}

		return 0;
	}

	// Cancels poll or idle wait
	void wakeup_thread()
	{
		scoped_lock l(mutex_);
		wakeup_thread(l);
	}

	void wakeup_thread(scoped_lock & l)
	{
		if (!thread_ || quit_) {
			return;
		}

		poller_.interrupt(l);
	}

protected:
	static socket::socket_t create_socket_fd(addrinfo const& addr)
	{
#ifndef FZ_WINDOWS
		disable_sigpipe();
#endif

		socket::socket_t fd;
#if defined(SOCK_CLOEXEC) && !defined(FZ_WINDOWS)
		fd = ::socket(addr.ai_family, addr.ai_socktype | SOCK_CLOEXEC, addr.ai_protocol);
		if (fd == -1 && errno == EINVAL)
#endif
		{
#if !defined(FZ_WINDOWS)
			forkblock b;
#endif
			fd = ::socket(addr.ai_family, addr.ai_socktype, addr.ai_protocol);

#if !defined(FZ_WINDOWS)
			set_cloexec(fd);
#endif
		}

		if (fd != -1) {
#if defined(SO_NOSIGPIPE) && !defined(MSG_NOSIGNAL)
			// We do not want SIGPIPE if writing to socket.
			const int value = 1;
			setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(int));
#endif
			set_nonblocking(fd);
		}

		return fd;
	}

	int try_connect_host(addrinfo & addr, sockaddr_u const& bindAddr, scoped_lock & l)
	{
		if (socket_->evt_handler_) {
			socket_->evt_handler_->send_event<hostaddress_event>(socket_->ev_source_, socket::address_to_string(addr.ai_addr, addr.ai_addrlen));
		}

		socket_->fd_ = create_socket_fd(addr);
		if (socket_->fd_ == -1) {
			if (socket_->evt_handler_) {
				socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, addr.ai_next ? socket_event_flag::connection_next : socket_event_flag::connection, last_socket_error());
			}

			return 0;
		}

		if (bindAddr.sockaddr_.sa_family != AF_UNSPEC && bindAddr.sockaddr_.sa_family == addr.ai_family) {
			(void)::bind(socket_->fd_, &bindAddr.sockaddr_, sizeof(bindAddr));
		}

		auto* s = static_cast<socket*>(socket_);
		do_set_flags(socket_->fd_, s->flags_, s->flags_, s->keepalive_interval_);
		do_set_buffer_sizes(socket_->fd_, socket_->buffer_sizes_[0], socket_->buffer_sizes_[1]);

		int res = ::connect(socket_->fd_, addr.ai_addr, addr.ai_addrlen);
		if (res == -1) {
#ifdef FZ_WINDOWS
			// Map to POSIX error codes
			int error = WSAGetLastError();
			if (error == WSAEWOULDBLOCK) {
				res = EINPROGRESS;
			}
			else {
				res = last_socket_error();
			}
#else
			res = errno;
#endif
		}

		while (res == EINPROGRESS) {
			bool wait_successful;
			do {
				wait_successful = do_wait(WAIT_CONNECT, l);
				if ((triggered_ & WAIT_CONNECT)) {
					break;
				}
			} while (wait_successful);

			if (!wait_successful) {
				if (socket_) {
					close_socket_fd(socket_->fd_);
				}
				return -1;
			}
			triggered_ &= ~WAIT_CONNECT;

			res = triggered_errors_[0];
		}

		if (res) {
			if (socket_->evt_handler_) {
				socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, addr.ai_next ? socket_event_flag::connection_next : socket_event_flag::connection, res);
			}

			close_socket_fd(socket_->fd_);
		}
		else {
			static_cast<socket*>(socket_)->state_ = socket_state::connected;
			if (socket_->family_ == AF_UNSPEC) {
				socket_->family_ = addr.ai_family;
			}
#if HAVE_TCP_INFO
			if (socket_->buffer_sizes_[0] == -1 && !unmodified_rcv_wscale) {
				unmodified_rcv_wscale = get_rcv_wscale(socket_->fd_);
			}
			else if (socket_->buffer_sizes_[0] != -1 && !modified_rcv_wscale) {
				modified_rcv_wscale = get_rcv_wscale(socket_->fd_);
			}
#endif

			if (socket_->evt_handler_) {
				socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::connection, 0);
			}

			// We're now interested in all the other nice events
			waiting_ |= WAIT_READ;

			return 1;
		}

		return 0;
	}

	// Only call while locked
	bool do_connect(scoped_lock & l)
	{
		if (host_.empty()) {
			static_cast<socket*>(socket_)->state_ = socket_state::failed;
			return false;
		}

		std::string host, port, bind;
		std::swap(host, host_);
		std::swap(port, port_);
		std::swap(bind, bind_);

		sockaddr_u bindAddr{};

#ifndef FZ_WINDOWS

		if (socket_->family_ == AF_UNIX) {
			host = fz::to_native(host);

			sockaddr_u u{};
			u.un.sun_family = AF_UNIX;
			if (host.size() >= sizeof(u.un.sun_path)) {
				if (socket_->evt_handler_) {
					socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::connection, EINVAL);
				}
				static_cast<socket*>(socket_)->state_ = socket_state::failed;
				return false;
			}
			strcpy(u.un.sun_path, host.c_str());

			addrinfo addr{};
			addr.ai_family = AF_UNIX;
			addr.ai_socktype = SOCK_STREAM;
			addr.ai_addr = &u.sockaddr_;
			addr.ai_addrlen = sizeof(u.un);

			int res = try_connect_host(addr, bindAddr, l);
			if (res == 1) {
				return true;
			}

			if (socket_) {
				if (socket_->evt_handler_) {
					socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::connection, ECONNABORTED);
				}
				static_cast<socket*>(socket_)->state_ = socket_state::failed;
			}

			return false;
		}
#endif

		if (!bind.empty()) {
			// Convert bind address
			addrinfo bind_hints{};
			bind_hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;
			bind_hints.ai_socktype = SOCK_STREAM;
			addrinfo *bindAddressList{};
			int res = getaddrinfo(bind.empty() ? nullptr : bind.c_str(), "0", &bind_hints, &bindAddressList);
			if (!res && bindAddressList) {
				if (bindAddressList->ai_addr) {
					memcpy(&bindAddr.storage, bindAddressList->ai_addr, bindAddressList->ai_addrlen);
				}
				freeaddrinfo(bindAddressList);
			}
		}

		addrinfo hints{};
		hints.ai_family = socket_->family_;

		l.unlock();

		hints.ai_socktype = SOCK_STREAM;
#ifdef AI_IDN
		hints.ai_flags |= AI_IDN;
#endif

		addrinfo *addressList{};
		int res = getaddrinfo(host.c_str(), port.c_str(), &hints, &addressList);

		l.lock();

		if (should_quit()) {
			if (!res && addressList) {
				freeaddrinfo(addressList);
			}
			return false;
		}

		// If state isn't connecting, close() was called.
		// If host_ is set, close() was called and connect()
		// afterwards, state is back at connecting.
		// In either case, we need to abort this connection attempt.
		if (static_cast<socket*>(socket_)->state_ != socket_state::connecting || !host_.empty()) {
			if (!res && addressList) {
				freeaddrinfo(addressList);
			}
			return false;
		}

		if (res) {
#ifdef FZ_WINDOWS
			res = convert_msw_error_code(res);
#endif

			if (socket_->evt_handler_) {
				socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::connection, res);
			}
			static_cast<socket*>(socket_)->state_ = socket_state::failed;

			return false;
		}

		res = 0;
		for (addrinfo *addr = addressList; addr && !res; addr = addr->ai_next) {
			res = try_connect_host(*addr, bindAddr, l);
		}
		freeaddrinfo(addressList);
		if (res == 1) {
			return true;
		}

		if (socket_) {
			if (socket_->evt_handler_) {
				socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::connection, ECONNABORTED);
			}
			static_cast<socket*>(socket_)->state_ = socket_state::failed;
		}

		return false;
	}

	bool should_quit() const
	{
		return quit_ || !socket_;
	}

	// Call only while locked
	bool do_wait(int wait, scoped_lock & l)
	{
		waiting_ |= wait;

		for (;;) {
#ifdef FZ_WINDOWS
			pollinfo info;
			info.fd_ = socket_->fd_;
			
			if (waiting_ & WAIT_CONNECT) {
				info.events_ |= FD_CONNECT;
			}
			if (waiting_ & WAIT_READ) {
				info.events_ |= FD_READ | FD_CLOSE;
			}
			if (waiting_ & WAIT_WRITE) {
				info.events_ |= FD_WRITE;
			}
			if (waiting_ & WAIT_ACCEPT) {
				info.events_ |= FD_ACCEPT;
			}
			bool res = poller_.wait(&info, 1, l);

			if (!res || should_quit() || socket_->fd_ == -1) {
				return false;
			}

			if (waiting_ & WAIT_CONNECT) {
				if (info.result_.lNetworkEvents & FD_CONNECT) {
					triggered_ |= WAIT_CONNECT;
					triggered_errors_[0] = convert_msw_error_code(info.result_.iErrorCode[FD_CONNECT_BIT]);
					waiting_ &= ~WAIT_CONNECT;
				}
			}
			if (waiting_ & WAIT_READ) {
				if (info.result_.lNetworkEvents & FD_READ) {
					triggered_ |= WAIT_READ;
					triggered_errors_[1] = convert_msw_error_code(info.result_.iErrorCode[FD_READ_BIT]);
					waiting_ &= ~WAIT_READ;
				}
				if (info.result_.lNetworkEvents & FD_CLOSE) {
					triggered_ |= WAIT_READ;
					int err = convert_msw_error_code(info.result_.iErrorCode[FD_CLOSE_BIT]);
					if (err) {
						triggered_errors_[1] = err;
					}
					waiting_ &= ~WAIT_READ;
				}
			}
			if (waiting_ & WAIT_WRITE) {
				if (info.result_.lNetworkEvents & FD_WRITE) {
					triggered_ |= WAIT_WRITE;
					triggered_errors_[2] = convert_msw_error_code(info.result_.iErrorCode[FD_WRITE_BIT]);
					waiting_ &= ~WAIT_WRITE;
				}
			}
			if (waiting_ & WAIT_ACCEPT) {
				if (info.result_.lNetworkEvents & FD_ACCEPT) {
					triggered_ |= WAIT_ACCEPT;
					triggered_errors_[3] = convert_msw_error_code(info.result_.iErrorCode[FD_ACCEPT_BIT]);
					waiting_ &= ~WAIT_ACCEPT;
				}
			}

			if (triggered_ || !waiting_) {
				return true;
			}
#else
			pollfd fds[2]{};
			fds[0].fd = socket_->fd_;
			fds[0].events = 0;

			if (waiting_ & (WAIT_READ|WAIT_ACCEPT)) {
				fds[0].events |= POLLIN;
			}
			if (waiting_ & (WAIT_WRITE | WAIT_CONNECT)) {
				fds[0].events |= POLLOUT;
			}
			bool res = poller_.wait(fds, 1, l);

			if (!res || should_quit() || socket_->fd_ == -1) {
				return false;
			}

			int const revents = fds[0].revents;
			if (waiting_ & WAIT_CONNECT) {
				if (revents & (POLLOUT|POLLERR|POLLHUP)) {
					int error;
					socklen_t len = sizeof(error);
					int getsockopt_res = getsockopt(socket_->fd_, SOL_SOCKET, SO_ERROR, &error, &len);
					if (getsockopt_res) {
						error = errno;
					}
					triggered_ |= WAIT_CONNECT;
					triggered_errors_[0] = error;
					waiting_ &= ~WAIT_CONNECT;
				}
			}
			else if (waiting_ & WAIT_ACCEPT) {
				if (revents & POLLIN) {
					triggered_ |= WAIT_ACCEPT;
					waiting_ &= ~WAIT_ACCEPT;
				}
			}
			else {
				if (waiting_ & WAIT_READ) {
					if (revents & (POLLIN|POLLHUP|POLLERR)) {
						triggered_ |= WAIT_READ;
						waiting_ &= ~WAIT_READ;
					}
				}
				if (waiting_ & WAIT_WRITE) {
					if (revents & (POLLOUT|POLLERR|POLLHUP)) {
						triggered_ |= WAIT_WRITE;
						waiting_ &= ~WAIT_WRITE;
					}
				}
			}

			if (triggered_ || !waiting_) {
				return true;
			}
#endif
		}
	}

	void send_events()
	{
		if (!socket_ || !socket_->evt_handler_) {
			return;
		}

		if (triggered_ & WAIT_READ) {
			socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::read, triggered_errors_[1]);
			triggered_ &= ~WAIT_READ;
		}
		if (triggered_ & WAIT_WRITE) {
			socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::write, triggered_errors_[2]);
			triggered_ &= ~WAIT_WRITE;
		}
		if (triggered_ & WAIT_ACCEPT) {
			socket_->evt_handler_->send_event<socket_event>(socket_->ev_source_, socket_event_flag::connection, triggered_errors_[3]);
			triggered_ &= ~WAIT_ACCEPT;
		}
	}

	// Call only while locked
	bool idle_loop(scoped_lock & l)
	{
		if (quit_) {
			return false;
		}
		while (!socket_ || (!waiting_ && host_.empty())) {

			poller_.wait(l);

			if (quit_) {
				return false;
			}
		}

		return true;
	}

	void entry()
	{
		scoped_lock l(mutex_);
		for (;;) {
			if (!idle_loop(l)) {
				break;
			}

			if (dynamic_cast<listen_socket*>(socket_)) {
				while (idle_loop(l)) {
					if (socket_->fd_ == -1) {
						waiting_ = 0;
						break;
					}
					if (!do_wait(0, l)) {
						break;
					}
					send_events();
				}
			}
			else {
				if (static_cast<socket*>(socket_)->state_ == socket_state::connecting) {
					if (!do_connect(l)) {
						continue;
					}
				}

				while (idle_loop(l)) {
					if (socket_->fd_ == -1) {
						waiting_ = 0;
						break;
					}
					bool res = do_wait(0, l);

					if (!res) {
						break;
					}

					send_events();
				}
			}
			close_socket_fds(fds_to_close_);
		}

		if (thread_) {
			quit_ = true;
		}
		else {
			l.unlock();
			delete this;
		}
		return;
	}

	socket_base* socket_{};

	std::string host_;
	std::string port_;
	std::string bind_;

	mutex mutex_;

	async_task thread_;

	std::vector<socket::socket_t> fds_to_close_;

	poller poller_;

	// The socket events we are waiting for
	int waiting_{};

	// The triggered socket events
	int triggered_{};
	int triggered_errors_[WAIT_EVENTCOUNT];

	bool quit_{};
};

socket_base::socket_base(thread_pool& pool, event_handler* evt_handler, socket_event_source* ev_source)
	: thread_pool_(pool)
	, evt_handler_(evt_handler)
	, socket_thread_(new socket_thread(this))
	, ev_source_(ev_source)
{
	family_ = AF_UNSPEC;

	buffer_sizes_[0] = -1;
	buffer_sizes_[1] = -1;
}

void socket_base::detach_thread(scoped_lock & l)
{
	if (!socket_thread_) {
		return;
	}

	socket_thread_->set_socket(nullptr, l);
	if (socket_thread_->quit_) {
		socket_thread_->wakeup_thread(l);
		l.unlock();
		delete socket_thread_;
		socket_thread_ = nullptr;
	}
	else {
		if (!socket_thread_->thread_) {
			auto thread = socket_thread_;
			socket_thread_ = nullptr;
			l.unlock();
			delete thread;
		}
		else {
			socket_thread_->wakeup_thread(l);
			socket_thread_->thread_.detach();
			socket_thread_->quit_ = true;
			socket_thread_ = nullptr;
			l.unlock();
		}
	}
}

int socket_base::close()
{
	if (!socket_thread_) {
		close_socket_fd(fd_);
		return 0;
	}

	scoped_lock l(socket_thread_->mutex_);
	if (fd_ != -1) {
		socket_thread_->fds_to_close_.emplace_back(fd_);
		fd_ = -1;
	}

	socket_thread_->host_.clear();
	socket_thread_->port_.clear();

	socket_thread_->wakeup_thread(l);

	if (dynamic_cast<socket*>(this)) {
		static_cast<socket*>(this)->state_ = socket_state::closed;
	}
	else {
		static_cast<listen_socket*>(this)->state_ = listen_socket_state{};
	}

	socket_thread_->triggered_ = 0;
	for (int i = 0; i < WAIT_EVENTCOUNT; ++i) {
		socket_thread_->triggered_errors_[i] = 0;
	}

	if (evt_handler_) {
		remove_socket_events(evt_handler_, ev_source_);
		evt_handler_ = nullptr;
	}
	detach_thread(l);

	return 0;
}


std::string socket_base::address_to_string(sockaddr const* addr, int addr_len, bool with_port, bool strip_zone_index)
{
	if (!addr) {
		return {};
	}

	char hostbuf[NI_MAXHOST];
	char portbuf[NI_MAXSERV];

	if (!addr_len) {
		switch (addr->sa_family) {
			case AF_INET:
				addr_len = sizeof(struct sockaddr_in);
				break;
			case AF_INET6:
				addr_len = sizeof(struct sockaddr_in6);
				break;
			default:
				return {};
		}
	}
	int res = getnameinfo(addr, addr_len, hostbuf, NI_MAXHOST, with_port ? portbuf : nullptr, with_port ? NI_MAXSERV : 0, NI_NUMERICHOST | NI_NUMERICSERV);
	if (res) { // Should never fail
		return std::string();
	}

	std::string host = hostbuf;

	// IPv6 uses colons as separator, need to enclose address
	// to avoid ambiguity if also showing port
	if (addr->sa_family == AF_INET6) {
		if (strip_zone_index) {
			auto pos = host.find('%');
			if (pos != std::string::npos) {
				host = host.substr(0, pos);
			}
		}
		if (with_port) {
			host = "[" + host + "]";
		}
	}

	if (with_port) {
		return host + ":" + std::string(portbuf);
	}
	else {
		return host;
	}
}

std::string socket_base::address_to_string(char const* buf, int buf_len)
{
	if (buf_len != 4 && buf_len != 16) {
		return std::string();
	}

	sockaddr_u addr{};
	if (buf_len == 16) {
		memcpy(&addr.in6.sin6_addr, buf, buf_len);
		addr.in6.sin6_family = AF_INET6;
	}
	else {
		memcpy(&addr.in4.sin_addr, buf, buf_len);
		addr.in4.sin_family = AF_INET;
	}

	return address_to_string(&addr.sockaddr_, sizeof(addr), false, true);
}

std::string socket_base::local_ip(bool strip_zone_index) const
{
	sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int res = getsockname(fd_, (sockaddr*)&addr, &addr_len);
	if (res) {
		return std::string();
	}

	return address_to_string((sockaddr *)&addr, addr_len, false, strip_zone_index);
}

address_type socket_base::address_family() const
{
	sockaddr_u addr;
	socklen_t addr_len = sizeof(addr);
	int res = getsockname(fd_, &addr.sockaddr_, &addr_len);
	if (res) {
		return address_type::unknown;
	}

	switch (addr.sockaddr_.sa_family)
	{
	case AF_INET:
		return address_type::ipv4;
	case AF_INET6:
		return address_type::ipv6;
#ifndef FZ_WINDOWS
	case AF_UNIX:
		return address_type::unix;
#endif
	default:
		return address_type::unknown;
	}
}

int socket_base::local_port(int& error) const
{
	sockaddr_u addr;
	socklen_t addr_len = sizeof(addr);
	error = getsockname(fd_, &addr.sockaddr_, &addr_len);
	if (error) {
#ifdef FZ_WINDOWS
		error = convert_msw_error_code(WSAGetLastError());
#else
		error = errno;
#endif
		return -1;
	}

	if (addr.storage.ss_family == AF_INET) {
		return ntohs(addr.in4.sin_port);
	}
	else if (addr.storage.ss_family == AF_INET6) {
		return ntohs(addr.in6.sin6_port);
	}

	error = EINVAL;
	return -1;
}

int socket_base::set_buffer_sizes(int size_receive, int size_send)
{
	if (!socket_thread_) {
		return ENOTCONN;
	}


	scoped_lock l(socket_thread_->mutex_);

#if HAVE_TCP_INFO
	// Explicitly ignore setting buffer size until after the unmodified window scale factor is known.
	if (unmodified_rcv_wscale)
#endif
	{
		if (size_receive < 0) {
			// Remember if we ever changd it
			buffer_sizes_[0] = (buffer_sizes_[0] == -1) ? -1 : -2;
		}
		else {
			buffer_sizes_[0] = size_receive;
		}
	}
	buffer_sizes_[1] = size_send;

	if (fd_ == -1) {
		return -1;
	}

	return do_set_buffer_sizes(fd_, size_receive, size_send);
}

bool socket_base::bind(std::string const& address)
{
	scoped_lock l(socket_thread_->mutex_);
	if (fd_ == -1) {
		socket_thread_->bind_ = address;
		return true;
	}

	return false;
}


namespace {
std::string get_peer_ip(int fd, bool strip_zone_index)
{
	sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int res = getpeername(fd, (sockaddr*)&addr, &addr_len);
	if (res) {
		return std::string();
	}

	return socket::address_to_string((sockaddr *)&addr, addr_len, false, strip_zone_index);
}

int get_peer_port(int fd, int& error)
{
	sockaddr_u addr;
	socklen_t addr_len = sizeof(addr);
	error = getpeername(fd, &addr.sockaddr_, &addr_len);
	if (error) {
#ifdef FZ_WINDOWS
		error = convert_msw_error_code(WSAGetLastError());
#else
		error = errno;
#endif
		return -1;
	}

	if (addr.storage.ss_family == AF_INET) {
		return ntohs(addr.in4.sin_port);
	}
	else if (addr.storage.ss_family == AF_INET6) {
		return ntohs(addr.in6.sin6_port);
	}

	error = EINVAL;
	return -1;
}
}

socket_descriptor::~socket_descriptor()
{
	close_socket_fd(fd_);
}

std::string socket_descriptor::peer_ip(bool strip_zone_index) const
{
	return get_peer_ip(fd_, strip_zone_index);
}

int socket_descriptor::peer_port(int& error) const
{
	return get_peer_port(fd_, error);
}


listen_socket::listen_socket(thread_pool & pool, event_handler* evt_handler)
	: socket_base(pool, evt_handler, this)
	, socket_event_source(this)
{
}

listen_socket::~listen_socket()
{
	close();
}

void listen_socket::set_event_handler(event_handler* pEvtHandler)
{
	if (!socket_thread_) {
		return;
	}

	scoped_lock l(socket_thread_->mutex_);

	if (evt_handler_ == pEvtHandler) {
		return;
	}

	change_socket_event_handler(evt_handler_, pEvtHandler, ev_source_, fz::socket_event_flag{});

	evt_handler_ = pEvtHandler;
}

int listen_socket::listen(address_type family, int port)
{
	if (state_ != listen_socket_state{}) {
		return EALREADY;
	}

	if (port < 0 || port > 65535) {
		return EINVAL;
	}

	switch (family)
	{
	case address_type::unknown:
		family_ = AF_UNSPEC;
		break;
	case address_type::ipv4:
		family_ = AF_INET;
		break;
	case address_type::ipv6:
		family_ = AF_INET6;
		break;
	default:
		return EINVAL;
	}

	{
		addrinfo hints = {};
		hints.ai_family = family_;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

		std::string portstring = fz::to_string(port);

		addrinfo* addressList = nullptr;

		int res = getaddrinfo(socket_thread_->bind_.empty() ? nullptr : socket_thread_->bind_.c_str(), portstring.c_str(), &hints, &addressList);

		if (res) {
#ifdef FZ_WINDOWS
			return convert_msw_error_code(res);
#else
			return res;
#endif
		}

		for (addrinfo* addr = addressList; addr; addr = addr->ai_next) {
			fd_ = socket_thread::create_socket_fd(*addr);
			res = last_socket_error();

			if (fd_ == -1) {
				continue;
			}

			if (addr->ai_family == AF_INET6) {
				int enable = 1;
				setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char const*>(&enable), sizeof(enable));
			}

			{
				int enable = 1;
#if FZ_WINDOWS
				int const flag = SO_EXCLUSIVEADDRUSE;
#else
				int const flag = SO_REUSEADDR;
#endif
				(void)setsockopt(fd_, SOL_SOCKET, flag, (const char*)&enable, sizeof(enable));
			}

			res = ::bind(fd_, addr->ai_addr, addr->ai_addrlen);
			if (!res) {
				break;
			}

			res = last_socket_error();
			close_socket_fd(fd_);
		}
		freeaddrinfo(addressList);
		if (fd_ == -1) {
			return res;
		}
	}

	int res = ::listen(fd_, 64);
	if (res) {
		res = last_socket_error();
		close_socket_fd(fd_);
		return res;
	}

	state_ = listen_socket_state::listening;

	socket_thread_->waiting_ = WAIT_ACCEPT;

	if (socket_thread_->start()) {
		state_ = listen_socket_state{};
		close_socket_fd(fd_);
		return EMFILE;
	}

	return 0;
}

std::unique_ptr<socket> listen_socket::accept(int &error, fz::event_handler * handler)
{
	socket_descriptor desc = fast_accept(error);
	if (!desc) {
		return std::unique_ptr<socket>();
	}

	auto ret = socket::from_descriptor(std::move(desc), thread_pool_, error, handler);
	if (!ret) {
		error = ENOMEM;
	}
	return ret;
}

std::unique_ptr<listen_socket> listen_socket::from_descriptor(socket_descriptor && desc, thread_pool & pool, int & error, fz::event_handler * handler)
{
	if (!desc) {
		error = ENOTSOCK;
		return nullptr;
	}

#ifndef FZ_WINDOWS
	disable_sigpipe();
#endif

	socket_t fd = desc.detach();

#if defined(SO_NOSIGPIPE) && !defined(MSG_NOSIGNAL)
	// We do not want SIGPIPE if writing to socket.
	const int value = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(int));
#endif

	set_nonblocking(fd);

	auto pSocket = std::make_unique<listen_socket>(pool, nullptr);
	if (!pSocket->socket_thread_) {
		error = ENOMEM;
		close_socket_fd(fd);
		return nullptr;
	}
	pSocket->state_ = listen_socket_state::listening;
	pSocket->fd_ = fd;

	pSocket->evt_handler_ = handler;
	pSocket->socket_thread_->waiting_ = WAIT_ACCEPT;

	sockaddr_u addr;
	socklen_t addr_len = sizeof(addr);
	if (!getsockname(pSocket->fd_, &addr.sockaddr_, &addr_len)) {
		pSocket->family_ = addr.sockaddr_.sa_family;
	}
	if (pSocket->socket_thread_->start()) {
		error = ENOMEM;
		pSocket.reset();
	}

	return pSocket;
}

socket_descriptor listen_socket::fast_accept(int &error)
{
	if (!socket_thread_) {
		error = ENOTSOCK;
		return socket_descriptor();
	}

	socket_t fd;

	{
		scoped_lock l(socket_thread_->mutex_);
		socket_thread_->waiting_ |= WAIT_ACCEPT;
		socket_thread_->wakeup_thread(l);

#if HAVE_ACCEPT4
		fd = ::accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
		if (fd == -1 && errno == ENOSYS)
#endif
		{
#if !defined(FZ_WINDOWS)
			forkblock b;
#endif
			fd = ::accept(fd_, nullptr, nullptr);
#if !defined(FZ_WINDOWS)
			set_cloexec(fd);
#endif
		}

		if (fd == -1) {
			error = errno;
		}
	}

	if (fd != -1) {
		do_set_buffer_sizes(fd, buffer_sizes_[0], buffer_sizes_[1]);
	}
	return socket_descriptor(fd);
}

listen_socket_state listen_socket::get_state() const
{
	if (!socket_thread_) {
		return listen_socket_state{};
	}

	scoped_lock l(socket_thread_->mutex_);
	return state_;
}



socket::socket(thread_pool & pool, event_handler* evt_handler)
	: socket_base(pool, evt_handler, this)
	, socket_interface(this)
	, keepalive_interval_(duration::from_hours(2))
{
}

socket::~socket()
{
	close();
}

std::unique_ptr<socket> socket::from_descriptor(socket_descriptor && desc, thread_pool & pool, int & error, fz::event_handler * handler)
{
	if (!desc) {
		error = ENOTSOCK;
		return nullptr;
	}

	socket_t fd = desc.detach();

#if defined(SO_NOSIGPIPE) && !defined(MSG_NOSIGNAL)
	// We do not want SIGPIPE if writing to socket.
	const int value = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(int));
#endif

	set_nonblocking(fd);

	auto pSocket = std::make_unique<socket>(pool, nullptr);
	if (!pSocket->socket_thread_) {
		error = ENOMEM;
		pSocket.reset();
	}
	else {
		pSocket->state_ = socket_state::connected;
		pSocket->fd_ = fd;
		fd = -1;
		pSocket->host_ = to_native(pSocket->peer_ip());
		pSocket->evt_handler_ = handler;
		pSocket->socket_thread_->waiting_ = WAIT_READ;

		sockaddr_u addr;
		socklen_t addr_len = sizeof(addr);
		if (!getsockname(pSocket->fd_, &addr.sockaddr_, &addr_len)) {
			pSocket->family_ = addr.sockaddr_.sa_family;
		}
		if (pSocket->socket_thread_->start()) {
			error = ENOMEM;
			pSocket.reset();
		}
	}
	close_socket_fd(fd);

	return pSocket;
}

int socket::connect(native_string const& host, unsigned int port, address_type family)
{
	if (state_ != socket_state{}) {
		return EISCONN;
	}

	if (family != address_type::unix && (port < 1 || port > 65535)) {
		return EINVAL;
	}

	if (host.empty()) {
		return EINVAL;
	}

	int af{};

	switch (family)
	{
	case address_type::unknown:
		af = AF_UNSPEC;
		break;
	case address_type::ipv4:
		af = AF_INET;
		break;
	case address_type::ipv6:
		af = AF_INET6;
		break;
#ifndef FZ_WINDOWS
	case address_type::unix:
		af = AF_UNIX;
		break;
#endif
	default:
		return EINVAL;
	}

	family_ = af;
	state_ = socket_state::connecting;

	host_ = host;
	port_ = port;
	int res = socket_thread_->connect((family != address_type::unix) ? to_utf8(host_) : to_string(host_), port_);
	if (res) {
		state_ = socket_state::failed;
		return res;
	}

	return 0;
}

socket_state socket::get_state() const
{
	if (!socket_thread_) {
		return socket_state{};
	}

	scoped_lock l(socket_thread_->mutex_);
	return state_;
}

int socket::read(void* buffer, unsigned int size, int& error)
{
#if DEBUG_SOCKETEVENTS
	assert(buffer && size);
#endif

	if (!socket_thread_) {
		error = ENOTCONN;
		return -1;
	}

#if DEBUG_SOCKETEVENTS
	{
		scoped_lock l(socket_thread_->mutex_);
		assert(!(socket_thread_->waiting_ & WAIT_READ));
		assert(!has_pending_event(evt_handler_, this, socket_event_flag::read));
	}
#endif

	int res = recv(fd_, (char*)buffer, size, 0);

	if (res == -1) {
		error = last_socket_error();
		if (error == EAGAIN) {
			scoped_lock l(socket_thread_->mutex_);
			if (!(socket_thread_->waiting_ & WAIT_READ)) {
				socket_thread_->waiting_ |= WAIT_READ;
				socket_thread_->wakeup_thread(l);
			}
		}
	}
	else {
		error = 0;
	}

	return res;
}

int socket::write(void const* buffer, unsigned int size, int& error)
{
#if DEBUG_SOCKETEVENTS
	assert(buffer && size);
#endif

#ifdef MSG_NOSIGNAL
	const int flags = MSG_NOSIGNAL;
#else
	const int flags = 0;
#endif

#if DEBUG_SOCKETEVENTS
	if (socket_thread_) {
		scoped_lock l(socket_thread_->mutex_);
		assert(!(socket_thread_->waiting_ & WAIT_WRITE));
		assert(!has_pending_event(evt_handler_, this, socket_event_flag::write | socket_event_flag::connection));
	}
#endif

	int res = send(fd_, (const char*)buffer, size, flags);

	if (res == -1) {
		error = last_socket_error();
		if (error == EAGAIN) {
			scoped_lock l (socket_thread_->mutex_);

#if DEBUG_SOCKETEVENTS
			assert(!(socket_thread_->waiting_ & WAIT_WRITE));
			assert(!has_pending_event(evt_handler_, this, socket_event_flag::write | socket_event_flag::connection));
#endif
			if (!(socket_thread_->waiting_ & WAIT_WRITE)) {
				socket_thread_->waiting_ |= WAIT_WRITE;
				socket_thread_->wakeup_thread(l);
			}
		}
	}
	else {
		error = 0;
	}

	return res;
}

std::string socket::peer_ip(bool strip_zone_index) const
{
	return get_peer_ip(fd_, strip_zone_index);
}

int socket::peer_port(int& error) const
{
	return get_peer_port(fd_, error);
}

int socket::ideal_send_buffer_size()
{
	if (!socket_thread_) {
		return -1;
	}

	int size = -1;
#ifdef FZ_WINDOWS
	scoped_lock l(socket_thread_->mutex_);

	if (fd_ != -1) {
		// MSDN says this:
		// "Dynamic send buffering for TCP was added on Windows 7 and Windows
		// Server 2008 R2. By default, dynamic send buffering for TCP is
		// enabled unless an application sets the SO_SNDBUF socket option on
		// the stream socket"
		//
		// Guess what: It doesn't do it by itself. Programs need to
		// periodically and manually update SO_SNDBUF based on what
		// SIO_IDEAL_SEND_BACKLOG_QUERY returns.
#ifndef SIO_IDEAL_SEND_BACKLOG_QUERY
#define SIO_IDEAL_SEND_BACKLOG_QUERY 0x4004747b
#endif
		ULONG v{};
		DWORD outlen{};
		if (!WSAIoctl(fd_, SIO_IDEAL_SEND_BACKLOG_QUERY, nullptr, 0, &v, sizeof(v), &outlen, nullptr, nullptr)) {
			size = v;
		}
	}
#endif

	return size;
}

native_string socket::peer_host() const
{
	return host_;
}

int socket::shutdown()
{
#ifdef FZ_WINDOWS
	int res = ::shutdown(fd_, SD_SEND);
#else
	int res = ::shutdown(fd_, SHUT_WR);
#endif
	if (res != 0) {
		return last_socket_error();
	}

	scoped_lock l(socket_thread_->mutex_);
	if (state_ == socket_state::connected) {
		state_ = socket_state::shut_down;
	}
	socket_thread_->waiting_ &= ~WAIT_WRITE;
	socket_thread_->triggered_ &= ~WAIT_WRITE;

	return 0;
}

void socket::set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block)
{
	if (!socket_thread_) {
		return;
	}

	scoped_lock l(socket_thread_->mutex_);

	fz::socket_event_flag const pending = change_socket_event_handler(evt_handler_, pEvtHandler, ev_source_, retrigger_block);
	evt_handler_ = pEvtHandler;

	if (pEvtHandler) {
		if (state_ == socket_state::connected && !(socket_thread_->waiting_ & WAIT_WRITE) && !(pending & (socket_event_flag::connection | socket_event_flag::write)) && !(retrigger_block & socket_event_flag::write)) {
			socket_thread_->triggered_ &= ~WAIT_WRITE;
			pEvtHandler->send_event<socket_event>(ev_source_, socket_event_flag::write, 0);
		}
		if ((state_ == socket_state::connected || state_ == socket_state::shut_down) && !(socket_thread_->waiting_ & WAIT_READ) && !(pending & socket_event_flag::read) && !(retrigger_block & socket_event_flag::read)) {
			socket_thread_->triggered_ &= ~WAIT_READ;
			pEvtHandler->send_event<socket_event>(ev_source_, socket_event_flag::read, 0);
		}
	}
}

void socket::set_keepalive_interval(duration const& d)
{
	if (!socket_thread_) {
		return;
	}

	if (d < duration::from_minutes(1)) {
		return;
	}

	scoped_lock l(socket_thread_->mutex_);

	keepalive_interval_ = d;
	if (fd_ != -1) {
		do_set_flags(fd_, flags_, flag_keepalive, keepalive_interval_);
	}
}

void socket::set_flags(int flags, bool enable)
{
	if (!socket_thread_) {
		return;
	}

	scoped_lock l(socket_thread_->mutex_);

	if (fd_ != -1) {
		do_set_flags(fd_, enable ? flags : 0, flags & (flags ^ flags_), keepalive_interval_);
	}
	if (enable) {
		flags_ |= flags;
	}
	else {
		flags_ &= ~flags;
	}
}

void socket::set_flags(int flags)
{
	if (!socket_thread_) {
		return;
	}

	scoped_lock l(socket_thread_->mutex_);

	if (fd_ != -1) {
		do_set_flags(fd_, flags, flags ^ flags_, keepalive_interval_);
	}
	flags_ = flags;
}

#ifndef FZ_WINDOWS
int socket::read_fd(fz::buffer & buf, int &fd, int & error)
{
	if (!socket_thread_) {
		fd = -1;
		error = EBADF;
		return -1;
	}

	{
		scoped_lock l(socket_thread_->mutex_);
		if (family_ != AF_UNIX) {
			fd = -1;
			error = EBADF;
			return -1;
		}
#if DEBUG_SOCKETEVENTS
		assert(!(socket_thread_->waiting_ & WAIT_READ));
		assert(!has_pending_event(evt_handler_, this, socket_event_flag::read));
#endif
	}

	int res = fz::read_fd(fd_, buf, fd, error);
	if (res == -1 && error == EAGAIN) {
		scoped_lock l(socket_thread_->mutex_);
		if (!(socket_thread_->waiting_ & WAIT_READ)) {
			socket_thread_->waiting_ |= WAIT_READ;
			socket_thread_->wakeup_thread(l);
		}
	}
	return res;
}

int socket::send_fd(fz::buffer & buf, int fd, int & error)
{
	if (!socket_thread_) {
		error = EBADF;
		return -1;
	}

	{
		scoped_lock l(socket_thread_->mutex_);
		if (family_ != AF_UNIX) {
			error = EBADF;
			return -1;
		}
#if DEBUG_SOCKETEVENTS
		assert(!(socket_thread_->waiting_ & WAIT_WRITE));
		assert(!has_pending_event(evt_handler_, this, socket_event_flag::write | socket_event_flag::connection));
#endif
	}

	int res = fz::send_fd(fd_, buf, fd, error);
	if (res == -1 && error == EAGAIN) {
		scoped_lock l(socket_thread_->mutex_);
		if (!(socket_thread_->waiting_ & WAIT_WRITE)) {
			socket_thread_->waiting_ |= WAIT_WRITE;
			socket_thread_->wakeup_thread(l);
		}
	}
	return res;
}
#endif

socket_layer::socket_layer(event_handler* handler, socket_interface& next_layer, bool event_passthrough)
	: socket_interface(next_layer.root())
	, event_handler_(handler)
	, next_layer_(next_layer)
	, event_passthrough_(event_passthrough)
{
	if (event_passthrough) {
		next_layer_.set_event_handler(handler);
	}
}

socket_layer::~socket_layer()
{
	next_layer_.set_event_handler(nullptr);
	remove_socket_events(event_handler_, this);
}

void socket_layer::set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block)
{
	auto old = event_handler_;
	event_handler_ = handler;
	socket_event_flag const pending = change_socket_event_handler(old, handler, this, retrigger_block);

	if (event_passthrough_) {
		retrigger_block |= pending;
		next_layer_.set_event_handler(handler, retrigger_block);
	}
}

void socket_layer::forward_socket_event(socket_event_source* source, socket_event_flag t, int error)
{
	if (event_handler_) {
		(*event_handler_)(socket_event(source, t, error));
	}
}

void socket_layer::forward_hostaddress_event(socket_event_source* source, std::string const& address)
{
	if (event_handler_) {
		(*event_handler_)(hostaddress_event(source, address));
	}
}

void socket_layer::set_event_passthrough(socket_event_flag retrigger_block)
{
	event_passthrough_ = true;
	next_layer_.set_event_handler(event_handler_, retrigger_block);
}

int socket_layer::shutdown_read()
{
	return next_layer_.shutdown_read();
}

socket_base::socket_t socket::get_descriptor()
{
	if (!socket_thread_) {
		return fd_;
	}

	scoped_lock l(socket_thread_->mutex_);
	return fd_; // Mutex as fd_ might change during connect
}
}
