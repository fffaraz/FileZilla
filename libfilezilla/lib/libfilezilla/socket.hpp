#ifndef LIBFILEZILLA_SOCKET_HEADER
#define LIBFILEZILLA_SOCKET_HEADER

/** \file
 * \brief Socket classes for networking
 *
 * Declares the \ref fz::socket and \ref fz::listen_socket classes,
 * alongside supporting classes to handle socket events.
 */

#include "libfilezilla.hpp"

#include "event_handler.hpp"
#include "iputils.hpp"

#include <memory>

#include <errno.h>

/// \private
struct sockaddr;

namespace fz {
class buffer;
class thread_pool;

/** \brief The type of a socket event
 *
 * In received events, exactly a single bit is always set.
 *
 * Flag combinations are used when changing event handlers,
 * \sa f::socket::set_event_handler
 */
enum class socket_event_flag
{
	/**
	 * Sent if connection attempt has failed, but there are still
	 * additional addresses to try.
	 * Errors can be ignored for this type.
	 */
	connection_next = 0x1,

	/**
	 * If no error is set, the connection has been established.
	 * If an error is set, the connection could not be established.
	 */
	connection = 0x2,

	/**
	 * If no error is set, data has become available.
	 * If an error is set, the connection has failed.
	 */
	read = 0x4,

	/**
	 * If no error is set, data can be written.
	 * If an error is set, the connection has failed.
	 */
	write = 0x8,
};

inline bool operator&(socket_event_flag lhs, socket_event_flag rhs) {
	return (static_cast<std::underlying_type_t<socket_event_flag>>(lhs) & static_cast<std::underlying_type_t<socket_event_flag>>(rhs)) != 0;
}
inline socket_event_flag operator|(socket_event_flag lhs, socket_event_flag rhs)
{
	return static_cast<socket_event_flag>(static_cast<std::underlying_type_t<socket_event_flag>>(lhs) | static_cast<std::underlying_type_t<socket_event_flag>>(rhs));
}
inline socket_event_flag& operator|=(socket_event_flag& lhs, socket_event_flag rhs)
{
	lhs = lhs | rhs;
	return lhs;
}


/**
 * \brief All classes sending socket events should derive from this.
 *
 * Allows implementing socket layers, e.g. for TLS.
 *
 * \sa fz::RemoveSocketEvents
 * \sa fz::ChangeSocketEventHandler
 */
class FZ_PUBLIC_SYMBOL socket_event_source
{
public:
	virtual ~socket_event_source() = default;

	/** \brief Gets the root source
	 *
	 * In a layered stack of sources this would be the socket itself.
	 */
	socket_event_source* root() const {
		return root_;
	}

protected:
	socket_event_source() = delete;
	explicit socket_event_source(socket_event_source* root)
		: root_(root)
	{}

	socket_event_source* const root_{};
};

/// \private
struct socket_event_type;

/**
 * All socket events are sent through this.
 *
 * \sa \ref fz::socket_event_flag
 *
 * If the error value is non-zero for the connection, read and write events,
 * the socket has failed and needs to be closed. Doing anything else with
 * failed sockets is undefined behavior.
 * Failure events can be received at any time.
 *
 * Read and write events are edge-triggered:
 * - After receiving a read event for a socket, it will not be sent again
 *   unless a subsequent call to socket_interface::read or
 *   socket_interface::shutdown_read has returned EAGAIN.
 * - The same holds for the write event and socket_interface::write and
 *   socket_interface::shutdown
 * - A successful connection events doubles as write event, it does not
 *   act as read event
 *
 * It is a grave violation to call the read/write/shutdown functions
 * again after they returned EAGAIN without first waiting for the event.
 */
typedef simple_event<socket_event_type, socket_event_source*, socket_event_flag, int> socket_event;

/// \private
struct hostaddress_event_type{};

/**
* Whenever a hostname has been resolved to an IP address, this event is sent with the resolved IP address literal.
*/
typedef simple_event<hostaddress_event_type, socket_event_source*, std::string> hostaddress_event;

/**
 * \brief Remove all pending socket events from source sent to handler.
 *
 * Useful e.g. if you want to destroy the handler but keep the source.
 * This function is called, through change_socket_event_handler, by socket::set_event_handler(0)
 */
void FZ_PUBLIC_SYMBOL remove_socket_events(event_handler * handler, socket_event_source const* const source);

/**
 * \brief Changes all pending socket events from source
 *
 * If newHandler is null, remove_socket_events is called.
 *
 * This function is called by socket::set_event_handler().
 *
 * Example use-cases: Handoff after proxy handshakes, or handoff to TLS classes in case of STARTTLS mechanism
 *
 * Returns which events are still pending.
 */
fz::socket_event_flag FZ_PUBLIC_SYMBOL change_socket_event_handler(event_handler * old_handler, event_handler * new_handler, socket_event_source const* const source, fz::socket_event_flag remove);

/// \private
class socket_thread;

/// Common base clase for fz::socket and fz::listen_socket
class FZ_PUBLIC_SYMBOL socket_base
{
public:
	/**
	 * \brief Sets socket buffer sizes.
	 *
	 * Internally this sets SO_RCVBUF and SO_SNDBUF on the socket.
	 *
	 * If called on listen socket, sizes will be inherited by accepted sockets.
	 */
	int set_buffer_sizes(int size_receive, int size_send);

	/// If connected, either ipv4, ipv6 or unix, unknown otherwise
	address_type address_family() const;

	/**
	 * \brief Returns local address of a connected socket
	 *
	 * \return empty string on error
	 */
	std::string local_ip(bool strip_zone_index = false) const;

	/**
	* \brief Returns local port of a connected socket
	*
	* \return -1 on error
	*/
	int local_port(int& error) const;

	static std::string address_to_string(sockaddr const* addr, int addr_len, bool with_port = true, bool strip_zone_index = false);
	static std::string address_to_string(char const* buf, int buf_len);

	/**
	 * \brief Bind socket to the specific local IP
	 *
	 * Undefined after having called connect/listen
	 */
	bool bind(std::string const& address);

#if FZ_WINDOWS
	typedef intptr_t socket_t;
#else
	typedef int socket_t;
#endif

	int close();

protected:
	friend class socket_thread;

	socket_base(thread_pool& pool, event_handler* evt_handler, socket_event_source* ev_source);
	virtual ~socket_base() = default;

	// Note: Unlocks the lock.
	void detach_thread(scoped_lock & l);

	thread_pool & thread_pool_;
	event_handler* evt_handler_;

	socket_thread* socket_thread_{};

	socket_event_source * const ev_source_{};

	socket_t fd_{-1};

	unsigned int port_{};

	int family_;

	int buffer_sizes_[2];
};

class socket;

enum class listen_socket_state
{
	/// How the socket is initially
	none,

	/// Only in listening state you can get a connection event.
	listening,
};

/// Lightweight holder for socket descriptors
class FZ_PUBLIC_SYMBOL socket_descriptor final
{
public:
	socket_descriptor() = default;
	~socket_descriptor();
	explicit socket_descriptor(socket_base::socket_t fd) noexcept : fd_(fd) {}

	socket_descriptor(socket_descriptor const&) = delete;
	socket_descriptor& operator=(socket_descriptor const&) = delete;

	socket_descriptor(socket_descriptor && rhs) noexcept { std::swap(fd_, rhs.fd_); }
	socket_descriptor& operator=(socket_descriptor && rhs) noexcept {
		std::swap(fd_, rhs.fd_);
		return *this;
	}

	socket_base::socket_t detach() {
		socket_base::socket_t ret = fd_;
		fd_ = -1;
		return ret;
	}

	explicit operator bool() const { return fd_ != -1; }

	/**
	 * \brief Returns remote address of a connected socket
	 *
	 * \return empty string on error
	 */
	std::string peer_ip(bool strip_zone_index = false) const;

	/**
	 * \brief Returns remote port of a connected socket
	 *
	 * \return -1 on error
	 */
	int peer_port(int& error) const;

private:
	socket_base::socket_t fd_{-1};
};

/**
 * \brief Simple Listen socket
 *
 * When a client connects, a socket event with the connection flag is send.
 *
 * Call accept to accept.
 */
class FZ_PUBLIC_SYMBOL listen_socket final : public socket_base, public socket_event_source
{
	friend class socket_base;
	friend class socket_thread;
public:
	listen_socket(thread_pool& pool, event_handler* evt_handler);
	virtual ~listen_socket();

	listen_socket(listen_socket const&) = delete;
	listen_socket& operator=(listen_socket const&) = delete;

	static std::unique_ptr<listen_socket> from_descriptor(socket_descriptor && desc, thread_pool & pool, int & error, fz::event_handler * handler = nullptr);

	/**
	 * \brief Starts listening
	 *
	 * If no port is given, let the operating system decide on a port. Can use local_port to query it afterwards.
	 *
	 * The address type, if not fz::address_type::unknown, must may the type of the address passed to bind()
	 */
	int listen(address_type family, int port = 0);

	/// Accepts incoming connection. If no socket is returned, error contains the reason
	std::unique_ptr<socket> accept(int& error, fz::event_handler * handler = nullptr);

	/**
	 * \brief Like accept, but only returns a socket descriptor.
	 *
	 * Best suited for tight accept loops where the descriptor is handed
	 * off to other threads.
	 */
	socket_descriptor fast_accept(int& error);

	listen_socket_state get_state() const;

	void set_event_handler(event_handler* pEvtHandler);

private:
	listen_socket_state state_{};
};


/// State transitions are monotonically increasing
enum class socket_state : unsigned char
{
	/// How the socket is initially
	none,

	/// Only in connecting state you can get a connection event.
	/// After sending the event, socket is in connected or failed state
	/// depending whether error value is set in the event.
	connecting,

	/// Socket is in its normal working state. You can get send and receive events
	connected,

	/// Shutting down of the write side. Transitions to
	/// shutdown with a single write event.
	shutting_down,

	/// Write side has finished shutting down. Receive still working normally.
	shut_down,

	/// Socket has been closed. Further events disabled.
	closed,

	/// Socket has failed. Further events disabled.
	failed
};

/**
 * \brief Interface for sockets
 *
 * Can be used for layers, see fz::socket for the expected semantics.
 */
class FZ_PUBLIC_SYMBOL socket_interface : public socket_event_source
{
public:
	socket_interface(socket_interface const&) = delete;
	socket_interface& operator=(socket_interface const&) = delete;

	virtual int read(void* buffer, unsigned int size, int& error) = 0;
	virtual int write(void const* buffer, unsigned int size, int& error) = 0;

	template<typename T, std::enable_if_t<std::is_signed_v<T>, int> = 0>
	int read(void* buffer, T size, int& error)
	{
		if (size < 0) {
			error = EINVAL;
			return -1;
		}

		return read(buffer, static_cast<unsigned int>(size), error);
	}
	template<typename T, std::enable_if_t<std::is_unsigned_v<T> && (sizeof(T) > sizeof(unsigned int)), int> = 0>
	int read(void* buffer, T size, int& error)
	{
		if (size > std::numeric_limits<unsigned int>::max()) {
			size = std::numeric_limits<unsigned int>::max();
		}
		return read(buffer, static_cast<unsigned int>(size), error);
	}

	template<typename T, std::enable_if_t<std::is_signed_v<T>, int> = 0>
	int write(void const* buffer, T size, int& error)
	{
		if (size < 0) {
			error = EINVAL;
			return -1;
		}

		return write(buffer, static_cast<std::make_unsigned_t<T>>(size), error);
	}
	template<typename T, std::enable_if_t<std::is_unsigned_v<T> && (sizeof(T) > sizeof(unsigned int)), int> = 0>
	int write(void const* buffer, T size, int& error)
	{
		if (size > std::numeric_limits<unsigned int>::max()) {
			size = std::numeric_limits<unsigned int>::max();
		}
		return write(buffer, static_cast<unsigned int>(size), error);
	}

	virtual void set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block = fz::socket_event_flag{}) = 0;

	virtual native_string peer_host() const = 0;
	virtual int peer_port(int& error) const = 0;

	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) = 0;

	virtual fz::socket_state get_state() const = 0;

	/**
	 * \brief Signals peers that we want to close the connections.
	 *
	 * Only disallows further sends, does not affect reading from the
	 * socket.
	 *
	 * Returns 0 on success, an error code otherwise.
	 * If it returns EGAIN, shutdown is not yet complete. Call shutdown
	 * again after the next write event.
	 */
	virtual int shutdown() = 0;

	/// \see socket_layer::shutdown_read
	virtual int shutdown_read() = 0;

protected:
	socket_interface() = delete;

	explicit socket_interface(socket_event_source * root)
		: socket_event_source(root)
	{}
};

/**
 * \brief IPv6 capable, non-blocking socket class
 *
 * Uses and edge-triggered socket events.
 *
 * Error codes are the same as used by the POSIX socket functions,
 * see 'man 2 socket', 'man 2 connect', ...
 */
class FZ_PUBLIC_SYMBOL socket final : public socket_base, public socket_interface
{
	friend class socket_thread;
public:
	socket(thread_pool& pool, event_handler* evt_handler);
	virtual ~socket();

	socket(socket const&) = delete;
	socket& operator=(socket const&) = delete;

	static std::unique_ptr<socket> from_descriptor(socket_descriptor && desc, thread_pool & pool, int & error, fz::event_handler * handler = nullptr);

	socket_state get_state() const override;
	bool is_connected() const {
		socket_state s = get_state();
		return s == socket_state::connected || s == socket_state::shutting_down || s == socket_state::shut_down;
	};

	/**
	 * \brief Starts connecting to the given host, given as name, IPv4 or IPv6 address.
	 *
	 * Returns 0 on success, else an error code.
	 *
	 * Success only means that the establishing of the connection
	 * has started. Once the connection gets fully established or
	 * establishment fails, a connection event gets sent, with the error
	 * parameter indicating success or failure.
	 *
	 * If host is a name that can be resolved, a hostaddress socket event gets
	 * sent during establishment.
	 */
	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) override;

	/**
	 * \brief Read data from socket
	 *
	 * Reads data from socket, returns the number of octets read or -1 on error.
	 *
	 * May return fewer  octets than requested. Return of 0 bytes read indicates EOF.
	 *
	 * Can be called after having receiving a socket event with the read
	 * flag and can thenceforth be called until until it returns an error.
	 *
	 * If the error is EAGAIN, wait for the next read event. On other errors
	 * the socket has failed and should be closed.
	 *
	 * Takes care of EINTR internally.
	 */
	virtual int read(void *buffer, unsigned int size, int& error) override;

	/**
	 * \brief Write data to socket
	 *
	 * Writes data to the socket, returns the number of octets written or -1 on error.
	 *
	 * May return fewer octets than requested.
	 *
	 * Can be called after having receiving a socket event with the write
	 * flag and can thenceforth be called until until it returns an error.
	 *
	 * If the error is EAGAIN, wait for the next write event. On other errors
	 * the socket has failed and should be closed.
	 *
	 * Takes care of EINTR internally.
	 */
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	/**
	 * \brief Returns remote address of a connected socket
	 *
	 * \return empty string on error
	 */
	std::string peer_ip(bool strip_zone_index = false) const;

	/// Returns the hostname passed to connect()
	virtual native_string peer_host() const override;

	/**
	 * \brief Returns remote port of a connected socket
	 *
	 * \return -1 on error
	 */
	virtual int peer_port(int& error) const override;

	/**
	 * On a connected socket, gets the ideal send buffer size or
	 * -1 if it cannot be determined.
	 *
	 * Currently only implemented for Windows.
	 */
	int ideal_send_buffer_size();

	virtual int shutdown() override;

	/**
	 * \brief Changes the associated event handler.
	 *
	 * Pending events are rewritten to the new handler, or deleted if there is no new handler.
	 *
	 * Initially, the new handler is assumed to be waiting on read and write events and if the
	 * socket is in a readable/writable state, the corresponding events are sent if not already
	 * pending.
	 *
	 * As exception, events passed in retrigger_block are always removed and not resent if the socket
	 * is in the readable/writable state.
	 */
	virtual void set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block = fz::socket_event_flag{}) override;

	enum
	{
		/// flag_nodelay disables Nagle's algorithm
		flag_nodelay = 0x01,

		/// flag_keepalive enables TCP keepalive.
		flag_keepalive = 0x02
	};

	int flags() const { return flags_; }

	/// Enables or disabled the passed flags
	void set_flags(int flags, bool enable);

	/// Sets the entire mask of enabled flag, disabling all others
	void set_flags(int flags);

	/**
	 * Sets the interval between TCP keepalive packets.
	 *
	 * Duration must not be smaller than 5 minutes. The default interval is 2 hours.
	 */
	void set_keepalive_interval(duration const& d);

	virtual int shutdown_read() override { return 0; }

	socket_t get_descriptor();

#ifndef FZ_WINDOWS
	/** Sends file descriptors over a Unix Domain Socket.
	 *
	 * fd may be -1.
	 * If fd is not -1, the buffer must not be empty.
	 *
	 * Returns the amount of bytes sent, which may be less than requested, or -1 on error.
	 *
	 * If any bytes got sent then the descriptor has been sent as well.
	 *
	 * If having sent an fd, you should not send any other fd until the buffer has been completely
	 * sent.
	 *
	 * The data you sent should be structured such that the receiving end can detect which
	 * parts of data in the stream have a descriptor associated with it.
	 */
	int send_fd(fz::buffer & buf, int fd, int & error);

	/** Reads data and file descriptors from a Unix Domain Socket
	 *
	 * Appends any read data to the buffer, returns the number of bytes added.
	 *
	 * Returns 0 on EOF, -1 on error.
	 *
	 * If a descriptor got read, it is returned in the fd argument. If no descriptor got read,
	 * fd is set to -1.
	 */
	int read_fd(fz::buffer & buf, int &fd, int & error);
#endif

private:
	friend class socket_base;
	friend class listen_socket;
	native_string host_;

	duration keepalive_interval_;

	int flags_{};
	socket_state state_{};
};

/**
 * \brief A base class for socket layers.
 *
 * Can be used to implement layers, e.g. for TLS or rate-limiting.
 *
 * Layers can in general be added on top of the next layer in any state,
 * though individual layers may post restrictions on this.
 *
 * Note instance lifetime, layers must be destroyed in reverse order.
 *
 * For safe closing of a layer hierarchy, both the write and read side
 * should be shut down first, otherwise pending data might get discarded.
 * The shutdown and shutdown_read functions may return EAGAIN, in which
 * case they must be called again after the next write/read event.
 */
class FZ_PUBLIC_SYMBOL socket_layer : public socket_interface
{
public:
	explicit socket_layer(event_handler* handler, socket_interface& next_layer, bool event_passthrough);
	virtual ~socket_layer();

	socket_layer(socket_layer const&) = delete;
	socket_layer& operator=(socket_layer const&) = delete;

	/// The handler for any events generated (or forwarded) by this layer.
	virtual void set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block = fz::socket_event_flag{}) override;

	/**
	 * Can be overridden to return something different, e.g. a proxy layer
	 * would return the hostname of the peer connected to through the proxy,
	 * whereas the next layer would return the address of the proxy itself.
	 */
	virtual native_string peer_host() const override { return next_layer_.peer_host(); }

	/**
	 * Can be overridden to return something different, e.g. a proxy layer
	 * would return the post of the peer connected to through the proxy,
	 * whereas the next layer would return the port of the proxy itself.
	 */
	virtual int peer_port(int& error) const override { return next_layer_.peer_port(error); }

	/// The next layer further down. Usually another layer or the actual socket.
	socket_interface& next() { return next_layer_; }

	/**
	 * \brief Check that all layers further down also have reached EOF.
	 *
	 * Can only be called after read has returned 0, calling it earlier is undefined.
	 * shutdown_read should be called after eof to ensure all layers have reached EOF.
	 *
	 * \return 0 on success
	 * \return EAGAIN if the shutdown cannot be completed, wait for a read event and try again.
	 * \return otherwise an error has occurred.
	 *
	 * On an ordinary socket, this is a no-op. Some layers however may return an EOF before the
	 * next lower layer has reached its own EOF, such as the EOF of the secure channel from
	 * \ref fz::tls_layer.
	 *
	 * Closing the layer stack without all layers having reached EOF can lead to truncation on
	 * the write side: With a lower layer's EOF waiting in TCP's receive buffer and data pending
	 * in the send buffer, closing the socket is not graceful, it discards all pending data.
	 * Through shutdown_read you can assure that no pending data is left to receive, on this or
	 * any lower layer, so that closing the socket is done graceful ensuring delivery of all
	 * data in the send buffer (assuming there are no network errors).
	 */
	virtual int shutdown_read() override;

	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) override {
		return next_layer_.connect(host, port, family);
	}

	virtual int shutdown() override {
		return next_layer_.shutdown();
	}

	virtual socket_state get_state() const override {
		return next_layer_.get_state();
	}

protected:
	/**
	 * Call in a derived classes handler for fz::socket_event. Results in
	 * a call to operator()(fz::event_base const&) on the event handler passed
	 * to socket_layer.
	 */
	void forward_socket_event(socket_event_source* source, socket_event_flag t, int error);

	/**
	 * Call in a derived classes handler for fz::hostaddress_event. Results in
	 * a call to operator()(fz::event_base const&) on the event handler passed
	 * to socket_layer.
	 */
	void forward_hostaddress_event(socket_event_source* source, std::string const& address);

	/**
	 * A pass-through layer does not handle events itself. Instead any events sent by the next layer get
	 * sent to the event handler passed to the layer.
	 */
	void set_event_passthrough(socket_event_flag retrigger_block = socket_event_flag{});

	event_handler* event_handler_{};
	socket_interface& next_layer_;
	bool event_passthrough_{};
};

/**
 * \brief Gets a symbolic name for socket errors.
 *
 * For example, <tt>error_string(EAGAIN) == "EAGAIN"</tt>
 *
 * \return name if the error code is known
 * \return number as string if the error code is not known
 */
std::string FZ_PUBLIC_SYMBOL socket_error_string(int error);

/**
 * \brief Gets a human-readable, translated description of the error
 */
native_string FZ_PUBLIC_SYMBOL socket_error_description(int error);


#ifdef FZ_WINDOWS

/// \private
class FZ_PRIVATE_SYMBOL winsock_initializer final
{
public:
	winsock_initializer();
	~winsock_initializer();

private:
	bool initialized_{};
};

#ifndef EISCONN
#define EISCONN WSAEISCONN
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEINPROGRESS
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#endif
#ifndef EADDRINUSE
#define EADDRINUSE WSAEADDRINUSE
#endif
#ifndef ENOBUFS
#define ENOBUFS WSAENOBUFS
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#endif
#ifndef EALREADY
#define EALREADY WSAEALREADY
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED WSAECONNREFUSED
#endif
#ifndef ENOTSOCK
#define ENOTSOCK WSAENOTSOCK
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT WSAETIMEDOUT
#endif
#ifndef ENETUNREACH
#define ENETUNREACH WSAENETUNREACH
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH WSAEHOSTUNREACH
#endif
#ifndef ENOTCONN
#define ENOTCONN WSAENOTCONN
#endif
#ifndef ENETRESET
#define ENETRESET WSAENETRESET
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP WSAEOPNOTSUPP
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN WSAESHUTDOWN
#endif
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#ifndef ECONNABORTED
#define ECONNABORTED WSAECONNABORTED
#endif
#ifndef ECONNRESET
#define ECONNRESET WSAECONNRESET
#endif
#ifndef EHOSTDOWN
#define EHOSTDOWN WSAEHOSTDOWN
#endif
#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT WSAESOCKTNOSUPPORT
#endif

// For the future:
// Handle ERROR_NETNAME_DELETED=64
#endif //FZ_WINDOWS

}

#endif
