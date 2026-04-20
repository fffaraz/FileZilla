#ifndef FZSSH_CHANNEL_HEADER
#define FZSSH_CHANNEL_HEADER

#include <libfilezilla/socket.hpp>

#include "visibility.hpp"

namespace fz {
class buffer;

namespace ssh {

/**
 * While the channels can be used exactly as an ordinary socket,
 * this can lead to inefficiency due to excessive memcpy.
 *
 * By allowing direct buffer access and a mechanism to re-trigger
 * the event, memcpy can be avoided.
 */
class FZSSH_PUBLIC_SYMBOL ssh_channel : public socket_interface
{
public:
	using socket_interface::socket_interface;

	/// Get direct access to the input buffer. Will be invalidated
	/// when the event loop runs
	virtual int inbuf(std::string_view &, int & error) = 0;
	virtual void consume_inbuf(size_t count) = 0;
	virtual void want_more() = 0;
};

}
}

#endif
