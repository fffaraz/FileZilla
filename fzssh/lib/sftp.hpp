#ifndef FZSSH_SFTP_BASE_HEADER
#define FZSSH_SFTP_BASE_HEADER

#include <string_view>

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/socket.hpp>

#include "fzssh/visibility.hpp"
#include "fzssh/sftp/sftp.hpp"

namespace fz {

class logger_interface;

namespace ssh::sftp {

size_t constexpr max_out_payload_size{64*1024};

enum class message_type : uint8_t
{
	none,

	SSH_FXP_INIT = 1,
	SSH_FXP_VERSION = 2,
	SSH_FXP_OPEN = 3,
	SSH_FXP_CLOSE = 4,
	SSH_FXP_READ = 5,
	SSH_FXP_WRITE = 6,
	SSH_FXP_LSTAT = 7,
	SSH_FXP_FSTAT = 8,
	SSH_FXP_SETSTAT = 9,
	SSH_FXP_FSETSTAT = 10,
	SSH_FXP_OPENDIR = 11,
	SSH_FXP_READDIR = 12,
	SSH_FXP_REMOVE = 13,
	SSH_FXP_MKDIR = 14,
	SSH_FXP_RMDIR = 15,
	SSH_FXP_REALPATH = 16,
	SSH_FXP_STAT = 17,
	SSH_FXP_RENAME = 18,
	SSH_FXP_READLINK = 19,
	SSH_FXP_SYMLINK = 20,
	SSH_FXP_STATUS = 101,
	SSH_FXP_HANDLE = 102,
	SSH_FXP_DATA = 103,
	SSH_FXP_NAME = 104,
	SSH_FXP_ATTRS = 105,
	SSH_FXP_EXTENDED = 200,
	SSH_FXP_EXTENDED_REPLY = 201
};

std::string_view to_string(message_type id);

class FZSSH_PUBLIC_SYMBOL sftp_base : public event_handler
{
public:
	sftp_base(std::unique_ptr<socket_interface> && channel, event_handler & handler, logger_interface & logger, size_t max_in_payload_size, bool server, compatibility_flags compatibility_flags);
	virtual ~sftp_base() = default;

	void dump();

	bool can_send_packets();
	void unblock_read();
	bool is_retrying_process();

	// Immediate
	virtual void stop(bool send_done) = 0;

	// Graceful
	void disconnect();

protected:
	virtual continuation process_packet(message_type type, uint32_t id, std::string_view data) = 0;
	bool can_send_packets(bool wait);
	virtual void on_can_send_packets() {}

	event_handler & event_handler_;
	logger_interface & logger_;
	uint32_t peer_version_{};

	virtual void operator()(event_base const& ev) override;
	void on_socket_event(socket_event_source *s, fz::socket_event_flag type, int error);
	virtual void on_connect();
	void on_read();
	void on_send();
	void do_send();

	std::unique_ptr<socket_interface> socket_;

	size_t const max_in_payload_size_{};
	bool const server_{};
	bool wait_read_{true};
	bool wait_write_{true};
	bool wait_processing_{false};
	bool wait_outbuf_empty_{};

	bool disconnecting_{};

	buffer outbuf_;
	buffer inbuf_;

	bool is_retrying_process_{};
	compatibility_flags compatibility_flags_{};

private:
	struct packet_type
	{
		size_t len{};
		message_type type{};
		uint32_t id{};
	};

	std::optional<packet_type> in_packet_;

	bool channel_is_fzssh_{};
};

void FZSSH_PUBLIC_SYMBOL write_attributes(buffer& buf, attributes const& attrs);
std::optional<attributes> FZSSH_PUBLIC_SYMBOL extract_attributes(std::string_view & data, fz::logger_interface & logger, compatibility_flags compatibility_flags);

}
}

#endif
