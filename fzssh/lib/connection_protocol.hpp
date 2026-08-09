#ifndef FZSSH_CONNECTION_PROTOCOL_HEADER
#define FZSSH_CONNECTION_PROTOCOL_HEADER

#include "fzssh/channel.hpp"
#include "fzssh/ssh.hpp"
#include "transport.hpp"

#include <map>
#include <set>

namespace fz::ssh {

enum class channel_state
{
	pending_auth,
	setup,
	pending_accept,
	pending_accept_noreply,
	active,
	closing
};

class ssh_channel_layer;
class channel_data
{
public:
	std::optional<channel_type> type_;
	std::string cmd_;

	uint32_t own_id_{};
	uint32_t peer_id_{};

	uint32_t window_in_max_{};
	uint32_t window_in_{};
	uint32_t window_out_{};
	size_t max_packet_size_out_{};

	buffer in_buf_;
	buffer out_buf_;
	bool in_eof_{};
	uint8_t out_eof_{};

	channel_state state_{};

	ssh_channel_layer* layer_{};
};

std::string_view FZSSH_PUBLIC_SYMBOL to_string(channel_type id);

size_t constexpr channel_overhead = 1 + 4 + 4 + 4; //type, channel id, data_type_code (if type is extdata), size(4)
size_t constexpr channel_limit = 16;

enum class open_failure : uint32_t {
	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
	SSH_OPEN_CONNECT_FAILED = 2,
	SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
	SSH_OPEN_RESOURCE_SHORTAGE = 4,
};

class FZSSH_PUBLIC_SYMBOL connection_protocol
{
public:
	connection_protocol(transport & t);
	virtual ~connection_protocol();

	continuation process_binary_packet(message_id id, std::string_view packet);

	bool send_data(channel_data & c);
	void send_data();

	void dump();

	size_t channel_count(bool exclude_eof = false);

	// True after there has been at least one successfully opened channel
	bool had_valid_channel();

protected:
	friend class ssh_channel_layer;
	friend class transport;

	continuation process_channel_packet(message_id id, std::string_view packet);
	virtual continuation process_channel_packet(message_id id, channel_data & channel, std::string_view packet);

	continuation process_global_request(std::string_view packet);
	virtual continuation process_global_request(std::string_view const& type, bool want_reply, std::string_view packet);
	continuation process_global_request_success(std::string_view packet);
	continuation process_global_request_failure(std::string_view packet);
	continuation process_channel_open(std::string_view packet);
	virtual continuation process_channel_open(std::string_view type, uint32_t peer_id, uint32_t window, uint32_t max_size, std::string_view packet) = 0;
	virtual continuation process_channel_open_confirmation(channel_data &, std::string_view) { return continuation::error_badside; }
	virtual continuation process_channel_open_failure(channel_data &, std::string_view) { return continuation::error_badside; }
	continuation process_channel_request(channel_data &, std::string_view);
	virtual continuation process_channel_request(channel_data & channel, std::string_view type, bool want_reply, std::string_view args) = 0;
	virtual continuation process_channel_success(channel_data &, std::string_view) { return continuation::error_badside; }
	virtual continuation process_channel_failure(channel_data &, std::string_view) { return continuation::error_badside; }
	continuation process_channel_data(channel_data & channel, std::string_view packet);
	continuation process_channel_extended_data(channel_data & channel, std::string_view packet);
	continuation process_channel_eof(channel_data & channel, std::string_view packet);
	continuation process_channel_close(channel_data & channel, std::string_view packet);
	continuation process_channel_window_adjust(channel_data & channel, std::string_view packet);

	virtual bool send_close(channel_data & channel);

	continuation disconnect_channel(channel_data & channel);
	void erase_channel(uint32_t id);

	bool consumed_input(channel_data& channel);

	transport & transport_;
	logger_interface & logger_;

	typedef std::map<uint32_t, std::shared_ptr<channel_data>> channels;
	channels channels_;
	channels::iterator next_sending_channel_{};
	std::optional<uint32_t> input_block_;

	bool no_flow_control_{};
	bool single_channel_{};
	bool had_valid_channel_{};
};

class FZSSH_PUBLIC_SYMBOL ssh_channel_layer : public ssh_channel
{
public:
	ssh_channel_layer(connection_protocol* conn, std::shared_ptr<channel_data> const& data)
		: ssh_channel(conn->transport_.s_.root())
		, conn_(conn)
		, data_(data)
	{
	}

	~ssh_channel_layer();

	virtual int read(void* buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	virtual void set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block = fz::socket_event_flag{}) override;

	virtual native_string peer_host() const override;
	virtual int peer_port(int& error) const override;

	virtual int connect(native_string const&, unsigned int, address_type) override;

	virtual socket_state get_state() const override;

	virtual int shutdown() override;

	virtual int shutdown_read() override;

	virtual int inbuf(std::string_view & in, int & error) override;
	virtual void consume_inbuf(size_t count) override;
	virtual void want_more() override;

	fz::event_handler * handler_{};

	connection_protocol* conn_;
	std::shared_ptr<channel_data> data_;

	bool wait_in_{true};
	bool wait_out_{false};
};

}

#endif

