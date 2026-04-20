#ifndef FZSSH_CLIENT_CONNECTION_PROTOCOL_HEADER
#define FZSSH_CLIENT_CONNECTION_PROTOCOL_HEADER

#include "../connection_protocol.hpp"

namespace fz::ssh {

class client_connection_protocol final : public connection_protocol
{
public:
	client_connection_protocol(transport & t, bool single_channel);

	virtual continuation process_channel_open(std::string_view type, uint32_t peer_id, uint32_t window, uint32_t max_size, std::string_view packet) override;
	virtual continuation process_channel_open_confirmation(channel_data & channel, std::string_view packet) override;
	virtual continuation process_channel_open_failure(channel_data &, std::string_view packet) override;
	virtual continuation process_channel_request(channel_data & channel, std::string_view type, bool want_reply, std::string_view args) override;
	virtual continuation process_channel_success(channel_data & channel, std::string_view packet) override;
	virtual continuation process_channel_failure(channel_data & channel, std::string_view packet) override;

	std::unique_ptr<socket_interface> open_channel(channel_type type, std::string_view const& cmd);

	continuation on_auth_success();

private:
	uint32_t calculate_window_in_max();
	bool send_channel_open(channel_data & channel);
};

}

#endif
