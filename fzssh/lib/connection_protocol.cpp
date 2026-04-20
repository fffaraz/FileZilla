#include "buffer_util.hpp"
#include "connection_protocol.hpp"

#include <libfilezilla/logger.hpp>

#include <string.h>

//#define DUMP_CHANNEL_DATA 1

using namespace std::literals;

namespace fz::ssh {

#define idtos(id) \
	case channel_type:: id: \
		return #id ""sv \

std::string_view to_string(channel_type id)
{
	switch (id) {
		idtos(shell);
		idtos(exec);
		idtos(subsystem);
	case channel_type::direct_tcpip:
		return "direct-tcpip"sv;
	default:
		return {};
	}
}
#undef idtos

size_t constexpr max_outbuf_size = max_payload_size * 10;

ssh_channel_layer::~ssh_channel_layer()
{
	if (data_) {
		data_->layer_ = nullptr;
		if (conn_) {
			conn_->disconnect_channel(*data_);
		}
	}
	remove_socket_events(handler_, this);
}

int ssh_channel_layer::read(void* buffer, unsigned int size, int& error)
{
	if (!data_) {
		error = EINVAL;
		return -1;
	}

	if (!buffer || !size) {
		error = EINVAL;
		return -1;
	}

	if (size > data_->in_buf_.size()) {
		size = data_->in_buf_.size();
	}

	if (!size) {
		if (data_->in_eof_) {
			return 0;
		}
		if (!conn_) {
			error = ECONNABORTED;
			return -1;
		}

		wait_in_ = true;
		error = EAGAIN;
		return -1;
	}

	if (conn_ && conn_->input_block_ == data_->own_id_) {
		conn_->input_block_ = std::nullopt;
		conn_->transport_.unblock_read();
	}

	memcpy(buffer, data_->in_buf_.get(), size);
	data_->in_buf_.consume(size);
	if (conn_) {
		conn_->consumed_input(*data_);
	}
	return size;
}

int ssh_channel_layer::write(void const* buffer, unsigned int size, int& error)
{
	if (!data_) {
		error = EINVAL;
		return -1;
	}

	if (!buffer || !size || data_->out_eof_ == 2) {
		error = EINVAL;
		return -1;
	}

	if (!conn_) {
		error = ECONNABORTED;
		return -1;
	}

	if (wait_out_) {
		error = EAGAIN;
		return -1;
	}

	if (max_outbuf_size <= data_->out_buf_.size()) {
		error = EAGAIN;
		wait_out_ = true;
		return -1;
	}

	size_t capacity = max_outbuf_size - data_->out_buf_.size();
	if (size > capacity) {
		size = capacity;
	}

	bool trigger_sending = data_->state_ >= channel_state::active && data_->out_buf_.empty() && data_->window_out_ && conn_->transport_.service_can_send();

	memcpy(data_->out_buf_.get(size), buffer, size);
	data_->out_buf_.add(size);

	if (trigger_sending) {
		if (!conn_->send_data(*data_)) {
			error = ECONNABORTED;
			return -1;
		}
	}

	return size;
}

void ssh_channel_layer::set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block)
{
	auto old = handler_;
	handler_ = pEvtHandler;

	socket_event_flag const pending = change_socket_event_handler(old, pEvtHandler, this, retrigger_block);
	if (handler_) {
		if (data_ && data_->state_ < channel_state::active) {
			return;
		}
		if (!wait_in_ && !(pending & socket_event_flag::read) && !(retrigger_block & socket_event_flag::read)) {
			handler_->send_event<socket_event>(this, socket_event_flag::read, 0);
		}
		if (!wait_out_ && !(pending & socket_event_flag::write) && !(retrigger_block & socket_event_flag::write)) {
			handler_->send_event<socket_event>(this, socket_event_flag::write, 0);
		}
	}
}

native_string ssh_channel_layer::peer_host() const
{
	if (!data_ || !conn_) {
		{};
	}
	return conn_->transport_.s_.peer_host();
}

int ssh_channel_layer::peer_port(int& error) const
{
	if (!data_ || !conn_) {
		error = ENOTSOCK;
		return -1;
	}
	return conn_->transport_.s_.peer_port(error);
}

int ssh_channel_layer::connect(native_string const&, unsigned int, address_type)
{
	return ENOTSUP;
}

socket_state ssh_channel_layer::get_state() const
{
	return socket_state::none;
}

int ssh_channel_layer::shutdown()
{
	if (!data_) {
		return ENOTSOCK;
	}

	if (data_->out_eof_ == 2) {
		return 0;
	}

	if (!conn_) {
		return ECONNABORTED;
	}

	if (!data_->out_buf_.empty() || data_->state_ < channel_state::active) {
		data_->out_eof_ = 1;
		wait_out_ = true;
		return EAGAIN;
	}

	packet_builder b(conn_->transport_, message_id::SSH_MSG_CHANNEL_EOF);
	write_uint32(b.buf_, data_->peer_id_);
	if (!b.commit()) {
		return ECONNABORTED;
	}

	data_->out_eof_ = true;

	return 0;
}

int ssh_channel_layer::shutdown_read()
{
	return ENOTSUP;
}

int ssh_channel_layer::inbuf(std::string_view & in, int & error)
{
	if (!data_) {
		error = EINVAL;
		return -1;
	}

	size_t size = data_->in_buf_.size();
	if (!size) {
		if (data_->in_eof_) {
			return 0;
		}
		if (!conn_) {
			error = ECONNABORTED;
			return -1;
		}

		wait_in_ = true;
		error = EAGAIN;
		return -1;
	}

	in = data_->in_buf_.to_view();
	return size;
}

void ssh_channel_layer::consume_inbuf(size_t count)
{
	if (!data_ || !count) {
		return;
	}

	if (conn_ && conn_->input_block_ == data_->own_id_) {
		conn_->input_block_ = std::nullopt;
		conn_->transport_.unblock_read();
	}

	data_->in_buf_.consume(count);
	if (conn_) {
		conn_->consumed_input(*data_);
	}
}

void ssh_channel_layer::want_more()
{
	wait_in_ = true;
}

connection_protocol::connection_protocol(transport & t)
    : transport_(t)
    , logger_(t.logger_)
    , next_sending_channel_(channels_.end())
{
}

connection_protocol::~connection_protocol()
{
	for (auto & channel : channels_) {
		if (channel.second->layer_) {
			channel.second->layer_->conn_ = nullptr;
		}
	}
}

continuation connection_protocol::process_binary_packet(message_id id, std::string_view packet)
{
	if (transport_.service_ != service_type::connection) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received packet for connection protocol service when service not authenticated for its use"sv);
	}

	switch (id) {
	case message_id::SSH_MSG_GLOBAL_REQUEST:
		return process_global_request(packet);
	case message_id::SSH_MSG_REQUEST_SUCCESS:
		return process_global_request_success(packet);
	case message_id::SSH_MSG_REQUEST_FAILURE:
		return process_global_request_failure(packet);
	case message_id::SSH_MSG_CHANNEL_OPEN:
		return process_channel_open(packet);
	default:
		break;
	}

	if (id >= message_id::SSH_MSG_CHANNEL_OPEN_CONFIRMATION && id <= message_id::SSH_MSG_CHANNEL_FAILURE) {
		return process_channel_packet(id, packet);
	}

	return continuation::error_unimplemented;
}

continuation connection_protocol::process_channel_packet(message_id id, std::string_view packet)
{
	uint32_t own_id{};
	if (!extract_uint32(packet, own_id)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, fz::sprintf("Malformed %s, could not extract channel id"sv, to_string(id)));
	}

	auto it = channels_.find(own_id);
	if (it == channels_.end()) {
		logger_.log(logmsg::debug_warning, "Cannot process %s, channel %u not found"sv, to_string(id), own_id);
		return continuation::next;
	}

	auto & channel = *it->second;
	return process_channel_packet(id, channel, packet);
}

continuation connection_protocol::process_channel_packet(message_id id, channel_data & channel, std::string_view packet)
{
	switch (id) {
	case message_id::SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
		return process_channel_open_confirmation(channel, packet);
	case message_id::SSH_MSG_CHANNEL_OPEN_FAILURE:
		return process_channel_open_failure(channel, packet);
	case message_id::SSH_MSG_CHANNEL_WINDOW_ADJUST:
		return process_channel_window_adjust(channel, packet);
	case message_id::SSH_MSG_CHANNEL_DATA:
		return process_channel_data(channel, packet);
	case message_id::SSH_MSG_CHANNEL_EXTENDED_DATA:
		return process_channel_extended_data(channel, packet);
	case message_id::SSH_MSG_CHANNEL_EOF:
		return process_channel_eof(channel, packet);
	case message_id::SSH_MSG_CHANNEL_CLOSE:
		return process_channel_close(channel, packet);
	case message_id::SSH_MSG_CHANNEL_REQUEST:
		return process_channel_request(channel, packet);
	case message_id::SSH_MSG_CHANNEL_SUCCESS:
		return process_channel_success(channel, packet);
	case message_id::SSH_MSG_CHANNEL_FAILURE:
		return process_channel_failure(channel, packet);
	default:
		break;
	}
	return continuation::error_unimplemented;
}

continuation connection_protocol::process_channel_request(channel_data & channel, std::string_view packet)
{
	auto type = extract_string(packet, string_type::ascii, false);
	if (!type) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_REQUEST, could not extract request type"sv);
	}
	auto want_reply = extract_bool(packet);
	if (!want_reply) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_REQUEST, could not extract reply flag"sv);
	}

	logger_.log(logmsg::debug_info, "Received channel request with type '%s' on channel %u, want_reply=%s", *type, channel.own_id_, *want_reply ? "TRUE"sv : "FALSE"sv);

	return process_channel_request(channel, *type, *want_reply, packet);
}

continuation connection_protocol::process_channel_open(std::string_view packet)
{
	auto type = extract_string(packet, string_type::ascii, false);
	if (!type) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN, could not extract channel type"sv);
	}
	uint32_t peer_id{};
	if (!extract_uint32(packet, peer_id)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN, could not extract sender id"sv);
	}
	uint32_t window{};
	if (!extract_uint32(packet, window)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN, could not extract intitial window size"sv);
	}
	uint32_t max_size{};
	if (!extract_uint32(packet, max_size)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN, could not extract max packet size"sv);
	}

	return process_channel_open(*type, peer_id, window, max_size, packet);
}

bool connection_protocol::consumed_input(channel_data& channel)
{
	if (no_flow_control_) {
		return true;
	}
	if (channel.in_buf_.size() + channel.window_in_ <= channel.window_in_max_ / 2 && channel.window_in_max_) {
		// Grow window
		packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_WINDOW_ADJUST);
		write_uint32(b.buf_, channel.peer_id_);
		write_uint32(b.buf_, channel.window_in_max_ - channel.window_in_ - channel.in_buf_.size());
		channel.window_in_ = channel.window_in_max_ - channel.in_buf_.size();
		if (!b.commit()) {
			return false;
		}
	}
	return true;
}

continuation connection_protocol::process_channel_data(channel_data & channel, std::string_view packet)
{
	auto data = extract_blob(packet);
	if (!data || data->empty() || !packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_DATA"sv);
	}

	if (channel.in_eof_) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_CHANNEL_DATA for a channel after EOF"sv);
	}

	if (channel.state_ != channel_state::active || !channel.layer_) {
		return continuation::next;
	}

	if (data->size() > channel.window_in_) {
		// While the specs allow for _MAY_ discard, we dont, as the results of such a discard could
		// have potentially damaging effects.
		// Imagine an SFTP client with broken SSH implementation that sends more than the window allows, uploading
		// an attacker-crafted file.
		// If the server would disard excess data, it could thus treat the contents of that file as SFTP packets.
		logger_.log(logmsg::debug_warning, "Received data in excess of window on channel %u, broken peer software. Connection might stall as result."sv, channel.own_id_);
	}

	if (channel.in_buf_.size() + data->size() > channel.window_in_max_) {
		logger_.log(logmsg::debug_info, "Input buffer on channel %u is full, waiting for space to become available"sv, channel.own_id_);
		input_block_ = channel.own_id_;
		return continuation::wait;
	}
#if DUMP_CHANNEL_DATA
	logger_.log(logmsg::debug_debug, "Incoming data on channel %u: %s"sv, channel.own_id_, fz::hex_encode<std::string>(*data));
#endif

	channel.in_buf_.append(*data);
	if (!no_flow_control_) {
		if (data->size() > channel.window_in_) {
			channel.window_in_ = 0;
		}
		else {
			channel.window_in_ -= data->size();
		}
	}

	if (channel.layer_->wait_in_) {
		channel.layer_->wait_in_ = false;
		if (channel.layer_->handler_) {
			channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::read, 0);
		}
	}

	return continuation::next;
}

continuation connection_protocol::process_channel_extended_data(channel_data & channel, std::string_view packet)
{
	uint32_t type{};
	if (!extract_uint32(packet, type)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_EXTENDED_DATA, could not extract data_type_code"sv);
	}

	auto data = extract_blob(packet);
	if (!data || data->empty() || !packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_EXTENDED_DATA"sv);
	}

	if (channel.in_eof_) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_CHANNEL_EXTENDED_DATA for a channel after EOF"sv);
	}

	if (channel.state_ != channel_state::active || !channel.layer_) {
		return continuation::next;
	}

	if (data->size() > channel.window_in_) {
		// While the specs allow for _MAY_ discard, we dont, as the results of such a discard could
		// have potentially damaging effects.
		// Imagine an SFTP client with broken SSH implementation that sends more than the window allows, uploading
		// an attacker-crafted file.
		// If the server would disard excess data, it could thus treat the contents of that file as SFTP packets.
		logger_.log(logmsg::debug_warning, "Received data in excess of window on channel %u, broken peer software. Connection might stall as result."sv, channel.own_id_);
	}

	// For now, discard the extended data.

#if DUMP_CHANNEL_DATA
	logger_.log(logmsg::debug_debug, "Incoming extended data on channel %u: %s", channel.own_id_, fz::hex_encode<std::string>(*data));
#endif

	if (!no_flow_control_) {
		if (data->size() > channel.window_in_) {
			channel.window_in_ = 0;
		}
		else {
			channel.window_in_ -= data->size();
		}
		if (!consumed_input(channel)) {
			return continuation::error;
		}
	}

	return continuation::next;
}

continuation connection_protocol::process_channel_eof(channel_data & channel, std::string_view)
{
	if (channel.in_eof_) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_CHANNEL_EOF twice on a channel"sv);
	}

	channel.in_eof_ = true;

	if (channel.state_ < channel_state::active || !channel.layer_) {
		return continuation::next;
	}

	if (channel.layer_->wait_in_) {
		channel.layer_->wait_in_ = false;
		if (channel.layer_->handler_) {
			channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::read, 0);
		}
	}

	return continuation::next;
}

continuation connection_protocol::process_channel_close(channel_data & channel, std::string_view)
{
	if (channel.state_ != channel_state::closing) {
		logger_.log(logmsg::debug_info, "Replying with our own SSH_MSG_CHANNEL_CLOSE"sv);
		auto res = disconnect_channel(channel);
		if (res == continuation::error) {
			return res;
		}
	}
	else {
		logger_.log(logmsg::debug_info, "Received a reply to a SSH_MSG_CHANNEL_CLOSE we sent"sv);
	}
	auto id = channel.own_id_;
	erase_channel(id);
	return continuation::next;
}

continuation connection_protocol::process_channel_window_adjust(channel_data & channel, std::string_view packet)
{
	uint32_t window{};
	if (!extract_uint32(packet, window)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_WINDOW_ADJUST, could not extract bytes to add"sv);
	}

	if (no_flow_control_) {
		return continuation::next;
	}

	size_t const old_window = channel.window_out_;
	logger_.log(logmsg::debug_debug, "Increasing peer window from %u by %u", old_window, window);
	channel.window_out_ += window;
	if (channel.window_out_ < old_window) {
		// Handle unsigned overflow, clamp to uin32_t::max
		channel.window_out_ = 0xffffffffu;
	}
	if (channel.state_ >= channel_state::active && !old_window && !channel.out_buf_.empty() && transport_.service_can_send()) {
		send_data(channel);
	}
	return continuation::next;
}

continuation connection_protocol::process_global_request(std::string_view packet)
{
	auto type = extract_string(packet, string_type::ascii, false);
	if (!type) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_GLOBAL_REQUEST, cound not extract request name"sv);
	}

	if (packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_GLOBAL_REQUEST, could not extract reply flag"sv);
	}
	bool want_reply = packet[0];
	packet.remove_prefix(1);

	logger_.log(logmsg::debug_info, "Received global request of type %s"sv, *type);

	return process_global_request(*type, want_reply, packet);
}

continuation connection_protocol::process_global_request(std::string_view const&, bool want_reply, std::string_view)
{
	if (want_reply) {
		packet_builder b(transport_, message_id::SSH_MSG_REQUEST_FAILURE);
		if (!b.commit()) {
			return continuation::error;
		}
	}

	return continuation::next;
}

continuation connection_protocol::process_global_request_success(std::string_view)
{
	return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_REQUEST_SUCCESS even though no request wanting a reply was sent."sv);
}

continuation connection_protocol::process_global_request_failure(std::string_view)
{
	return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_REQUEST_FAILURE even though no request wanting a reply was sent."sv);
}

continuation connection_protocol::disconnect_channel(channel_data & channel)
{
	logger_.log(logmsg::debug_info, "disconnect_channel(%u)"sv, channel.own_id_);

	if (channel.state_ == channel_state::closing) {
		logger_.log(logmsg::debug_info, "Channel %u is already closing"sv, channel.own_id_);
		return continuation::next;
	}

	if (channel.layer_) {
		if (channel.layer_->wait_in_) {
			channel.layer_->wait_in_ = false;
			if (channel.layer_->handler_) {
				channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::read, channel.in_buf_.empty() ? ECONNABORTED : 0);
			}
		}
		else if (channel.layer_->wait_out_) {
			channel.layer_->wait_out_ = false;
			if (channel.layer_->handler_) {
				channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::write, ECONNABORTED);
			}
		}
		channel.layer_->conn_ = nullptr;
		channel.layer_ = nullptr;
	}

	if (channel.own_id_ == input_block_) {
		transport_.unblock_read();
	}

	if (channel.state_ == channel_state::pending_auth) {
		logger_.log(logmsg::debug_info, "No need to send SSH_MSG_CHANNEL_CLOSE as SSH_MSG_CHANNEL_OPEN has not yet been sent"sv, channel.own_id_);

		auto id = channel.own_id_;
		erase_channel(id);

		return continuation::next;
	}

	if (channel.state_ == channel_state::setup) {
		logger_.log(logmsg::debug_info, "Cannot send SSH_MSG_CHANNEL_CLOSE on channel %u yet, still awaiting peer id"sv, channel.own_id_);
		return continuation::next;
	}
	channel.state_ = channel_state::closing;

	if (!transport_.disconnecting_) {
		if (channel.in_eof_ && channel.out_eof_ && (channel.type_ == channel_type::exec || channel.type_ == channel_type::shell || channel.type_ == channel_type::subsystem)) {
			packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_REQUEST, fz::sprintf("channel=%u, type=\"exit-status\", want_reply=FALSE"sv, channel.peer_id_));
			write_uint32(b.buf_, channel.peer_id_);
			write_string(b.buf_, "exit-status"sv);
			b.buf_.append('\0');
			write_uint32(b.buf_, 0);
			if (!b.commit()) {
				return continuation::error;
			}
		}
		packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_CLOSE);
		write_uint32(b.buf_, channel.peer_id_);
		if (!b.commit()) {
			return continuation::error;
		}
	}

	return continuation::next;
}

bool connection_protocol::send_data(channel_data & c)
{
	if (c.state_ < channel_state::active) {
		return false;
	}

	bool ret = false;

	if (!c.out_buf_.empty()) {
		if (!c.window_out_) {
			return false;
		}

		size_t s = std::min(c.max_packet_size_out_, c.out_buf_.size());
		if (c.window_out_ < s) {
			s = c.window_out_;
		}

		auto v = c.out_buf_.to_view().substr(0, s);
	#if DUMP_CHANNEL_DATA
		logger_.log(logmsg::debug_debug, "Outgoing data on channel %u: %s", 0, fz::hex_encode<std::string>(v));
	#endif
		packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_DATA, fz::sprintf("for %u bytes"sv, v.size()));
		write_uint32(b.buf_, c.peer_id_);
		write_string(b.buf_, v);
		c.out_buf_.consume(s);
		if (!no_flow_control_) {
			c.window_out_ -= s;
		}

		b.commit();
		ret = true;
	}

	if (c.layer_ && c.layer_->wait_out_ && c.out_buf_.size() < (c.out_eof_ ? 1 : max_outbuf_size)) {
		c.layer_->wait_out_ = false;
		if (c.layer_->handler_) {
			c.layer_->handler_->send_event<socket_event>(c.layer_, socket_event_flag::write, 0);
		}
		ret = true;
	}

	return ret;
}

void connection_protocol::send_data()
{
	if (channels_.empty()) {
		return;
	}

	if (next_sending_channel_ == channels_.end()) {
		next_sending_channel_ = channels_.begin();
	}

	auto const start = next_sending_channel_;

	do {
		auto & channel = *next_sending_channel_->second;

		++next_sending_channel_;
		if (next_sending_channel_ == channels_.end()) {
			next_sending_channel_ = channels_.begin();
		}

		if (send_data(channel)) {
			return;
		}
	} while (next_sending_channel_ != start && !transport_.disconnecting_);
}

void connection_protocol::dump()
{
	for (auto & cp : channels_) {
		channel_data& c = *cp.second;
		logger_.log(logmsg::debug_info, "Channel %u in state %u, inbuf size %u, outbuf size %u, inwin %u, outwin %u"sv, c.own_id_, c.state_, c.in_buf_.size(), c.out_buf_.size(), c.window_in_, c.window_out_);
	}
}

void connection_protocol::erase_channel(uint32_t id)
{
	if (next_sending_channel_ != channels_.end() && next_sending_channel_->first == id) {
		++next_sending_channel_;
	}
	channels_.erase(id);
}

size_t connection_protocol::channel_count()
{
	return channels_.size();
}

}
