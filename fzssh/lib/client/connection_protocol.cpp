#include "connection_protocol.hpp"

#include "../buffer_util.hpp"

#include <libfilezilla/logger.hpp>

using namespace std::literals;

namespace fz::ssh {

client_connection_protocol::client_connection_protocol(transport & t, bool single_channel)
	: connection_protocol(t)
{
	single_channel_ = single_channel;
}

continuation client_connection_protocol::process_channel_open(std::string_view, uint32_t peer_id, uint32_t, uint32_t, std::string_view)
{
	packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_OPEN_FAILURE);
	write_uint32(b.buf_, peer_id);
	write_uint32(b.buf_, static_cast<uint32_t>(open_failure::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED));
	write_string(b.buf_, "This is client, sir."sv);
	write_string(b.buf_, "en"sv);
	return b.commit() ? continuation::next : continuation::error;
}

continuation client_connection_protocol::process_channel_open_confirmation(channel_data & channel, std::string_view packet)
{
	uint32_t peer_id;
	if (!extract_uint32(packet, peer_id)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_CONFIRMATION, could not extract sender channel"sv);
	}

	uint32_t window_out;
	if (!extract_uint32(packet, window_out)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_CONFIRMATION, could not extract initial window size"sv);
	}

	uint32_t max_size;
	if (!extract_uint32(packet, max_size) || !max_size) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_CONFIRMATION, could not extract max packet size"sv);
	}

	if (!packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_CONFIRMATION, packet too big"sv);
	}

	if (max_size <= channel_overhead) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received nonsensical maximum package size in SSH_MSG_CHANNEL_OPEN_CONFIRMATION"sv);
	}

	channel.state_ = channel_state::pending_accept;
	channel.peer_id_ = peer_id;

	if (!channel.layer_) {
		return disconnect_channel(channel);
	}

	channel.window_out_ = no_flow_control_ ? 0xffffffffu : window_out;
	channel.max_packet_size_out_ = std::min(static_cast<size_t>(max_size), max_payload_size) - channel_overhead;

	if (channel.type_ == channel_type::direct_tcpip) {
		channel.state_ = channel_state::active;
		if (channel.layer_) {
			if (channel.layer_->handler_) {
				channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::connection, 0);
			}
		}
		return continuation::next;
	}

	packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_REQUEST, fz::sprintf("channel=%u, type=\"%s\", want_reply=TRUE"sv, peer_id, to_string(*channel.type_)));
	write_uint32(b.buf_, peer_id);
	write_string(b.buf_, to_string(*channel.type_));
	b.buf_.append(1);
	if (channel.type_ != channel_type::shell) {
		write_string(b.buf_, channel.cmd_);
	}
	if (!b.commit()) {
		return continuation::error;
	}

	return continuation::next;
}

continuation client_connection_protocol::process_channel_open_failure(channel_data & channel, std::string_view packet)
{
	uint32_t reason;
	if (!extract_uint32(packet, reason)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_FAILURE, could not extract reason code"sv);
	}

	auto description = extract_string(packet, string_type::utf8, true);
	if (!description) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_FAILURE, could not extract description"sv);
	}
	if (description->empty()) {
		logger_.log(fz::logmsg::error, "Could not open channel %u, reason code %d, no description was provided"sv, channel.own_id_, reason);
	}
	else {
		logger_.log(fz::logmsg::error, "Could not open channel %u, reason code %d, description: %s"sv, channel.own_id_, reason, *description);
	}

	auto langtag = extract_string(packet, string_type::ascii, true);
	if (!langtag) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_FAILURE, could not extract language tag"sv);
	}

	if (!packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_OPEN_FAILURE, packet too big"sv);
	}

	if (channel.layer_) {
		channel.layer_->conn_ = nullptr;
		if (channel.layer_->handler_) {
			channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::connection, ECONNREFUSED);
		}
	}

	auto id = channel.own_id_;
	erase_channel(id);

	return continuation::next;
}

continuation client_connection_protocol::process_channel_request(channel_data & channel, std::string_view, bool want_reply, std::string_view)
{
	if (want_reply) {
		packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_FAILURE);
		write_uint32(b.buf_, channel.peer_id_);
		return b.commit() ? continuation::next : continuation::error;
	}
	return continuation::next;
}


continuation client_connection_protocol::process_channel_success(channel_data & channel, std::string_view packet)
{
	if (!packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_SUCCESS, packet too big"sv);
	}

	if (channel.state_ != channel_state::pending_accept) {
		logger_.log(logmsg::debug_warning, "Ignoring SSH_MSG_CHANNEL_SUCCESS on channel %u, wrong channel state."sv, channel.own_id_);
		return continuation::next;
	}
	channel.state_ = channel_state::active;
	if (channel.layer_) {
		if (channel.layer_->handler_) {
			channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::connection, 0);
		}
	}

	return continuation::next;
}

continuation client_connection_protocol::process_channel_failure(channel_data & channel, std::string_view packet)
{
	if (!packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_CHANNEL_FAILURE, packet too big"sv);
	}

	if (channel.state_ != channel_state::pending_accept) {
		logger_.log(logmsg::debug_warning, "Ignoring SSH_MSG_CHANNEL_FAILURE on channel %u, wrong channel state."sv, channel.own_id_);
		return continuation::next;
	}
	if (channel.layer_) {
		channel.layer_->conn_ = nullptr;
		if (channel.layer_->handler_) {
			channel.layer_->handler_->send_event<socket_event>(channel.layer_, socket_event_flag::connection, ECONNREFUSED);
		}
	}

	disconnect_channel(channel);

	return continuation::next;
}

uint32_t client_connection_protocol::calculate_window_in_max()
{
	// RFC 4254 mandates that every implementation MUST be able to handle
	// receive windows of 2^32 - 1 octets
	uint32_t constexpr large_window_max = 0xffffffffu;

	// Yet some servers violate the spec and seemingly use signed 32-bit integers,
	// so only windows of up to 2^31 - 1 octets can be used
	uint32_t constexpr large_window_signed_int_safe = 0x7fffffffu;

	// If there are going to be multiple channels, use a very small value
	// so that one channel cannot choke the others
	uint32_t constexpr multi_channel_window = max_payload_size * 16;

	if (no_flow_control_) {
		return large_window_max;
	}
	if (single_channel_) {
		auto peer_version = transport_.peer_version();

		// Check for known-good
		if (fz::starts_with(peer_version, "SSH-2.0-fzssh_"sv) ||
			fz::starts_with(peer_version, "SSH-2.0-OpenSSH"sv))
		{
			return large_window_max;
		}
		// And known-bad servers
		else if (
			fz::starts_with(peer_version, "SSH-2.0-CrushFTPSSHD"sv) ||
			fz::starts_with(peer_version, "SSH-2.0-MOVEit "sv))
		{
			logger_.log(logmsg::debug_warning, "Broken server detected. This server cannot large receive windows up to 2^32 - 1. As per RFC 4254, implementations MUST correctly handle window sizes of up to 2^32 - 1 bytes"sv);
			return large_window_signed_int_safe;
		}

		return large_window_signed_int_safe;
	}

	return multi_channel_window;
}

std::unique_ptr<socket_interface> client_connection_protocol::open_channel(channel_type type, std::string_view const& cmd)
{
	auto tname = to_string(type);
	if (tname.empty()) {
		logger_.log(logmsg::error, "Cannot open channel with unknown type"sv);
		return {};
	}

	if (type == channel_type::shell && !cmd.empty()) {
		logger_.log(logmsg::error, "Cannot open shell with non-empty name"sv);
		return {};
	}
	else if (type == channel_type::direct_tcpip) {
		auto tokens = fz::strtok_view(cmd, ',', false);
		if (tokens.size() != 2 && tokens.size() != 4) {
			logger_.log(logmsg::error, "Invalid direct-tcpip parameters"sv);
			return {};
		}
		for (auto const& tok : tokens) {
			if (tok.empty()) {
				logger_.log(logmsg::error, "Invalid direct-tcpip parameters"sv);
				return {};
			}
		}
	}
	else if (type != channel_type::shell && cmd.empty()) {
		logger_.log(logmsg::error, "Cannot open channel of type %s with empty command"sv, tname);
		return {};
	}

	if (channels_.size() >= channel_limit) {
		logger_.log(logmsg::error, "Too many open channels"sv);
		return {};
	}

	uint32_t own_id = channels_.empty() ? 0 : channels_.rbegin()->first + 1;
	while (channels_.find(own_id) != channels_.end()) {
		++own_id;
	}
	auto schannel = (channels_[own_id] = std::make_shared<channel_data>());
	auto & channel = *schannel;
	channel.type_ = type;
	channel.cmd_ = cmd;
	channel.own_id_ = own_id;
	channel.window_in_max_ = calculate_window_in_max();
	channel.window_in_ = channel.window_in_max_;

	if (transport_.service_ != service_type::connection) {
		logger_.log(logmsg::debug_info, "Deferring channel request until authentication is complete"sv);
		channel.state_ = channel_state::pending_auth;
	}
	else {
		if (!send_channel_open(channel)) {
			return {};
		}
	}

	auto layer = std::make_unique<ssh_channel_layer>(this, schannel);
	channel.layer_ = layer.get();

	return layer;
}

bool client_connection_protocol::send_channel_open(channel_data& channel)
{
	logger_.log(logmsg::debug_info, "Requesting to open new channel of type %s, command %s"sv, to_string(*channel.type_), channel.cmd_);
	channel.state_ = channel_state::setup;

	packet_builder b(transport_, message_id::SSH_MSG_CHANNEL_OPEN);
	if (channel.type_ == channel_type::direct_tcpip) {
		write_string(b.buf_, "direct-tcpip"sv);
	}
	else {
		write_string(b.buf_, "session"sv);
	}
	write_uint32(b.buf_, channel.own_id_);
	write_uint32(b.buf_, channel.window_in_);
	write_uint32(b.buf_, max_payload_size - channel_overhead);

	if (channel.type_ == channel_type::direct_tcpip) {
		auto tokens = fz::strtok_view(channel.cmd_, ',', false);
		write_string(b.buf_, tokens[0]);
		write_uint32(b.buf_, fz::to_integral<unsigned short>(tokens[1])); // For some reason ports are uint32 on the wire
		if (tokens.size() == 4) {
			write_string(b.buf_, tokens[2]);
			write_uint32(b.buf_, fz::to_integral<unsigned short>(tokens[3]));
		}
		else {
			write_string(b.buf_, "127.0.0.1"sv);
			write_uint32(b.buf_, fz::to_integral<unsigned short>(tokens[1]));
		}
	}

	return b.commit();
}

continuation client_connection_protocol::on_auth_success()
{
	for (auto & it : channels_) {
		auto & channel = *it.second;
		if (channel.state_ != channel_state::pending_auth) {
			continue;
		}
		if (!send_channel_open(channel)) {
			return continuation::error;
		}
	}

	return continuation::next;
}

}
