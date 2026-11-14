#include "connection_protocol.hpp"
#include "userauth.hpp"
#include "transport.hpp"

#include "../buffer_util.hpp"
#include "../dh.hpp"
#include "../fzssh/client.hpp"
#include "../fzssh/pubkey.hpp"
#include "../fzssh/privkey.hpp"

#include <libfilezilla/logger.hpp>
#include <libfilezilla/util.hpp>

namespace fz::ssh {

client_transport::client_transport(session& sess, client_parameters const& params, std::string_view username, socket_interface & s, event_handler & h, logger_interface & logger)
	: transport(sess, params, s, false, h, logger)
{
	auth_ = std::make_unique<client_userauth>(*this, username);
	connection_protocol_ = std::make_unique<client_connection_protocol>(*this, params.single_channel_);

	if (params.single_channel_) {
		own_ext_info_["no-flow-control"s] = "p"sv;
	}
}

client_transport::~client_transport()
{
	remove_handler();
}

continuation client_transport::process_dh_gex_group(std::string_view packet)
{
	if (keying_ != keying_state::gex) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_KEX_DH_GEX_GROUP when not going a group exchange"sv);
	}

	gex_info_.group_.append(packet);
	std::tie(peer_dh_, own_dh_) = get_dh_group(packet, gex_info_.min_, gex_info_.max_, logger_);
	if (!own_dh_ || !peer_dh_) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_KEX_DH_GEX_GROUP without a valid group"sv);
	}

	logger_.log(logmsg::debug_info, "Negotiated DH group with %u bits"sv, peer_dh_->octet_size());

	return init_dh();
}

bool FZSSH_PUBLIC_SYMBOL known_algorithm(std::string_view const& in, std::string_view const& algs);

continuation client_transport::finalize_kexinit(std::string_view peer_hostkeys, bool)
{
	if (initial_kex_) {
		// This is a bit of a kludge to select an appropriate rsa signature algorithm for
		// 'publickey' authentication in case the server does not send the 'server-sig-algs'
		// ext-info:
		// If there is a ssh-rsa hostkey, see which signature algorithms it supports, and
		// filter the default accepted_pk_auth_signatures_, assuming
		// that the server supports the same set for 'publickey' authentication.

		bool peer_has_rsa_hostkey{};
		for (auto alg : fz::strtokenizer(peer_hostkeys, ',', true)) {
			if (supports_signature_algorithm("ssh-rsa"sv, alg)) {
				peer_has_rsa_hostkey = true;
				break;
			}
		}

		auto known = get_known_pubkey_signature_algorithms();
		if (peer_has_rsa_hostkey) {
			auth_->accepted_pk_auth_signatures_.clear();
			for (auto alg : strtokenizer(known, ",", true)) {
				if (!supports_signature_algorithm("ssh-rsa"sv, alg) || known_algorithm(alg, peer_hostkeys)) {
					append_comma_sep(auth_->accepted_pk_auth_signatures_, alg);
				}
			}
		}
		else {
			auth_->accepted_pk_auth_signatures_ = known;
		}
	}

	if (ping_state_.timer_) {
		ping_state_.interrupted_by_keying_ = true;
	}

	if (kex_type_ == kex_type::dhge) {
		keying_ = keying_state::gex;
		packet_builder b(*this, message_id::SSH_MSG_KEX_DH_GEX_REQUEST);
		gex_info_.min_ = 1024;
		gex_info_.n_ = 2048;
		gex_info_.max_ = 8192;
		write_uint32(b.buf_, gex_info_.min_);
		write_uint32(b.buf_, gex_info_.n_);
		write_uint32(b.buf_, gex_info_.max_);
		if (!b.commit()) {
			return continuation::error;
		}
		return continuation::next;
	}
	else {
		return init_dh();
	}
}

continuation client_transport::init_dh()
{
	keying_ = keying_state::diffie_hellman;

	if (!create_dh_keys(algorithms_next_.kex_)) {
		return continuation::error;
	}

	message_id id{};
	switch (*kex_type_) {
	case kex_type::dh:
		id = message_id::SSH_MSG_KEXDH_INIT;
		break;
	case kex_type::ecdh:
		id = message_id::SSH_MSG_KEX_ECDH_INIT;
		break;
	case kex_type::dhge:
		id = message_id::SSH_MSG_KEX_DH_GEX_INIT;
		break;
	case kex_type::pqth:
		id = message_id::SSH_MSG_KEX_HYBRID_INIT;
		break;
	}

	packet_builder b(*this, id);
	write_string(b.buf_, own_dh_->pubkey());
	if (!b.commit()) {
		return continuation::error;
	}
	return continuation::next;
}

continuation client_transport::process_dh_reply(std::string_view name, std::string_view packet)
{
	if (keying_ != keying_state::diffie_hellman) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Received %s outside of key exchange"sv, name));
	}

	auto hostkey = extract_blob(packet);
	if (!hostkey) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Malformed %s, could not extract public host key"sv, name));
	}

	bool const is_same_hostkey = previous_hostkey_ == *hostkey;
	previous_hostkey_ = *hostkey;

	if (!host_pubkey_->parse(*hostkey)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, sprintf("Malformed %s, could not parse public host key"sv, name));
	}

	auto pub = extract_blob(packet);
	if (!pub) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Malformed %s, could not extract peer public key"sv, name));
	}
	if (!peer_dh_->parse(*pub)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, sprintf("Malformed %s, could not parse peer public key"sv, name));
	}

	auto sig = extract_blob(packet);
	if (!sig) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Malformed %s, could not extract signature"sv, name));
	}

	if (!packet.empty()) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Malformed %s, packet too big"sv, name));
	}

	auto [shared_secret, exchange_hash] = compute_exchange_hash();
	scoped_wiper w(shared_secret);
	if (exchange_hash.empty()) {
		return continuation::error;
	}

	if (!host_pubkey_->verify(exchange_hash, *sig)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not verify signature over exchange hash"sv);
	}

	logger_.log(logmsg::debug_info, "Received signature is valid"sv);

	if (initial_kex_) {
		session_id_ = exchange_hash;
	}

	if (!derive_keys(shared_secret, exchange_hash)) {
		return continuation::error;
	}

	keying_ = keying_state::hostkey;
	if (is_same_hostkey && algorithms_ == algorithms_next_) {
		hostkey_decision(true);
		return disconnecting_ ? continuation::error : continuation::next;
	}
	else {
		logger_.log(logmsg::debug_info, "Awaiting trust decision"sv);
		handler_.send_event<hostkey_verification_event>(static_cast<client*>(&session_), std::move(host_pubkey_), algorithms_next_);
		return continuation::consume_and_wait;
	}
}

continuation client_transport::process_service_accept(std::string_view packet)
{
	auto service = extract_string(packet, string_type::ascii, false);
	if (!service) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_SERVICE_ACCEPT, could not extract a service name"sv);
	}

	if (!packet.empty()) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_SERVICE_ACCEPT, packet too big"sv);
	}

	if (service == "ssh-userauth"sv) {
		if (service_ != service_type::userauth_requested) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_SERVICE_ACCEPT for a service we did not request"sv);
		}
		service_ = service_type::userauth;

		return static_cast<client_userauth&>(*auth_).auth_none();
	}

	return send_disconnect(disconnect_reason::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "Developer is lazy, this service has not left his fingertips yet."sv);
}

bool client_transport::setup_hostkey()
{
	if (!host_pubkey_ || !host_pubkey_->supports_signature_algorithm(algorithms_next_.hostkey_signature_)) {
		host_pubkey_ = create_public_key(algorithms_next_.hostkey_signature_);
	}
	if (!host_pubkey_) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not initialize public hostkey"sv);
		return false;
	}

	return true;
}

std::string_view client_transport::host_pubkey() const
{
	return host_pubkey_ ? host_pubkey_->pubkey_blob() : std::string_view{};
}

void client_transport::hostkey_decision(bool accept)
{
	if (keying_ != keying_state::hostkey || disconnecting_) {
		return;
	}

	if (accept) {
		logger_.log_raw(logmsg::debug_info, "Hostkey has been trusted"sv);
	}
	else {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "Hostkey is not trusted"sv);
		return;
	}

	if (!init_out()) {
		return;
	}

	if (initial_kex_) {
		if (!send_ext_info()) {
			return;
		}

		service_ = service_type::userauth_requested;
		packet_builder b(*this, message_id::SSH_MSG_SERVICE_REQUEST);
		write_string(b.buf_, "ssh-userauth"sv);
		if (!b.commit()) {
			return;
		}
	}

	unblock_read();
}

void client_transport::check_peer_compatibility(bool preliminary)
{
	if (preliminary) {
		// Mainly older versions that don't support the ping extension, but are known to properly handle global channel reqeuests
		if (fz::starts_with(peer_version_, "SSH-2.0-OpenSSH_"sv) ||
			fz::starts_with(peer_version_, "SSH-2.0-fzssh_"sv))
		{
			ping_state_.mode_ = ping_mode::fallback;
		}
	}
}

continuation client_transport::process_ext_info(std::string_view name, std::string_view value)
{
	if (name == "server-sig-algs"sv) {
		if (!is_namelist(value, logger_)) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_EXT_INFO, server-sig-algs does not have a valid namelist"sv);
		}

		logger_.log(logmsg::debug_info, "Server supports signatures with these algorithms: %s"sv, value);

		auth_->accepted_pk_auth_signatures_.clear();
		for (auto alg : strtokenizer(get_known_pubkey_signature_algorithms(), ","sv, true)) {
			if (known_algorithm(alg, value)) {
				append_comma_sep(auth_->accepted_pk_auth_signatures_, alg);
			}
		}
	}
	else if (name == "publickey-hostbound@openssh.com"sv) {
		if (value == "0"sv) {
			logger_.log(logmsg::debug_info, "Extension version is \"0\", enabling use of this extension."sv);
			static_cast<client_userauth&>(*auth_).hostbound_pubkey_auth_ = true;
		}
		else {
			logger_.log(logmsg::debug_warning, "Unsupported extension version, cannot use this extension."sv);
		}
	}
	else if (name == "ping@openssh.com"sv) {
		if (value == "0"sv) {
			logger_.log(logmsg::debug_info, "Extension version is \"0\", enabling use of this extension."sv);
			ping_state_.mode_ = ping_mode::supported;
		}
		else {
			logger_.log(logmsg::debug_warning, "Unsupported extension version, cannot use this extension."sv);
		}
	}

	return continuation::next;
}

continuation client_transport::on_auth_success()
{
	service_ = service_type::connection;
	handler_.send_event<auth_done_event>(static_cast<client*>(&session_));

	return static_cast<client_connection_protocol&>(*connection_protocol_).on_auth_success();
}

continuation client_transport::process_local_extension(message_id id, std::string_view packet)
{
	if (id == message_id::SSH_MSG_PONG) {
		return process_pong(packet);
	}

	return continuation::error_unimplemented;
}

continuation client_transport::process_pong(std::string_view packet)
{
	if (!ping_state_.sent_ || ping_state_.mode_ != ping_mode::supported) {
		logger_.log(logmsg::debug_info, "Ignoring unexpected or stale SSH_MSG_PONG."sv);
		return continuation::next;
	}

	auto value = extract_blob(packet);
	if (!value) {
		logger_.log(logmsg::error, "Received malformed SSH_MSG_PONG, disabling ping functionality: %s"sv, *value);
		ping_state_.mode_ = ping_mode::unsupported;
		stop_ping({});
		return continuation::next;
	}

	if (!packet.empty()) {
		logger_.log(logmsg::debug_warning, "Received malformed SSH_MSG_PONG with trailing data, disabling ping functionality."sv);
		ping_state_.mode_ = ping_mode::unsupported;
		stop_ping({});
		return continuation::next;
	}

	continue_process_pong(*value);
	return continuation::next;
}

void client_transport::continue_process_pong(std::string_view data)
{
	if (!ping_state_.sent_) {
		return;
	}

	if (data.size() != 4 || read_uint32(data.data()) != ping_state_.data_) {
		logger_.log(logmsg::debug_info, "Ignoring stale pong."sv);
		return;
	}

	if (ping_state_.interrupted_by_keying_) {
		if (++ping_state_.retries_ > 2) {
			logger_.log(logmsg::debug_warning, "Too many retries, aborting ping"sv);
			stop_ping({});
			return;
		}
		logger_.log(logmsg::debug_info, "Ping got interrupted by re-keying, need to retry"sv);
		ping_state_.sent_ = false;
		send_ping(false);
		return;
	}

	auto rtt = monotonic_clock::now() - ping_state_.start_;
	logger_.log(logmsg::debug_info, "Measured transport layer RTT of %u ms", rtt.get_milliseconds());
	stop_ping(rtt);
}

void client_transport::operator()(event_base const& ev)
{
	if (!fz::dispatch<timer_event>(ev, this, &client_transport::on_timer)) {
		transport::operator ()(ev);
	}
}

void client_transport::on_timer(timer_id t)
{
	if (t != ping_state_.timer_) {
		return;
	}

	if (disconnecting_) {
		stop_ping({});
		return;
	}

	if ((fz::monotonic_clock::now() - ping_state_.start_) >= duration::from_seconds(3)) {
		stop_ping({});
		return;
	}

	if (ping_state_.mode_ == ping_mode::supported) {
		if (ping_state_.sent_ && ping_state_.interrupted_by_keying_) {
			if (++ping_state_.retries_ > 2) {
				logger_.log(logmsg::debug_warning, "Too many retries, aborting ping"sv);
				stop_ping({});
				return;
			}
			logger_.log(logmsg::debug_info, "Ping got interrupted by re-keying, need to retry"sv);
			ping_state_.sent_ = false;
		}
	}
	if (!ping_state_.sent_) {
		send_ping(false);
	}
}

void client_transport::ping()
{
	if (disconnecting_ || service_ != service_type::connection) {
		return;
	}

	if (ping_state_.mode_ == ping_mode::unsupported || ping_state_.timer_) {
		handler_.send_event<pong_event>(static_cast<client*>(&session_), std::nullopt);
		return;
	}

	ping_state_.timer_ = add_timer(duration::from_milliseconds(100), false);
	ping_state_.start_ = fz::monotonic_clock::now();
	send_ping(true);
}

void client_transport::stop_ping(std::optional<duration> const& rtt)
{
	if (ping_state_.timer_) {
		if (!disconnecting_) {
			handler_.send_event<pong_event>(static_cast<client*>(&session_), rtt);
		}
		stop_timer(ping_state_.timer_);
	}
	ping_state_.timer_ = timer_id{};
	ping_state_.start_ = fz::monotonic_clock();
	ping_state_.retries_ = 0;
	ping_state_.sent_ = false;
	ping_state_.interrupted_by_keying_ = false;
}

void client_transport::send_ping(bool  from_ping)
{
	if (keying_ != keying_state::no) {
		if (from_ping) {
			logger_.log(logmsg::debug_verbose, "Deferring ping, keying in progress."sv);
		}
		return;
	}

	if (ping_state_.mode_ == ping_mode::fallback) {
		for (auto const& req : connection_protocol_->pending_global_requests_) {
			if (req.type_ == "keepalive@openssh.com"sv) {
				if (from_ping) {
					logger_.log(logmsg::debug_verbose, "Deferring ping, there are still pending global requests."sv);
				}
				return;
			}
		}
	}

	ping_state_.interrupted_by_keying_ = false;

	++ping_state_.data_;

	ping_state_.start_ = fz::monotonic_clock::now();

	if (ping_state_.mode_ == ping_mode::supported) {
		packet_builder b(*this, message_id::SSH_MSG_PING);
		write_uint32(b.buf_, 4);
		write_uint32(b.buf_, ping_state_.data_);
		if (!b.commit()) {
			stop_ping({});
			return;
		}
	}
	else {
		packet_builder b(*this, message_id::SSH_MSG_GLOBAL_REQUEST, "type=\"keepalive@openssh.com\", want_reply=TRUE"sv);
		write_string(b.buf_, "keepalive@openssh.com"sv);
		b.buf_.append(1);
		if (!b.commit()) {
			stop_ping({});
			return;
		}

		connection_protocol::pending_request req;
		req.type_ = "keepalive@openssh.com"sv;
		req.data_.resize(4);
		write_uint32(req.data_.data(), ping_state_.data_);

		connection_protocol_->pending_global_requests_.emplace_back(std::move(req));
	}
	ping_state_.sent_ = true;
}
}
