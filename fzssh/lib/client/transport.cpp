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

	return continuation::next;
}

continuation client_transport::on_auth_success()
{
	service_ = service_type::connection;
	handler_.send_event<auth_done_event>(static_cast<client*>(&session_));

	return static_cast<client_connection_protocol&>(*connection_protocol_).on_auth_success();
}

}
