#include "userauth.hpp"

#include "fzssh/pubkey.hpp"

#include <libfilezilla/logger.hpp>

using namespace std::literals;

namespace fz::ssh {

bool is_accepted_signature_algorithm(std::string_view supported, std::string_view alg)
{
	strtokenizer tok(supported, ',', true);
	for (auto const& t : tok) {
		if (t == alg) {
			return true;
		}
	}

	return false;
}


userauth::userauth(transport & t)
	: transport_(t)
	, logger_(t.logger_)
{
}

userauth::~userauth()
{
}

continuation userauth::process_binary_packet(message_id id, std::string_view packet)
{
	if (done_) {
		logger_.log(logmsg::debug_info, "Discarding auth message %s following successful auth"sv, to_string(id));
		return continuation::next;
	}

	if (transport_.service_ != service_type::userauth) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received package for userauth service when not authenticating"sv);
	}

	switch (id) {
	case message_id::SSH_MSG_USERAUTH_BANNER:
		return process_auth_banner(packet);
	case message_id::SSH_MSG_USERAUTH_REQUEST:
		return process_auth_request(packet);
	case message_id::SSH_MSG_USERAUTH_FAILURE:
		return process_auth_failure(packet);
	case message_id::SSH_MSG_USERAUTH_SUCCESS:
		return process_auth_success(packet);
	case message_id::SSH_MSG_USERAUTH_PK_OK:
		return process_auth_pubkey_ok(packet);
	case message_id::SSH_MSG_USERAUTH_INFO_REQUEST:
		return process_auth_info_request(packet);
	case message_id::SSH_MSG_USERAUTH_INFO_RESPONSE:
		return process_auth_info_response(packet);
	default:
		break;
	}

	return continuation::error_unimplemented;
}

}
