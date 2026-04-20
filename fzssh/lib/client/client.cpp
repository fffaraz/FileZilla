#include "connection_protocol.hpp"
#include "transport.hpp"
#include "userauth.hpp"
#include "../fzssh/client.hpp"
#include "../fzssh/pubkey.hpp"

namespace fz::ssh {

client_parameters::client_parameters()
	: parameters(get_default_parameters())
{
}

client::client(client_parameters const& params, std::string_view username, socket_interface & s, event_handler & h, logger_interface & logger)
{
	impl_ = std::make_unique<client_transport>(*this, params, username, s, h, logger);
}

client::~client()
{
	if (impl_) {
		impl_->stop(false);
	}
}

std::unique_ptr<socket_interface> client::open_channel(channel_type type, std::string_view const& cmd)
{
	return static_cast<client_connection_protocol&>(*impl_->connection_protocol_).open_channel(type, cmd);
}

void client::hostkey_decision(bool accept)
{
	return static_cast<client_transport&>(*impl_).hostkey_decision(accept);
}

std::string client::accepted_pubkey_algorithms()
{
	return static_cast<client_userauth&>(*impl_->auth_).accepted_pk_auth_signatures_;
}

void client::auth_with_key(std::unique_ptr<private_key> const& key, bool with_signature, std::string_view const& signature_algorithm)
{
	return static_cast<client_userauth&>(*impl_->auth_).auth_with_key(key, with_signature, signature_algorithm);
}

void client::auth_with_key(std::unique_ptr<public_key> const& key, std::string_view const& signature_algorithm)
{
	return static_cast<client_userauth&>(*impl_->auth_).auth_with_key(key, signature_algorithm);
}

void client::auth_with_password(std::string_view const& pw)
{
	return static_cast<client_userauth&>(*impl_->auth_).auth_with_password(pw);
}

void client::auth_keyboard_interactive()
{
	return static_cast<client_userauth&>(*impl_->auth_).auth_keyboard_interactive();
}

void client::auth_keyboard_interactive_response(std::vector<std::string> const& responses)
{
	return static_cast<client_userauth&>(*impl_->auth_).auth_keyboard_interactive_response(responses);
}
}
