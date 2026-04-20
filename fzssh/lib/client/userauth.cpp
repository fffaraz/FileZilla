#include "transport.hpp"
#include "userauth.hpp"
#include "../buffer_util.hpp"
#include "../transport.hpp"
#include "../fzssh/client.hpp"
#include "../fzssh/privkey.hpp"

#include <libfilezilla/logger.hpp>
#include <libfilezilla/translate.hpp>

namespace fz::ssh {

client_userauth::client_userauth(transport& t, std::string_view username)
	: userauth(t)
	, event_handler(t, child_event_handler)
{
	user_ = username;
}

client_userauth::~client_userauth()
{
	remove_handler();
	if (privkey_) {
		privkey_->cancel(*this);
	}
}

continuation client_userauth::auth_none()
{
	packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_REQUEST, "method=none"sv);
	write_string(b.buf_, user_);
	write_string(b.buf_, "ssh-connection"sv);
	write_string(b.buf_, "none"sv);
	if (!b.commit()) {
		return continuation::error;
	}

	pending_auths_.emplace_back("none"sv, false);

	return continuation::next;
}

void client_userauth::auth_with_password(std::string_view const& pw)
{
	packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_REQUEST, "method=password"sv);
	write_string(b.buf_, user_);
	write_string(b.buf_, "ssh-connection"sv);
	write_string(b.buf_, "password"sv);
	b.buf_.append(0);
	write_string(b.buf_, pw);
	b.commit();

	pending_auths_.emplace_back("password", false);
}

void client_userauth::auth_with_key(std::string_view const& pubblob, std::string_view const& signature_algorithm)
{
	packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_REQUEST, sprintf("method=publickey, without %s signature"sv, signature_algorithm));
	write_string(b.buf_, user_);
	write_string(b.buf_, "ssh-connection"sv);
	write_string(b.buf_, "publickey"sv);
	b.buf_.append(0);

	write_string(b.buf_, signature_algorithm);
	write_string(b.buf_, pubblob);
	b.commit();
	pending_auths_.emplace_back("publickey", true);
}

namespace {
template<typename T>
bool select_signature_algorithm(std::unique_ptr<T> const& key, std::string_view & signature_algorithm, std::string_view const& accepted_pk_auth_signatures)
{
	if (!key) {
		return false;
	}

	if (signature_algorithm.empty()) {
		signature_algorithm = key->name();
		if (signature_algorithm == "ssh-rsa"sv) {
			for (auto alg : strtokenizer(accepted_pk_auth_signatures, ","sv, true)) {
				if (key->supports_signature_algorithm(alg)) {
					signature_algorithm = alg;
					break;
				}
			}
		}
		return true;
	}
	else {
		return key->supports_signature_algorithm(signature_algorithm);
	}
}
}

void client_userauth::auth_with_key(std::unique_ptr<private_key> const& key, bool with_signature, std::string_view signature_algorithm)
{
	if (!key) {
		logger_.log(logmsg::error, "Cannot authenticate with key: No key given"sv);
		transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
	}

	if (!select_signature_algorithm(key, signature_algorithm, accepted_pk_auth_signatures_)) {
		logger_.log(logmsg::error, "Key does not support signature algorithm"sv);
		transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
		return;
	}

	if (with_signature) {
		privkey_ = key->clone();
		if (!privkey_) {
			logger_.log(logmsg::error, "Could not clone key"sv);
			transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
			return;
		}
		buffer sigdata;
		write_string(sigdata, transport_.session_id_);
		sigdata.append(static_cast<uint8_t>(message_id::SSH_MSG_USERAUTH_REQUEST));
		write_string(sigdata, user_);
		write_string(sigdata, "ssh-connection"sv);
		write_string(sigdata, hostbound_pubkey_auth_ ? "publickey-hostbound-v00@openssh.com"sv : "publickey"sv);
		sigdata.append(1);
		write_string(sigdata, signature_algorithm);
		write_string(sigdata, privkey_->pubkey_blob());
		if (hostbound_pubkey_auth_) {
			write_string(sigdata, static_cast<client_transport&>(transport_).previous_hostkey_);
		}
		if (privkey_->sign(sigdata.to_view(), signature_algorithm, *this)) {
			signature_algorithm_ = signature_algorithm;
		}
		else {
			transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
			privkey_.reset();
		}
	}
	else {
		auth_with_key(key->pubkey_blob(), signature_algorithm);
	}
}

void client_userauth::auth_with_key(std::unique_ptr<public_key> const& key, std::string_view signature_algorithm)
{
	if (!key || !*key) {
		logger_.log(logmsg::error, "Cannot authenticate with key: No key given"sv);
		transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
	}

	if (!select_signature_algorithm(key, signature_algorithm, accepted_pk_auth_signatures_)) {
		logger_.log(logmsg::error, "Key does not support signature algorithm"sv);
		transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
		return;
	}

	auth_with_key(key->pubkey_blob(), signature_algorithm);
}

void client_userauth::auth_keyboard_interactive()
{
	packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_REQUEST, "method=keyboard-interactive"sv);
	write_string(b.buf_, user_);
	write_string(b.buf_, "ssh-connection"sv);
	write_string(b.buf_, "keyboard-interactive"sv);
	write_string(b.buf_, "en"sv);
	write_string(b.buf_, ""sv);

	pending_auths_.emplace_back("keyboard-interactive", true);

	b.commit();
}

void client_userauth::auth_keyboard_interactive_response(std::vector<std::string> const& responses)
{
	if (pending_auths_.empty() || pending_auths_.front().name_ != "keyboard-interactive"sv) {
		transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_BY_APPLICATION, "Logic error in client"sv);
		return;
	}

	pending_auths_.front().request_only_ = false;

	packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_INFO_RESPONSE);
	write_uint32(b.buf_, responses.size());
	for (auto const& r : responses) {
		write_string(b.buf_, r);
	}

	b.commit();
}

continuation client_userauth::process_auth_banner(std::string_view packet)
{
	auto msg = extract_string(packet, string_type::utf8, true);
	if (!msg) {
		logger_.log(logmsg::error, fztranslate("Received malformed SSH_MSG_USERAUTH_BANNER, cannot extract banner: %s"), *msg);
		return continuation::next;
	}
	auto lang = extract_string(packet, string_type::ascii, true);
	if (!lang) {
		logger_.log(logmsg::error, fztranslate("Received malformed SSH_MSG_USERAUTH_BANNER, cannot extract language tag: %s"), *lang);
		return continuation::next;
	}

	// TODO: Filter and display message
	return continuation::next;
}

continuation client_userauth::process_auth_success(std::string_view packet)
{
	if (!packet.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_USERAUTH_SUCCESS with excessive data"sv);
	}

	if (pending_auths_.empty() || pending_auths_.front().request_only_) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_USERAUTH_SUCCESS without pending auth attempt"sv);
	}
	pending_auths_.pop_front();

	done_ = true;

	return transport_.on_auth_success();
}

continuation client_userauth::process_auth_failure(std::string_view packet)
{
	if (pending_auths_.empty()) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_USERAUTH_FAILURE without pending auth attempt"sv);
	}
	pending_auths_.pop_front();

	std::string_view methods;
	if (!extract_namelist(packet, methods, logger_)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_FAILURE, cannot extract methods"sv);
	}

	if (packet.size() != 1) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_FAILURE, packet too big"sv);
	}

	bool partial = packet[0];
	if (partial) {
		if (methods.empty()) {
			return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Partial auth failure with no methods to continue."sv);
		}
		logger_.log(logmsg::debug_info, "Partial authentication success. Available methods to continue: %s"sv, methods);
	}
	else {
		logger_.log(logmsg::debug_info, "Authentication attempt failed. Available methods to try again: %s"sv, methods);
	}

	transport_.handler_.send_event<auth_requested_event>(static_cast<client*>(&transport_.session_), methods, partial);

	return continuation::next;
}

continuation client_userauth::process_auth_pubkey_ok(std::string_view)
{
	if (pending_auths_.empty() || pending_auths_.front().name_ != "publickey"sv || !pending_auths_.front().request_only_) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_USERAUTH_PK_OK when not having sent a signature-less public key request"sv);
	}
	pending_auths_.pop_front();

	transport_.handler_.send_event<auth_public_key_okay_event>(static_cast<client*>(&transport_.session_));
	return continuation::next;
}

void client_userauth::operator()(event_base const& ev)
{
	fz::dispatch<signature_event>(ev, this, &client_userauth::on_signature);
}

void client_userauth::on_signature(private_key const& k, fz::buffer const& sig)
{
	if (!privkey_ || &k != privkey_.get()) {
		return;
	}

	if (sig.empty()) {
		transport_.handler_.send_event<auth_signature_failure_event>(static_cast<client*>(&transport_.session_));
		privkey_.reset();
		return;
	}

	packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_REQUEST, sprintf("method=%s, with %s signature"sv, hostbound_pubkey_auth_ ? "publickey-hostbound-v00@openssh.com"sv : "publickey"sv, signature_algorithm_));
	write_string(b.buf_, user_);
	write_string(b.buf_, "ssh-connection"sv);
	write_string(b.buf_, hostbound_pubkey_auth_ ? "publickey-hostbound-v00@openssh.com"sv : "publickey"sv);
	b.buf_.append(1);
	write_string(b.buf_, signature_algorithm_);
	write_string(b.buf_, privkey_->pubkey_blob());
	if (hostbound_pubkey_auth_) {
		write_string(b.buf_, static_cast<client_transport&>(transport_).previous_hostkey_);
	}
	write_string(b.buf_, sig);
	b.commit();
	privkey_.reset();

	pending_auths_.emplace_back("publickey", false);
}

message_id client_userauth::get_method_flag()
{
	if (!pending_auths_.empty()) {
		auto const& auth = pending_auths_.front();
		if (auth.name_ == "publickey"sv) {
			return message_id::FLAG_USERAUTH_PK;
		}
		else if (auth.name_ == "keyboard-interactive"sv) {
			return message_id::FLAG_USERAUTH_KEYBOARD_INTERACTIVE;
		}
	}
	return {};
}

continuation client_userauth::process_auth_info_request(std::string_view packet)
{
	if (pending_auths_.empty() || pending_auths_.front().name_ != "keyboard-interactive"sv) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_USERAUTH_INFO_REQUEST when not doing keyboard-interactive authentication"sv);
	}

	auto name = extract_string(packet, string_type::utf8, true);
	if (!name) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_INFO_REQUEST, cannot extract name"sv);
	}
	auto instruction = extract_string(packet, string_type::utf8, true);
	if (!instruction) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_INFO_REQUEST, cannot extract instruction"sv);
	}
	auto lang = extract_string(packet, string_type::ascii, true);
	if (!lang) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_INFO_REQUEST, cannot extract language tag"sv);
	}
	uint32_t count{};
	if (!extract_uint32(packet, count)) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_INFO_REQUEST, cannot extract number of prompts"sv);
	}

	std::vector<keyboard_interactive_prompt> prompts;
	if (count > 10) {
		return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_USERAUTH_INFO_REQUEST with more than 10 prompts"sv);
	}

	for (size_t i = 0; i < count; ++i) {
		auto p = extract_string(packet, string_type::utf8, false);
		if (!p || packet.empty()) {
			return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_USERAUTH_INFO_REQUEST, cannot extract prompt"sv);
		}
		bool echo = packet[0] != '\0';
		packet.remove_prefix(1);

		keyboard_interactive_prompt prompt;
		prompt.prompt_ = std::move(*p);
		prompt.echo_ = echo;
		prompts.emplace_back(std::move(prompt));
	}

	// For reasons unknown, OpenSSH sends an empty request
	if (prompts.empty() && name->empty() && instruction->empty()) {
		if (pending_auths_.front().flags_) {
			return transport_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received multiple SSH_MSG_USERAUTH_INFO_REQUEST messages with no name, no instructions and no prompt."sv);
		}
		pending_auths_.front().request_only_ = false;
		pending_auths_.front().flags_ = 1;

		packet_builder b(transport_, message_id::SSH_MSG_USERAUTH_INFO_RESPONSE);
		write_uint32(b.buf_, 0);
		return b.commit() ? continuation::next : continuation::error;
	}

	transport_.handler_.send_event<auth_keyboard_interactive_prompt_event>(static_cast<client*>(&transport_.session_), *name, *instruction, std::move(prompts));
	return continuation::next;
}

}
