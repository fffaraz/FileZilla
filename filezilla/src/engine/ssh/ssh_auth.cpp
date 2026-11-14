#include "../filezilla.h"
#include "ssh_auth.h"

#include "../../include/engine_options.h"
#include "../engineprivate.h"

#include <algorithm>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

namespace {
bool method_available(std::string_view const& methods, std::string_view method)
{
	for (auto m : fz::strtokenizer(methods, ","sv, true)) {
		if (m == method) {
			return true;
		}
	}
	return false;
}
}

SshAuth::SshAuth(fz::event_handler& parent, CControlSocket& controlSocket,	CServer server,
		ServerHandle handle, Credentials credentials, std::unique_ptr<fz::ssh::client> & ssh,
		SuccessHandler success, FailureHandler failure)
	: event_handler(parent, fz::child_event_handler), controlSocket_(controlSocket), server_(std::move(server))
	, handle_(std::move(handle)), credentials_(std::move(credentials)), ssh_(ssh)
	, success_(std::move(success)), failure_(std::move(failure))
{
}

SshAuth::~SshAuth()
{
	pending_request_.reset();
	remove_handler();
	agent_.reset();
}

void SshAuth::fail(int result)
{
	if (failure_) {
		failure_(result);
	}
}

bool SshAuth::load_keys()
{
	if (keys_loaded_) {
		return false;
	}

	auto names = credentials_.keyFile_;
	names += '\n';
	names += controlSocket_.GetEngine().GetOptions().get_string(OPTION_SFTP_KEYFILES);
	std::set<std::wstring> seen_names;
	for (auto k : fz::strtokenizer(names, L"\r\n"sv, true)) {
		if (!seen_names.emplace(k).second) {
			continue;
		}
		fz::buffer b;
		if (!fz::read_file(fz::to_native(k), b, 128 * 1024)) {
			log(logmsg::error, _("Could not read key file '%s'."), k);
			continue;
		}

		auto infos = fz::ssh::load_private_key_infos(b.to_view(), controlSocket_.logger(), {});
		if (infos.empty()) {
			log(logmsg::error, _("The file '%s' does not contain any private keys"), k);
			continue;
		}

		for (auto& i : infos) {
			if (i.pubkey_ && !used_keys_.emplace(i.pubkey_->pubkey_blob()).second) {
				continue;
			}
			i.name_ = fz::to_utf8(k);
			keys_.emplace_back(std::move(i));
		}
	}

	if (!controlSocket_.GetEngine().GetOptions().get_bool(OPTION_SFTP_USE_AGENT)) {
		log(logmsg::debug_info, "Use of SSH has been disabled");
		set_keys_loaded();
		return false;
	}

	fz::ssh::agent_compatibility_flags flags{};
#ifdef USE_MAC_SANDBOX
	flags |= fz::ssh::agent_compatibility_flags::suppress_agent_connection_error;
#endif
	if (server_.GetExtraParameter("allow_agent_keys_of_unknown_type"sv) == L"1") {
		flags |= fz::ssh::agent_compatibility_flags::allow_keys_with_unknown_types;
	}
	agent_ = std::make_unique<fz::ssh::agent_connection>(controlSocket_.GetEngine().GetThreadPool(), *this, controlSocket_.logger(), flags);
	agent_->get_keys(*this);
	return true;
}

bool SshAuth::auth_with_key()
{
	if (load_keys()) {
		return true;
	}

	if (!ssh_) {
		return false;
	}

	while (!keys_.empty()) {
		method_ = "publickey"sv;

		auto& key = keys_.back();
		if (key.pubkey_) {
			tried_key_ = true;
			used_keys_.emplace(key.pubkey_->pubkey_blob());
			log(logmsg::command, _("Authenticating with public key"));
			ssh_->auth_with_key(key.pubkey_);
			return true;
		}

		if (!key.privkey_) {
			ask_key_password(false);
			return true;
		}

		log(logmsg::debug_warning, _("Bad key info"));
		keys_.pop_back();
	}

	return false;
}

void SshAuth::on_auth_requested(fz::ssh::client* ssh, std::string const& methods, bool is_continuation)
{
	if (ssh != ssh_.get()) {
		return;
	}

	controlSocket_.SetAlive();
	methods_ = methods;

	if (!is_continuation) {
		if (tried_key_ || tried_pw_ || tried_interactive_ != interactive_state::unused) {
			log(logmsg::reply, _("Authentication failed"));
			if (tried_interactive_ == interactive_state::tried && method_ == "keyboard-interactive"sv) {
				if (++retry_counter_ < 3) {
					tried_pw_ = tried_key_ = false;
					tried_interactive_ = interactive_state::unused;
					log(logmsg::debug_warning, L"Server rejected entered response. Starting over authentication from scratch."sv);
				}
			}
			else if (tried_key_ && !keys_.empty()) {
				keys_.pop_back();
				if (!keys_.empty()) {
					log(logmsg::debug_info, L"Starting over authentication with next available public key"sv);
					tried_pw_ = tried_key_ = false;
					tried_interactive_ = interactive_state::unused;
				}
			}
		}
		else {
			log(logmsg::reply, _("Authentication required"));
		}
	}
	else {
		log(logmsg::reply, _("Further authentication required"));
	}

	next_auth();
}

void SshAuth::next_auth()
{
	if (!ssh_) {
		return;
	}

	if (method_available(methods_, "publickey"sv) && !tried_key_) {
		if (auth_with_key()) {
			return;
		}
	}

	if (method_available(methods_, "password"sv) && !tried_pw_) {
		if (credentials_.logonType_ == LogonType::interactive) {
			if (!method_available(methods_, "keyboard-interactive"sv)) {
				send_async_request(std::make_unique<PasswordRequest>(server_, handle_, false));
				return;
			}
		}
		else if (!credentials_.GetPass().empty()) {
			tried_pw_ = true;
			log(logmsg::command, _("Sending password"));
			method_ = "password"sv;
			ssh_->auth_with_password(fz::to_utf8(credentials_.GetPass()));
			return;
		}
	}

	if (credentials_.logonType_ != LogonType::anonymous && method_available(methods_, "keyboard-interactive"sv) && tried_interactive_ == interactive_state::unused) {
		tried_interactive_ = interactive_state::requested;
		log(logmsg::command, _("Requesting keyboard-interactive authentication"));
		method_ = "keyboard-interactive"sv;
		ssh_->auth_keyboard_interactive();
		return;
	}

	log(logmsg::error, fztranslate("No more authentication methods available"));
	fail(FZ_REPLY_CRITICALERROR | FZ_REPLY_DISCONNECTED | FZ_REPLY_PASSWORDFAILED);
}

void SshAuth::on_auth_done(fz::ssh::client* ssh)
{
	if (ssh != ssh_.get()) {
		return;
	}

	controlSocket_.SetAlive();
	log(logmsg::reply, _("Authentication successful"));
	if (success_) {
		success_();
	}
}

void SshAuth::operator()(fz::event_base const& ev)
{
	fz::dispatch<
		fz::ssh::auth_requested_event,
		fz::ssh::auth_done_event,
		fz::ssh::auth_public_key_okay_event,
		fz::ssh::auth_signature_failure_event,
		fz::ssh::auth_keyboard_interactive_prompt_event,
		fz::ssh::auth_password_change_request_event,
		fz::ssh::available_keys_event
	>(
		ev, this,
		&SshAuth::on_auth_requested,
		&SshAuth::on_auth_done,
		&SshAuth::on_auth_pubkey_ok,
		&SshAuth::on_auth_signature_failed,
		&SshAuth::on_auth_keyboard_interactive_prompt,
		&SshAuth::on_auth_password_change_requested,
		&SshAuth::on_agent_keys
	);
}

void SshAuth::on_agent_keys(fz::ssh::agent_connection* conn, std::vector<std::unique_ptr<fz::ssh::private_key>>& keys)
{
	if (!agent_ || conn != agent_.get()) {
		return;
	}

	for (auto& k : keys) {
		if (!used_keys_.emplace(k->pubkey_blob()).second) {
			continue;
		}
		fz::ssh::private_key_info i;
		i.privkey_ = std::move(k);
		i.pubkey_ = i.privkey_->pubkey();
		keys_.emplace_back(std::move(i));
	}

	set_keys_loaded();
	next_auth();
}

void SshAuth::set_keys_loaded()
{
	if (keys_loaded_) {
		return;
	}

	keys_loaded_ = true;
	used_keys_.clear();
	log(logmsg::debug_info, fztranslate("Loaded %u distinct key", "Loaded %u distinct keys", keys_.size()), keys_.size());
	std::reverse(keys_.begin(), keys_.end());
}

void SshAuth::on_auth_pubkey_ok(fz::ssh::client* ssh)
{
	if (ssh != ssh_.get()) {
		return;
	}
	if (keys_.empty()) {
		fail(FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED);
		return;
	}

	auto& key = keys_.back();
	if (!key.privkey_) {
		ask_key_password(false);
		return;
	}

	ssh->auth_with_key(key.privkey_, true);
}

void SshAuth::ask_key_password(bool repeated)
{
	if (keys_.empty()) {
		fail(FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED);
		return;
	}

	auto req = std::make_unique<KeyfilePasswordRequest>(server_, handle_);
	req->repeated_ = repeated;

	auto const& info = keys_.back();
	if (info.pubkey_) {
		req->fingerprint_ = info.pubkey_->fingerprint();
		req->comment_ = info.pubkey_->comment_;
	}
	req->file_ = info.name_;

	send_async_request(std::move(req));
}

void SshAuth::set_password(std::string const& password)
{
	if (!ssh_) {
		return;
	}

	tried_pw_ = true;
	log(logmsg::command, _("Sending password"));
	method_ = "password"sv;
	ssh_->auth_with_password(password);
}

void SshAuth::set_keyfile_password(std::string const& password)
{
	if (keys_.empty() || keys_.back().privkey_) {
		fail(FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED);
		return;
	}

	if (!ssh_) {
		return;
	}

	auto& info = keys_.back();
	bool const try_pubkey = info.pubkey_ == nullptr;
	if (!info.decrypt(password, &controlSocket_.logger())) {
		ask_key_password(true);
		return;
	}

	if (try_pubkey) {
		ssh_->auth_with_key(info.pubkey_);
	}
	else {
		ssh_->auth_with_key(info.privkey_, true);
	}
}

void SshAuth::on_auth_signature_failed(fz::ssh::client* ssh)
{
	if (ssh != ssh_.get()) {
		return;
	}
	if (!tried_key_ || keys_.empty()) {
		fail(FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED);
		return;
	}

	keys_.pop_back();
	if (!keys_.empty()) {
		log(logmsg::debug_info, L"Starting over authentication with next available public key");
		tried_pw_ = tried_key_ = false;
		tried_interactive_ = interactive_state::unused;
	}
	next_auth();
}

bool SshAuth::interactive_prompt_asks_for_password(std::string_view prompt) const
{
	fz::rtrim(prompt, "\r\n :"sv);
	if (fz::equal_insensitive_ascii(prompt, "password"sv)) {
		return true;
	}

	return fz::equal_insensitive_ascii(prompt, fz::sprintf("password for %s:%s"sv, fz::to_utf8(server_.GetUser()), fz::to_utf8(server_.GetHost())));
}

void SshAuth::on_auth_keyboard_interactive_prompt(fz::ssh::client* ssh, std::string const& name, std::string const& instruction, std::vector<fz::ssh::keyboard_interactive_prompt>& prompts)
{
	if (ssh != ssh_.get()) {
		return;
	}
	if (tried_interactive_ == interactive_state::unused) {
		fail(FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED);
		return;
	}

	if (prompts.size() == 1 && prompts[0].prompt_ == "TOTP: "sv && ssh->peer_identification().find("_FileZillaProEnterpriseServer_"sv) != std::string::npos) {
		send_async_request(std::make_unique<OtpRequest>(server_, handle_));
		tried_interactive_ = interactive_state::tried;
		return;
	}

	if (credentials_.logonType_ != LogonType::interactive && (!credentials_.GetPass().empty()) && prompts.size() == 1 && interactive_prompt_asks_for_password(prompts[0].prompt_)) {
		if (tried_pw_) {
			log(logmsg::status, _("The server sent a single keyboard-interactive prompt named \"%s\", but we already have sent the password. Select interactive login type to force an interactive prompt."), prompts[0].prompt_);
			log(logmsg::error, fztranslate("No more authentication methods available"));
			fail(FZ_REPLY_CRITICALERROR | FZ_REPLY_DISCONNECTED | FZ_REPLY_PASSWORDFAILED);
		}
		else {
			// As this password isn't changing, don't set tried_interactive to interactive_state::tried
			tried_pw_ = true;
			log(logmsg::status, _("The server does not support password authentication, but sent a single keyboard-interactive prompt named \"%s\". Sending password as response. Select interactive login type to force an interactive prompt."), prompts[0].prompt_);
			log(logmsg::command, _("Sending password as response"));
			std::vector<std::string> responses{fz::to_utf8(credentials_.GetPass())};
			ssh->auth_keyboard_interactive_response(std::move(responses));
		}
		return;
	}

	log(logmsg::reply, fztranslate("Received %u keyboard-interactive prompt.", "Received %u keyboard-interactive prompts.", prompts.size()), prompts.size());
	auto req = std::make_unique<CInteractiveLoginNotification>(server_, handle_);
	req->name_ = name;
	req->instruction_ = instruction;
	req->prompts_ = std::move(prompts);
	send_async_request(std::move(req));
}

void SshAuth::set_interactive_responses(std::vector<std::string> const& responses)
{
	if (!ssh_) {
		return;
	}

	tried_interactive_ = interactive_state::tried;
	log(logmsg::command, L"Sending keyboard-interactive reply");
	ssh_->auth_keyboard_interactive_response(responses);
}

void SshAuth::on_auth_password_change_requested(fz::ssh::client* ssh)
{
	if (ssh != ssh_.get()) {
		return;
	}
	log(logmsg::error, L"Server requested password change. This functionality is not currently supported.");
	fail(FZ_REPLY_CRITICALERROR);
}

void SshAuth::send_async_request(std::unique_ptr<CAsyncRequestNotification>&& notification)
{
	AsyncRequestHandle::Reply reply = [this](CAsyncRequestNotification* request) {
		pending_request_.reset();
		set_async_request_reply(request);
	};
	pending_request_ = controlSocket_.SendAsyncRequest(std::move(notification), async_request_type::waiting, std::move(reply));
}

void SshAuth::set_async_request_reply(CAsyncRequestNotification* notification)
{
	if (!notification) {
		return;
	}

	switch (notification->GetRequestID()) {
	case reqId_interactiveLogin:
		{
			auto& req = static_cast<CInteractiveLoginNotification&>(*notification);
			if (!req.responses_) {
				fail(FZ_REPLY_CANCELED | FZ_REPLY_DISCONNECTED);
				return;
			}
			set_interactive_responses(*req.responses_);
		}
		break;
	case reqId_password:
		{
			auto& req = static_cast<PasswordRequest&>(*notification);
			if (!req.password_) {
				fail(FZ_REPLY_CANCELED | FZ_REPLY_DISCONNECTED);
				return;
			}
			set_password(fz::to_utf8(*req.password_));
		}
		break;
	case reqId_otp:
		{
			auto& req = static_cast<OtpRequest&>(*notification);
			if (req.otp_.empty()) {
				fail(FZ_REPLY_CANCELED | FZ_REPLY_DISCONNECTED);
				return;
			}
			std::vector<std::string> responses{req.otp_};
			set_interactive_responses(responses);
		}
		break;
	case reqId_keyfile_password:
		{
			auto& req = static_cast<KeyfilePasswordRequest&>(*notification);
			if (!req.password_) {
				fail(FZ_REPLY_CANCELED | FZ_REPLY_DISCONNECTED);
				return;
			}
			set_keyfile_password(*req.password_);
		}
		break;
	default:
		log(logmsg::debug_warning, L"Unknown SSH authentication request reply id: %d", notification->GetRequestID());
		break;
	}
}
