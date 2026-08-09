#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/event_loop.hpp>
#include <libfilezilla/time.hpp>
#include <libfilezilla/buffer.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/socket.hpp>
#include <libfilezilla/thread_pool.hpp>
#include <libfilezilla/util.hpp>
#include <libfilezilla/uri.hpp>

#include <fzssh/sftp/sftp_client.hpp>

#include <fzssh/agent.hpp>
#include <fzssh/client.hpp>
#include <fzssh/privkey.hpp>

#include <iostream>
#include <optional>

#include <locale.h>
#include <string.h>

using namespace std::literals;

class sftp : public fz::ssh::sftp::response_handler
{
public:
	using continuation = fz::ssh::sftp::continuation;

	sftp(fz::event_handler& h, std::unique_ptr<fz::ssh::sftp::sftp_client> && client, fz::logger_interface & log)
		: event_handler_(h)
		, client_(std::move(client))
		, log_(log)
	{
	}

	void prompt()
	{
		std::cout << "Command: "sv << std::flush;

		std::string cmd;
		std::getline(std::cin, cmd);

		std::string args;
		size_t pos = cmd.find(' ');
		if (pos != std::string::npos) {
			args = cmd.substr(pos + 1);
			cmd = cmd.substr(0, pos);
		}

		if (cmd == "ls") {
			client_->opendir(this, args.empty() ? "."sv : args);
		}
		else if (cmd == "realpath") {
			client_->realpath(this, args);
		}
	}

	virtual ~sftp()
	{
		client_.reset();
	}

	virtual continuation process_handle(std::string_view handle) override
	{
		handle_ = handle;

		client_->readdir(this, handle);
		client_->readdir(this, handle);
		client_->readdir(this, handle);
		client_->readdir(this, handle);

		return continuation::next;
	}

	virtual continuation process_status(fz::ssh::sftp::status_code /*status*/, std::string_view /*message*/) override
	{
		if (!handle_.empty()) {
			client_->close(nullptr, handle_);
			handle_.clear();
		}
		client_->cancel(this);
		prompt();
		return continuation::next;
	}

	virtual continuation process_name(fz::ssh::sftp::entry & e, bool more) override
	{
		log_.log_raw(fz::logmsg::reply, e.longname_);
		if (!more) {
			if (!handle_.empty()) {
				client_->readdir(this, handle_);
			}
			else {
				prompt();
			}
		}
		return continuation::next;
	}

	fz::event_handler & event_handler_;
	std::string handle_;
	std::unique_ptr<fz::ssh::sftp::sftp_client> client_;
	fz::logger_interface & log_;
};

class runner final : public fz::event_handler
{
public:
	runner(fz::logger_interface & log, fz::thread_pool & pool, fz::event_loop& l, std::string_view host, uint16_t port, std::string_view user)
		: fz::event_handler(l)
		, log_(log)
		, pool_(pool)
		, agent_(pool, *this, log)
		, user_(user)
	{
		s_ = std::make_unique<fz::socket>(pool_, this);
		if (s_->connect(fz::to_native(host), port)) {
			log_.log(fz::logmsg::error, "Cannot connect to %s:%u"sv, host, port);
			exit(1);
		}
	}

	~runner()
	{
		remove_handler();
	}

	virtual void operator()(fz::event_base const& ev) override
	{
		fz::dispatch<
			fz::socket_event,
			fz::ssh::auth_done_event,
			fz::ssh::session_done_event, fz::ssh::hostkey_verification_event, fz::ssh::auth_requested_event, fz::ssh::available_keys_event, fz::ssh::auth_public_key_okay_event, fz::ssh::auth_signature_failure_event, fz::ssh::sftp::sftp_client::ready_event, fz::ssh::sftp::sftp_client::done_event
		>(ev, this,
			&runner::on_socket_event,
			&runner::on_auth_done,
			&runner::on_session_done,
			&runner::on_hostkey_event,
			&runner::on_auth_requested,
			&runner::on_agent_keys,
			&runner::on_auth_pubkey_ok,
			&runner::on_auth_signature_failure,
			&runner::on_sftp_ready,
			&runner::on_sftp_done);
	}

	void on_socket_event(fz::socket_event_source *s, fz::socket_event_flag type, int error)
	{
		if (error) {
			log_.log(fz::logmsg::error, "Could not connect socket: %u"sv, error);
			exit(1);
		}
		if (s == s_.get() && type == fz::socket_event_flag::connection && !error) {

			log_.log(fz::logmsg::status, "TCP connection established"sv);

			fz::ssh::client_parameters param;
			param.single_channel_ = true;

			ssh_ = std::make_unique<fz::ssh::client>(param, user_, *s_, *this, log_);
			// TODO log error
		}
	}

	void on_auth_done(fz::ssh::session* s)
	{
		if (!ssh_ || ssh_.get() != s) {
			return;
		}

		log_.log(fz::logmsg::status, "Logged in"sv);

		std::cout << "Channel type: "sv << std::flush;

		std::string type;
		std::getline(std::cin, type);
		if (type == "shell"sv) {
			// TODO
			//auto si = ssh_->open_channel(fz::ssh::channel_type::shell, {});
			//auto channel = ???
			//channels_.emplace_back(std::move(channel));
		}
		else if (type == "sftp"sv) {
			auto si = ssh_->open_channel(fz::ssh::channel_type::subsystem, "sftp"sv);
			auto channel = std::make_unique<fz::ssh::sftp::sftp_client>(std::move(si), *this, log_);
			sftp_.emplace(*this, std::move(channel), log_);
		}
		else {
			std::cerr << "Unsupported channel type"sv;
			exit(1);
		}
	}

	void on_session_done(fz::ssh::session*)
	{
		sftp_.reset();
		ssh_.reset();
		s_.reset();
		exit(1);
	}

	void on_hostkey_event(fz::ssh::session* s, std::unique_ptr<fz::ssh::public_key> const& k, fz::ssh::algorithm_info const&)
	{
		log_.log(fz::logmsg::status, "Got host key verification event"sv);
		if (s == ssh_.get()) {
			std::cout << "Trust hostkey of type "sv << k->name() << " with fingerprint "sv << k->fingerprint() << "? (yes/no/fingerprint)? "sv << std::flush;
			std::string decision;
			std::getline(std::cin, decision);
			ssh_->hostkey_decision(decision[0] == 'y' || decision[0] == 'Y' || decision == k->fingerprint());
		}
	}

	void on_auth_requested(fz::ssh::session*, std::string const& methods, bool is_continuation)
	{
		log_.log(fz::logmsg::status, is_continuation ? "Further authentication required. Available methods: %s"sv : "Authentication required. Available methods: %s"sv, methods);
		ask_method();
	}

	void ask_method()
	{
		while (true) {
			std::string method;
			std::cout << "Method (Password, Agent, publicKey, keyboard-Interactive): "sv << std::flush;
			std::getline(std::cin, method);
			if (fz::starts_with(method, "a"sv)) {
				agent_.get_keys(*this);
				return;
			}
			else if (fz::starts_with(method, "p"sv)) {
				std::string pw;
				std::cout << "Password: "sv << std::flush;
				std::getline(std::cin, pw);
				ssh_->auth_with_password(pw);
				return;
			}
			else if (fz::starts_with(method, "i"sv)) {
				ssh_->auth_keyboard_interactive();
				return;
			}
			else if (fz::starts_with(method, "r"sv)) {
				ssh_->auth_keyboard_interactive_response({});
				return;
			}
			else if (fz::starts_with(method, "k"sv)) {
				// TODO
				return;
			}
			log_.log(fz::logmsg::error, "Unknown method"sv);
		}
	}

	void on_agent_keys(fz::ssh::agent_connection* agent, std::vector<std::unique_ptr<fz::ssh::private_key>> & keys)
	{
		if (agent != &agent_) {
			return;
		}

		if (keys.empty()) {
			log_.log(fz::logmsg::status, "No agent keys available");
			return;
		}

		log_.log(fz::logmsg::status, "Available keys:"sv);
		for (size_t i = 0; i < keys.size(); ++i) {
			auto const& key = keys[i];
			log_.log(fz::logmsg::status, "%u: %s %s %s"sv, i + 1, key->name(), key->fingerprint(), key->comment_);
		}

		while (true) {
			std::cout << "Select key (negative to not sign): "sv << std::flush;
			std::string is;
			std::getline(std::cin, is);
			int i = fz::to_integral<int>(is);

			if (!i) {
				ask_method();
				return;
			}

			bool with_signature = true;
			if (i < 0) {
				with_signature = false;
				i = -i;
			}
			--i;
			if (i >= 0 && static_cast<size_t>(i) < keys.size()) {
				// TODO: Could ask for signature algorithm in case of ssh-rsa key
				ssh_->auth_with_key(keys[i], with_signature);
				return;
			}
		}
	}

	void on_auth_pubkey_ok(fz::ssh::session*) {
		log_.log(fz::logmsg::status, "Server accepted public key"sv);
		ask_method();
	}

	void on_auth_signature_failure(fz::ssh::session*)
	{
		log_.log(fz::logmsg::error, "Signing failed"sv);
		ask_method();
	}

	void on_sftp_ready(fz::ssh::sftp::sftp_client*)
	{
		sftp_->prompt();
	}

	void on_sftp_done(fz::ssh::sftp::sftp_client*)
	{
		sftp_.reset();
	}

	fz::logger_interface & log_;
	fz::thread_pool & pool_;
	std::unique_ptr<fz::socket> s_;
	std::unique_ptr<fz::ssh::client> ssh_;
	fz::ssh::agent_connection agent_;
	std::string user_;

	std::optional<sftp> sftp_;
};

int main(int argc, char *argv[])
{
	std::setlocale(LC_ALL, "");

	fz::stdout_logger log;

	std::optional<fz::uri> u;

	for (int i = 1; i < argc; ++i) {
		std::string_view arg(argv[i], strlen(argv[i]));
		if (arg.empty()) {
			continue;
		}

		if (arg == "-v"sv) {
			log.set_all(fz::logmsg::type(-1));
		}
		else if (arg.front() == '-') {
			log.log(fz::logmsg::error, "Unknown option: %s"sv, arg);
			return 1;
		}
		else {
			u = fz::uri(arg, fz::uri_parsing_flags::assume_authority);
		}
	}

	if (!u) {
		log.log(fz::logmsg::error, "Must pass server address as argument: [user@]host:[port]"sv);
		return 1;
	}

	// Literal IPv6
	if (u->host_.size() >= 2 && u->host_[0] == '[' && u->host_.back() == ']') {
		u->host_ = u->host_.substr(1, u->host_.size() - 2);
	}

	if (u->host_.empty()) {
		log.log(fz::logmsg::error, "Must pass server address as argument: [user@]host:[port]"sv);
		return 1;
	}

	if (!u->port_) {
		u->port_ = 22;
	}

	if (u->user_.empty()) {
		u->user_ = "test"sv;
	}

	fz::thread_pool pool;

	fz::event_loop loop(fz::event_loop::threadless);
	runner r(log, pool, loop, u->host_, u->port_, u->user_);
	loop.run();

	return 0;
}
