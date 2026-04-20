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

using namespace std::literals;

class sftp : public fz::ssh::sftp::response_handler, fz::event_handler
{
public:
	using continuation = fz::ssh::sftp::continuation;

	sftp(fz::event_loop& l, std::unique_ptr<fz::ssh::sftp::sftp_client> && client, fz::logger_interface & log)
		: event_handler(l)
		, event_loop_(l)
		, client_(std::move(client))
		, log_(log)
	{
		client_->open(this, "/dev/zero"sv, fz::ssh::sftp::file_flags::SSH_FXF_READ);
	}

	virtual ~sftp()
	{
		remove_handler();
		auto stop = fz::monotonic_clock::now();
		fz::duration d = stop - start_;
		log_.log(fz::logmsg::status, "Read speed: %u KiB/s", (received_ * 1000 / d.get_milliseconds()) / 1024);
		client_.reset();
	}

	virtual continuation process_handle(std::string_view handle) override
	{
		handle_ = handle;

		for (size_t i = 0; i < 4; ++i) {
			client_->read(this, handle_, offset_, 32768);
			offset_ += 32768;
		}

		start_ = fz::monotonic_clock::now();
		add_timer(fz::duration::from_seconds(5), true);

		return continuation::next;
	}

	virtual continuation process_status(fz::ssh::sftp::status_code /*status*/, std::string_view /*message*/) override
	{
		if (!handle_.empty()) {
			client_->close(nullptr, handle_);
			handle_.clear();
		}
		client_->cancel(this);
		event_loop_.stop();
		return continuation::next;
	}

	virtual continuation process_data(std::string_view data) override
	{
		received_ += data.size();
		client_->read(this, handle_, offset_, 32768);
		offset_ += 32768;

		return continuation::next;
	}

	virtual void operator()(fz::event_base const&) override
	{
		event_loop_.stop();
	}

	uint64_t received_{};
	uint64_t offset_{};

	fz::monotonic_clock start_;

	fz::event_loop & event_loop_;
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
		, user_(user)
	{
		s_ = std::make_unique<fz::socket>(pool_, this);
		s_->set_flags(fz::socket::flag_nodelay);
		if (s_->connect(fz::to_native(host), port)) {
			log_.log(fz::logmsg::error, "Cannot connect to %s:%u"sv, host, port);
			event_loop_.stop();
		}
	}

	~runner()
	{
		remove_handler();
	}

	virtual void operator()(fz::event_base const& ev) override
	{
		fz::dispatch<fz::socket_event, fz::ssh::auth_done_event, fz::ssh::session_done_event, fz::ssh::hostkey_verification_event, fz::ssh::auth_requested_event, fz::ssh::available_keys_event, fz::ssh::auth_signature_failure_event>(ev, this,
			&runner::on_socket_event,
			&runner::on_auth_done,
			&runner::on_session_done,
			&runner::on_hostkey_event,
			&runner::on_auth_requested,
			&runner::on_agent_keys,
			&runner::on_auth_signature_failure
		);
	}

	void on_socket_event(fz::socket_event_source *s, fz::socket_event_flag type, int error)
	{
		if (error) {
			log_.log(fz::logmsg::error, "Could not connect socket: %u"sv, error);
			event_loop_.stop();
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

		auto si = ssh_->open_channel(fz::ssh::channel_type::subsystem, "sftp"sv);
		auto channel = std::make_unique<fz::ssh::sftp::sftp_client>(std::move(si), *this, log_);
		sftp_.emplace(event_loop_, std::move(channel), log_);
	}

	void on_session_done(fz::ssh::session*)
	{
		sftp_.reset();
		ssh_.reset();
		s_.reset();
		exit(1);
	}

	void on_hostkey_event(fz::ssh::session* s, std::unique_ptr<fz::ssh::public_key> const&, fz::ssh::algorithm_info const&)
	{
		log_.log(fz::logmsg::status, "Got host key verification event"sv);
		if (s == ssh_.get()) {
			ssh_->hostkey_decision(true);
		}
	}

	void on_auth_requested(fz::ssh::session*, std::string const& methods, bool /*is_continuation*/)
	{
		log_.log(fz::logmsg::status, "Authentication required. Available methods: %s"sv, methods);
		if (!agent_) {
			agent_.emplace(pool_, *this, log_);
			agent_->get_keys(*this);
		}
	}

	void on_agent_keys(fz::ssh::agent_connection* agent, std::vector<std::unique_ptr<fz::ssh::private_key>> & keys)
	{
		if (!agent_ || agent != &*agent_) {
			return;
		}

		if (keys.empty()) {
			log_.log(fz::logmsg::error, "No agent keys available");
			event_loop_.stop();
			return;
		}

		ssh_->auth_with_key(keys[0], true);
	}

	void on_auth_signature_failure(fz::ssh::session*)
	{
		log_.log(fz::logmsg::error, "Signing failed"sv);
		event_loop_.stop();
	}

	fz::logger_interface & log_;
	fz::thread_pool & pool_;
	std::unique_ptr<fz::socket> s_;
	std::unique_ptr<fz::ssh::client> ssh_;
	std::optional<fz::ssh::agent_connection> agent_;
	std::string user_;

	std::optional<sftp> sftp_;
};

int main(int argc, char *argv[])
{
	std::setlocale(LC_ALL, "");

	fz::stdout_logger log;
	//log.set_all(fz::logmsg::type(0));

	if (argc < 2) {
		log.log(fz::logmsg::error, "Must pass server address as argument: [user@]host:[port]"sv);
		return 1;
	}
	fz::uri u(argv[1], fz::uri_parsing_flags::assume_authority);

	// Literal IPv6
	if (u.host_.size() >= 2 && u.host_[0] == '[' && u.host_.back() == ']') {
		u.host_ = u.host_.substr(1, u.host_.size() - 2);
	}

	if (u.host_.empty()) {
		log.log(fz::logmsg::error, "Must pass server address as argument: [user@]host:[port]"sv);
		return 1;
	}

	if (!u.port_) {
		u.port_ = 22;
	}

	if (u.user_.empty()) {
		u.user_ = "none"sv;
	}


	fz::thread_pool pool;

	{
		fz::event_loop loop(fz::event_loop::threadless);
		runner r(log, pool, loop, u.host_, u.port_, u.user_);
		loop.run();
	}

	return 0;
}
