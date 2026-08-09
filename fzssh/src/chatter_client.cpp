#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/event_loop.hpp>
#include <libfilezilla/time.hpp>
#include <libfilezilla/buffer.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/socket.hpp>
#include <libfilezilla/thread_pool.hpp>
#include <libfilezilla/tls_layer.hpp>
#include <libfilezilla/tls_info.hpp>
#include <libfilezilla/util.hpp>

#include <fzssh/client.hpp>

#include <locale.h>

using namespace std::literals;

namespace {

class chatter_channel : public fz::event_handler
{
public:
	chatter_channel(std::unique_ptr<fz::socket_interface> && channel, fz::event_loop & loop, fz::logger_interface & logger);
	virtual ~chatter_channel();

protected:
	fz::logger_interface & logger_;

private:
	virtual void operator()(fz::event_base const& ev);
	void on_socket_event(fz::socket_event_source *s, fz::socket_event_flag type, int error);
	void on_read();
	void on_send();

	std::unique_ptr<fz::socket_interface> s_;

	fz::buffer outbuf_;
};

chatter_channel::chatter_channel(std::unique_ptr<fz::socket_interface> && channel, fz::event_loop & loop, fz::logger_interface & logger)
    : event_handler(loop)
    , logger_(logger)
    , s_(std::move(channel))
{
	s_->set_event_handler(this);
}

chatter_channel::~chatter_channel()
{
	remove_handler();
}

void chatter_channel::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::socket_event>(ev, this,
		&chatter_channel::on_socket_event);
}

void chatter_channel::on_socket_event(fz::socket_event_source */*s*/, fz::socket_event_flag type, int error)
{
	if (error) {
		// TODO
		logger_.log(fz::logmsg::error, "ERROR %d todo", error);
		return;
	}

	if (type == fz::socket_event_flag::read) {
		on_read();
	}
	else if (type == fz::socket_event_flag::write) {
		on_send();
	}
}

void chatter_channel::on_read()
{
	uint8_t buf[32768];
	int err{};
	int read = s_->read(buf, 32768, err);
	if (read > 0) {
		resend_current_event();
	}
}

void chatter_channel::on_send()
{
	while (outbuf_.size() < 32768) {
		outbuf_.append("echo Hello world\n"sv);
	}

	int err{};
	int sent = s_->write(outbuf_.get(), outbuf_.size(), err);
	if (sent > 0) {
		outbuf_.consume(sent);
		resend_current_event();
	}
}

}


class runner final : public fz::event_handler
{
public:
	runner(fz::event_loop& l)
		: fz::event_handler(l)
	{
		log_.set_all(fz::logmsg::type(-1));
		s_ = std::make_unique<fz::socket>(pool_, this);
		if (s_->connect(fz::to_native("127.0.0.1"), 2223)) {
			log_.log(fz::logmsg::error, "Cannot connect"sv);
			exit(1);
		}
	}

	~runner()
	{
		remove_handler();
	}

	virtual void operator()(fz::event_base const& ev) override
	{
		fz::dispatch<fz::socket_event, fz::ssh::hostkey_verification_event, fz::ssh::auth_done_event, fz::ssh::session_done_event>(ev, this,
			&runner::on_socket_event, &runner::on_hostkey_event, &runner::on_auth_done, &runner::on_session_done);
	}

	void on_socket_event(fz::socket_event_source *s, fz::socket_event_flag type, int error)
	{
		if (error) {
			log_.log(fz::logmsg::error, "Connect failed with socket error %d", error);
			event_loop_.stop();
			return;
		}
		if (s == s_.get() && type == fz::socket_event_flag::connection && !error) {
			ssh_ = std::make_unique<fz::ssh::client>(fz::ssh::client_parameters{}, "test"sv, *s_, *this, log_);
			// TODO log error
		}
	}

	void on_auth_done(fz::ssh::session* s)
	{
		if (!ssh_ || ssh_.get() != s) {
			return;
		}
		auto si = ssh_->open_channel(fz::ssh::channel_type::shell, {});
		auto channel = std::make_unique<chatter_channel>(std::move(si), event_loop_, log_);
		channels_.emplace_back(std::move(channel));
	}

	void on_session_done(fz::ssh::session*)
	{
		channels_.clear();
		ssh_.reset();
		event_loop_.stop();
	}

	void on_hostkey_event(fz::ssh::session* s, std::unique_ptr<fz::ssh::public_key> const&, fz::ssh::algorithm_info const&)
	{
		log_.log(fz::logmsg::status, "Got host key verification event"sv);
		if (s == ssh_.get()) {
			ssh_->hostkey_decision(true);
		}
	}

	fz::stdout_logger log_;
	fz::thread_pool pool_;
	std::unique_ptr<fz::socket> s_;
	std::unique_ptr<fz::ssh::client> ssh_;

	std::vector<std::unique_ptr<chatter_channel>> channels_;
};

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	std::setlocale(LC_ALL, "");

	fz::event_loop loop(fz::event_loop::threadless);

	runner r(loop);

	loop.run();

	return 0;
}
