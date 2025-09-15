#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/socket.hpp>
#include <libfilezilla/thread_pool.hpp>
#include <libfilezilla/tls_layer.hpp>
#include <libfilezilla/tls_system_trust_store.hpp>
#include <libfilezilla/util.hpp>

#include <iostream>
#include <type_traits>

namespace {
struct logger : public fz::logger_interface
{
	logger()
	{
		// For debugging
		// set_all(static_cast<fz::logmsg::type>(~std::underlying_type_t<fz::logmsg::type>(0)));
	}

	virtual void do_log(fz::logmsg::type t, std::wstring && msg) {
		std::cerr << "Log: " << int(t) << " " << fz::to_string(msg) << "\n";
	}
};
}

// A simple event handler
class handler final : public fz::event_handler
{
public:
	handler(fz::event_loop& l, std::string const& host)
	    : fz::event_handler(l)
	    , trust_store_(pool_)
	{
		s_ = std::make_unique<fz::socket>(pool_, this);
		int res = s_->connect(fz::to_native(host), 443);
		if (res) {
			log_.log(fz::logmsg::error, "Connect failed with %s", fz::socket_error_description(res));
			event_loop_.stop();
			return;
		}

		tls_ = std::make_unique<fz::tls_layer>(event_loop_, this, *s_, &trust_store_, log_);
		if (!tls_->client_handshake(nullptr, {}, fz::to_native(host))) {
			log_.log(fz::logmsg::error, "Could not start handshake");
			event_loop_.stop();
			return;
		}

		snd_.append("GET / HTTP/1.1\r\nConnection: close\r\nUser-Agent: lfz (socket demo)\r\nHost: ");
		snd_.append(host);
		snd_.append("\r\n\r\n");
	}

	virtual ~handler()
	{
		// This _MUST_ be called to avoid a race so that operator()(fz::event_base const&) is not called on a partially destructed object.
		remove_handler();
	}

	bool success_{};

private:
	// The event loop calls this function for every event sent to this handler.
	virtual void operator()(fz::event_base const& ev)
	{
		// Dispatch the event to the correct function.
		fz::dispatch<fz::socket_event>(ev, this, &handler::on_socket_event);
	}

	void on_socket_event(fz::socket_event_source*, fz::socket_event_flag type, int error) {
		if (error) {
			auto desc = fz::socket_error_description(error);
			switch (type) {
			case fz::socket_event_flag::connection:
				log_.log(fz::logmsg::error, "Connection failed: %s", desc);
				break;
			case fz::socket_event_flag::read:
				log_.log(fz::logmsg::error, "Reading failed: %s", desc);
				break;
			case fz::socket_event_flag::write:
				log_.log(fz::logmsg::error, "Connection failed %s", desc);
				break;
			default:
				log_.log(fz::logmsg::error, "Unknown error: %s", desc);
				break;
			}
			event_loop_.stop();
			return;
		}

		if (type == fz::socket_event_flag::write || type == fz::socket_event_flag::connection) {
			while (!snd_.empty()) {
				int w = tls_->write(snd_.get(), snd_.size(), error);
				if (w > 0) {
					snd_.consume(w);
				}
				else {
					if (w < 0) {
						if (error == EAGAIN) {
							return;
						}
						log_.log(fz::logmsg::error, "Error writing: %", fz::socket_error_description(error));
					}
					event_loop_.stop();
					return;
				}
			}
			log_.log(fz::logmsg::status, "Sent request");
		}
		else if (type == fz::socket_event_flag::read) {
			char buf[1024];
			while (true) {
				int r = tls_->read(buf, 1024, error);
				if (r > 0) {
					std::cout << std::string_view(buf, r);
					continue;
				}

				if (!r) {
					log_.log(fz::logmsg::status, "Got eof");
					success_ = true;
				}
				else {
					if (error == EAGAIN) {
						return;
					}
					log_.log(fz::logmsg::error, "Error reading: %s", fz::socket_error_description(error));
				}
				event_loop_.stop();
				return;
			}
		}
	}

	logger log_;
	fz::thread_pool pool_;
	fz::tls_system_trust_store trust_store_;
	std::unique_ptr<fz::socket> s_;
	std::unique_ptr<fz::tls_layer> tls_;
	fz::buffer snd_;
};

int main(int argc , char * argv[])
{
	if (argc <= 1) {
		std::cerr << "Need to pass hostname\n";
		return 1;
	}

	std::string host = argv[1];

	// Start an event loop
	fz::event_loop l(fz::event_loop::threadless);

	// Create a handler
	handler h(l, host);

	l.run();

	// All done.
	return h.success_ ? 0 : 1;
}
