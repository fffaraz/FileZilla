#include <libfilezilla/aio/aio.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/http/client.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/socket.hpp>
#include <libfilezilla/tls_layer.hpp>
#include <libfilezilla/tls_system_trust_store.hpp>

using namespace std::literals;

typedef fz::http::client::request_response_holder<fz::http::client::request, fz::http::client::response> request_response;

class client : public fz::event_handler, public fz::http::client::client
{
public:
	client(std::vector<fz::uri> const& uris, fz::thread_pool & tpool, fz::event_loop & loop, fz::aio_buffer_pool & buffer_pool, fz::logger_interface & logger)
		: fz::event_handler(loop)
		, fz::http::client::client(*this, buffer_pool, logger, "libfilezilla_https_demo")
		, pool_(tpool)
		, logger_(logger)
		, trust_store_(pool_)
	{
		for (auto const& uri : uris) {
			auto srr = std::make_shared<request_response>();
			srr->request_.uri_ = uri;
			srr->request_.headers_["Connection"] = "keep-alive";
			if (add_request(srr)) {
				requests_.push_back(srr);
			}
		}
		if (requests_.empty()) {
			event_loop_.stop();
		}
	}

	~client()
	{
		remove_handler();
		destroy();
	}

	virtual fz::socket_interface* create_socket(fz::native_string const& host, unsigned short, bool tls) override
	{
		destroy_socket();
		socket_ = std::make_unique<fz::socket>(pool_, nullptr);
		if (tls) {
			tls_ = std::make_unique<fz::tls_layer>(event_loop_, nullptr, *socket_, &trust_store_, logger_);
			tls_->client_handshake({}, {}, host);
			return tls_.get();
		}
		else {
			return socket_.get();
		}
	}

	virtual void destroy_socket() override
	{
		tls_.reset();
		socket_.reset();
	}

	virtual void operator()(fz::event_base const& ev) override
	{
		fz::dispatch<fz::http::client::done_event>(ev, this, &client::on_request_done);
	}

	void on_request_done(uint64_t, bool success)
	{
		auto & srr = requests_.front();
		if (success) {
			logger_.log(fz::logmsg::error, "Got response for %s with code %d", srr->req().uri_.to_string(), srr->res().code_);
		}
		else {
			logger_.log(fz::logmsg::error, "Could not read response for %s", srr->req().uri_.to_string());
		}
		requests_.pop_front();

		if (requests_.empty()) {
			event_loop_.stop();
		}
	}

	fz::thread_pool & pool_;
	fz::logger_interface & logger_;
	fz::tls_system_trust_store trust_store_;

	std::unique_ptr<fz::socket> socket_;
	std::unique_ptr<fz::tls_layer> tls_;

	std::deque<fz::http::client::shared_request_response> requests_;
};

int main(int argc , char * argv[])
{
	fz::stdout_logger logger;
	if (argc < 2) {
		logger.log(fz::logmsg::error, "Pass at least one URI"sv);
		return 1;
	}
	std::vector<fz::uri> uris;
	for (int i = 1; i < argc; ++i) {
		auto uri = fz::uri(argv[i]);
		if (!uri) {
			logger.log(fz::logmsg::error, "Invalid URI: '%s'", argv[i]);
			return 1;
		}
		uris.emplace_back(std::move(uri));
	}
	// Start an event loop
	fz::event_loop loop(fz::event_loop::threadless);

	//logger.set_all(fz::logmsg::type(-1));

	// Create a handler
	fz::thread_pool tpool;
	fz::aio_buffer_pool buffer_pool(tpool, logger, 8);
	client c(uris, tpool, loop, buffer_pool, logger);

	loop.run();

	// All done.
	return 0;
}
