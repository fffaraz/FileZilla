#ifndef LIBFILEZILLA_HTTP_CLIENT_HEADER
#define LIBFILEZILLA_HTTP_CLIENT_HEADER

/** \file
 * \brief A HTTP \ref fz::client "client"
 */

#include "../string.hpp"
#include "client_request.hpp"
#include "client_response.hpp"

#include <memory>

namespace fz {

class event_handler;
class logger_interface;
class socket_interface;

namespace http::client {

/// Used for type erasure, so the internals don't need to know the full request/response
class FZ_PUBLIC_SYMBOL request_response_interface
{
public:
	virtual ~request_response_interface() = default;

	virtual request & req() = 0;
	virtual response & res() = 0;

	uint64_t request_id_{}; // Gets updated by add client::add_request()
};

template<class Request, class Response>
class request_response_holder : public request_response_interface
{
public:
	virtual request & req() override { return request_; }
	virtual response & res() override { return response_; }

	void set_on_header(std::function<continuation(std::shared_ptr<request_response_holder<Request, Response>> const&)> cb)
	{
		if (cb) {
			response_.on_header_ = [cb = std::move(cb)](shared_request_response const& srr) {
				auto p = std::static_pointer_cast<request_response_holder<Request, Response>>(srr);
				return cb(p);
			};
		}
		else {
			response_.on_header_ = nullptr;
		}
	}

	void set_body_sending_progress(std::function<void(std::shared_ptr<request_response_holder<Request, Response>> const&, size_t)> cb)
	{
		if (cb) {
			request_.on_body_sending_progress_ = [cb = std::move(cb)](shared_request_response const& srr, size_t c) {
				auto p = std::static_pointer_cast<request_response_holder<Request, Response>>(srr);
				cb(p, c);
			};
		}
		else {
			request_.on_body_sending_progress_ = nullptr;
		}
	}

	Request request_;
	Response response_;
};
typedef std::shared_ptr<request_response_interface> shared_request_response;

/// \private
struct done_event_type;

/// Unless stop was called, exactly one done_event is sent for every request
/// that was added successfully.
typedef simple_event<done_event_type, uint64_t, bool> done_event;

/**
 * \brief HTTP client capable of pipelining
 *
 * To use this class, two function need to be overriden.
 */
class FZ_PUBLIC_SYMBOL client
{
public:
	/// A buffer pool is optional. If no pool is given, writers cannot be used in responses.
	client(event_handler & handler, aio_buffer_pool & buffer_pool, logger_interface & logger, std::string user_agent);
	client(event_handler & handler, logger_interface & logger, std::string user_agent);
	virtual ~client();

	bool add_request(shared_request_response const& srr);

	/// Call this after having returned wait from on_header
	void next();

	/**
	 * \brief Stops the client, deletes all requests.
	 */
	void stop(bool keep_alive);

	/// Must be called in the destructor of the derived class
	void destroy();

protected:
	virtual void on_alive() {}

	/// Called when the client requests a new socket.
	virtual socket_interface* create_socket(native_string const& host, unsigned short port, bool tls) = 0;

	/// Called when the client no longer needs the socket.
	virtual void destroy_socket() = 0;

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
}

#endif
