#ifndef LIBFILEZILLA_HTTP_CLIENT_RESPONSE_HEADER
#define LIBFILEZILLA_HTTP_CLIENT_RESPONSE_HEADER

/** \file
 * \brief HTTP responses, client-side view.
 */

#include "headers.hpp"
#include "../aio/writer.hpp"
#include "../buffer.hpp"

namespace fz::http::client {

class request_response_interface;
typedef std::shared_ptr<request_response_interface> shared_request_response;

/** \brief A single HTTP response received by the client.
 *
 * Has a callback to process the header before the response body is read.
 */
class FZ_PUBLIC_SYMBOL response : public with_headers
{
public:
	unsigned int code_{};
	std::string reason_;

	enum flags {
		flag_got_code = 0x01,
		flag_got_header = 0x02,
		flag_got_body = 0x04,
		flag_no_body = 0x08, // e.g. on HEAD requests, or 204/304 responses
	};
	int flags_{};

	bool got_code() const { return flags_ & flag_got_code; }
	bool got_header() const { return flags_ & flag_got_header; }
	bool got_body() const { return (flags_ & (flag_got_body | flag_no_body)) == flag_got_body; }
	bool no_body() const { return flags_ & flag_no_body; }

	/**
	 * \brief Called once the complete header has been received.
	 *
	 * Can be used to for example set up the writer_
	 *
	 * Return one of:
	 *   next: All is well
	 *   done: When you are not interested in the request body, but continue, e.g. with next request
	 *   error: Abort processing
	 *   wait: not yet ready. Once ready, call next() on the client.
	 */
	std::function<continuation(std::shared_ptr<request_response_interface> const&)> on_header_;

	/// Writer isn't used if !success(), failure responses always go into body_
	std::unique_ptr<fz::writer_base> writer_;

	/// Holds error body and success body if there is no writer.
	fz::buffer body_;

	/// Only if body_ is used. Has no effect if writers are used.
	size_t max_body_size_{16 * 1024 * 1024};

	bool success() const {
		return code_ >= 200 && code_ < 300;
	}

	bool is_redirect() const {
		return code_ >= 300 && code_ < 400 && code_ != 304 && code_ != 305 && code_ != 306;
	}

	/// Some HTTP responses cannot possibly have a body.
	bool code_prohobits_body() const {
		return (code_ >= 100 && code_ < 200) || code_ == 304 || code_ == 204;
	}

	virtual bool reset();
};
}

#endif
