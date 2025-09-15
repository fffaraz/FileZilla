#ifndef LIBFILEZILLA_HTTP_CLIENT_REQUEST_HEADER
#define LIBFILEZILLA_HTTP_CLIENT_REQUEST_HEADER

/** \file
 * \brief HTTP requests, client-side view.
 */

#include "headers.hpp"
#include "../aio/reader.hpp"
#include "../uri.hpp"

namespace fz::http::client {

class request_response_interface;

/** \brief A single HTTP request to be sent by the client.
 */
class FZ_PUBLIC_SYMBOL request : public with_headers
{
public:
	fz::uri uri_;
	std::string verb_;

	enum flags : uint64_t {
		/// Avoids logging the path of the URI when processing request
		flag_confidential_path = 0x01,

		/// Avoids logging the path of the URI when processing request
		flag_confidential_querystring = 0x2,

		flag_force_ipv4 = 0x4,
		flag_force_ipv6 = 0x8
	};
	uint64_t flags_{};

	std::unique_ptr<fz::reader_base> body_;

	std::function<void(std::shared_ptr<request_response_interface> const&, size_t c)> on_body_sending_progress_;

	std::optional<uint64_t> update_content_length_from_body();

	[[nodiscard]] virtual bool reset();
};
}

#endif
