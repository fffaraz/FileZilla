#include "../libfilezilla/http/client_request.hpp"

using namespace std::literals;

namespace fz::http::client {

std::optional<uint64_t> request::update_content_length_from_body()
{
	std::optional<uint64_t> ret;
	if (body_) {
		auto size = body_->size();
		if (size != fz::aio_base::nosize) {
			ret = size;
			set_content_length(size);
		}
		else {
			set_chunked_encoding();
		}
	}
	else {
		ret = 0;
		if (verb_ == "GET"sv || verb_ == "HEAD"sv || verb_ == "OPTIONS"sv) {
			headers_.erase("Transfer-Encoding"s);
			headers_.erase("Content-Length"s);
		}
		else {
			set_content_length(0);
		}
	}
	return ret;
}

bool request::reset()
{
	if (body_) {
		if (!body_->rewind()) {
			return false;
		}
	}

	return true;
}

}
