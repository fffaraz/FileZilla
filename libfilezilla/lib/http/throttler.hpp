#ifndef LIBFILEZILLA_HTTP_THROTTLER_HEADER
#define LIBFILEZILLA_HTTP_THROTTLER_HEADER

#include "../libfilezilla/mutex.hpp"
#include "../libfilezilla/time.hpp"

namespace fz::http::client {

class request_throttler final
{
public:
	void throttle(std::string const& hostname, datetime const& backoff);
	duration get_throttle(std::string const& hostname);

private:
	mutex mtx_{false};
	std::vector<std::pair<std::string, datetime>> backoff_;
};

}

#endif
