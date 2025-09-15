#include "throttler.hpp"

namespace fz::http::client {

void request_throttler::throttle(std::string const& hostname, datetime const& backoff)
{
	if (hostname.empty() || !backoff) {
		return;
	}

	scoped_lock l(mtx_);

	bool found{};
	auto now = datetime::now();
	for (size_t i = 0; i < backoff_.size(); ) {
		auto & entry = backoff_[i];
		if (entry.first == hostname) {
			found = true;
			if (entry.second < backoff) {
				entry.second = backoff;
			}
		}
		if (entry.second < now) {
			backoff_[i] = std::move(backoff_.back());
			backoff_.pop_back();
		}
		else {
			++i;
		}
	}
	if (!found) {
		backoff_.emplace_back(hostname, backoff);
	}
}

duration request_throttler::get_throttle(std::string const& hostname)
{
	scoped_lock l(mtx_);

	duration ret;

	auto now = datetime::now();
	for (size_t i = 0; i < backoff_.size(); ) {
		auto & entry = backoff_[i];
		if (entry.second < now) {
			backoff_[i] = std::move(backoff_.back());
			backoff_.pop_back();
		}
		else {
			if (entry.first == hostname) {
				ret = entry.second - now;
			}
			++i;
		}
	}

	return ret;
}

}
