#include "libfilezilla/invoker.hpp"

#include <optional>

namespace fz {
thread_invoker::thread_invoker(event_loop& loop)
	: event_handler(loop)
{
}

thread_invoker::~thread_invoker()
{
	remove_handler();
}

void thread_invoker::operator()(fz::event_base const& ev)
{
	if (ev.derived_type() == invoker_event::type()) {
		auto const& cb = std::get<0>(static_cast<invoker_event const&>(ev).v_);
		if (cb) {
			cb();
		}
	}
}

invoker_factory get_invoker_factory(event_loop& loop)
{
	return [handler = std::optional<thread_invoker>(), &loop](std::function<void()> const& cb) mutable {
		if (!handler) {
			handler.emplace(loop);
		}
		handler->send_event<invoker_event>(cb);
	};
}
}
