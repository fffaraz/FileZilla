#include "libfilezilla/event_handler.hpp"

#include <cassert>

namespace fz {

event_handler::event_handler(event_loop& loop)
	: event_loop_(loop)
{
}

event_handler::event_handler(event_handler const& h)
	: event_loop_(h.event_loop_)
{
}

event_handler::event_handler(event_handler & h, event_handler_option)
	: event_loop_(h.event_loop_)
{
	scoped_lock l(event_loop_.sync_);
	if (h.removing_) {
		removing_ = true;
	}
	else {
		next_ = h.child_;
		h.child_ = this;
		parent_ = &h;
	}
}

event_handler::~event_handler()
{
	assert(removing_); // To avoid races, the base class must have removed us already

	// No need to lock here, the subtree is inert

	// Split the children
	while (child_) {
		child_->parent_ = nullptr;
		auto n = child_->next_;
		child_->next_ = nullptr;
		child_ = n;
	}
}

void event_handler::remove_from_parent()
{
	if (parent_) {
		// By construction, we only have siblings if there is a parent.

		if (parent_->child_ == this) {
			// We're first in the list
			parent_->child_ = next_;
		}
		else {
			auto* cur = parent_->child_;
			while (cur->next_ != this) {
				cur = cur->next_;
			}
			cur->next_ = next_;
		}
		parent_ = nullptr;
	}
}

void event_handler::remove_handler()
{
	event_loop_.remove_handler(this);
}

timer_id event_handler::add_timer(duration const& interval, bool one_shot)
{
	return event_loop_.add_timer(this, monotonic_clock::now() + interval, one_shot ? duration() : interval);
}

timer_id event_handler::add_timer(monotonic_clock const& deadline, duration const& interval)
{
	return event_loop_.add_timer(this, deadline, interval);
}

void event_handler::stop_timer(timer_id id)
{
	event_loop_.stop_timer(id);
}

timer_id event_handler::stop_add_timer(timer_id id, duration const& interval, bool one_shot)
{
	return event_loop_.stop_add_timer(id, this, monotonic_clock::now() + interval, one_shot ? duration() : interval);
}

timer_id event_handler::stop_add_timer(timer_id id, monotonic_clock const& deadline, duration const& interval)
{
	return event_loop_.stop_add_timer(id, this, deadline, interval);
}

void event_handler::remove_events(event_source const* const source)
{
	auto event_filter = [&](event_base& ev) -> bool {
			auto sev = dynamic_cast<event_with_source_base*>(&ev);
			if (sev) {
				return sev->source() == source;
			}
			return false;
		};
	filter_events(event_filter);
}

}
