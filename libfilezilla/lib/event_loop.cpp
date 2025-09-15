#include "libfilezilla/event_loop.hpp"
#include "libfilezilla/event_handler.hpp"
#include "libfilezilla/thread_pool.hpp"
#include "libfilezilla/util.hpp"

#include <algorithm>

#ifdef LFZ_EVENT_DEBUG
#include <assert.h>
#define event_assert(pred) assert((pred))
#else
#define event_assert(pred)
#endif

namespace fz {

event_loop::event_loop()
	: sync_(false)
	, thread_(std::make_unique<thread>())
	, mode_(Mode::thread)
{
	thread_->run([this] { entry(); });
}

event_loop::event_loop(thread_pool & pool)
	: sync_(false)
	, pool_(&pool)
	, mode_(Mode::tasks)
{
	task_ = std::make_unique<async_task>(pool.spawn([this] { entry(); }));
}

event_loop::event_loop(event_loop::loop_option)
	: sync_(false)
	, mode_(Mode::threadless)
{
}

event_loop::~event_loop()
{
	stop(true);
}

bool event_loop::running() const
{
	scoped_lock lock(sync_);
	return task_ || thread_ || threadless_;
}

void event_loop::send_event(event_handler* handler, event_base* evt, bool deletable)
{
	event_assert(handler);
	event_assert(evt);

	{
		scoped_lock lock(sync_);
		if (!handler->removing_) {
			if (pending_events_.empty() && !active_handler_) {
				cond_.signal(lock);
			}
			pending_events_.emplace_back(handler, evt, deletable);
			return;
		}
	}

	if (deletable) {
		delete evt;
	}
}

void event_loop::remove_handler(event_handler* handler)
{
	scoped_lock l(sync_);

	handler->removing_ = true;

	pending_events_.erase(
		std::remove_if(pending_events_.begin(), pending_events_.end(),
			[&](Events::value_type const& v) {
				if (std::get<0>(v) == handler && std::get<2>(v)) {
					delete std::get<1>(v);
				}
				return std::get<0>(v) == handler;
			}
		),
		pending_events_.end()
	);

	timers_.erase(
		std::remove_if(timers_.begin(), timers_.end(),
			[&](timer_data const& v) {
				return v.handler_ == handler;
			}
		),
		timers_.end()
	);
	if (timers_.empty()) {
		deadline_ = monotonic_clock();
	}

	if (active_handler_ == handler) {
		if (thread::own_id() != thread_id_) {
			while (active_handler_ == handler) {
				l.unlock();
				yield();
				l.lock();
			}
		}
		else {
			resend_ = false;
		}
	}
}

void event_loop::filter_events(std::function<bool(event_handler*& h, event_base& ev)> const& filter)
{
	scoped_lock l(sync_);

	pending_events_.erase(
		std::remove_if(pending_events_.begin(), pending_events_.end(),
			[&](Events::value_type & v) {
				auto *& h = std::get<0>(v);
				bool const remove = filter(h, *std::get<1>(v));
				event_assert(h);
				if (remove && std::get<2>(v)) {
					delete std::get<1>(v);
				}
				return remove;
			}
		),
		pending_events_.end()
	);
}

timer_id event_loop::add_timer(event_handler* handler, monotonic_clock const &deadline, duration const& interval)
{
	timer_id id = 0;

	if (deadline) {
		timer_data d;

		scoped_lock lock(sync_);

		id = setup_timer(lock, d, handler, deadline, interval);

		if (id) {
			timers_.push_back(std::move(d));
		}
	}

	return id;
}

void event_loop::stop_timer(timer_id id)
{
	if (id) {
		scoped_lock lock(sync_);
		for (auto it = timers_.begin(); it != timers_.end(); ++it) {
			if (it->id_ == id) {
				if (&*it != &timers_.back()) {
					*it = std::move(timers_.back());
				}
				timers_.pop_back();

				if (timers_.empty()) {
					deadline_ = monotonic_clock();
				}
				break;
			}
		}
	}
}

timer_id event_loop::stop_add_timer(timer_id id, event_handler* handler, monotonic_clock const &deadline, duration const& interval)
{
	scoped_lock lock(sync_);

	if (id) {
		for (auto it = timers_.begin(); it != timers_.end(); ++it) {
			if (it->id_ == id) {
				return setup_timer(lock, *it, handler, deadline, interval);
			}
		}
	}

	timer_data d;

	id = setup_timer(lock, d, handler, deadline, interval);

	if (id) {
		timers_.push_back(std::move(d));
	}

	return id;
}

timer_id event_loop::setup_timer(scoped_lock &l, timer_data &d, event_handler* handler, monotonic_clock const& deadline, duration const& interval)
{
	if (handler->removing_) {
		return 0;
	}

	d.interval_ = interval;
	d.deadline_ = deadline;
	d.handler_ = handler;
	d.id_ = ++next_timer_id_; // 64bit, can this really ever overflow?

	if (!deadline_ || d.deadline_ < deadline_) {
		// Our new time is the next timer to trigger
		deadline_ = d.deadline_;

		switch (mode_) {
		case Mode::thread:
			if (!timer_thread_) {
				timer_thread_ = std::make_unique<thread>();
				timer_thread_->run([this] { timer_entry(); });
			}
			timer_cond_.signal(l);
			break;
		case Mode::tasks:
			if (!timer_task_) {
				timer_task_ = std::make_unique<async_task>(pool_->spawn([this] { timer_entry(); }));
			}
			timer_cond_.signal(l);
			break;
		default:
			do_timers_ = true;
			cond_.signal(l);
			break;
		}
	}

	return d.id_;
}

bool event_loop::process_event(scoped_lock & l)
{
	Events::value_type ev{};

	if (pending_events_.empty()) {
		return false;
	}
	ev = pending_events_.front();
	pending_events_.pop_front();

	event_assert(std::get<0>(ev));
	event_assert(std::get<1>(ev));
	event_assert(!std::get<0>(ev)->removing_);

	active_handler_ = std::get<0>(ev);

	l.unlock();

	event_assert(!resend_);

	(*std::get<0>(ev))(*std::get<1>(ev));
	if (resend_) {
		resend_ = false;
		l.lock();
		if (!std::get<0>(ev)->removing_) {
			pending_events_.emplace_back(ev);
		}
		else { // Unlikely, but possible to get into this branch branch
			if (std::get<2>(ev)) {
				delete std::get<1>(ev);
			}
		}
	}
	else {
		if (std::get<2>(ev)) {
			delete std::get<1>(ev);
		}
		l.lock();
	}

	active_handler_ = nullptr;

	return true;
}

void event_loop::run()
{
	{
		scoped_lock l(sync_);
		if (threadless_ || task_ || thread_ || thread_id_ != thread::id()) {
			return;
		}
		threadless_ = true;
	}

	entry();

	{
		scoped_lock l(sync_);
		threadless_ = false;
	}
}

void event_loop::entry()
{
	thread_id_ = thread::own_id();

	scoped_lock l(sync_);
	while (!quit_) {
		if (do_timers_ && process_timers(l)) {
			// Ensure that timers cannnot starve normal event processing
			if (!quit_) {
				process_event(l);
			}
			continue;
		}
		if (process_event(l)) {
			continue;
		}

		// Nothing to do, now we wait
		if (threadless_ && deadline_) {
			cond_.wait(l, deadline_ - fz::monotonic_clock::now());
		}
		else {
			cond_.wait(l);
		}
	}
}

void event_loop::timer_entry()
{
	monotonic_clock now;

	scoped_lock l(sync_);
	while (!quit_) {
		if (deadline_ && !do_timers_) {
			now = fz::monotonic_clock::now();
			if (deadline_ <= now) {
				do_timers_ = true;
				if (pending_events_.empty() && !active_handler_) {
					cond_.signal(l);
				}
			}
			else {
				timer_cond_.wait(l, deadline_ - now);
			}
		}
		else {
			timer_cond_.wait(l);
		}
	}
}

bool event_loop::process_timers(scoped_lock & l)
{
	if (!deadline_) {
		if (!threadless_) {
			do_timers_ = false;
		}
		// There's no deadline
		return false;
	}

	auto now = monotonic_clock::now();
	if (now < deadline_) {
		// Deadline has not yet expired
		if (!threadless_) {
			do_timers_ = false;
			timer_cond_.signal(l);
		}
		return false;
	}

	// Update deadline_, stop at first expired timer
	deadline_ = monotonic_clock();
	auto it = timers_.begin();
	for (; it != timers_.end(); ++it) {
		if (!deadline_ || it->deadline_ < deadline_) {
			if (it->deadline_ <= now) {
				break;
			}
			deadline_ = it->deadline_;
		}
	}

	if (it != timers_.end()) {
		// 'it' is now expired
		// deadline_ has been updated with prior timers
		// go through remaining elements to update deadline_
		for (auto it2 = std::next(it); it2 != timers_.end(); ++it2) {
			if (!deadline_ || it2->deadline_ < deadline_) {
				deadline_ = it2->deadline_;
			}
		}

		event_handler *const handler = it->handler_;
		auto const id = it->id_;

		// Update the expired timer
		if (!it->interval_) {
			// Remove one-shot timer
			if (&*it != &timers_.back()) {
				*it = std::move(timers_.back());
			}
			timers_.pop_back();
		}
		else {
			it->deadline_ = std::max(now, it->deadline_ + it->interval_);
			if (!deadline_ || it->deadline_ < deadline_) {
				deadline_ = it->deadline_;
			}
		}

		// Call event handler
		event_assert(!handler->removing_);

		active_handler_ = handler;

		l.unlock();
		(*handler)(timer_event(id));
		l.lock();

		active_handler_ = nullptr;

		return true;
	}

	if (deadline_ && !threadless_) {
		do_timers_ = false;
		timer_cond_.signal(l);
	}

	return false;
}

void event_loop::stop(bool join)
{
	{
		scoped_lock l(sync_);
		quit_ = true;
		cond_.signal(l);
		timer_cond_.signal(l);
	}

	if (join) {
		thread_.reset();
		task_.reset();
		timer_thread_.reset();
		timer_task_.reset();

		scoped_lock lock(sync_);
		for (auto & v : pending_events_) {
			if (std::get<2>(v)) {
				delete std::get<1>(v);
			}
		}
		pending_events_.clear();

		timers_.clear();
		deadline_ = monotonic_clock();
	}
}

}
