#include "libfilezilla/rate_limited_layer.hpp"

#if DEBUG_SOCKETEVENTS
#include <assert.h>

namespace fz {
bool FZ_PRIVATE_SYMBOL has_pending_event(event_handler * handler, socket_event_source const* const source, socket_event_flag event);
}
#endif

namespace fz {

rate_limited_layer::rate_limited_layer(event_handler* handler, socket_interface& next_layer, rate_limiter * limiter)
	: socket_layer(handler, next_layer, true)
{
	next_layer.set_event_handler(handler);
	if (limiter) {
		limiter->add(this);
	}
}

rate_limited_layer::~rate_limited_layer()
{
	remove_bucket();
	next_layer_.set_event_handler(nullptr);
}

void rate_limited_layer::wakeup(direction::type d)
{
	// mtx_ is held by the caller, no need to lock here.

	if (!event_handler_) {
		return;
	}

	if (d == direction::inbound) {
		event_handler_->send_event<socket_event>(this, socket_event_flag::read, 0);
	}
	else {
		event_handler_->send_event<socket_event>(this, socket_event_flag::write, 0);
	}
}

int rate_limited_layer::read(void* buffer, unsigned int size, int& error)
{
#if DEBUG_SOCKETEVENTS
	assert(!has_pending_event(event_handler_, this, socket_event_flag::read));
	assert(!has_pending_event(event_handler_, &next_layer_, socket_event_flag::read));
#endif

	auto const max = available(direction::inbound);
	if (!max) {
		error = EAGAIN;
		return -1;
	}

	static_assert(sizeof(size) <= sizeof(max));
	if (max < static_cast<std::decay_t<decltype(max)>>(size)) {
		size = static_cast<unsigned int>(max);
	}

	int read = next_layer_.read(buffer, size, error);
	if (read > 0 && max != rate::unlimited) {
		consume(direction::inbound, read);
	}

	return read;
}

int rate_limited_layer::write(void const* buffer, unsigned int size, int& error)
{
#if DEBUG_SOCKETEVENTS
	assert(!has_pending_event(event_handler_, this, socket_event_flag::write));
	assert(!has_pending_event(event_handler_, &next_layer_, socket_event_flag::write));
#endif

	auto const max = available(direction::outbound);
	if (!max) {
		error = EAGAIN;
		return -1;
	}

	static_assert(sizeof(size) <= sizeof(max));
	if (max < static_cast<std::decay_t<decltype(max)>>(size)) {
		size = static_cast<unsigned int>(max);
	}

	int written = next_layer_.write(buffer, size, error);
	if (written > 0 && max != rate::unlimited) {
		consume(direction::outbound, written);
	}

	return written;
}


void rate_limited_layer::set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block)
{
	scoped_lock l(mtx_);

	if (waiting(l, direction::inbound)) {
		retrigger_block |= socket_event_flag::read;
	}
	if (waiting(l, direction::outbound)) {
		retrigger_block |= socket_event_flag::write;
	}

	socket_layer::set_event_handler(handler, retrigger_block);
}


class compound_rate_limited_layer::crll_bucket : public bucket
{
public:
	friend class compound_rate_limited_layer;

	crll_bucket(compound_rate_limited_layer & parent, rate_limiter& limiter)
		: parent_(parent)
		, limiter_(limiter)
	{}

	virtual void wakeup(direction::type d) override
	{
		if (!waiting_[d].exchange(false)) {
			return;
		}

		fz::scoped_lock l(parent_.mtx_);
		if (!parent_.event_handler_) {
			return;
		}
		if (d == direction::inbound) {
			parent_.event_handler_->send_event<socket_event>(&parent_, socket_event_flag::read, 0);
		}
		else {
			parent_.event_handler_->send_event<socket_event>(&parent_, socket_event_flag::write, 0);
		}
	}

	compound_rate_limited_layer & parent_;
	rate_limiter const& limiter_;

	rate::type max_{};

	std::atomic<bool> waiting_[2]{};
};

compound_rate_limited_layer::compound_rate_limited_layer(event_handler* handler, socket_interface& next_layer)
	: socket_layer(handler, next_layer, true)
{
	next_layer.set_event_handler(handler);
}

compound_rate_limited_layer::~compound_rate_limited_layer()
{
	for (auto & b : buckets_) {
		b->remove_bucket();
	}
	next_layer_.set_event_handler(nullptr);
}

void compound_rate_limited_layer::add_limiter(rate_limiter* limiter)
{
	if (!limiter) {
		return;
	}

	for (auto const& b : buckets_) {
		if (&b->limiter_ == limiter) {
			return;
		}
	}

	buckets_.emplace_back(std::make_unique<crll_bucket>(*this, *limiter));
	limiter->add(buckets_.back().get());
}

void compound_rate_limited_layer::remove_limiter(rate_limiter* limiter)
{
	for (auto & b : buckets_) {
		if (&b->limiter_ == limiter) {
			b->remove_bucket();
			b->wakeup(direction::inbound);
			b->wakeup(direction::outbound);

			b = std::move(buckets_.back());
			buckets_.pop_back();
			return;
		}
	}
}

int compound_rate_limited_layer::read(void* buffer, unsigned int size, int& error)
{
	rate::type max = rate::unlimited;
	for (auto & b : buckets_) {
		b->waiting_[direction::inbound] = true;
		b->max_ = b->available(direction::inbound);
		if (!b->max_) {
			error = EAGAIN;
			return -1;
		}
		b->waiting_[direction::inbound] = false;

		if (b->max_ < max) {
			max = b->max_;
		}
	}

	static_assert(sizeof(size) <= sizeof(max));
	if (max < static_cast<std::decay_t<decltype(max)>>(size)) {
		size = static_cast<unsigned int>(max);
	}

	int read = next_layer_.read(buffer, size, error);
	if (read > 0) {
		for (auto & b : buckets_) {
			if (b->max_ != rate::unlimited) {
				b->consume(direction::inbound, read);
			}
		}
	}

	return read;
}


int compound_rate_limited_layer::write(void const* buffer, unsigned int size, int& error)
{
	rate::type max = rate::unlimited;
	for (auto & b : buckets_) {
		b->waiting_[direction::outbound] = true;
		b->max_ = b->available(direction::outbound);
		if (!b->max_) {
			error = EAGAIN;
			return -1;
		}
		b->waiting_[direction::outbound] = false;

		if (b->max_ < max) {
			max = b->max_;
		}
	}

	static_assert(sizeof(size) <= sizeof(max));
	if (max < static_cast<std::decay_t<decltype(max)>>(size)) {
		size = static_cast<unsigned int>(max);
	}

	int written = next_layer_.write(buffer, size, error);
	if (written > 0) {
		for (auto & b : buckets_) {
			if (b->max_ != rate::unlimited) {
				b->consume(direction::outbound, written);
			}
		}
	}

	return written;
}

void compound_rate_limited_layer::set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block)
{
	for (auto & b : buckets_) {
		fz::scoped_lock l(b->mtx_);
		if (b->waiting_[direction::inbound]) {
			retrigger_block |= socket_event_flag::read;
		}
		if (b->waiting_[direction::outbound]) {
			retrigger_block |= socket_event_flag::write;
		}
	}

	scoped_lock l(mtx_);
	socket_layer::set_event_handler(handler, retrigger_block);
}

}
