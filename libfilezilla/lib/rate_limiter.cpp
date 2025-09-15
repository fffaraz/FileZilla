#include "libfilezilla/rate_limiter.hpp"
#include "libfilezilla/util.hpp"

#include <array>

#include <assert.h>

/*
  Rate limiting machinery based on token buckets with hierarchical limits.
  - Hierarchical: Limits can be nested
  - Fairness: All buckets get a fair share of tokens
  - No waste, excess tokens distributed fairly to buckets with spare capacity
  - Complexity:
	- Token distribution in O(n)
	- Adding/removing buckets/limiters in O(1)
  - No uneeded wakeups during periods of idleness
  - Thread-safe
*/
namespace fz {

namespace {
auto const delay = duration::from_milliseconds(200);
int const frequency = 5;
std::array<direction::type, 2> directions { direction::inbound, direction::outbound };
}

rate_limit_manager::rate_limit_manager(event_loop & loop)
	: event_handler(loop)
{
}

rate_limit_manager::~rate_limit_manager()
{
	assert(limiters_.empty());
	remove_handler();
}

void rate_limit_manager::operator()(event_base const& ev)
{
	dispatch<timer_event>(ev, this, &rate_limit_manager::on_timer);
}

void rate_limit_manager::on_timer(timer_id const& id)
{
	scoped_lock l(mtx_);
	if (++activity_ == 2) {
		timer_id expected = id;
		if (timer_.compare_exchange_strong(expected, 0)) {
			stop_timer(id);
		}

	}
	for (auto * limiter : limiters_) {
		process(limiter, false);
	}
}

void rate_limit_manager::record_activity()
{
	if (activity_.exchange(0) == 2) {
		timer_id old = timer_.exchange(add_timer(duration::from_milliseconds(1000 / frequency), false));
		stop_timer(old);
	}
}

void rate_limit_manager::add(rate_limiter* limiter)
{
	if (!limiter) {
		return;
	}

	limiter->remove_bucket();

	scoped_lock l(mtx_);

	limiter->lock_tree();

	limiter->set_mgr_recursive(this);
	limiter->parent_ = this;
	limiter->idx_ = limiters_.size();
	limiters_.push_back(limiter);

	process(limiter, true);

	limiter->unlock_tree();
}

void rate_limit_manager::process(rate_limiter* limiter, bool locked)
{
	if (!limiter) {
		return;
	}

	// Step 0: Lock all mutexes
	if (!locked) {
		limiter->lock_tree();
	}

	// Step 1: Update stats such as weight and unsaturated buckets
	bool active{};
	limiter->update_stats(active);
	if (active) {
		record_activity();
	}
	for (auto const& d : directions) {
		// Step 2: Add the normal tokens
		limiter->add_tokens(d, rate::unlimited, rate::unlimited);

		// Step 3: Distribute overflow to unsaturated buckets
		limiter->distribute_overflow(d, 0);
	}

	// Step 4: Unlock the tree and potentially wake up consumers
	if (!locked) {
		limiter->unlock_tree();
	}
}

void rate_limit_manager::set_burst_tolerance(rate::type tolerance)
{
	if (tolerance < 1) {
		tolerance = 1;
	}
	else if (tolerance > 10) {
		tolerance = 10;
	}
	burst_tolerance_ = tolerance;
}

void bucket_base::remove_bucket()
{
	scoped_lock l(mtx_);
	while (idx_ != size_t(-1) && parent_) {
		if (parent_ == mgr_) {
			if (mgr_->mtx_.try_lock()) {
				auto * other = mgr_->limiters_.back();
				if (other != this) {
					scoped_lock ol(other->mtx_);
					other->idx_ = idx_;
					mgr_->limiters_[idx_] = other;
				}
				mgr_->limiters_.pop_back();
				mgr_->mtx_.unlock();
				break;
			}
		}
		else {
			auto * parent = reinterpret_cast<rate_limiter*>(parent_);
			if (parent->mtx_.try_lock()) {
				auto * other = parent->buckets_.back();
				if (other != this) {
					scoped_lock ol(other->mtx_);
					other->idx_ = idx_;
					parent->buckets_[idx_] = other;
				}
				parent->buckets_.pop_back();
				std::array<rate::type, 2> unspent = gather_unspent_for_removal();
				for (size_t i = 0; i < 2; ++i) {
					parent->data_[i].debt_ -= std::min(parent->data_[i].debt_, unspent[i]);
				}
				parent->mtx_.unlock();
				break;
			}
		}

		// Break deadlock
		l.unlock();
		yield();
		l.lock();
	}
	parent_ = nullptr;
	idx_ = size_t(-1);
}

void bucket_base::set_mgr_recursive(rate_limit_manager * mgr)
{
	mgr_ = mgr;
}

rate_limiter::rate_limiter(rate_limit_manager *mgr)
{
	if (mgr) {
		mgr->add(this);
	}
}

rate_limiter::~rate_limiter()
{
	{
		scoped_lock l(mtx_);
		for (auto * bucket : buckets_) {
			bucket->parent_ = nullptr;
			bucket->idx_ = size_t(-1);
		}
		buckets_.clear();
	}

	remove_bucket();
}

void rate_limiter::set_mgr_recursive(rate_limit_manager * mgr)
{
	if (mgr != mgr_) {
		mgr_ = mgr;
		for (auto * bucket : buckets_) {
			bucket->set_mgr_recursive(mgr);
		}
	}
}

void rate_limiter::set_limits(rate::type download_limit, rate::type upload_limit)
{
	scoped_lock l(mtx_);
	bool changed = do_set_limit(direction::inbound, download_limit);
	changed |= do_set_limit(direction::outbound, upload_limit);
	if (changed && mgr_) {
		mgr_->record_activity();
	}
}

bool rate_limiter::do_set_limit(direction::type const d, rate::type limit)
{
	auto & data = data_[d];
	if (data.limit_ == limit) {
		return false;
	}

	data.limit_ = limit;

	size_t weight = weight_ ? weight_ : 1;
	if (data.limit_ != rate::unlimited) {
		data.merged_tokens_ = std::min(data.merged_tokens_, data.limit_ / weight);
	}
	return true;
}

rate::type rate_limiter::limit(direction::type const d)
{
	scoped_lock l(mtx_);
	return data_[d ? 1 : 0].limit_;
}

void rate_limiter::add(bucket_base* bucket)
{
	if (!bucket) {
		return;
	}

	bucket->remove_bucket();

	scoped_lock l(mtx_);

	bucket->lock_tree();

	bucket->set_mgr_recursive(mgr_);
	bucket->parent_ = this;
	bucket->idx_ = buckets_.size();
	buckets_.push_back(bucket);

	bool active{};
	bucket->update_stats(active);
	if (active && mgr_) {
		mgr_->record_activity();
	}

	size_t bucket_weight = bucket->weight();
	if (!bucket_weight) {
		bucket_weight = 1;
	}
	weight_ += bucket_weight;

	for (auto const& d : directions) {
		auto & data = data_[d];
		rate::type tokens;
		if (data.merged_tokens_ == rate::unlimited) {
			tokens = rate::unlimited;
		}
		else {
			tokens = data.merged_tokens_ / (bucket_weight * 2);
		}
		bucket->add_tokens(d, tokens, tokens);
		bucket->distribute_overflow(d, 0);

		if (tokens != rate::unlimited) {
			data.debt_ += tokens * bucket_weight;
		}
	}

	bucket->unlock_tree();
}

void rate_limiter::lock_tree()
{
	mtx_.lock();
	for (auto * bucket : buckets_) {
		bucket->lock_tree();
	}
}

void rate_limiter::unlock_tree()
{
	for (auto * bucket : buckets_) {
		bucket->unlock_tree();
	}
	mtx_.unlock();
}

void rate_limiter::pay_debt(direction::type const d)
{
	auto & data = data_[d];
	if (data.merged_tokens_ != rate::unlimited) {
		size_t weight = weight_ ? weight_ : 1;
		rate::type debt_reduction = std::min(data.merged_tokens_, data.debt_ / weight);
		data.merged_tokens_ -= debt_reduction;
		data.debt_ -= debt_reduction * weight;
	}
	else {
		data.debt_ = 0;
	}
}

rate::type rate_limiter::add_tokens(direction::type const d, rate::type tokens, rate::type limit)
{
	scratch_buffer_.clear();
	
	auto & data = data_[d];
	data.overflow_ = 0;

	if (!weight_) {
		data.merged_tokens_ = std::min(data.limit_, tokens);
		pay_debt(d);
		return (tokens == rate::unlimited) ? 0 : tokens;
	}

	rate::type merged_limit = limit;
	if (data.limit_ != rate::unlimited) {
		rate::type my_limit = (data.carry_ + data.limit_) / weight_;
		data.carry_ = (data.carry_ + data.limit_) % weight_;
		if (my_limit < merged_limit) {
			merged_limit = my_limit;
		}
		data.carry_ += (merged_limit % frequency) * weight_;
	}

	data.unused_capacity_ = 0;

	if (merged_limit != rate::unlimited) {
		data.merged_tokens_ = merged_limit / frequency;
	}
	else {
		data.merged_tokens_ = rate::unlimited;
	}

	if (tokens < data.merged_tokens_) {
		data.merged_tokens_ = tokens;
	}

	pay_debt(d);

	if (data.limit_ == rate::unlimited) {
		data.unused_capacity_ = rate::unlimited;
	}
	else {
		if (data.merged_tokens_ * weight_ * frequency < data.limit_) {
			data.unused_capacity_ = data.limit_ - data.merged_tokens_ * weight_ * frequency;
			data.unused_capacity_ /= frequency;
		}
		else {
			data.unused_capacity_ = 0;
		}
	}

	for (size_t i = 0; i < buckets_.size(); ++i) {
		rate::type overflow = buckets_[i]->add_tokens(d, data.merged_tokens_, merged_limit);
		if (overflow) {
			data.overflow_ += overflow;
		}
		if (buckets_[i]->unsaturated(d)) {
			scratch_buffer_.push_back(i);
		}
		else {
			data.overflow_ += buckets_[i]->distribute_overflow(d, 0);
		}
	}
	if (data.overflow_ >= data.unused_capacity_) {
		data.unused_capacity_ = 0;
	}
	else if (data.unused_capacity_ != rate::unlimited) {
		data.unused_capacity_ -= data.overflow_;
	}

	if (tokens == rate::unlimited) {
		return 0;
	}
	else {
		return (tokens - data.merged_tokens_) * weight_;
	}
}


rate::type rate_limiter::distribute_overflow(direction::type const d, rate::type overflow)
{
	auto & data = data_[d];
	rate::type usable_external_overflow;
	if (data.unused_capacity_ == rate::unlimited) {
		usable_external_overflow = overflow;
	}
	else {
		usable_external_overflow = std::min(overflow, data.unused_capacity_);
	}
	rate::type const overflow_sum = data.overflow_ + usable_external_overflow;
	rate::type remaining = overflow_sum;

	while (true) {
		data.unsaturated_ = 0;
		for (auto idx : scratch_buffer_) {
			data.unsaturated_ += buckets_[idx]->unsaturated(d);
		}

		rate::type const extra_tokens = data.unsaturated_ ? (remaining / data.unsaturated_) : 0;
		if (data.unsaturated_) {
			remaining %= data.unsaturated_;
		}
		for (size_t i = 0; i < scratch_buffer_.size(); ) {
			auto & bucket = *buckets_[scratch_buffer_[i]];
			rate::type sub_overflow = bucket.distribute_overflow(d, extra_tokens);
			if (sub_overflow || !bucket.unsaturated(d)) {
				remaining += sub_overflow;
				scratch_buffer_[i] = scratch_buffer_.back();
				scratch_buffer_.pop_back();
			}
			else {
				++i;
			}
		}
		if (!extra_tokens) {
			data.unsaturated_ = 0;
			for (auto idx : scratch_buffer_) {
				data.unsaturated_ += buckets_[idx]->unsaturated(d);
			}
			break;
		}
	}

	if (usable_external_overflow > remaining) {
		// Exhausted internal overflow
		data.unused_capacity_ -= usable_external_overflow - remaining;
		data.overflow_ = 0;
		return remaining + overflow - usable_external_overflow;
	}
	else {
		// Internal overflow not exhausted
		data.overflow_ = remaining - usable_external_overflow;
		return overflow;
	}
}

void rate_limiter::update_stats(bool & active)
{
	weight_ = 0;

	data_[0].unsaturated_ = 0;
	data_[1].unsaturated_ = 0;
	for (size_t i = 0; i < buckets_.size(); ++i) {
		buckets_[i]->update_stats(active);
		weight_ += buckets_[i]->weight();
		for (auto const d : directions) {
			data_[d].unsaturated_ += buckets_[i]->unsaturated(d);
		}
	}
}

std::array<rate::type, 2> rate_limiter::gather_unspent_for_removal()
{
	std::array<rate::type, 2> ret = {0, 0};

	for (auto & bucket : buckets_) {
		scoped_lock l(bucket->mtx_);
		auto u = bucket->gather_unspent_for_removal();
		ret[0] += u[0];
		ret[1] += u[1];
	}

	for (size_t i = 0; i < 2; ++i) {
		rate::type debt_reduction = std::min(ret[i], data_[i].debt_);
		ret[i] -= debt_reduction;
		data_[i].debt_ -= debt_reduction;
	}

	return ret;
}

bucket::~bucket()
{
	remove_bucket();
}

void bucket::remove_bucket()
{
	bucket_base::remove_bucket();
	data_[0] = data_[1] = data_t{};
}

rate::type bucket::add_tokens(direction::type const d, rate::type tokens, rate::type limit)
{
	auto & data = data_[d];
	if (limit == rate::unlimited) {
		data.bucket_size_ = rate::unlimited;
		data.available_ = rate::unlimited;
		return 0;
	}
	else {
		data.bucket_size_ = limit * data.overflow_multiplier_;
		if (mgr_) {
			data.bucket_size_ *= mgr_->burst_tolerance_;
		}
		if (data.available_ == rate::unlimited) {
			data.available_ = tokens;
			return 0;
		}
		else if (data.bucket_size_ < data.available_) {
			data.available_ = data.bucket_size_;
			return tokens;
		}
		else {
			rate::type capacity = data.bucket_size_ - data.available_;
			if (capacity < tokens && data.unsaturated_) {
				data.unsaturated_ = false;
				if (data.overflow_multiplier_ < 1024*1024) {
					capacity += data.bucket_size_;
					data.bucket_size_ *= 2;
					data.overflow_multiplier_ *= 2;
				}
			}
			rate::type added = std::min(tokens, capacity);
			rate::type ret = tokens - added;
			data.available_ += added;
			return ret;
		}
	}
}

rate::type bucket::distribute_overflow(direction::type const d, rate::type tokens)
{
	auto & data = data_[d];
	if (data.available_ == rate::unlimited) {
		return 0;
	}

	rate::type capacity = data.bucket_size_ - data.available_;
	if (capacity < tokens && data.unsaturated_) {
		data.unsaturated_ = false;
		if (data.overflow_multiplier_ < 1024*1024) {
			capacity += data.bucket_size_;
			data.bucket_size_ *= 2;
			data.overflow_multiplier_ *= 2;
		}
	}
	rate::type added = std::min(tokens, capacity);
	rate::type ret = tokens - added;
	data.available_ += added;
	return ret;
}

void bucket::unlock_tree()
{
	for (auto const& d : directions) {
		auto & data = data_[d];
		if (data.waiting_ && data.available_) {
			data.waiting_ = false;
			wakeup(static_cast<direction::type>(d));
		}
	}
	bucket_base::unlock_tree();
}

void bucket::update_stats(bool & active)
{
	for (auto const& d : directions) {
		auto & data = data_[d];
		if (data.bucket_size_ == rate::unlimited) {
			data.overflow_multiplier_ = 1;
		}
		else {
			if (data.available_ > data.bucket_size_ / 2 && data.overflow_multiplier_ > 1) {
				data.overflow_multiplier_ /= 2;
			}
			else {
				data.unsaturated_ = data.waiting_;
				if (data.waiting_) {
					active = true;
				}
			}
		}
	}
}

rate::type bucket::available(direction::type const d)
{
	if (d != direction::inbound && d != direction::outbound) {
		return rate::unlimited;
	}

	scoped_lock l(mtx_);
	auto & data = data_[d];
	if (!data.available_) {
		data.waiting_ = true;
		if (mgr_) {
			mgr_->record_activity();
		}
	}
	return data.available_;
}

void bucket::consume(direction::type const d, rate::type amount)
{
	if (!amount) {
		return;
	}
	if (d != direction::inbound && d != direction::outbound) {
		return;
	}
	scoped_lock l(mtx_);
	auto & data = data_[d];
	if (data.available_ != rate::unlimited) {
		if (mgr_) {
			mgr_->record_activity();
		}
		if (data.available_ > amount) {
			data.available_ -= amount;
		}
		else {
			data.available_ = 0;
		}
	}
}

std::array<rate::type, 2> bucket::gather_unspent_for_removal()
{
	std::array<rate::type, 2> ret = {0, 0};
	for (size_t i = 0; i < 2; ++i) {
		if (data_[i].available_ != rate::unlimited) {
			ret[i] = data_[i].available_;
			data_[i].available_ = 0;
		}
	}

	return ret;
}

bool bucket::waiting(scoped_lock &, direction::type d)
{
	if (d != direction::inbound && d != direction::outbound) {
		return false;
	}

	return data_[d].waiting_;
}

}
