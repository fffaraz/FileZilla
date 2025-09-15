#include "../lib/libfilezilla/rate_limiter.hpp"

#include <array>
#include <iostream>

struct handler : public fz::event_handler
{
	handler(fz::event_loop & loop)
	    : fz::event_handler(loop)
	    , loop_(loop)
	    , mgr_(loop)
	    , start_(fz::monotonic_clock::now())
	{
		mgr_.add(&limiter_);

		add_timer(fz::duration::from_milliseconds(10), false);

		limiter_.add(&buckets_[0]);
		limiter_.add(&buckets_[1]);
		limiter_.add(&buckets_[2]);
		limiter_.add(&sub_limiter_[0]);
		limiter_.add(&sub_limiter_[1]);
		limiter_.add(&sub_limiter_[2]);
		sub_limiter_[0].add(&buckets_[3]);
		sub_limiter_[0].add(&buckets_[4]);
		sub_limiter_[1].add(&buckets_[5]);
		sub_limiter_[2].add(&buckets_[6]);
		limiter_.set_limits(10000, fz::rate::unlimited);
		sub_limiter_[0].set_limits(1000, fz::rate::unlimited);

		sub_limiter_[1].set_limits(2500, fz::rate::unlimited);
	}

	~handler()
	{
		remove_handler();
	}

	void operator()(fz::event_base const& ev)
	{
		fz::dispatch<fz::timer_event>(ev, this, &handler::on_timer);
	}

	void on_timer(fz::timer_id const&)
	{
		auto const now = fz::monotonic_clock::now();
		int const elapsed = (now - start_).get_seconds();

		int const delay = 3;
		int const duration = 5;
		if (elapsed >= delay + duration) {
			fz::rate::type sum{};
			for (size_t i = 0; i < buckets_.size(); ++i) {
				sum += consumed_[i];
				std::cout << "Bucket " << i << " has rate of " << consumed_[i] / duration << " bytes/s\n";
			}
			std::cout << "Total rate is " << sum / duration << " bytes/s\n";

			float ratio = float(sum) / (limiter_.limit(fz::direction::inbound) * duration);
			if (ratio < 0.9 || ratio > 1.1) {
				std::cout << "Bad total rate ratio: " << ratio << std::endl;
				exit(1);
			}

			ratio = float(consumed_[3] + consumed_[4]) / (sub_limiter_[0].limit(fz::direction::inbound) * duration);
			if (ratio < 0.9 || ratio > 1.1) {
				std::cout << "Bad sublimit rate ratio: " << ratio << std::endl;
				exit(1);
			}

			loop_.stop();
		}

		for (size_t i = 0; i < buckets_.size(); ++i) {
			fz::rate::type amount = rates_[i];
			fz::rate::type available = buckets_[i].available(fz::direction::inbound);
			if (available != fz::rate::unlimited && available < amount) {
				amount = available;
			}
			if (elapsed >= delay) {
				consumed_[i] += amount;
			}
			buckets_[i].consume(fz::direction::inbound, amount);
		}
	}

	fz::event_loop & loop_;

	fz::rate_limit_manager mgr_;
	fz::rate_limiter limiter_;
	fz::rate_limiter sub_limiter_[3];

	std::array<fz::rate::type, 7> rates_{1, 2, 1000, 3, 1000, 100000, 100000};
	std::array<fz::bucket, 7> buckets_;
	std::array<fz::rate::type, 7> consumed_{};

	fz::monotonic_clock start_;
};

int main()
{
	fz::event_loop loop(fz::event_loop::threadless);

	handler h(loop);

	loop.run();

	return 0;
}

