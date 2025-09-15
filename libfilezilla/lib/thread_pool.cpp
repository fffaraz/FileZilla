#include "libfilezilla/thread_pool.hpp"
#include "libfilezilla/thread.hpp"

#include <cassert>

namespace fz {

class pooled_thread_impl;
class async_task_impl final
{
public:
	pooled_thread_impl * thread_{};
};

class pooled_thread_impl final
{
public:
	pooled_thread_impl(thread_pool & pool)
		: m_(pool.m_)
		, pool_(pool)
	{}

	virtual ~pooled_thread_impl()
	{
		thread_.join();
	}

	bool run()
	{
		return thread_.run([this] { entry(); });
	}

	virtual void entry() {
		scoped_lock l(m_);
		while (!quit_) {
			thread_cond_.wait(l);

			if (f_) {
				l.unlock();
				f_();
				l.lock();
				task_ = nullptr;
				f_ = std::function<void()>();
				pool_.idle_.emplace_back(this);
				if (task_waiting_) {
					task_waiting_ = false;
					task_cond_.signal(l);
				}
			}
		}
	}

	void quit(scoped_lock & l)
	{
		quit_ = true;
		thread_cond_.signal(l);
	}

	thread thread_;
	async_task_impl* task_{};
	std::function<void()> f_{};
	mutex & m_;
	condition thread_cond_;

	condition task_cond_;

	thread_pool& pool_;

	bool task_waiting_{};
private:
	bool quit_{};
};


async_task::async_task(async_task && other) noexcept
{
	std::swap(impl_, other.impl_);
}

async_task& async_task::operator=(async_task && other) noexcept
{
	std::swap(impl_, other.impl_);
	return *this;
}

async_task::~async_task()
{
	join();
}

void async_task::join()
{
	if (impl_) {
		scoped_lock l(impl_->thread_->m_);
		if (impl_->thread_->task_ == impl_) {
			impl_->thread_->task_waiting_ = true;
			impl_->thread_->task_cond_.wait(l);
		}
		delete impl_;
		impl_ = nullptr;
	}
}

void async_task::detach()
{
	if (impl_) {
		scoped_lock l(impl_->thread_->m_);
		if (impl_->thread_->task_ == impl_) {
			impl_->thread_->task_ = nullptr;
		}
		delete impl_;
		impl_ = nullptr;
	}
}

thread_pool::thread_pool()
{
}

thread_pool::~thread_pool()
{
	std::vector<pooled_thread_impl*> threads;
	{
		scoped_lock l(m_);
		quit_ = true;
		for (auto thread : threads_) {
			thread->quit(l);
		}
		threads.swap(threads_);
	}

	for (auto thread : threads) {
		delete thread;
	}
}

pooled_thread_impl* thread_pool::get_or_create_thread()
{
	if (quit_) {
		return {};
	}

	pooled_thread_impl *t{};
	if (idle_.empty()) {
		t = new pooled_thread_impl(*this);
		if (!t->run()) {
			delete t;
			return {};
		}
		threads_.emplace_back(t);
	}
	else {
		t = idle_.back();
		idle_.pop_back();
	}
	return t;
}

async_task thread_pool::spawn(std::function<void()> const& f)
{
	if (!f) {
		return {};
	}

	scoped_lock l(m_);

	auto *t = get_or_create_thread();
	if (!t) {
		return {};
	}

	async_task ret;
	ret.impl_ = new async_task_impl;
	ret.impl_->thread_ = t;
	t->task_ = ret.impl_;
	t->f_ = f;
	t->thread_cond_.signal(l);

	return ret;
}

async_task thread_pool::spawn(std::function<void()> && f)
{
	if (!f) {
		return {};
	}

	scoped_lock l(m_);

	auto *t = get_or_create_thread();
	if (!t) {
		return {};
	}

	async_task ret;
	ret.impl_ = new async_task_impl;
	ret.impl_->thread_ = t;
	t->task_ = ret.impl_;
	t->f_ = std::move(f);
	t->thread_cond_.signal(l);

	return ret;
}

}
