#include "libfilezilla/mutex.hpp"

#ifndef FZ_WINDOWS
#include <errno.h>
#include <sys/time.h>

#endif

#ifdef LFZ_DEBUG_MUTEXES
#include <assert.h>
#include <execinfo.h>
#include <stdlib.h>
#include <cstddef>
#include <memory>
#include <tuple>
#include <iostream>
#include "libfilezilla/format.hpp"

namespace fz {
namespace debug {
static mutex m_;
thread_local std::vector<mutex*> lock_stack;

std::list<lock_order> orders;

thread_local size_t waitcounter{};
static std::ptrdiff_t mutex_offset{};

void FZ_PUBLIC_SYMBOL dump_orders()
{
	scoped_lock l(debug::m_);

	std::cerr << "Known orders:\n";
	for (auto const& order : orders) {
		for (auto & m : order.mutexes_) {
			std::cerr << fz::sprintf(" %p", m);
		}
		std::cerr << "\n";
	}
}

namespace {
bool match(lock_order const& order, std::vector<mutex*> & stack)
{
	if (order.mutexes_.size() != stack.size()) {
		return false;
	}
	for (size_t i = 0; i < order.mutexes_.size(); ++i) {
		if (order.mutexes_[i] != stack[i]) {
			return false;
		}
	}

	return true;
}

// Precondition: order contains stack.back(), its position is the pivot
void check_inversion(lock_order const& order, std::vector<mutex*> & stack)
{
	size_t i{};
	for (;; ++i) {
		if (order.mutexes_[i] == stack.back()) {
			break;
		}
		// We're still to the left of the pivot.

		// Check if this a common guard mutex also on the lock stack. If that's the case, no deadlock due to inversion is possible
		if (std::find(stack.begin(), stack.begin() + stack.size() - 1, order.mutexes_[i]) != stack.end()) {
			return;
		}
	}

	// We found the pivot. Check right half of order, if any of it matches, it's an inversion
	for (size_t j = i + 1; j < order.mutexes_.size(); ++j) {
		if (std::find(stack.begin(), stack.begin() + stack.size() - 1, order.mutexes_[j]) != stack.begin() + stack.size() - 1) {
			std::cerr << fz::sprintf("\nLocking order violation. fz::mutex %p locked after %p\n\n", stack.back(), order.mutexes_[j]);

			std::cerr << "New order:\n";
			for (auto & m : stack) {
				std::cerr << fz::sprintf(" %p", m);
			}
			std::cerr << "\n\n";

			std::cerr << "Established order:\n";
			for (auto & m : order.mutexes_) {
				std::cerr << fz::sprintf(" %p", m);
			}
			std::cerr << "\n\n";
#if FZ_UNIX
			std::cerr << "Reverse order was established at:\n";
			auto symbols = backtrace_symbols(order.backtrace_.data(), order.backtrace_.size());
			if (symbols) {
				for (size_t i = 0; i < order.backtrace_.size(); ++i) {
					if (symbols[i]) {
						std::cerr << symbols[i] << "\n";
					}
					else {
						std::cerr << "unknown\n";
					}
				}
			}
			else {
				std::cerr << "Stacktrace unavailable\n";
			}
#endif
			abort();
		}
	}
}

void order_cleanup(mutex& m)
{
	scoped_lock l(debug::m_);
	std::vector<std::list<lock_order>::iterator> own_orders;
	std::swap(own_orders, m.debug_.own_orders_);
	for (auto & order : own_orders) {
		for (mutex* om : order->mutexes_) {
			for (size_t i = 0; i < om->debug_.own_orders_.size(); ++i) {
				if (om->debug_.own_orders_[i] == order) {
					if (i + 1 < om->debug_.own_orders_.size()) {
						om->debug_.own_orders_[i] = om->debug_.own_orders_.back();
					}
					om->debug_.own_orders_.pop_back();
					break;
				}
			}
		}
		orders.erase(order);
	}
}

// Returns true if it's a new order
void record_order(mutex& m, bool from_try)
{
	if (lock_stack.size() < 2) {
		return;
	}

	scoped_lock l(debug::m_);
	for (auto & order : m.debug_.own_orders_) {
		if (match(*order, lock_stack)) {
			// Order has already been seen
			return;
		}
	}

	// It's a new order, if not from a try_lock, check for inversion
	if (!from_try) {
		for (auto const& order : m.debug_.own_orders_) {
			check_inversion(*order, lock_stack);
		}
	}

	// Record the new order
	orders.push_front({});
	auto & order = orders.front();
	order.mutexes_ = lock_stack;
#if FZ_UNIX
	order.backtrace_.resize(100);
	order.backtrace_.resize(backtrace(order.backtrace_.data(), 100));
#endif
	for (auto & sm : lock_stack) {
		sm->debug_.own_orders_.push_back(orders.begin());
	}
}

void lock(mutex* m, bool from_try) {
	if (m == &debug::m_) {
		return;
	}

	if (!m->debug_.count_++) {
		m->debug_.id_ = std::this_thread::get_id();
		lock_stack.push_back(m);
		record_order(*m, from_try);
	}
}
}

void unlock(mutex* m) {
	if (m == &debug::m_) {
		return;
	}

	size_t count = m->debug_.count_--;
	assert(count);
	assert(m->debug_.id_ == std::this_thread::get_id());
	if (count != 1) {
		return;
	}

	for (size_t i = lock_stack.size() - 1; i != size_t(-1); --i) {
		if (lock_stack[i] == m) {
			if (i != lock_stack.size() - 1) {
				for(; i < lock_stack.size() - 1; ++i) {
					lock_stack[i] = lock_stack[i + 1];
				}
				// This may establish a new order
				lock_stack.pop_back();
				record_order(*m, true);
			}
			else {
				lock_stack.pop_back();
			}
			return;
		}
	}
	abort();
}
}

void mutex_debug::record_lock(void* m)
{
	debug::lock(reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(m) - debug::mutex_offset), false);
}

void mutex_debug::record_unlock(void* m)
{
	debug::unlock(reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(m) - debug::mutex_offset));
}

void debug_prepare_wait(void* p)
{
	auto m = reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(p) - debug::mutex_offset);
	debug::waitcounter = m->debug_.count_;
	assert(debug::waitcounter);
	assert(m->debug_.id_ == std::this_thread::get_id());
	m->debug_.count_ = 0;
}

void debug_post_wait(void* p)
{
	auto m = reinterpret_cast<mutex*>(reinterpret_cast<unsigned char*>(p) - debug::mutex_offset);
	assert(!m->debug_.count_);
	m->debug_.count_ = debug::waitcounter;
	m->debug_.id_ = std::this_thread::get_id();
}
}
#else
constexpr void debug_prepare_wait(void*) {}
constexpr void debug_post_wait(void*) {}
#endif

#ifndef FZ_WINDOWS
namespace {
// Static initializers for mutex and condition attributes
template<int type>
pthread_mutexattr_t* init_mutexattr()
{
	static pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, type);

	return &attr;
}

pthread_mutexattr_t* get_mutex_attributes(bool recursive)
{
	if (recursive) {
		static pthread_mutexattr_t *attr = init_mutexattr<PTHREAD_MUTEX_RECURSIVE>();
		return attr;
	}
	else {
		static pthread_mutexattr_t *attr = init_mutexattr<PTHREAD_MUTEX_NORMAL>();
		return attr;
	}
}

pthread_condattr_t* init_condattr()
{
#if defined(CLOCK_MONOTONIC) && HAVE_DECL_PTHREAD_CONDATTR_SETCLOCK
	static pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	return &attr;
#else
	return 0;
#endif
}
}
#endif

namespace fz {

mutex::mutex(bool recursive)
{
#ifdef FZ_WINDOWS
	(void)recursive; // Critical sections are always recursive
	InitializeCriticalSectionEx(&m_, 0, CRITICAL_SECTION_NO_DEBUG_INFO);
#else
	pthread_mutex_init(&m_, get_mutex_attributes(recursive));
#endif
#ifdef LFZ_DEBUG_MUTEXES
	[[maybe_unused]] static bool init = [this]() {
		debug::mutex_offset = reinterpret_cast<unsigned char*>(&m_) - reinterpret_cast<unsigned char*>(this);
		return true;
	}();
#endif
}

mutex::~mutex()
{
#ifdef LFZ_DEBUG_MUTEXES
	assert(!debug_.count_);
	debug::order_cleanup(*this);
#endif
#ifdef FZ_WINDOWS
	DeleteCriticalSection(&m_);
#else
	pthread_mutex_destroy(&m_);
#endif
}

void mutex::lock()
{
#ifdef FZ_WINDOWS
	EnterCriticalSection(&m_);
#else
	pthread_mutex_lock(&m_);
#endif

#ifdef LFZ_DEBUG_MUTEXES
	debug::lock(this, false);
#endif
}

void mutex::unlock()
{
#ifdef LFZ_DEBUG_MUTEXES
	debug::unlock(this);
#endif
#ifdef FZ_WINDOWS
	LeaveCriticalSection(&m_);
#else
	pthread_mutex_unlock(&m_);
#endif
}

bool mutex::try_lock()
{
#ifdef FZ_WINDOWS
	bool locked = TryEnterCriticalSection(&m_) != 0;
#else
	bool locked = pthread_mutex_trylock(&m_) == 0;
#endif
#ifdef LFZ_DEBUG_MUTEXES
	if (locked) {
		debug::lock(this, true);
	}
#endif
	return locked;
}


condition::condition()
{
#ifdef FZ_WINDOWS
	InitializeConditionVariable(&cond_);
#else

	static pthread_condattr_t *attr = init_condattr();
	pthread_cond_init(&cond_, attr);
#endif
}


condition::~condition()
{
#ifdef FZ_WINDOWS
#else
	pthread_cond_destroy(&cond_);
#endif
}

void condition::wait(scoped_lock& l)
{
	while (!signalled_) {
		debug_prepare_wait(l.m_);
#ifdef FZ_WINDOWS
		SleepConditionVariableCS(&cond_, l.m_, INFINITE);
#else
		pthread_cond_wait(&cond_, l.m_);
#endif
		debug_post_wait(l.m_);
	}
	signalled_ = false;
}

bool condition::wait(scoped_lock& l, duration const& timeout)
{
	if (signalled_) {
		signalled_ = false;
		return true;
	}
#ifdef FZ_WINDOWS
	auto ms = timeout.get_milliseconds();
	if (ms < 0) {
		ms = 0;
	}
	debug_prepare_wait(l.m_);
	bool const success = SleepConditionVariableCS(&cond_, l.m_, static_cast<DWORD>(ms)) != 0;
	debug_post_wait(l.m_);
#else

	timespec ts;
#if defined(CLOCK_MONOTONIC) && HAVE_DECL_PTHREAD_CONDATTR_SETCLOCK
	clock_gettime(CLOCK_MONOTONIC, &ts);
#else
	timeval tv{};
	gettimeofday(&tv, 0);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;
#endif

	ts.tv_sec += timeout.get_milliseconds() / 1000;
	ts.tv_nsec += (timeout.get_milliseconds() % 1000) * 1000 * 1000;
	if (ts.tv_nsec >= 1000000000ll) {
		++ts.tv_sec;
		ts.tv_nsec -= 1000000000ll;
	}

	int res;
	do {
		debug_prepare_wait(l.m_);
		res = pthread_cond_timedwait(&cond_, l.m_, &ts);
		debug_post_wait(l.m_);
	}
	while (res == EINTR);
	bool const success = res == 0;
#endif
	if (success) {
		signalled_ = false;
	}

	return success;
}


void condition::signal(scoped_lock &)
{
	if (!signalled_) {
		signalled_ = true;
#ifdef FZ_WINDOWS
		WakeConditionVariable(&cond_);
#else
		pthread_cond_signal(&cond_);
#endif
	}
}

}
