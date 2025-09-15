#include "libfilezilla/thread.hpp"

#include <cstdlib>
#include <thread>

#if defined(FZ_WINDOWS) && (defined(__MINGW32__) || defined(__MINGW64__))
#define USE_CUSTOM_THREADS 1
#include "libfilezilla/glue/windows.hpp"
#include <process.h>
#endif

namespace fz {

bool thread::joinable() const
{
	return impl_ != nullptr;
}

#ifdef USE_CUSTOM_THREADS
// MinGW is a special snowflake...

namespace {
class entry_dispatch
{
public:
	virtual ~entry_dispatch() {}

	std::function<void()> f_;
};

static unsigned __stdcall thread_proc(void* arg)
{
	entry_dispatch* e = static_cast<entry_dispatch*>(arg);
	if (e && e->f_) {
		e->f_();
		e->f_ = nullptr;
	}
	return 0;
}
}

class thread::impl final : public entry_dispatch
{
public:
	HANDLE handle_{INVALID_HANDLE_VALUE};
};

bool thread::run(std::function<void()> && f)
{
	if (impl_) {
		return false;
	}

	impl_ = new impl();
	impl_->f_ = std::move(f);
	impl_->handle_ = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, thread_proc, impl_, 0, nullptr));

	// _beginthreadex returns 0 on error, whereas _beginthread returns -1
	// According to MSDN, _beginthreadex can also return -1 if invalid parameters are passed to it,
	// so we check that as well.
	if (!impl_->handle_ || impl_->handle_ == INVALID_HANDLE_VALUE) {
		delete impl_;
		impl_ = nullptr;
	}

	return impl_ != nullptr;
}

void thread::join()
{
	if (impl_) {
		WaitForSingleObject(impl_->handle_, INFINITE);
		CloseHandle(impl_->handle_);
		delete impl_;
		impl_ = nullptr;
	}
}

thread::id thread::own_id()
{
	return static_cast<id>(GetCurrentThreadId());
}

#else

// Canonical implentation for everyone else
class thread::impl final
{
public:
	std::thread t_;
};

bool thread::run(std::function<void()> && f)
{
	if (impl_) {
		return false;
	}

	try {
		impl_ = new impl;
		impl_->t_ = std::thread(std::move(f));
	}
	catch (std::exception const&) {
		delete impl_;
		impl_ = nullptr;
	}

	return impl_ != nullptr;
}

void thread::join()
{
	if (impl_) {
		impl_->t_.join();
		delete impl_;
		impl_ = nullptr;
	}
}

thread::id thread::own_id()
{
	return std::this_thread::get_id();
}

#endif

thread::~thread()
{
	join();
	delete impl_;
}

}
