#ifndef LIBFILEZILLA_WINDOWS_POLLER_HEADER
#define LIBFILEZILLA_WINDOWS_POLLER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#if FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"
#include "../libfilezilla/mutex.hpp"
#include <winsock2.h>

namespace fz {

struct pollinfo
{
	intptr_t fd_{-1};
	int events_{};
	WSANETWORKEVENTS result_{};
};

class poller final
{
public:
	poller() = default;

	poller(poller const&) = delete;
	poller& operator=(poller const&) = delete;

	~poller();

	// zero on success, else errno
	int init();

	// Must call locked
	bool wait(scoped_lock & l);

	bool wait(pollinfo* fds, size_t n, scoped_lock& l);

	void interrupt(scoped_lock& l);

	WSAEVENT sync_event_{WSA_INVALID_EVENT};

	condition cond_;
	bool signalled_{};
	bool idle_wait_{};
};
}

#else

#error windows/poller.hpp is not for non-Windows

#endif

#endif
