#include "poller.hpp"
#include "../libfilezilla/mutex.hpp"

namespace fz {

poller::~poller()
{
	if (sync_event_ != WSA_INVALID_EVENT) {
		WSACloseEvent(sync_event_);
	}
}

// zero on success, else errno
int poller::init()
{
	if (sync_event_ == WSA_INVALID_EVENT) {
		sync_event_ = WSACreateEvent();
	}
	if (sync_event_ == WSA_INVALID_EVENT) {
		return 1;
	}
	return 0;
}

bool poller::wait(scoped_lock & l)
{
    if (!signalled_) {
		idle_wait_ = true;
		cond_.wait(l);
		idle_wait_ = false;
	}
	signalled_ = false;
	return true;
}

// fds must be large enough to hold n+1 entries, but fds[n] must not be filled by caller
bool poller::wait(pollinfo* fds, size_t n, scoped_lock& l)
{
	for (size_t i = 0; i < n; ++i) {
		WSAEventSelect(fds[i].fd_, sync_event_, fds[i].events_);
	}

	l.unlock();
	// We intentionally ignore return code
	DWORD res = WSAWaitForMultipleEvents(1, &sync_event_, false, INFINITE, false);

	l.lock();
	signalled_ = false;

	if (res == WSA_WAIT_FAILED) {
		for (size_t i = 0; i < n; ++i) {
			WSAEventSelect(fds[i].fd_, sync_event_, 0);
		}
		return false;
	}

	bool failure{};
	for (size_t i = 0; i < n; ++i) {
		if (WSAEnumNetworkEvents(fds[i].fd_, sync_event_, &fds[i].result_)) {
			failure = true;
		}
		WSAEventSelect(fds[i].fd_, sync_event_, 0);
	}
	if (failure) {
		return false;
	}

	return true;
}

void poller::interrupt(scoped_lock& l)
{
	signalled_ = true;
	if (idle_wait_) {
		cond_.signal(l);
	}
	else {
		WSASetEvent(sync_event_);
	}
}

}
