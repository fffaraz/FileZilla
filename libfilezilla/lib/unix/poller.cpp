#include "poller.hpp"
#include "../libfilezilla/mutex.hpp"

#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>
#else
#include "../libfilezilla/glue/unix.hpp"
#endif
#include <unistd.h>

namespace fz {

poller::~poller()
{
#ifdef HAVE_EVENTFD
	if (event_fd_ != -1) {
		::close(event_fd_);
		event_fd_ = -1;
	}
#else
	if (pipe_[0] != -1) {
		::close(pipe_[0]);
		pipe_[0] = -1;
	}
	if (pipe_[1] != -1) {
		::close(pipe_[1]);
		pipe_[1] = -1;
	}
#endif
}

// zero on success, else errno
int poller::init()
{
#ifdef HAVE_EVENTFD
   if (event_fd_ == -1) {
	   event_fd_ = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
	   if (event_fd_ == -1) {
		   return errno;
	   }
    }
#else
	if (pipe_[0] == -1) {
		if (!create_pipe(pipe_)) {
			return errno;
		}
	}
#endif
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
bool poller::wait(struct pollfd *fds, nfds_t n, scoped_lock & l)
{
#ifdef HAVE_EVENTFD
	fds[n].fd = event_fd_;
#else
	fds[n].fd = pipe_[0];
#endif
	fds[n].events = POLLIN;

	l.unlock();

	int res{};
	do {
		res = poll(fds, n + 1, -1);
	} while (res == -1 && errno == EINTR);

	l.lock();
	signalled_ = false;

	if (res > 0 && fds[n].revents) {
		char buffer[100];
#ifdef HAVE_EVENTFD
		int damn_spurious_warning = read(event_fd_, buffer, 8);
#else
		int damn_spurious_warning = read(pipe_[0], buffer, 100);
#endif
		(void)damn_spurious_warning; // We do not care about return value and this is definitely correct!
	}
	return res > 0;
}

void poller::interrupt(scoped_lock & l)
{
	signalled_ = true;
	if (idle_wait_) {
		cond_.signal(l);
	}
	else {
#ifdef HAVE_EVENTFD
		uint64_t tmp = 1;

		int ret;
		do {
			ret = write(event_fd_, &tmp, 8);
		} while (ret == -1 && errno == EINTR);
#else
		char tmp = 0;

		int ret;
		do {
			ret = write(pipe_[1], &tmp, 1);
		} while (ret == -1 && errno == EINTR);
#endif
	}
}

}
