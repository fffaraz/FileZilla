#include "libfilezilla/event_handler.hpp"
#include "libfilezilla/impersonation.hpp"
#include "libfilezilla/process.hpp"
#include "libfilezilla/thread_pool.hpp"
#include "libfilezilla/util.hpp"

#ifdef FZ_WINDOWS

#include "libfilezilla/buffer.hpp"
#include "libfilezilla/encode.hpp"
#include "libfilezilla/glue/async_pipe.hpp"
#include "libfilezilla/glue/windows.hpp"
#include "windows/security_descriptor_builder.hpp"

namespace fz {

namespace {
void reset_handle(HANDLE& handle)
{
	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
		handle = INVALID_HANDLE_VALUE;
	}
}

class pipe final
{
public:
	pipe() = default;

	~pipe()
	{
		reset();
	}

	pipe(pipe const&) = delete;
	pipe& operator=(pipe const&) = delete;

	bool create(bool parent_is_reading, bool overlapped)
	{
		reset();

		auto name = "\\\\.\\pipe\\" + base32_encode(random_bytes(64), base32_type::locale_safe, false);

		DWORD openMode{FILE_FLAG_FIRST_PIPE_INSTANCE};
		if (overlapped) {
			openMode |= FILE_FLAG_OVERLAPPED;
		}
		openMode |= parent_is_reading ? PIPE_ACCESS_INBOUND : PIPE_ACCESS_OUTBOUND;

		SECURITY_ATTRIBUTES attr{};
		attr.nLength = sizeof(SECURITY_ATTRIBUTES);

		// Restrict pipe to self
		security_descriptor_builder sdb;
		sdb.add(security_descriptor_builder::self);
		auto sd = sdb.get_sd(sdb_flags::none);
		if (!sd) {
			return false;
		}
		attr.lpSecurityDescriptor = sd;
		HANDLE parent_handle = CreateNamedPipeA(name.c_str(), openMode, PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, 64 * 1024, 64 * 1024, 0, &attr);
		if (parent_handle == INVALID_HANDLE_VALUE) {
			return false;
		}

		attr.bInheritHandle = true;
		HANDLE child_handle = CreateFileA(name.c_str(), parent_is_reading ? GENERIC_WRITE : GENERIC_READ, 0, &attr, OPEN_EXISTING, 0, nullptr);
		if (child_handle == INVALID_HANDLE_VALUE) {
			CloseHandle(parent_handle);
			return false;
		}

		read_ = parent_is_reading ? parent_handle : child_handle;
		write_ = parent_is_reading ? child_handle : parent_handle;

		return valid();
	}

	bool valid() const {
		return read_ != INVALID_HANDLE_VALUE && write_ != INVALID_HANDLE_VALUE;
	}

	void reset()
	{
		reset_handle(read_);
		reset_handle(write_);
	}

	HANDLE read_{INVALID_HANDLE_VALUE};
	HANDLE write_{INVALID_HANDLE_VALUE};
};

native_string escape_argument(native_string const& arg)
{
	native_string ret;

	// Treat newlines as whitespace just to be sure, even if MSDN doesn't mention it
	if (arg.find_first_of(fzT(" \"\t\r\n\v")) != native_string::npos) {
		// Quite horrible, as per MSDN:
		// Backslashes are interpreted literally, unless they immediately precede a double quotation mark.
		// If an even number of backslashes is followed by a double quotation mark, one backslash is placed in the argv array for every pair of backslashes, and the double quotation mark is interpreted as a string delimiter.
		// If an odd number of backslashes is followed by a double quotation mark, one backslash is placed in the argv array for every pair of backslashes, and the double quotation mark is "escaped" by the remaining backslash, causing a literal double quotation mark (") to be placed in argv.

		ret = fzT("\"");
		int backslashCount = 0;
		for (auto it = arg.begin(); it != arg.end(); ++it) {
			if (*it == '\\') {
				++backslashCount;
			}
			else {
				if (*it == '"') {
					// Escape all preceeding backslashes and escape the quote
					ret += native_string(backslashCount + 1, '\\');
				}
				backslashCount = 0;
			}
			ret += *it;
		}
		if (backslashCount) {
			// Escape all preceeding backslashes
			ret += native_string(backslashCount, '\\');
		}

		ret += fzT("\"");
	}
	else {
		ret = arg;
	}

	return ret;
}

native_string get_cmd_line(native_string const& cmd, std::vector<native_string>::const_iterator const& begin, std::vector<native_string>::const_iterator const& end)
{
	native_string cmdline = escape_argument(cmd);

	for (auto it = begin; it != end; ++it) {
		auto const& arg = *it;
		if (!arg.empty()) {
			cmdline += fzT(" ") + escape_argument(arg);
		}
	}

	return cmdline;
}

event_loop& get_unused_loop()
{
	static event_loop unused_loop(event_loop::threadless);
	return unused_loop;
}
}

HANDLE get_handle(impersonation_token const& t);
class process::impl : public event_handler
{
public:
	impl(process& p)
		: event_handler(get_unused_loop())
		, process_(p)
	{
	}

	impl(process& p, thread_pool& pool, event_handler& handler)
		: event_handler(handler.event_loop_)
		, process_(p)
		, pool_(&pool)
		, handler_(&handler)
	{
	}

	~impl()
	{
		remove_handler();
		kill();
	}

	impl(impl const&) = delete;
	impl& operator=(impl const&) = delete;

	bool create_pipes(bool include_stderr)
	{
		return
			in_.create(false, handler_ != nullptr) &&
			out_.create(true, handler_ != nullptr) &&
			(!include_stderr || err_.create(true, false));
	}

	bool spawn(native_string const& cmd, std::vector<native_string>::const_iterator const& begin, std::vector<native_string>::const_iterator const& end, io_redirection redirect_mode, impersonation_token const* it = nullptr)
	{
		if (process_handle_ != INVALID_HANDLE_VALUE) {
			return false;
		}

		auto cmdline = get_cmd_line(cmd, begin, end);

		bool const inherit = redirect_mode != io_redirection::none;
		if (inherit) {
			if (!create_pipes(redirect_mode != io_redirection::redirect_except_stderr)) {
				return false;
			}
		}

		if (handler_ && inherit && redirect_mode != io_redirection::closeall) {
			async_pipe_.emplace(*pool_, *this, out_.read_, in_.write_);
			in_.write_ = INVALID_HANDLE_VALUE;
			out_.read_ = INVALID_HANDLE_VALUE;
		}

		DWORD flags = CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW;

		STARTUPINFOEXW si{};
		si.StartupInfo.cb = sizeof(si);

		HANDLE handles[3];
		if (inherit) {
			flags |= EXTENDED_STARTUPINFO_PRESENT;

			si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
			si.StartupInfo.hStdInput = in_.read_;
			si.StartupInfo.hStdOutput = out_.write_;
			si.StartupInfo.hStdError = err_.write_;

			SIZE_T size_needed{};
			InitializeProcThreadAttributeList(nullptr, 1, 0, &size_needed);

			si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(size_needed));
			if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size_needed) == 0) {
				free(si.lpAttributeList);
				return false;
			}
			handles[0] = in_.read_;
			handles[1] = out_.write_;
			handles[2] = (redirect_mode == io_redirection::redirect_except_stderr) ? GetStdHandle(STD_ERROR_HANDLE) : err_.write_;

			if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) {
				DeleteProcThreadAttributeList(si.lpAttributeList);
				free(si.lpAttributeList);
				return false;
			}
		}

		PROCESS_INFORMATION pi{};

		BOOL res;
		if (it) {
			 res = CreateProcessAsUserW(get_handle(*it), cmd.c_str(), cmdline.data(), nullptr, nullptr, inherit, flags, nullptr, nullptr, reinterpret_cast<STARTUPINFOW*>(&si), &pi);
		}
		else {
			res = CreateProcessW(cmd.c_str(), cmdline.data(), nullptr, nullptr, inherit, flags, nullptr, nullptr, reinterpret_cast<STARTUPINFOW*>(&si), &pi);
		}

		if (inherit) {
			DeleteProcThreadAttributeList(si.lpAttributeList);
			free(si.lpAttributeList);
		}

		if (!res) {
			kill();
			return false;
		}

		process_handle_ = pi.hProcess;
		reset_handle(pi.hThread);

		// We don't need to use these
		if (redirect_mode != io_redirection::none) {
			reset_handle(in_.read_);
			reset_handle(out_.write_);
			reset_handle(err_.write_);
			if (redirect_mode == io_redirection::closeall) {
				reset_handle(in_.write_);
				reset_handle(out_.read_);
				reset_handle(err_.read_);
			}
		}

		return true;
	}

	void remove_pending_events()
	{
		if (!handler_) {
			return;
		}

		auto process_event_filter = [&](event_base const& ev) -> bool {
			if (ev.derived_type() == process_event::type()) {
				return std::get<0>(static_cast<process_event const&>(ev).v_) == &process_;
			}
			return false;
		};

		handler_->filter_events(process_event_filter);
	}

	bool kill(bool force = true, duration const& timeout = {})
	{
		if (handler_) {
			async_pipe_.reset();
			remove_pending_events();
		}

		in_.reset();
		if (process_handle_ != INVALID_HANDLE_VALUE) {
			if (force) {
				TerminateProcess(process_handle_, 0);
			}
			else {
				DWORD wait = (timeout >= duration()) ? clamped_cast<DWORD>(timeout.get_milliseconds()) : INFINITE;
				if (WaitForSingleObject(process_handle_, wait) == WAIT_TIMEOUT) {
					return false;
				}
			}
			reset_handle(process_handle_);
		}
		out_.reset();
		err_.reset();

		return true;
	}

	rwresult read(void* buffer, size_t len)
	{
		if (handler_) {
			if (!async_pipe_) {
				return rwresult{rwresult::invalid, 0};
			}
			return async_pipe_->read(buffer, len);
		}
		else {
			if (!len || out_.read_ == INVALID_HANDLE_VALUE) {
				return rwresult{rwresult::invalid, 0};
			}
			DWORD read = 0;
			DWORD to_read = clamped_cast<DWORD>(len);
			BOOL res = ReadFile(out_.read_, buffer, to_read, &read, nullptr);
			if (!res) {
				DWORD const err = GetLastError();
				// ERROR_BROKEN_PIPE indicates EOF.
				if (err == ERROR_BROKEN_PIPE) {
					return rwresult(0);
				}
				return rwresult{ rwresult::other, err };
			}
			return rwresult(static_cast<size_t>(read));
		}
	}

	rwresult write(void const* buffer, size_t len)
	{
		if (handler_) {
			if (!async_pipe_) {
				return rwresult{rwresult::invalid, 0};
			}
			return async_pipe_->write(buffer, len);
		}
		else {
			if (!len || in_.write_ == INVALID_HANDLE_VALUE) {
				return rwresult{rwresult::invalid, 0};
			}

			DWORD written = 0;
			DWORD to_write = clamped_cast<DWORD>(len);
			BOOL res = WriteFile(in_.write_, buffer, to_write, &written, nullptr);
			if (!res || written == 0) {
				return rwresult{ rwresult::other, GetLastError() };
			}
			return rwresult{ static_cast<size_t>(written) };
		}
	}

	HANDLE handle() const { return process_handle_; }

	virtual void operator()(fz::event_base const& ev) override
	{
		fz::dispatch<fz::pipe_event>(ev, this, &impl::on_pipe_event);
	}

	void on_pipe_event(async_pipe*, pipe_event_flag type)
	{
		if (!handler_) {
			return;
		}
		handler_->send_event<process_event>(&process_, type == pipe_event_flag::read ? process_event_flag::read : process_event_flag::write);
	}

private:
	process & process_;
	thread_pool * pool_{};
	event_handler * handler_{};

	HANDLE process_handle_{INVALID_HANDLE_VALUE};

	pipe in_;
	pipe out_;
	pipe err_;
	std::optional<async_pipe> async_pipe_;
};

#else

#include "libfilezilla/glue/unix.hpp"
#include "libfilezilla/mutex.hpp"
#include "unix/poller.hpp"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <vector>

#if FZ_MAC && !FZ_IOS
#include "libfilezilla/local_filesys.hpp"

#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFURL.h>
#include <CoreFoundation/CFBundle.h>

#include <ApplicationServices/ApplicationServices.h>
#endif

#if DEBUG_SOCKETEVENTS
#include <assert.h>
#endif

namespace fz {

namespace {
void reset_fd(int& fd)
{
	if (fd != -1) {
		close(fd);
		fd = -1;
	}
}

class pipe final
{
public:
	pipe() = default;

	~pipe()
	{
		reset();
	}

	pipe(pipe const&) = delete;
	pipe& operator=(pipe const&) = delete;

	bool create()
	{
		reset();

		int fds[2];
		if (!create_pipe(fds)) {
			return false;
		}

		read_ = fds[0];
		write_ = fds[1];

		return valid();
	}

	bool valid() const {
		return read_ != -1 && write_ != -1;
	}

	void reset()
	{
		reset_fd(read_);
		reset_fd(write_);
	}

	int read_{-1};
	int write_{-1};
};

void get_argv(native_string const& cmd, std::vector<native_string>::const_iterator const& begin, std::vector<native_string>::const_iterator const& end, std::vector<char*> & argV)
{
	argV.reserve(end - begin + 2);
	argV.emplace_back(const_cast<char*>(cmd.c_str()));
	for (auto it = begin; it != end; ++it) {
		argV.emplace_back(const_cast<char*>(it->c_str()));
	}
	argV.emplace_back(nullptr);
}

std::atomic<unsigned int> forkblocks_{};
mutex forkblock_mtx_;
}

class process::impl
{
public:
	impl(process & p)
		: process_(p)
	{}

	impl(process & p, thread_pool & pool, event_handler & handler)
		: process_(p)
		, pool_(&pool)
		, handler_(&handler)
	{
	}

	~impl()
	{
		kill();
	}

	impl(impl const&) = delete;
	impl& operator=(impl const&) = delete;

	bool create_pipes(bool include_stderr)
	{
		return
			in_.create() &&
			out_.create() &&
			(!include_stderr || err_.create());
	}

	void thread_entry()
	{
		scoped_lock l(mutex_);
		while (!quit_) {
			if (waiting_read_ || waiting_write_) {
				struct pollfd fds[3]{};
				nfds_t n{};
				if (waiting_read_) {
					fds[n].fd = out_.read_;
					fds[n++].events = POLLIN;
				}
				if (waiting_write_) {
					fds[n].fd = in_.write_;
					fds[n++].events = POLLOUT;
				}
				if (!poller_.wait(fds, n, l)) {
					break;
				}

				if (quit_) {
					break;
				}

				for (size_t i = 0; i < n; ++i) {
					if (fds[i].fd == out_.read_ && waiting_read_) {
						if (fds[i].revents & (POLLIN|POLLHUP|POLLERR)) {
							waiting_read_ = false;

							handler_->send_event<process_event>(&process_, process_event_flag::read);
						}
					}
					else if (fds[i].fd == in_.write_ && waiting_write_) {
						if (fds[i].revents & (POLLOUT|POLLHUP|POLLERR)) {
							waiting_write_ = false;

							handler_->send_event<process_event>(&process_, process_event_flag::write);
						}
					}
				}
			}
			else {

				if (!poller_.wait(l)) {
					break;
				}
			}
		}
	}

	bool spawn(native_string const& cmd, std::vector<native_string>::const_iterator const& begin, std::vector<native_string>::const_iterator const& end, io_redirection redirect_mode, std::vector<int> const& extra_fds = std::vector<int>(), impersonation_token const* it = nullptr)
	{
		if (pid_ != -1) {
			return false;
		}

		if (redirect_mode != io_redirection::none && !create_pipes(redirect_mode != io_redirection::redirect_except_stderr)) {
			kill();
			return false;
		}

		std::vector<char*> argV;
		get_argv(cmd, begin, end, argV);

		scoped_lock l(mutex_);
		if (handler_) {
			if (poller_.init() != 0) {
				kill();
				return false;
			}
			task_ = pool_->spawn([this]() { thread_entry(); });
			if (!task_) {
				kill();
				return false;
			}
		}
		else {
			waiting_read_ = false;
		}

		scoped_lock fbl(forkblock_mtx_);
		pid_t pid = fork();
		if (pid < 0) {
			kill();
			return false;
		}
		else if (!pid) {
			// We're the child.

			if (redirect_mode != io_redirection::none) {
				// Close uneeded descriptors
				reset_fd(in_.write_);
				reset_fd(out_.read_);
				reset_fd(err_.read_);

				// Redirect to pipe. The redirected descriptors don't have
				// FD_CLOEXEC set.
				// Note that even if redirect_mode is closeall, we still leave valid descriptors
				// at stdin/out/err as we do not want to have these re-used for other things.
				if (dup2(in_.read_, STDIN_FILENO) == -1 ||
					dup2(out_.write_, STDOUT_FILENO) == -1 ||
					(redirect_mode != io_redirection::redirect_except_stderr && dup2(err_.write_, STDERR_FILENO) == -1))
				{
					_exit(-1);
				}
			}

			// Clear FD_CLOEXEC on extra descriptors
			for (int fd : extra_fds) {
				int flags = fcntl(fd, F_GETFD);
				if (flags == -1) {
					_exit(1);
				}
				if (fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) != 0) {
					_exit(1);
				}
			}

			if (it && *it) {
				if (!set_process_impersonation(*it)) {
					_exit(1);
				}
			}

			// Execute process
			execv(cmd.c_str(), argV.data()); // noreturn on success

			_exit(-1);
		}
		else {
			// We're the parent
			pid_ = pid;

			fbl.unlock();

			// Close unneeded descriptors
			if (redirect_mode != io_redirection::none) {
				reset_fd(in_.read_);
				reset_fd(out_.write_);
				reset_fd(err_.write_);
				if (redirect_mode == io_redirection::closeall) {
					reset_fd(in_.write_);
					reset_fd(out_.read_);
					reset_fd(err_.read_);
				}
				else {
					if (handler_) {
						set_nonblocking(in_.write_);
						set_nonblocking(out_.read_);
						set_nonblocking(err_.read_);

						waiting_read_ = true;
						waiting_write_ = false;
					}
				}
			}
		}

		return true;
	}

	void remove_pending_events()
	{
		if (!handler_) {
			return;
		}

		auto process_event_filter = [&](event_base const& ev) -> bool {
			if (ev.derived_type() == process_event::type()) {
				return std::get<0>(static_cast<process_event const&>(ev).v_) == &process_;
			}
			return false;
		};

		handler_->filter_events(process_event_filter);
	}

	bool do_waitpid(bool wait = false)
	{
		pid_t ret;
		do {
			ret = waitpid(pid_, nullptr, wait ? 0 : WNOHANG);
		} while (ret == -1 && errno == EINTR);
		return ret != 0;
	}

	bool wait(duration const& timeout)
	{
		if (do_waitpid()) {
			return true;
		}
		if (!timeout) {
			return false;
		}

		monotonic_clock const deadline = monotonic_clock::now() + timeout;

#ifdef SYS_pidfd_open
		int pidfd = syscall(SYS_pidfd_open, pid_, 0);
		if (pidfd >= 0) {
			for (duration wait; wait = deadline - monotonic_clock::now(), wait > duration();) {
				pollfd fds{};
				fds.fd = pidfd;
				fds.events = POLLIN;
				if (poll(&fds, 1, wait.get_milliseconds()) > 0) {
					if (do_waitpid()) {
						close(pidfd);
						return true;
					}
				}
			}
			close(pidfd);
			return do_waitpid();
		}
#endif
		// Sadly need to fall back to waidpid with WNOHANG.
		// Poll fast at first, then slow down
		//
		// Signals are no option here, this is multi-threaded
		// library code. We cannot control what other components are doing.
		for (duration wait, sd = duration::from_milliseconds(1); wait = deadline - monotonic_clock::now(), wait > duration(); sd += sd / 10 + duration::from_milliseconds(1)) {
			sleep(wait > sd ? sd : wait);
			if (do_waitpid()) {
				return true;
			}
		}

		return false;
	}

	bool kill(bool force = true, duration const& timeout = {})
	{
		if (handler_) {
			{
				scoped_lock l(mutex_);
				quit_ = true;
				poller_.interrupt(l);
			}
			task_.join();
			quit_ = false;

			remove_pending_events();
		}
		in_.reset();

		if (pid_ != -1) {
			::kill(pid_, force ? SIGKILL : SIGTERM);

			if (force || timeout < duration()) {
				do_waitpid(true);
			}
			else {
				if (!wait(timeout)) {
					return false;
				}
			}

			pid_ = -1;
		}

		out_.reset();
		err_.reset();

		return true;
	}

	rwresult read(void* buffer, unsigned int len)
	{
#if DEBUG_SOCKETEVENTS
		assert(!waiting_read_);
#endif
		while (true) {
			ssize_t r = ::read(out_.read_, buffer, len);
			int const err = errno;
			if (r >= 0) {
				return rwresult{static_cast<size_t>(r)};
			}
			if (err == EINTR) {
				continue;
			}
			if (err == EAGAIN && !handler_) {
				continue;
			}
			switch (err) {
			case EAGAIN:
				{
					scoped_lock l(mutex_);
					waiting_read_ = true;
					poller_.interrupt(l);
				}
				return rwresult{rwresult::wouldblock, err};
			case EIO:
				return rwresult{rwresult::other, err};
			default:
				return rwresult{rwresult::invalid, err};
			}
		}
	}

	rwresult write(void const* buffer, unsigned int len)
	{
#if DEBUG_SOCKETEVENTS
		assert(!waiting_write_);
#endif
		while (true) {
			ssize_t written = ::write(in_.write_, buffer, len);
			if (written >= 0) {
				return rwresult{static_cast<size_t>(written)};
			}
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN && !handler_) {
				continue;
			}
			int const err = errno;
			switch (err) {
			case EAGAIN:
				{
					scoped_lock l(mutex_);
					waiting_write_ = true;
					poller_.interrupt(l);
				}
				return rwresult{rwresult::wouldblock, err};
			case EIO:
				return rwresult{rwresult::other, err};
			case ENOSPC:
				return rwresult{rwresult::nospace, err};
			default:
				return rwresult{rwresult::invalid, err};
			}
		}
	}

	process & process_;

	thread_pool * pool_{};
	event_handler * handler_{};
	mutex mutex_;
	async_task task_;
	bool quit_{};

	poller poller_;

	pipe in_;
	pipe out_;
	pipe err_;

	bool waiting_read_{true};
	bool waiting_write_{};

	int pid_{-1};
};

#endif


process::process()
	: impl_(new impl(*this))
{
}

process::process(thread_pool & pool, event_handler & handler)
	: impl_(new impl(*this, pool, handler))
{
}

process::~process()
{
	delete impl_;
}

bool process::spawn(native_string const& cmd, std::vector<native_string> const& args, io_redirection redirect_mode)
{
	return impl_ ? impl_->spawn(cmd, args.cbegin(), args.cend(), redirect_mode) : false;
}

#if FZ_WINDOWS || FZ_UNIX
bool process::spawn(impersonation_token const& it, native_string const& cmd, std::vector<native_string> const& args, io_redirection redirect_mode)
{
#if FZ_WINDOWS
	return impl_ ? impl_->spawn(cmd, args.cbegin(), args.cend(), redirect_mode, &it) : false;
#else
	return impl_ ? impl_->spawn(cmd, args.cbegin(), args.cend(), redirect_mode, {}, &it) : false;
#endif
}
#endif

#ifndef FZ_WINDOWS
bool process::spawn(native_string const& cmd, std::vector<native_string> const& args, std::vector<int> const& extra_fds, io_redirection redirect_mode)
{
	return impl_ ? impl_->spawn(cmd, args.cbegin(), args.cend(), redirect_mode, extra_fds) : false;
}

bool process::spawn(impersonation_token const& it, native_string const& cmd, std::vector<native_string> const& args, std::vector<int> const& extra_fds, io_redirection redirect_mode)
{
	return impl_ ? impl_->spawn(cmd, args.cbegin(), args.cend(), redirect_mode, extra_fds, &it) : false;
}

#endif

bool process::spawn(std::vector<native_string> const& command_with_args, io_redirection redirect_mode)
{
	if (command_with_args.empty()) {
		return false;
	}
	auto begin = command_with_args.begin() + 1;
	return impl_ ? impl_->spawn(command_with_args.front(), begin, command_with_args.end(), redirect_mode) : false;
}

void process::kill()
{
	if (impl_) {
		impl_->kill(true, {});
	}
}

bool process::stop(duration const& timeout)
{
	if (impl_) {
		return impl_->kill(false, timeout);
	}
	return false;
}

rwresult process::read(void* buffer, size_t len)
{
	return impl_ ? impl_->read(buffer, len) : rwresult{rwresult::invalid, 0};
}

rwresult process::write(void const* buffer, size_t len)
{
	return impl_ ? impl_->write(buffer, len) : rwresult{rwresult::invalid, 0};
}

#if FZ_WINDOWS
HANDLE process::handle() const
{
	return impl_ ? impl_->handle() : INVALID_HANDLE_VALUE;
}
#endif

#if FZ_MAC && !FZ_IOS
namespace {
template<typename T>
class cfref final
{
public:
	cfref() = default;
	~cfref() {
		if (ref_) {
			CFRelease(ref_);
		}
	}

	explicit cfref(T ref, bool fromCreate = true)
		: ref_(ref)
	{
		if (ref_ && !fromCreate) {
			CFRetain(ref_);
		}
	}

	cfref(cfref const& op)
		: ref_(op.ref_)
	{
		if (ref_) {
			CFRetain(ref_);
		}
	}

	cfref& operator=(cfref const& op)
	{
		if (this != &op) {
			if (ref_) {
				CFRelease(ref_);
			}
			ref_ = op.ref_;
			if (ref_) {
				CFRetain(ref_);
			}
		}

		return *this;

	}

	explicit operator bool() const { return ref_ != nullptr; }

	operator T& () { return ref_; }
	operator T const& () const { return ref_; }

private:
	T ref_{};
};

typedef cfref<CFStringRef> cfsr;
typedef cfref<CFURLRef> cfurl;
typedef cfref<CFBundleRef> cfbundle;
typedef cfref<CFMutableArrayRef> cfma;

cfsr cfsr_view(std::string_view const& v)
{
	return cfsr(CFStringCreateWithBytesNoCopy(nullptr, reinterpret_cast<uint8_t const*>(v.data()), v.size(), kCFStringEncodingUTF8, false, kCFAllocatorNull), true);
}

int try_launch_bundle(std::vector<std::string> const& cmd_with_args)
{
	std::string_view cmd(cmd_with_args[0]);
	if (!cmd.empty() && cmd.back() == '/') {
		cmd = cmd.substr(0, cmd.size() - 1);
	}
	if (!ends_with(cmd, std::string_view(".app"))) {
		return -1;
	}

	if (local_filesys::get_file_type(cmd_with_args[0], true) != local_filesys::dir) {
		return -1;
	}

	// Treat it as a bundle


	cfurl bundle_url(CFURLCreateWithFileSystemPath(nullptr, cfsr_view(cmd), kCFURLPOSIXPathStyle, true));
	if (!bundle_url) {
		return 0;
	}

	cfbundle bundle(CFBundleCreate(nullptr, bundle_url));
	if (!bundle) {
		return 0;
	}

	// Require the bundle to be an application
	uint32_t type, creator;
	CFBundleGetPackageInfo(bundle, &type, &creator);
	if (type != 'APPL') {
		return 0;
	}

	cfma args(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
	if (!args) {
		return 0;
	}

	for (size_t i = 1; i < cmd_with_args.size(); ++i) {
		cfurl arg_url;

		auto const& arg = cmd_with_args[i];

		if (!arg.empty() && arg.front() == '/') {
			auto t = local_filesys::get_file_type(cmd_with_args[i], true);
			if (t != local_filesys::unknown) {
				arg_url = cfurl(CFURLCreateWithFileSystemPath(nullptr, cfsr_view(arg), kCFURLPOSIXPathStyle, t == local_filesys::dir));
				if (!arg_url) {
					return 0;
				}
			}
		}

		if (!arg_url) {
			arg_url = cfurl(CFURLCreateWithString(nullptr, cfsr_view(arg), nullptr));
		}

		if (!arg_url) {
			return 0;
		}
		CFArrayAppendValue(args, arg_url);
	}

	LSLaunchURLSpec ls{};
	ls.appURL = bundle_url;
	ls.launchFlags = kLSLaunchDefaults;
	ls.itemURLs = args;
	if (LSOpenFromURLSpec(&ls, nullptr) != noErr) {
		return 0;
	}

	return 1;
}
}
#endif

bool spawn_detached_process(std::vector<native_string> const& cmd_with_args)
{
	if (cmd_with_args.empty() || cmd_with_args[0].empty()) {
		return false;
	}

#ifdef FZ_WINDOWS
	STARTUPINFO si{};
	si.cb = sizeof(si);

	auto begin = cmd_with_args.cbegin() + 1;
	auto cmdline = get_cmd_line(cmd_with_args.front(), begin, cmd_with_args.cend());

	PROCESS_INFORMATION pi{};

	auto cmdline_buf = cmdline.data();

	DWORD const flags = CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW;
	BOOL res = CreateProcess(cmd_with_args.front().c_str(), cmdline_buf, nullptr, nullptr, false, flags, nullptr, nullptr, &si, &pi);
	if (!res) {
		return false;
	}

	reset_handle(pi.hProcess);
	reset_handle(pi.hThread);
	return true;
#else
	if (cmd_with_args[0][0] != '/') {
		return false;
	}

#if FZ_MAC && !FZ_IOS
	// Special handling for application bundles if passed a single file name
	int res = try_launch_bundle(cmd_with_args);
	if (res != -1) {
		return res == 1;
	}
#endif

	std::vector<char *> argV;
	auto begin = cmd_with_args.cbegin() + 1;
	get_argv(cmd_with_args.front(), begin, cmd_with_args.cend(), argV);

	pid_t const parent = getppid();
	pid_t const ppgid = getpgid(parent);

	scoped_lock l(forkblock_mtx_);

	// We're using a pipe created with O_CLOEXEC to signal failure from execv.
	// Fortunately the forkblock avoids a deadlock if the cloexec flag isn't set
	// atomically and another thread execs in-between, as even in 2022, macOS
	// doesn't have pipe2.
	pipe errpipe;
	errpipe.create();

	pid_t pid = fork();
	if (!pid) {
		reset_fd(errpipe.read_);

		// We're the child
		pid_t inner_pid = fork();
		if (!inner_pid) {
			// Change the process group ID of the new process so that terminating the outer process does not terminate the child
			setpgid(0, ppgid);
			execv(cmd_with_args[0].c_str(), argV.data());

			if (errpipe.write_ != -1) {
				ssize_t w;
				do {
					w = ::write(errpipe.write_, "", 1);
				} while (w == -1 && (errno == EAGAIN || errno == EINTR));
			}

			_exit(-1);
		}
		else {
			_exit(0);
		}

		return false;
	}
	else {
		reset_fd(errpipe.write_);

		// We're the parent
		int ret;
		do {
		} while ((ret = waitpid(pid, nullptr, 0)) == -1 && errno == EINTR);

		if (ret == -1) {
			return false;
		}

		if (errpipe.read_ != -1) {
			ssize_t r;
			char tmp;
			do {
				r = ::read(errpipe.read_, &tmp, 1);
			} while (r == -1 && (errno == EAGAIN || errno == EINTR));
			if (r == 1) {
				// execv failed in the child.
				return false;
			}
		}

		return true;
	}
#endif
}

#if !FZ_WINDOWS
forkblock::forkblock()
{
	forkblock_mtx_.lock();
	++forkblocks_;
}

forkblock::~forkblock()
{
	--forkblocks_;
	forkblock_mtx_.unlock();
}

namespace {
bool forked_child_{};
void atfork_lock_forkblock()
{
	// Unsafe if fork is called from a signal handler
	if (!forked_child_) {
		forkblock_mtx_.lock();
	}
}

void atfork_unlock_forkblock()
{
	// Unsafe if fork is called from a signal handler
	if (!forked_child_) {
		forkblock_mtx_.unlock();
	}
}

void atfork_check_forkblocks()
{
	// Last line of defense.
	if (forkblocks_) {
		_exit(1);
	}
	forked_child_ = true;
}


int const atfork_registered = []() {
	return pthread_atfork(&atfork_lock_forkblock, &atfork_unlock_forkblock, &atfork_check_forkblocks);
}();
}
#endif

}
