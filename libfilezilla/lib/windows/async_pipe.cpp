#include "../libfilezilla/glue/async_pipe.hpp"
#include "../libfilezilla/event_handler.hpp"
#include "../libfilezilla/util.hpp"

using namespace std::literals;

namespace fz {

namespace {
void reset_handle(HANDLE& handle)
{
	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
		handle = INVALID_HANDLE_VALUE;
	}
}

void reset_event(HANDLE& handle)
{
	if (handle && handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
		handle = 0;
	}
}
}

async_pipe::async_pipe(thread_pool & pool, event_handler & handler)
	: pool_(pool)
	, handler_(handler)
{
}

async_pipe::async_pipe(thread_pool & pool, event_handler& handler, HANDLE read_pipe, HANDLE write_pipe)
	: pool_(pool)
	, handler_(handler)
{
	read_ = read_pipe;
	write_ = write_pipe;
	init();
}

async_pipe::async_pipe(thread_pool & pool, event_handler & handler, std::wstring_view name)
	: pool_(pool)
	, handler_(handler)
{
	connect_named_pipe(name);
}

async_pipe::~async_pipe()
{
	reset();
}

bool async_pipe::connect_named_pipe(std::wstring_view name)
{
	reset();

	std::wstring fullname = L"\\\\.\\pipe\\"s;
	fullname += name;
	read_ = CreateFileW(fullname.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (read_ == INVALID_HANDLE_VALUE) {
		return false;
	}
	write_ = read_;

	return init();
}

bool async_pipe::init()
{
	quit_ = false;
	write_error_ = rwresult{0};
	waiting_read_ = true;
	waiting_write_ = false;

	sync_ = CreateEvent(nullptr, false, false, nullptr);
	ol_read_.hEvent = CreateEvent(nullptr, true, false, nullptr);
	ol_write_.hEvent = CreateEvent(nullptr, true, false, nullptr);
	if (!sync_ || !ol_read_.hEvent || !ol_write_.hEvent) {
		reset();
		return false;
	}

	DWORD res = ReadFile(read_, read_buffer_.get(64 * 1024), 64 * 1024, nullptr, &ol_read_);
	DWORD err = GetLastError();
	if (!res && err != ERROR_IO_PENDING) {
		reset();
		return false;
	}

	task_ = pool_.spawn([this]() { thread_entry(); });
	if (!task_) {
		reset();
		return false;
	}

	return true;
}

bool async_pipe::valid() const
{
	return read_ != INVALID_HANDLE_VALUE && write_ != INVALID_HANDLE_VALUE;
}

namespace {
void remove_pending_events(async_pipe& pipe, fz::event_handler & handler)
{
	auto pipe_event_filter = [&](event_base const& ev) -> bool {
		if (ev.derived_type() == pipe_event::type()) {
			return std::get<0>(static_cast<pipe_event const&>(ev).v_) == &pipe;
		}
		return false;
	};

	handler.filter_events(pipe_event_filter);
}
}

void async_pipe::reset()
{
	{
		scoped_lock l(mutex_);
		if (task_) {
			quit_ = true;
			SetEvent(sync_);
		}
	}
	task_.join();

	if (read_ != INVALID_HANDLE_VALUE && ol_read_.hEvent) {
		if (CancelIoEx(read_, &ol_read_)) {
			DWORD read{};
			while (!GetOverlappedResult(read_, &ol_read_, &read, false) && (GetLastError() == ERROR_IO_PENDING || GetLastError() == ERROR_IO_INCOMPLETE)) {
				yield();
			}
		}
	}
	if (write_ != INVALID_HANDLE_VALUE && ol_write_.hEvent) {
		if (CancelIoEx(write_, &ol_write_)) {
			DWORD written{};
			while (!GetOverlappedResult(write_, &ol_write_, &written, false) && (GetLastError() == ERROR_IO_PENDING || GetLastError() == ERROR_IO_INCOMPLETE)) {
				yield();
			}
		}
	}

	remove_pending_events(*this, handler_);

	reset_event(ol_read_.hEvent);
	reset_event(ol_write_.hEvent);
	reset_event(sync_);

	if (read_ != INVALID_HANDLE_VALUE && read_ != write_) {
		reset_handle(read_);
	}
	reset_handle(write_);

	read_buffer_.clear();
	write_buffer_.clear();
}

void async_pipe::thread_entry()
{
	scoped_lock l(mutex_);
	HANDLE handles[3];
	handles[0] = sync_;

	while (!quit_) {

		DWORD n = 1;
		if (waiting_read_) {
			handles[n++] = ol_read_.hEvent;
		}
		if (!write_buffer_.empty()) {
			handles[n++] = ol_write_.hEvent;
		}

		l.unlock();
		DWORD res = WaitForMultipleObjects(n, handles, false, INFINITE);
		l.lock();
		if (quit_) {
			break;
		}

		if (res > WAIT_OBJECT_0 && res < (WAIT_OBJECT_0 + n)) {
			HANDLE h = handles[res - WAIT_OBJECT_0];
			if (h == ol_read_.hEvent) {
				waiting_read_ = false;
				handler_.send_event<pipe_event>(this, pipe_event_flag::read);
			}
			else if (h == ol_write_.hEvent && !write_buffer_.empty()) {
				DWORD written{};
				DWORD res = GetOverlappedResult(write_, &ol_write_, &written, false);
				if (res) {
					write_buffer_.consume(written);
					if (!write_buffer_.empty()) {
						DWORD res = WriteFile(write_, write_buffer_.get(), clamped_cast<DWORD>(write_buffer_.size()), nullptr, &ol_write_);
						DWORD err = GetLastError();
						if (res || err == ERROR_IO_PENDING) {
							continue;
						}
						write_buffer_.clear();
						write_error_ = rwresult{rwresult::other, err};
					}
				}
				else {
					DWORD err = GetLastError();
					if (err == ERROR_IO_PENDING || err == ERROR_IO_INCOMPLETE) {
						continue;
					}
					write_buffer_.clear();
					write_error_ = rwresult{rwresult::other, err};
				}

				if (waiting_write_) {
					waiting_write_ = false;
					handler_.send_event<pipe_event>(this, pipe_event_flag::write);
				}
			}
		}
		else if (res != WAIT_OBJECT_0) {
			break;
		}
	}
}

rwresult async_pipe::read(void* buffer, size_t len)
{
	if (!len || read_ == INVALID_HANDLE_VALUE) {
		return rwresult{rwresult::invalid, 0};
	}

	scoped_lock l(mutex_);
	while (true) {
		if (!read_buffer_.empty()) {
			len = std::min(read_buffer_.size(), len);
			memcpy(buffer, read_buffer_.get(), len);
			read_buffer_.consume(len);

			if (read_buffer_.empty()) {
				DWORD res = ReadFile(read_, read_buffer_.get(64 * 1024), 64 * 1024, nullptr, &ol_read_);
				DWORD err = GetLastError();
				if (!res) {
					if (err != ERROR_IO_PENDING) {
						return rwresult{rwresult::other, err};
					}
				}
			}
			return rwresult(len);
		}
		if (waiting_read_) {
			return rwresult{rwresult::wouldblock, 0};
		}

		DWORD read{};
		DWORD res = GetOverlappedResult(read_, &ol_read_, &read, false);
		if (res) {
			read_buffer_.add(read);
		}
		else {
			DWORD err = GetLastError();
			if (err == ERROR_IO_PENDING || err == ERROR_IO_INCOMPLETE) {
				waiting_read_ = true;
				SetEvent(sync_);
				return rwresult{rwresult::wouldblock, 0};
			}
			else if (err == ERROR_HANDLE_EOF || err == ERROR_BROKEN_PIPE) {
				return rwresult(0);
			}
			return rwresult{rwresult::other, err};
		}
	}
}

rwresult async_pipe::write(void const* buffer, size_t len)
{
	scoped_lock l(mutex_);
	if (write_ == INVALID_HANDLE_VALUE) {
		return rwresult{rwresult::invalid, 0};
	}
	if (waiting_write_ || !write_buffer_.empty()) {
		waiting_write_ = true;
		return rwresult{rwresult::wouldblock, 0};
	}
	if (write_error_.error_) {
		return write_error_;
	}
	write_buffer_.append(reinterpret_cast<unsigned char const*>(buffer), len);

	DWORD res = WriteFile(write_, write_buffer_.get(), clamped_cast<DWORD>(write_buffer_.size()), nullptr, &ol_write_);
	DWORD err = GetLastError();
	if (res || err == ERROR_IO_PENDING) {
		SetEvent(sync_);
		return rwresult(len);
	}
	write_error_ = rwresult{rwresult::other, err};
	return write_error_;
}

}
