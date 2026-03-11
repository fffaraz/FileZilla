#ifndef LIBFILEZILLA_GLUE_ASYNC_PIPE_HEADER
#define LIBFILEZILLA_GLUE_ASYNC_PIPE_HEADER

#include "../libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../buffer.hpp"
#include "../event.hpp"
#include "../fsresult.hpp"
#include "../thread_pool.hpp"

#include "windows.hpp"

namespace fz {

class event_handler;


/** \brief The type of a pipe event
 *
 * In received events, exactly a single bit is always set.
 */
enum class pipe_event_flag
{
	/// Data has become available.
	read = 0x1,

	/// data can be written.
	write = 0x2,
};

/// \private
struct pipe_event_type;

class async_pipe;

/**
 * All processevents are sent through this.
 *
 * \sa \ref fz::process_event_flag
 *
 * Read and write events are edge-triggered:
 * - After receiving a read event for a process, it will not be sent again
 *   unless a subsequent call to process::read has returned EAGAIN.
 * - The same holds for the write event and process::write
 *
 * It is a grave violation to call the read/write functions
 * again after they returned EAGAIN without first waiting for the event.
 */
typedef simple_event<pipe_event_type, async_pipe*, pipe_event_flag> pipe_event;


class FZ_PUBLIC_SYMBOL async_pipe final
{
public:
	// Connect a named pipe to a pipe server
	async_pipe(thread_pool & pool, event_handler& h);
	async_pipe(thread_pool & pool, event_handler& h, HANDLE read_pipe, HANDLE write_pipe);
	async_pipe(thread_pool & pool, event_handler& h, std::wstring_view name);
	~async_pipe();

	async_pipe(async_pipe const&) = delete;
	async_pipe& operator=(async_pipe const&) = delete;

	bool connect_named_pipe(std::wstring_view name);

	bool valid() const;

	void reset();

	/** \brief Read data from process
	 *
	 * \return >0 Number of octets read, can be less than requested
	 * \return 0 on EOF
	 * \return -1 on error.
	 */
	rwresult read(void* buffer, size_t len);

	/** \brief Write data data process
	 *
	 * \return true if all octets have been written.
	 * \return false on error.
	 */
	rwresult write(void const* buffer, size_t len);

	inline rwresult write(std::string_view const& s) {
		return write(s.data(), s.size());
	}

private:
	bool init();
	void thread_entry();
	thread_pool & pool_;
	event_handler & handler_;

	mutex mutex_{false};
	async_task task_;
	buffer read_buffer_;
	buffer write_buffer_;
	HANDLE sync_{INVALID_HANDLE_VALUE};
	OVERLAPPED ol_read_{};
	OVERLAPPED ol_write_{};
	rwresult write_error_{0};
	bool waiting_read_{true};
	bool waiting_write_{};
	bool quit_{};

	HANDLE read_{INVALID_HANDLE_VALUE};
	HANDLE write_{INVALID_HANDLE_VALUE};
};

}

#else
#error This file is for Windows only
#endif

#endif
