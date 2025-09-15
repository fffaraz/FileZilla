#ifndef LIBFILEZILLA_PROCESS_HEADER
#define LIBFILEZILLA_PROCESS_HEADER

#include "libfilezilla.hpp"
#include "fsresult.hpp"
#include "event.hpp"
#include "time.hpp"

/** \file
 * \brief Header for the #\ref fz::process "process" class
 */

#include <vector>

namespace fz {
class event_handler;
class impersonation_token;
class thread_pool;


/** \brief The type of a process event
 *
 * In received events, exactly a single bit is always set.
 */
enum class process_event_flag
{
	/// Data has become available.
	read = 0x1,

	/// data can be written.
	write = 0x2,
};

/// \private
struct process_event_type;

class process;

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
typedef simple_event<process_event_type, process*, process_event_flag> process_event;

/** \brief The process class manages an asynchronous process with redirected IO.
 *
 * No console window is being created.

 * To use, spawn the process and, since it's blocking, call read from a different thread.
 */
class FZ_PUBLIC_SYMBOL process final
{
public:
	/// Creates instance for blocking I/O
	process();

	/** \brief Creates instance with non-blocking event-based redirected communication
	 *
	 * Event semantic akin to \ref fz::socket
	 */
	process(thread_pool & pool, event_handler & handler);

	/// If process still running, calls process::kill()
	~process();
	process(process const&) = delete;
	process& operator=(process const&) = delete;

	/// IO redirection modes.
	enum class io_redirection {
		/// Redirect the child's stdin/out/err to pipes which will be interacted with through fz::process::read and fz::process::write
		redirect,

		/// Parent and child share the same stdin/out/err
		none,

		/// Redirects the child's stdin/out/err to pipes closed in the parent process
		closeall,

		/// As redirect, but passes through the parent's stderr
		redirect_except_stderr
	};

	/** \brief Start the process
	 *
	 * This function takes care of properly quoting and escaping the the program's path and its arguments.
	 * Fails if process has already been spawned.
	 *
	 * \param cmd The path of the program to execute
	 * \param args The command-line arguments for the process.
	 *
	 * \note May return \c true even if the process cannot be started. In that case, trying to read from the process
	 * will fail with an error or EOF.
	 *
	 * If the communication is non-blocking, a successful spawn doubles as process event with write flag
	 */
	bool spawn(native_string const& cmd, std::vector<native_string> const& args = std::vector<native_string>(), io_redirection redirect_mode = io_redirection::redirect);

	bool spawn(std::vector<native_string> const& command_with_args, io_redirection redirect_mode = io_redirection::redirect);

#if FZ_WINDOWS || FZ_UNIX
	/// Creates a process running under the user represented by the impersonation token
	bool spawn(impersonation_token const& it, native_string const& cmd, std::vector<native_string> const& args, io_redirection redirect_mode = io_redirection::redirect);
#endif

#ifndef FZ_WINDOWS
	/**
	 * \brief Allows passing additional file descriptors to the process
	 *
	 * This function only exists on *nix, it is not needed on Windows where
	 * DuplicateHandle() can be used instead with the target process as argument.
	 */
	bool spawn(native_string const& cmd, std::vector<native_string> const& args, std::vector<int> const& extra_fds, io_redirection redirect_mode = io_redirection::redirect);

	bool spawn(impersonation_token const& it, native_string const& cmd, std::vector<native_string> const& args, std::vector<int> const& extra_fds, io_redirection redirect_mode = io_redirection::redirect);
#endif

	/**
	 * Forcefully kills the process.
	 *
	 * SIGKILL on *nix, TerminateProcess on Windows.
	 */
	void kill();

	/** \brief Stops the spawned process
	 *
	 * Waits until the process has quit, or the timeout has elapsed. Pass negative timeout to wait indefinately.
	 *
	 * Returns whether the process has quit.
	 *
	 * Sequence of events:
	 * - Closes write side of the communication pipe (after this, child
	 *   will see EOF if reading from its stdin
	 * - On *nix, SIGTERM is also sent to the process
	 * - Function waits until the process has stopped or the timeout has expired.
	 */
	bool stop(duration const& timeout = {});

	/** \brief Read data from process
	 *
	 * This function blocks
	 *
	 * \return >0 Number of octets read, can be less than requested
	 * \return 0 on EOF
	 * \return -1 on error.
	 */
	rwresult read(void* buffer, size_t len);

	/** \brief Write data data process
	 *
	 * This function blocks
	 *
	 * \return true if all octets have been written.
	 * \return false on error.
	 */
	rwresult write(void const* buffer, size_t len);

	inline rwresult write(std::string_view const& s) {
		return write(s.data(), s.size());
	}

#if FZ_WINDOWS
	/** \brief
	 * Returns the HANDLE of the process
	 */
	void* handle() const;
#endif

private:
	class impl;
	impl* impl_;
};


/** \brief Starts a detached process
 *
 * This function takes care of properly quoting and escaping the the program's path and its arguments.
 *
 * \param cmd_with_args The full path of the program to execute and any additional arguments
 *
 * \note May return \c true even if the process cannot be started.
 */
bool FZ_PUBLIC_SYMBOL spawn_detached_process(std::vector<native_string> const& cmd_with_args);

#if !FZ_WINDOWS
/** \brief Temporarily suppress fork() if CLOEXEC cannot be set atomically at creation
 *
 * fz::process::spawn() will wait until there is no forkblock.
 *
 * In case of a wild fork() in third-party code, pthread_atfork handlers will enforce a wait.
 * This may deadlock. Behavior is undefined if fork is called from a signal handler.
 *
 * If you fork while the current thread holds a forklock, the child will immediately exit.
 */
class FZ_PUBLIC_SYMBOL forkblock final
{
public:
	forkblock();
	~forkblock();

	forkblock(forkblock const&) = delete;
	forkblock& operator=(forkblock const&) = delete;
};
#endif

}

#endif
