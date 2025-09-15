#ifndef LIBFILEZILLA_THREAD_HEADER
#define LIBFILEZILLA_THREAD_HEADER

#include "libfilezilla.hpp"

#include <functional>

#if !defined(FZ_WINDOWS) || !(defined(__MINGW32__) || defined(__MINGW64__))
#include <thread>
#endif

/** \file
 * \brief Declares \ref fz::thread "thread"
 */

namespace fz {

/** \brief Spawns and represents a new thread of execution
 *
 * This is a replacement of std::thread. Unfortunately std::thread isn't implemented
 * on all MinGW flavors. Most notably, MinGW as shipped by Debian Jessie does not
 * have std::thread.
 *
 * This class only supports joinable threads.
 *
 * \remark Detached threads aren't implemented since they essentially race conditions
 * by design. You cannot use a detached thread and shutdown your program cleanly.
 */
class FZ_PUBLIC_SYMBOL thread final
{
public:
#if defined(FZ_WINDOWS) && (defined(__MINGW32__) || defined(__MINGW64__))
	typedef uint32_t id;
#else
	typedef std::thread::id id;
#endif

	thread() = default;

	/** \brief Implicitly calls join()
	 */
	~thread();

	/** \brief Start the thread.
	 *
	 * If a thread has already been started and not yet joined, this function fails.
	 */
	bool run(std::function<void()> && f);

	/** \brief Join the thread
	 *
	 * join blocks until the spawn thread has quit.
	 *
	 * You must call this at the latest in the destructor of the most-derived class.
	 *
	 * Must not be called from the spawned thread.
	 *
	 * After a successful join you can call \ref run again to spawn another thread.
	 */
	void join();

	/** \brief A thread is joinable after having been started and before it has been joined.
	 *
	 * Must not be called from the spawned thread.
	 */
	bool joinable() const;

	/// Returns unique id of the thread calling the function
	static id own_id();

private:
	class impl;
	friend class impl;
	impl* impl_{};
};
}

#endif
