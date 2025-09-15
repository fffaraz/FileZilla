#ifndef LIBFILEZILLA_THREAD_POOL_HEADER
#define LIBFILEZILLA_THREAD_POOL_HEADER

#include "libfilezilla.hpp"
#include "mutex.hpp"

#include <functional>
#include <memory>
#include <vector>

/** \file
 * \brief Declares \ref fz::thread_pool "thread_pool" and \ref fz::async_task "async_task"
 */

namespace fz {

class thread_pool;

/// \private
class async_task_impl;

/** \brief Handle for asynchronous tasks
 */
class FZ_PUBLIC_SYMBOL async_task final {
public:
	async_task() = default;

	/// If task has not been detached, calls join
	~async_task();

	async_task(async_task const&) = delete;
	async_task& operator=(async_task const&) = delete;

	async_task(async_task && other) noexcept;
	async_task& operator=(async_task && other) noexcept;

	/// Wait for the task to finish, adds the now idle thread back into the pool
	void join();

	/// Check whether it's a spawned, unjoined task.
	explicit operator bool() const { return impl_ != nullptr; }

	/// Detach the running thread from the task. Once done, the thread adds itself back into the pool
	void detach();

private:
	friend class thread_pool;

	async_task_impl* impl_{};
};

/// \private
class pooled_thread_impl;

/** \brief A dumb thread-pool for asynchronous tasks
 *
 * If there are no idle threads, threads are created on-demand if spawning an asynchronous task.
 * Once an asynchronous task finishes, the corresponding thread is kept idle until the pool is
 * destroyed.
 *
 * Any number of tasks can be run concurrently.
 */
class FZ_PUBLIC_SYMBOL thread_pool final
{
public:
	thread_pool();
	~thread_pool();

	thread_pool(thread_pool const&) = delete;
	thread_pool& operator=(thread_pool const&) = delete;

	/// Spawns a new asynchronous task.
	async_task spawn(std::function<void()> const& f);
	async_task spawn(std::function<void()> && f);

private:
	FZ_PRIVATE_SYMBOL pooled_thread_impl* get_or_create_thread();

	friend class async_task;
	friend class pooled_thread_impl;

	std::vector<pooled_thread_impl*> threads_;
	std::vector<pooled_thread_impl*> idle_;
	mutex m_{false};
	bool quit_{};
};

}

#endif
