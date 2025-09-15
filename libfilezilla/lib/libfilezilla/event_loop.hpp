#ifndef LIBFILEZILLA_EVENT_LOOP_HEADER
#define LIBFILEZILLA_EVENT_LOOP_HEADER

#include "apply.hpp"
#include "event.hpp"
#include "mutex.hpp"
#include "time.hpp"
#include "thread.hpp"

#include <deque>
#include <functional>
#include <memory>
#include <vector>

/** \file
 * \brief A simple threaded event loop for the typesafe event system
 */

namespace fz {

class async_task;
class event_handler;
class thread_pool;

/** \brief A threaded event loop that supports sending events and timers
 *
 * Timers abd queued events are treated fairly, neither can starve the other by being too frequent.
 *
 * If the deadlines of multiple timers have expired, they get processed in an unspecified order.
 *
 * \sa event_handler for a complete usage example.
 */
class FZ_PUBLIC_SYMBOL event_loop final
{
public:
	/// Spawns a thread and starts the loop
	event_loop();

	/// Takes a thread from the pool and starts the loop
	explicit event_loop(thread_pool & pool);

	enum loop_option
	{
		threadless
	};
	explicit event_loop(loop_option);

	/// Stops the thread
	~event_loop();

	event_loop(event_loop const&) = delete;
	event_loop& operator=(event_loop const&) = delete;

	/** \brief Allows filtering of queued events
	 *
	 * Puts all queued events through the filter function.
	 * The filter function can freely change the passed events.
	 * If the filter function returns true, the corresponding event
	 * gets removed.
	 *
	 * The filter function must not call any function of event_loop.
	 *
	 * Filtering events is a blocking operation and temporarily pauses the loop.
	 */
	void filter_events(std::function<bool (event_handler*&, event_base&)> const& filter);

	/** \brief Stops the loop
	 *
	 * Stops the event loop. It is automatically called by the destructor.
	 *
	 * Does not wait for the loop if the join argument isn't set.
	 */
	void stop(bool join = false);

	 /// Starts the loop in the caller's thread.
	void run();

	bool running() const;

	void resend_current_event() {
		resend_ = true;
	}

private:
	friend class event_handler;

	void FZ_PRIVATE_SYMBOL remove_handler(event_handler* handler);

	timer_id FZ_PRIVATE_SYMBOL add_timer(event_handler* handler, monotonic_clock const& deadline, duration const& interval);
	void FZ_PRIVATE_SYMBOL stop_timer(timer_id id);
	timer_id FZ_PRIVATE_SYMBOL stop_add_timer(timer_id id, event_handler* handler, monotonic_clock const& deadline, duration const& interval);

	void send_event(event_handler* handler, event_base* evt, bool deletable);

	// Process the next (if any) event. Returns true if an event has been processed
	bool FZ_PRIVATE_SYMBOL process_event(scoped_lock & l);

	// Process timers. Returns true if a timer has been triggered
	bool FZ_PRIVATE_SYMBOL process_timers(scoped_lock & l);

	void FZ_PRIVATE_SYMBOL entry();
	void FZ_PRIVATE_SYMBOL timer_entry();

	struct FZ_PRIVATE_SYMBOL timer_data final
	{
		event_handler* handler_{};
		timer_id id_{};
		monotonic_clock deadline_;
		duration interval_{};
	};

	timer_id FZ_PRIVATE_SYMBOL setup_timer(scoped_lock &lock, timer_data &d, event_handler* handler, monotonic_clock const& deadline, duration const& interval);

	typedef std::vector<timer_data> Timers;

	typedef std::deque<std::tuple<event_handler*, event_base*, bool>> Events;
	Events pending_events_;
	Timers timers_;

	mutable mutex sync_;
	condition cond_;

	condition timer_cond_;
	bool do_timers_{};

	event_handler * active_handler_{};

	monotonic_clock deadline_;

	timer_id next_timer_id_{};

	thread::id thread_id_{};

	std::unique_ptr<thread> thread_;
	std::unique_ptr<async_task> task_;

	thread_pool* pool_{};
	std::unique_ptr<thread> timer_thread_;
	std::unique_ptr<async_task> timer_task_;

	bool quit_{};
	bool threadless_{};
	bool resend_{};

	enum class Mode {
		thread,
		tasks,
		threadless
	};
	Mode mode_{};
};

}
#endif
