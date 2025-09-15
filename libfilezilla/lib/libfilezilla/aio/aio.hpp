#ifndef LIBFILEZILLA_AIO_HEADER
#define LIBFILEZILLA_AIO_HEADER

/** \file
 * \brief Buffer management and wait machinery for asynchronous I/O
 */

#include "../event.hpp"
#include "../event_handler.hpp"
#include "../mutex.hpp"
#include "../nonowning_buffer.hpp"

#include <tuple>

namespace fz {

class aio_buffer_pool;

/**
 * A buffer leased from aio_buffer_pool
 *
 * The owner of the buffer_lease has exclusive access to the buffer until
 * the buffer_lease is released back into the pool. Ownership can be moved.
 */
class FZ_PUBLIC_SYMBOL buffer_lease final
{
public:
	constexpr buffer_lease() noexcept = default;
	~buffer_lease() noexcept
	{
		release();
	}

	buffer_lease(buffer_lease && op) noexcept;
	buffer_lease& operator=(buffer_lease && op) noexcept;

	buffer_lease(buffer_lease const&) = delete;
	buffer_lease& operator=(buffer_lease const&) = delete;

	explicit operator bool() const { return pool_ != nullptr; }

	// operator. would be nice
	nonowning_buffer const* operator->() const { return &buffer_; }
	nonowning_buffer* operator->() { return &buffer_; }
	nonowning_buffer const& operator*() const { return buffer_; }
	nonowning_buffer & operator*() { return buffer_; }

	void release();

	nonowning_buffer buffer_;
private:
	friend class aio_buffer_pool;
	FZ_PRIVATE_SYMBOL buffer_lease(nonowning_buffer b, aio_buffer_pool* pool)
	    : buffer_(b)
	    , pool_(pool)
	{
	}

	aio_buffer_pool* pool_{};
};

class aio_waitable;
class event_handler;

/**
 * Object that can be waited on, such as fz::io_buffer_pool or fz::reader_base
 */
class FZ_PUBLIC_SYMBOL aio_waitable
{
public:
	virtual ~aio_waitable() = default;

	/** Waiters should call these in the destructor of the most-derived
	 * class, \sa fz::event_handler::remove_handler
	 */
	void remove_waiter(event_handler & h);

protected:

	/// Call in destructor of most-derived class
	void remove_waiters();

	void add_waiter(event_handler & h);

	///
	void signal_availibility();

private:

	mutex m_;
	std::vector<event_handler*> waiting_handlers_;
};

/// \private
struct aio_buffer_event_type{};

typedef simple_event<aio_buffer_event_type, aio_waitable const*> aio_buffer_event;

class logger_interface;

/**
 * \brief A buffer pool for use with async readers/writers
 *
 * Can use shared memory, see \ref shared_memory_info()
 */
class FZ_PUBLIC_SYMBOL aio_buffer_pool final : public aio_waitable
{
public:
	// If buffer_size is 0, it picks a suitable default
#if FZ_MAC
	// On macOS, if using sandboxing, you need to pass an application group identifier.
	aio_buffer_pool(thread_pool & tpool, logger_interface & logger, size_t buffer_count = 1, size_t buffer_size = 0, bool use_shm = false, std::string_view application_group_id = {});
#else
	aio_buffer_pool(thread_pool & tpool, logger_interface & logger, size_t buffer_count = 1, size_t buffer_size = 0, bool use_shm = false);
#endif
	~aio_buffer_pool() noexcept;

	operator bool() const {
		return memory_ != nullptr;
	}

	/**
	 * \brief Returns either a buffer lease, or records the passed waiter/handler as waiting.
	 *
	 * If waiting, do not call get_buffer again until after waiter/handler got signalled.
	 *
	 * If a buffer becomes available and there are multiple waiters, the order in
	 * waiters are signaled is undefined.
	 */
	buffer_lease get_buffer(event_handler & h);

	logger_interface & logger() const { return logger_; }

#if FZ_WINDOWS
	// A HANDLE
	typedef void* shm_handle;
	static shm_handle const shm_handle_default;
#else
	// A file descriptor
	typedef int shm_handle;
	static shm_handle constexpr shm_handle_default{-1};
#endif

	/**
	 * Returns a tuple with information on the mapping
	 *
	 * - A file descriptor or handle backing the memory
	 * - The base address of the mapping
	 * - Total size of the memory mapping
	 *
	 * To pass buffer leases to a child process:
	 * - Pass the fd/handle and total size to the child
	 * - Create mapping in the child, obtaining its own base address
	 * - If parent gets a buffer lease, parent calculates offset to the base
	 *   address, passes offset and buffer size to child
	 * - Child computes actuall address from offset and its own base address
	 * - Parent keeps lease until the child signals that it's done with that
	 *   buffer
	 *
	 * \warning The child has write access to the mapping, do not pass the
	 * fd/handle to untrusted children
	 */
	std::tuple<shm_handle, uint8_t const*, size_t> shared_memory_info() const;

	size_t buffer_count() const { return buffer_count_; }

	event_loop& loop() { return loop_; }

private:
	friend class buffer_lease;
	void FZ_PRIVATE_SYMBOL release(nonowning_buffer && b);

	event_loop loop_;
	logger_interface & logger_;

	mutable mutex mtx_;

	uint64_t memory_size_{};
	uint8_t* memory_{};

	std::vector<nonowning_buffer> buffers_;

	shm_handle shm_{shm_handle_default};

	size_t const buffer_count_{};
};

/// Result of aio operations
enum class aio_result
{
	/// Success, proceed.
	ok,

	/// Must wait on being signalled before either retrying or continuing,
	/// exact semantics depend on the function returning this value.
	wait,

	/// Operationf failed.
	error
};

class FZ_PUBLIC_SYMBOL aio_base
{
public:
	virtual ~aio_base() noexcept = default;

	using size_type = uint64_t;
	static constexpr auto nosize = static_cast<size_type>(-1);
};

}

#endif
