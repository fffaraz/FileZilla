#ifndef LIBFILEZILLA_RWMUTEX_HEADER
#define LIBFILEZILLA_RWMUTEX_HEADER

/** \file
 * \brief Thread synchronization primitives: rwmutex, scoped_read_lock and scoped_write_lock
 */
#include "libfilezilla.hpp"
#include "time.hpp"

#ifdef FZ_WINDOWS
#include "glue/windows.hpp"
#else
#include <pthread.h>
#endif

namespace fz {

/**
 * \brief Lean rw mutex.
 *
 * This mutex is neither recursive, nor can read locks be upgraded to write locks.
 */
class FZ_PUBLIC_SYMBOL rwmutex final
{
public:
#ifdef FZ_WINDOWS
	explicit rwmutex() = default;
#else
	explicit rwmutex()
	{
		pthread_rwlock_init(&m_, nullptr);
	}
	~rwmutex()
	{
		pthread_rwlock_destroy(&m_);
	}
#endif

	rwmutex(rwmutex const&) = delete;
	rwmutex& operator=(rwmutex const&) = delete;

	/// Beware, manual locking isn't exception safe, use scoped_lock
	void lock_read()
	{
#ifdef FZ_WINDOWS
		AcquireSRWLockShared(&m_);
#else
		pthread_rwlock_rdlock(&m_);
#endif
	}

	void lock_write()
	{
#ifdef FZ_WINDOWS
		AcquireSRWLockExclusive(&m_);
#else
		pthread_rwlock_wrlock(&m_);
#endif
	}

	/// Beware, manual locking isn't exception safe, use scoped_lock
	void unlock_read()
	{
#ifdef FZ_WINDOWS
		ReleaseSRWLockShared(&m_);
#else
		pthread_rwlock_unlock(&m_);
#endif
	}

	void unlock_write()
	{
#ifdef FZ_WINDOWS
		ReleaseSRWLockExclusive(&m_);
#else
		pthread_rwlock_unlock(&m_);
#endif
	}

private:
	friend class scoped_read_lock;
	friend class scoped_write_lock;

#ifdef FZ_WINDOWS
	SRWLOCK m_{};
#else
	pthread_rwlock_t m_;
#endif
};

/** \brief A simple scoped read lock.
 *
 * The lock is acquired on construction and, if still locked, released on destruction.
 * You can manually unlock and re-lock if needed.
 *
 * There can be multiple readers.
 * If there is a writer there's no readers and no other writer.
 */
class FZ_PUBLIC_SYMBOL scoped_read_lock final
{
public:
	explicit scoped_read_lock(rwmutex& m)
		: m_(&m.m_)
	{
#ifdef FZ_WINDOWS
		AcquireSRWLockShared(m_);
#else
		pthread_rwlock_rdlock(m_);
#endif
	}

	~scoped_read_lock()
	{
		if (locked_) {
#ifdef FZ_WINDOWS
			ReleaseSRWLockShared(m_);
#else
			pthread_rwlock_unlock(m_);
#endif
		}

	}

	scoped_read_lock(scoped_read_lock const&) = delete;
	scoped_read_lock& operator=(scoped_read_lock const&) = delete;

	scoped_read_lock(scoped_read_lock&& op) noexcept
	{
		m_ = op.m_;
		op.m_ = 0;
		locked_ = op.locked_;
		op.locked_ = false;
	}

	scoped_read_lock& operator=(scoped_read_lock&& op) noexcept
	{
		if (this != &op) {
			m_ = op.m_;
			op.m_ = 0;
			locked_ = op.locked_;
			op.locked_ = false;
		}
		return *this;
	}

	/** \brief Obtains the mutex.
	 *
	 * Locking an already locked scoped_read_lock results in undefined behavior.
	 */
	void lock()
	{
		locked_ = true;
#ifdef FZ_WINDOWS
		AcquireSRWLockShared(m_);
#else
		pthread_rwlock_rdlock(m_);
#endif
	}

	/** \brief Releases the mutex.
	 *
	 * Releasing a scoped_read_lock that isn't locked results in undefined behavior.
	 */
	void unlock()
	{
		locked_ = false;
#ifdef FZ_WINDOWS
		ReleaseSRWLockShared(m_);
#else
		pthread_rwlock_unlock(m_);
#endif
	}

private:
#ifdef FZ_WINDOWS
	SRWLOCK* m_;
#else
	pthread_rwlock_t* m_;
#endif
	bool locked_{ true };
};

/** \brief A simple scoped read lock.
 *
 * The lock is acquired on construction and, if still locked, released on destruction.
 * You can manually unlock and re-lock if needed.
 */
class FZ_PUBLIC_SYMBOL scoped_write_lock final
{
public:
	explicit scoped_write_lock(rwmutex& m)
		: m_(&m.m_)
	{
#ifdef FZ_WINDOWS
		AcquireSRWLockExclusive(m_);
#else
		pthread_rwlock_wrlock(m_);
#endif
	}

	~scoped_write_lock()
	{
		if (locked_) {
#ifdef FZ_WINDOWS
			ReleaseSRWLockExclusive(m_);
#else
			pthread_rwlock_unlock(m_);
#endif
		}

	}

	scoped_write_lock(scoped_write_lock const&) = delete;
	scoped_write_lock& operator=(scoped_write_lock const&) = delete;

	scoped_write_lock(scoped_write_lock&& op) noexcept
	{
		m_ = op.m_;
		op.m_ = 0;
		locked_ = op.locked_;
		op.locked_ = false;
	}

	scoped_write_lock& operator=(scoped_write_lock&& op) noexcept
	{
		if (this != &op) {
			m_ = op.m_;
			op.m_ = 0;
			locked_ = op.locked_;
			op.locked_ = false;
		}
		return *this;
	}

	/** \brief Obtains the mutex.
	 *
	 * Locking an already locked scoped_write_lock results in undefined behavior.
	 */
	void lock()
	{
		locked_ = true;
#ifdef FZ_WINDOWS
		AcquireSRWLockExclusive(m_);
#else
		pthread_rwlock_wrlock(m_);
#endif
	}

	/** \brief Releases the mutex.
	 *
	 * Releasing a scoped_write_lock that isn't locked results in undefined behavior.
	 */
	void unlock()
	{
		locked_ = false;
#ifdef FZ_WINDOWS
		ReleaseSRWLockExclusive(m_);
#else
		pthread_rwlock_unlock(m_);
#endif
	}

private:
#ifdef FZ_WINDOWS
	SRWLOCK* m_;
#else
	pthread_rwlock_t* m_;
#endif
	bool locked_{ true };
};

}

#endif
