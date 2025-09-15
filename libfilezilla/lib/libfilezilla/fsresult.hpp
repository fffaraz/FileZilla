#ifndef LIBFILEZILLA_FSRESULT_HEADER
#define LIBFILEZILLA_FSRESULT_HEADER

/** \file
 * \brief \ref fz::result and \ref fz::rwresult wrappers for dealing with file system errors.
 */

#include "private/visibility.hpp"

#include <stdint.h>
#include <stddef.h>

namespace fz {

/**
 * \brief Small class to return filesystem errors
 *
 * Note that now all system errors are recognized in all situations,
 * "other" is always a possible error value even if another category
 * would fit better.
 *
 * The raw error code isn't always available. If available, it is
 * the value of errno/GetLastError() when the failure occurred.
 */
class FZ_PUBLIC_SYMBOL result
{
public:
	enum error {
		ok,
		none = ok,

		/// Invalid arguments, syntax error
		invalid,

		/// Permission denied
		noperm,

		/// Requested file does not exist or is not a file
		nofile,

		/// Requested dir does not exist or is not a dir
		nodir,

		/// Out of disk space (physical, or space quota)
		nospace,

		/// Dynamic resource utilization, like too many open files
		resource_limit,

		/// File already exists when asked to explicitly create a new file
		preexisting,

		/// Some other error
		other
	};

#if FZ_WINDOWS
	typedef uint32_t raw_t; // DWORD alternative without windows.h
#else
	typedef int raw_t;
#endif

	explicit operator bool() const { return error_ == 0; }

	error error_{};

	raw_t raw_{};
};

/**
 * \brief Holds the result of read/write operations.
 *
 * On success, returns the number of bytes read/written.
 *
 * The raw error code isn't always available. If available, it is
 * the value of errno/GetLastError() when the failure occurred.
 */

class FZ_PUBLIC_SYMBOL rwresult final
{
public:
#if FZ_WINDOWS
	typedef uint32_t raw_t; // DWORD alternative without windows.h
#else
	typedef int raw_t;
#endif

	enum error {
		none,

		/// Invalid arguments, syntax error
		invalid,

		/// Out of disk space
		nospace,

		/// The operation would have blocked, but the file descriptor is marked non-blocking
		wouldblock,

		/// Some other error
		other
	};

	rwresult() = default;

	explicit rwresult(error e, raw_t raw)
	    : error_(e)
	    , raw_(raw)
	{}

	explicit rwresult(size_t value)
	    : value_(value)
	{}

	explicit operator bool() const { return error_ == 0; }

	error error_{};

	union {
		/// Undefined if error_ is none
		raw_t raw_;

		/// Undefined if error_ is not none
		size_t value_{};
	};
};
}

#endif
