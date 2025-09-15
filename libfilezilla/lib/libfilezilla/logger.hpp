#ifndef LIBFILEZILLA_LOGGER_HEADER
#define LIBFILEZILLA_LOGGER_HEADER

/** \file
 * \brief Interface for logging
 */

#include "format.hpp"

#include <atomic>

namespace fz {
namespace logmsg
{
	enum type : uint64_t
	{
		/// Generic status messages aimed at the user
		status        = 1ull,

		/// Error messages aimed at the user
		error         = 1ull << 1,

		/// Commands, aimed at the users
		command       = 1ull << 2,

		/// Replies, aimed at the users
		reply         = 1ull << 3,

		/// Debug messages aimed at developers
		debug_warning = 1ull << 4,
		debug_info    = 1ull << 5,
		debug_verbose = 1ull << 6,
		debug_debug   = 1ull << 7,

		/// The types in the range custom1 to custom32 are free to use
		/// by programs using libfilezilla for their own use
		custom1     = 1ull << 32,
		custom32    = 1ull << 63
	};
}

/**
 * \brief Abstract interface for logging strings.
 *
 * Each log message has a type. Logging can be enabled or disabled for each type.
 *
 * The actual string to log gets assembled from the format string and its
 * arguments only if the type is supposed to be logged.
 */
class FZ_PUBLIC_SYMBOL logger_interface
{
public:
	logger_interface() noexcept = default;
	virtual ~logger_interface() = default;

	logger_interface(logger_interface const&) = delete;
	logger_interface& operator=(logger_interface const&) = delete;


	/// The one thing you need to override
	virtual void do_log(logmsg::type t, std::wstring && msg) = 0;

	/**
	 * The \arg fmt argument is a format string suitable for fz::sprintf
	 *
	 * Assumes that all narrow string arguments are in the locale's current encoding.
	 */
	template<typename String, typename...Args>
	void log(logmsg::type t, String&& fmt, Args&& ...args)
	{
		if (should_log(t)) {
			std::wstring formatted = fz::sprintf(fz::to_wstring(std::forward<String>(fmt)), args...);
			do_log(t, std::move(formatted));
		}
	}

	/**
	 * The \arg fmt argument is a format string suitable for fz::sprintf
	 *
	 * Assumes that all narrow string arguments, excluding the format string, are in UTF-8
	 */
	template<typename String, typename...Args>
	void log_u(logmsg::type t, String&& fmt, Args const& ...args)
	{
		if (should_log(t)) {
			std::wstring formatted = fz::sprintf(fz::to_wstring(std::forward<String>(fmt)), assume_strings_are_utf8(args)...);
			do_log(t, std::move(formatted));
		}
	}

	/// Logs the raw string, it is not treated as format string
	template<typename String>
	void log_raw(logmsg::type t, String&& msg)
	{
		if (should_log(t)) {
			std::wstring formatted = fz::to_wstring(std::forward<String>(msg));
			do_log(t, std::move(formatted));
		}
	}

	template<typename String>
	void log_u_raw(logmsg::type t, String&& msg)
	{
		if (should_log(t)) {
			std::wstring formatted = fz::to_wstring_from_utf8(std::forward<String>(msg));
			do_log(t, std::move(formatted));
		}
	}

	/// Is any of the passed log levels set
	bool should_log(logmsg::type t) const {
		return level_ & t;
	}

	/// Returns all currently enabled log levels
	logmsg::type levels() const {
		return static_cast<logmsg::type>(level_.load());
	}

	/// Sets which message types should be logged
	virtual void set_all(logmsg::type t) {
		level_ = t;
	}

	/// Sets whether the given types should be logged
	void set(logmsg::type t, bool flag) {
		if (flag) {
			enable(t);
		}
		else {
			disable(t);
		}
	}

	/// Enables logging for the passed message types
	virtual void enable(logmsg::type t) {
		level_ |= t;
	}

	/// Disables logging for the passed message types
	virtual void disable(logmsg::type t) {
		level_ &= ~t;
	}

protected:
	std::atomic<uint64_t> level_{logmsg::status | logmsg::error | logmsg::command | logmsg::reply};

private:
	std::wstring assume_strings_are_utf8(std::string_view const& arg) {
		return fz::to_wstring_from_utf8(arg);
	}
	std::wstring assume_strings_are_utf8(std::string const& arg) {
		return fz::to_wstring_from_utf8(arg);
	}
	std::wstring assume_strings_are_utf8(char const* arg) {
		return fz::to_wstring_from_utf8(arg);
	}

	template <typename T>
	T const& assume_strings_are_utf8(T const& arg) {
		return arg;
	}
};

/// A logger that does not log anything.
class FZ_PUBLIC_SYMBOL null_logger final : public logger_interface
{
public:
	null_logger() noexcept
	{
		disable(levels());
	}

	virtual void do_log(logmsg::type, std::wstring &&) override {}
	virtual void set_all(logmsg::type) override {}
	virtual void enable(logmsg::type) override {}
};

null_logger FZ_PUBLIC_SYMBOL & get_null_logger();

/**
 * \brief A simple logger that writes to stdout
 *
 * Logging will fail for lines that cannot be converted to the current
 * locale's narrow character encoding.
 */
class FZ_PUBLIC_SYMBOL stdout_logger final : public logger_interface
{
public:
	virtual void do_log(logmsg::type, std::wstring &&) override;
};

/**
 * \brief A logger that appends to a native_string
 *
 * Logging will fail for lines that cannot be converted to native_string.
 */
class FZ_PUBLIC_SYMBOL native_string_logger final : public fz::logger_interface
{
public:
	native_string_logger(fz::native_string &str, logmsg::type);

	virtual void do_log(fz::logmsg::type, std::wstring &&) override;

private:
	fz::native_string &str_;
};
}

#endif
