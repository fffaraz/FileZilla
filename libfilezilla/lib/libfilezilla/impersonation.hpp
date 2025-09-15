#ifndef LIBFILEZILLA_IMPERSONATION_HEADER
#define LIBFILEZILLA_IMPERSONATION_HEADER

/** \file
* \brief Declares \ref fz::impersonation_token
*/

#include <memory>
#include <functional>

#include "string.hpp"
#include "logger.hpp"

#ifdef FZ_WINDOWS
#include "glue/windows.hpp"
#endif

namespace fz {

class logger_interface;

struct impersonation_options
{
	/// Impersonate as any user without checking credentials
	struct pwless_type{};
	static constexpr pwless_type pwless{};

#if FZ_WINDOWS
	bool drop_admin_privileges = true;
#else
	/// If set, overrides the group id.
	fz::native_string group;
#endif
};

class impersonation_token_impl;

/**
 * \brief Impersonation tokens for a given user can be used to spawn processes running as that user
 *
 * Under *nix, the caller needs to be root. On Linux, CAP_SETUID/CAP_SETGID is also sufficient.
 *
 * On Windows, the caller needs to have "Replace a process level token" rights, to be found
 * through secpol.msc -> Local Policies -> User Rights Assignment
 */
class FZ_PUBLIC_SYMBOL impersonation_token final
{
public:
	impersonation_token();

	impersonation_token(impersonation_token&&) noexcept;
	impersonation_token& operator=(impersonation_token&&) noexcept;

	/// Creates an impersonation token, verifying credentials in the process.
	explicit impersonation_token(fz::native_string const& username, fz::native_string const &password, fz::logger_interface& logger = get_null_logger(), impersonation_options const& opts = {});
	explicit impersonation_token(fz::native_string const& username, impersonation_options::pwless_type, fz::logger_interface& logger = get_null_logger(), impersonation_options const& opts = {});

	~impersonation_token() noexcept;

	explicit operator bool() const {
		return impl_.operator bool();
	}

	bool operator==(impersonation_token const&) const;
	bool operator<(impersonation_token const&) const;

	/// Returns the name of the impersonated user
	fz::native_string username() const;

	/// Returns home directory, may be empty.
	fz::native_string home() const;

	/// For std::hash
	std::size_t hash() const noexcept;

	/// A opaque unique identifier
	std::string uid() const;

private:
	impersonation_token(fz::native_string const& username, fz::native_string const *password, fz::logger_interface& logger = get_null_logger(), impersonation_options const& opts = {});

	friend class impersonation_token_impl;
	std::unique_ptr<impersonation_token_impl> impl_;
};

#if !FZ_WINDOWS
/// Applies to the entire current process, calls setuid/setgid
bool FZ_PUBLIC_SYMBOL set_process_impersonation(impersonation_token const& token);
#endif

/// Returns the username the calling thread is running under
native_string FZ_PUBLIC_SYMBOL current_username();

/// \returns An opaque user unique identifier, if the user exists and no error occurs, an empty string otherwise.
/// \note On some systems, different user names can resolve to the same unique identifier.
std::string FZ_PUBLIC_SYMBOL get_user_uid(native_string const& username);

}

namespace std {

/// \private
template <>
struct hash<fz::impersonation_token>
{
	std::size_t operator()(fz::impersonation_token const& op) const noexcept
	{
		return op.hash();
	}
};

}

#endif
