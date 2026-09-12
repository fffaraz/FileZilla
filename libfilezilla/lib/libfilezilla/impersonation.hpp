#ifndef LIBFILEZILLA_IMPERSONATION_HEADER
#define LIBFILEZILLA_IMPERSONATION_HEADER

/** \file
* \brief Declares \ref fz::impersonation_token
*/

#include <array>
#include <cstddef>
#include <functional>
#include <initializer_list>
#include <memory>
#include <variant>
#include <type_traits>
#include <utility>

#include "string.hpp"
#include "logger.hpp"

#ifdef FZ_WINDOWS
#include "glue/windows.hpp"
#endif

namespace fz {

class logger_interface;

class FZ_PUBLIC_SYMBOL user
{
	// An invalid user. Used only during default construction
	struct FZ_PUBLIC_SYMBOL invalid
	{
		explicit operator bool() const;
	};

public:
	/// A user name
	struct FZ_PUBLIC_SYMBOL name
	{
		fz::native_string value;

		name() = default;
		name(fz::native_string v);

		explicit operator bool() const;
	};

	/// Numeric UID on Unix-like systems, string SID on Windows.
	struct FZ_PUBLIC_SYMBOL id
	{
		std::string value;

		explicit operator bool() const;
	};

	user() = default;

	template <typename T, std::enable_if_t<std::is_constructible_v<name, T>>* = nullptr>
	user(T && user_name)
		: value_(name{std::forward<T>(user_name)})
	{
	}

	user(id user_id);

	explicit operator bool() const;

	fz::native_string const *get_name() const;

	std::string const *get_id() const;

private:
	std::variant<invalid, name, id> value_;
};

#if FZ_WINDOWS
namespace impersonation_desktop
{
	/// Leave STARTUPINFO::lpDesktop unspecified and let Windows select the
	/// window station and desktop.
	///
	/// The selected objects are not prevalidated against the impersonation token.
	/// Spawning may therefore fail, or the process may terminate during startup
	/// if it cannot use the selected window station or desktop.
	struct automatic {};

	/// Create an isolated window station and desktop for spawned processes.
	struct isolated {
		/// Prefix used to create the isolated desktop as <prefix>-<random>.
		/// If empty, the desktop name is just random. Must not contain path separators.
		std::wstring desktop_name_prefix;
	};

	/// Use a caller-provided desktop name, such as L"WinSta0\\Default".
	struct named {
		std::wstring name;
	};

	/// Window station and desktop selection mode for impersonated processes.
	using mode = std::variant<automatic, isolated, named>;
};

enum class impersonation_profile_mode
{
	/// Do not load the user's profile.
	skip,

	/// Load roaming profiles and fail token construction if loading fails.
	/// Do not load local profiles.
	require_if_roaming,

	/// Load the user's profile and fail token construction if loading fails.
	require
};
#endif

struct impersonation_options
{
	/// Impersonate as any user without checking credentials
	struct pwless_type{};
	static constexpr pwless_type pwless{};

#if FZ_WINDOWS
	/// Window station and desktop to assign to processes spawned with the impersonation token.
	/// Defaults to automatic, which leaves STARTUPINFO::lpDesktop unspecified and lets
	/// Windows select the window station and desktop.
	impersonation_desktop::mode desktop = impersonation_desktop::automatic{};

	/// Controls whether the user's profile is loaded.
	impersonation_profile_mode profile = impersonation_profile_mode::require;

	/// If true, remove administrative privileges from the impersonation token.
	bool drop_admin_privileges = true;
#else
	/// If set, overrides the group id.
	fz::native_string group;
#endif
};

class impersonation_token_impl;
class impersonation_token;

enum class impersonation_capability : std::size_t
{
	/// Create and use an impersonation token after verifying a password.
	///
	/// On Unix-like systems, requires root. On Linux, effective CAP_SETUID and
	/// CAP_SETGID capabilities are also sufficient.
	///
	/// On Windows, requires "Replace a process level token"
	/// (SeAssignPrimaryTokenPrivilege).
	password,

	/// Create and use an impersonation token without verifying a password.
	///
	/// On Unix-like systems, requires root. On Linux, effective CAP_SETUID and
	/// CAP_SETGID capabilities are also sufficient.
	///
	/// On Windows, requires "Replace a process level token"
	/// (SeAssignPrimaryTokenPrivilege) and "Act as part of the operating system"
	/// (SeTcbPrivilege).
	passwordless,

	/// Obtain the user's home and initialize any platform user profile state.
	///
	/// On Unix-like systems, this capability is always available.
	///
	/// On Windows, requires running as Administrator or LocalSystem and holding
	/// the backup and restore privileges.
	user_profile
};

enum class impersonation_capability_state
{
	/// The capability was not requested.
	not_requested,

	/// The capability does not apply to the platform.
	not_applicable,

	/// The capability's prerequisites could not be determined.
	indeterminate,

	/// The process does not satisfy the capability's known prerequisites.
	unavailable,

	/// The process satisfies the capability's known prerequisites.
	available
};

class FZ_PUBLIC_SYMBOL impersonation_capabilities final
{
public:
	impersonation_capability_state operator[](impersonation_capability capability) const;

private:
	friend class impersonation_token;

	std::array<impersonation_capability_state, 3> states_{};
};

/**
 * \brief Impersonation tokens for a given user can be used to spawn processes running as that user
 *
 * Platform-specific prerequisites are documented by \ref impersonation_capability.
 * On Windows, the required user rights can be configured through secpol.msc under
 * Local Policies -> User Rights Assignment.
 *
 * Use get_capabilities() to query the process-wide prerequisites that can be determined in advance.
 * User-specific operations can still fail when a token is created or used.
 */
class FZ_PUBLIC_SYMBOL impersonation_token final
{
public:
	impersonation_token();

	impersonation_token(impersonation_token&&) noexcept;
	impersonation_token& operator=(impersonation_token&&) noexcept;

	/// Creates an impersonation token, verifying credentials in the process.
	explicit impersonation_token(fz::user const& user, fz::native_string const &password, fz::logger_interface& logger = get_null_logger(), impersonation_options const& opts = {});
	explicit impersonation_token(fz::user const& user, impersonation_options::pwless_type, fz::logger_interface& logger = get_null_logger(), impersonation_options const& opts = {});

	/// Returns the availability of the requested impersonation capabilities.
	/// Unrequested capabilities are returned as impersonation_capability_state::not_requested.
	static impersonation_capabilities get_capabilities(std::initializer_list<impersonation_capability> requested);

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
	impersonation_token(fz::user const& user, fz::native_string const *password, fz::logger_interface& logger = get_null_logger(), impersonation_options const& opts = {});

	friend class impersonation_token_impl;
	std::unique_ptr<impersonation_token_impl> impl_;
};

#if !FZ_WINDOWS
/// Applies to the entire current process, calls setuid/setgid
bool FZ_PUBLIC_SYMBOL set_process_impersonation(impersonation_token const& token);
#else
HANDLE FZ_PUBLIC_SYMBOL get_handle(impersonation_token const& token);
#endif

/// Returns the username the calling thread is running under
native_string FZ_PUBLIC_SYMBOL current_username();

/// \returns An opaque user unique identifier, if the user exists and no error occurs, an empty string otherwise.
/// \note On some systems, different user names can resolve to the same unique identifier.
std::string FZ_PUBLIC_SYMBOL get_user_id(native_string const& name);

/// \returns A user name suitable for passing to impersonation_token, if the user id exists and no error occurs, an empty string otherwise.
native_string FZ_PUBLIC_SYMBOL get_user_name(std::string const& id);

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
