#include "impersonation_desktop_helper.hpp"

#ifdef FZ_WINDOWS

#include "helpers.hpp"
#include "impersonation_helper.hpp"

#include "../libfilezilla/encode.hpp"
#include "../libfilezilla/format.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/process.hpp"
#include "../libfilezilla/translate.hpp"
#include "../libfilezilla/util.hpp"
#include "../libfilezilla/glue/dll.hpp"

#include <aclapi.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

extern "C" FZ_PUBLIC_SYMBOL void CALLBACK fz_impersonation_desktop_helper(HWND, HINSTANCE, LPSTR, int);

namespace fz::windows {
void window_station_closer::operator()(HWINSTA h) const
{
	if (h) {
		FZ_DLL_IMPORT(user32dll(), CloseWindowStation);
		if (CloseWindowStation) {
			CloseWindowStation(h);
		}
	}
}

void desktop_closer::operator()(HDESK h) const
{
	if (h) {
		FZ_DLL_IMPORT(user32dll(), CloseDesktop);
		if (CloseDesktop) {
    		CloseDesktop(h);
		}
	}
}
}

namespace {

namespace helper = fz::windows::impersonation_helper;

constexpr DWORD desktop_all_access =
	STANDARD_RIGHTS_REQUIRED |
	DESKTOP_CREATEMENU |
	DESKTOP_CREATEWINDOW |
	DESKTOP_ENUMERATE |
	DESKTOP_HOOKCONTROL |
	DESKTOP_READOBJECTS |
	DESKTOP_WRITEOBJECTS;

/*
Desktop helper request:

  helper::header header   flags must be 0
  uintptr token           helper-local duplicated token handle
  string desktop_prefix   prefix used to create the desktop name

Desktop helper success response:

  helper::header header   success flag set
  uintptr window_station  helper-local window station handle
  uintptr desktop         helper-local desktop handle
*/
struct helper_desktop final
{
	fz::windows::unique_window_station window_station;
	fz::windows::unique_desktop desktop;

	explicit operator bool() const
	{
		return window_station && desktop;
	}
};

struct helper_desktop_result final
{
	helper_desktop desktop;
	std::wstring error;
};

struct token_groups_holder final
{
	explicit token_groups_holder(HANDLE token)
	{
		DWORD needed{};
		GetTokenInformation(token, TokenGroups, nullptr, 0, &needed);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed) {
			return;
		}

		buffer_.resize(needed);
		groups_ = reinterpret_cast<TOKEN_GROUPS *>(buffer_.data());
		if (!GetTokenInformation(token, TokenGroups, groups_, needed, &needed)) {
			groups_ = nullptr;
		}
	}

	token_groups_holder(token_groups_holder const&) = delete;
	token_groups_holder& operator=(token_groups_holder const&) = delete;
	token_groups_holder(token_groups_holder&&) = delete;
	token_groups_holder& operator=(token_groups_holder&&) = delete;

	PSID logon_sid() const
	{
		if (!groups_) {
			return nullptr;
		}

		for (DWORD i = 0; i < groups_->GroupCount; ++i) {
			auto const &group = groups_->Groups[i];
			if (group.Attributes & SE_GROUP_LOGON_ID) {
				return group.Sid;
			}
		}

		return nullptr;
	}

private:
	std::vector<unsigned char> buffer_;
	TOKEN_GROUPS *groups_{};
};

class user_object_security final
{
public:
	explicit user_object_security(PSID sid)
	{
		auto process_user = get_process_user();
		if (!process_user) {
			return;
		}

		std::array<EXPLICIT_ACCESSW, 2> access{};
		init_access(access[0], sid);
		init_access(access[1], process_user);

		auto const error = SetEntriesInAclW(static_cast<ULONG>(access.size()), access.data(), nullptr, &acl_);
		if (error != ERROR_SUCCESS) {
			return;
		}

		if (!InitializeSecurityDescriptor(&sd_, SECURITY_DESCRIPTOR_REVISION)) {
			return;
		}

		if (!SetSecurityDescriptorDacl(&sd_, TRUE, acl_, FALSE)) {
			return;
		}

		attr_.nLength = sizeof(attr_);
		attr_.lpSecurityDescriptor = &sd_;
		attr_.bInheritHandle = FALSE;
		valid_ = true;
	}

	~user_object_security()
	{
		if (acl_) {
			LocalFree(acl_);
		}
	}

	user_object_security(user_object_security const&) = delete;
	user_object_security& operator=(user_object_security const&) = delete;

	explicit operator bool() const
	{
		return valid_;
	}

	SECURITY_ATTRIBUTES *attributes()
	{
		return &attr_;
	}

private:
	static void init_access(EXPLICIT_ACCESSW &access, PSID sid)
	{
		access.grfAccessPermissions = GENERIC_ALL;
		access.grfAccessMode = SET_ACCESS;
		access.grfInheritance = NO_INHERITANCE;
		access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		access.Trustee.TrusteeType = TRUSTEE_IS_USER;
		access.Trustee.ptstrName = static_cast<LPWSTR>(sid);
	}

	PSID get_process_user()
	{
		fz::windows::unique_handle token;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, fz::windows::out_ptr(token))) {
			return nullptr;
		}

		DWORD needed{};
		GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !needed) {
			return nullptr;
		}

		process_user_.resize(needed);
		auto user = reinterpret_cast<TOKEN_USER *>(process_user_.data());
		if (!GetTokenInformation(token.get(), TokenUser, user, needed, &needed)) {
			return nullptr;
		}

		return user->User.Sid;
	}

	PACL acl_{};
	SECURITY_DESCRIPTOR sd_{};
	SECURITY_ATTRIBUTES attr_{};
	std::vector<unsigned char> process_user_;
	bool valid_{};
};

class scoped_token_impersonation final
{
public:
	explicit scoped_token_impersonation(HANDLE token)
		: active_(ImpersonateLoggedOnUser(token))
	{
	}

	~scoped_token_impersonation()
	{
		if (active_ && !RevertToSelf()) {
			TerminateProcess(GetCurrentProcess(), 1);
		}
	}

	scoped_token_impersonation(scoped_token_impersonation const&) = delete;
	scoped_token_impersonation& operator=(scoped_token_impersonation const&) = delete;

	explicit operator bool() const
	{
		return active_;
	}

	bool revert()
	{
		if (!active_) {
			return true;
		}

		if (!RevertToSelf()) {
			return false;
		}

		active_ = false;
		return true;
	}

private:
	bool active_{};
};

class window_station final
{
public:
	window_station() = default;

	static window_station create(wchar_t const *name, DWORD access, SECURITY_ATTRIBUTES *security)
	{
		FZ_DLL_IMPORT(fz::user32dll(), CreateWindowStationW);
		if (!CreateWindowStationW) {
			SetLastError(ERROR_DLL_INIT_FAILED);
			return {};
		}

		return window_station(fz::windows::unique_window_station(CreateWindowStationW(name, 0, access, security)));
	}

	static window_station open(std::wstring const &name, DWORD access)
	{
		return window_station(fz::windows::unique_window_station(OpenWindowStationW(name.c_str(), FALSE, access)));
	}

	explicit operator bool() const
	{
		return !!station_;
	}

	HWINSTA get() const
	{
		return station_.get();
	}

	fz::windows::unique_window_station release()
	{
		return std::move(station_);
	}

	fz::windows::unique_desktop create_desktop(std::wstring const &name, DWORD access, SECURITY_ATTRIBUTES *security, DWORD &error)
	{
		return with_selected(error, [&]() {
			FZ_DLL_IMPORT(fz::user32dll(), CreateDesktopW);
			if (!CreateDesktopW) {
				error = ERROR_DLL_INIT_FAILED;
				return fz::windows::unique_desktop{nullptr};
			}
			return fz::windows::unique_desktop(CreateDesktopW(name.c_str(), nullptr, nullptr, 0, access, security));
		});
	}

private:
	explicit window_station(fz::windows::unique_window_station station)
		: station_(std::move(station))
	{
	}

	template <typename F>
	fz::windows::unique_desktop with_selected(DWORD &error, F &&f)
	{
		FZ_DLL_IMPORT(fz::user32dll(), GetProcessWindowStation);
		FZ_DLL_IMPORT(fz::user32dll(), SetProcessWindowStation);
		if (!GetProcessWindowStation || !SetProcessWindowStation) {
			error = ERROR_DLL_INIT_FAILED;
			return {};
		}

		auto previous = GetProcessWindowStation();
		if (!SetProcessWindowStation(station_.get())) {
			error = GetLastError();
			return {};
		}

		auto ret = f();
		error = ret ? ERROR_SUCCESS : GetLastError();
		if (!SetProcessWindowStation(previous)) {
			TerminateProcess(GetCurrentProcess(), 1);
		}

		return ret;
	}

	fz::windows::unique_window_station station_;
};

std::wstring get_user_object_name(HANDLE object)
{
	FZ_DLL_IMPORT(fz::user32dll(), GetUserObjectInformationW);
	if (!GetUserObjectInformationW) {
		SetLastError(ERROR_DLL_INIT_FAILED);
		return {};
	}

	DWORD needed{};
	GetUserObjectInformationW(object, UOI_NAME, nullptr, 0, &needed);
	if (!needed) {
		return {};
	}

	std::wstring name(needed / sizeof(wchar_t), L'\0');
	if (!GetUserObjectInformationW(object, UOI_NAME, name.data(), needed, &needed)) {
		return {};
	}

	name.resize(std::char_traits<wchar_t>::length(name.data()));
	return name;
}

bool is_valid_desktop_name_prefix(std::wstring const &prefix)
{
	return prefix.find_first_of(L"\\/") == std::wstring::npos;
}

std::wstring make_isolated_desktop_name(std::wstring const &prefix)
{
	auto random = fz::hex_encode<std::wstring>(fz::random_bytes(16));
	if (prefix.empty()) {
		return random;
	}

	return prefix + L'-' + random;
}

std::wstring win32_error_string(wchar_t const *what, DWORD error)
{
	return fz::sprintf(fztranslate("%s failed. Last Error: %d."), what, error);
}

fz::windows::unique_handle make_desktop_token(HANDLE token, DWORD &error)
{
	fz::windows::unique_handle desktop_token;
	if (!DuplicateTokenEx(
		token,
		TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
		nullptr,
		SecurityImpersonation,
		TokenImpersonation,
		fz::windows::out_ptr(desktop_token)
	)) {
		error = GetLastError();
		return {};
	}

	auto sid = fz::windows::holder<SID>::create(SECURITY_MAX_SID_SIZE);
	DWORD sid_size = SECURITY_MAX_SID_SIZE;
	if (!CreateWellKnownSid(WinUntrustedLabelSid, nullptr, sid.get(), &sid_size)) {
		error = GetLastError();
		return {};
	}

	TOKEN_MANDATORY_LABEL label{};
	label.Label.Sid = sid.get();
	label.Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
	if (!SetTokenInformation(
		desktop_token.get(),
		TokenIntegrityLevel,
		&label,
		static_cast<DWORD>(sizeof(label) + sid_size)
	)) {
		error = GetLastError();
		return {};
	}

	error = ERROR_SUCCESS;
	return desktop_token;
}

helper_desktop_result create_isolated_desktop(HANDLE token, std::wstring const &desktop_name_prefix)
{
	DWORD token_error{};
	auto desktop_token = make_desktop_token(token, token_error);
	if (!desktop_token) {
		return {{}, win32_error_string(L"Desktop token creation", token_error)};
	}

	token_groups_holder groups(desktop_token.get());
	auto logon_sid = groups.logon_sid();
	if (!logon_sid) {
		return {{}, L"Token has no logon SID."};
	}

	user_object_security security(logon_sid);
	if (!security) {
		return {{}, L"Could not create security descriptor for user objects."};
	}

	scoped_token_impersonation impersonation(desktop_token.get());
	if (!impersonation) {
		return {{}, win32_error_string(L"ImpersonateLoggedOnUser", GetLastError())};
	}

	// A null name creates/opens the station bound to the impersonated user's logon session.
	// If the station already exists, Windows ignores the security attributes.
	auto station = window_station::create(nullptr, WINSTA_ALL_ACCESS, security.attributes());
	if (!station) {
		return {{}, win32_error_string(L"CreateWindowStationW", GetLastError())};
	}

	if (!impersonation.revert()) {
		return {{}, win32_error_string(L"RevertToSelf", GetLastError())};
	}

	auto station_name = get_user_object_name(station.get());
	if (station_name.empty()) {
		return {{}, L"Could not read the generated window station name."};
	}

	auto desktop_name = make_isolated_desktop_name(desktop_name_prefix);
	DWORD desktop_error{};
	auto desktop = station.create_desktop(desktop_name, desktop_all_access, security.attributes(), desktop_error);
	if (!desktop) {
		return {{}, win32_error_string(L"CreateDesktopW", desktop_error)};
	}

	helper_desktop ret;
	ret.window_station = station.release();
	ret.desktop = std::move(desktop);
	return {std::move(ret), {}};
}

}

namespace fz::windows {

std::optional<resolved_impersonation_desktop> resolve_impersonation_desktop(HANDLE token, std::wstring const &desktop_name_prefix, logger_interface &logger)
{
	FZ_DLL_IMPORT(user32dll(), CloseWindowStation);
	FZ_DLL_IMPORT(user32dll(), CloseDesktop);
	if (!CloseWindowStation || !CloseDesktop) {
		logger.log(logmsg::error, fztranslate("impersonation_desktop: use32.dll is not available."));
		return std::nullopt;
	}

	auto const dll_path = helper::current_module_path(reinterpret_cast<void const *>(&fz_impersonation_desktop_helper));
	if (dll_path.empty()) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_desktop: could not locate libfilezilla module. Last Error: %d."), err);
		return std::nullopt;
	}

	fz::process helper_process;
	auto const &rundll32_path = helper::rundll32_path();
	if (rundll32_path.empty()) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_desktop: could not locate rundll32.exe. Last Error: %d."), err);
		return std::nullopt;
	}

	if (!is_valid_desktop_name_prefix(desktop_name_prefix)) {
		logger.log(logmsg::error, fztranslate("impersonation_desktop: invalid isolated desktop name prefix: '%s'."), desktop_name_prefix);
		return std::nullopt;
	}

	logger.log(logmsg::debug_debug, L"impersonation_desktop: starting helper. Rundll32: '%s', Module: '%s', Entry point: 'fz_impersonation_desktop_helper'.", rundll32_path, dll_path);
	if (!helper_process.spawn(rundll32_path, { dll_path, L"fz_impersonation_desktop_helper" }, fz::process::io_redirection::redirect)) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_desktop: could not start rundll32 helper."));
		return std::nullopt;
	}

	HANDLE helper_token{};
	if (!DuplicateHandle(GetCurrentProcess(), token, static_cast<HANDLE>(helper_process.handle()), &helper_token, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_desktop: could not duplicate token into helper. Last Error: %d."), err);
		return std::nullopt;
	}

	auto const token_value = reinterpret_cast<std::uintptr_t>(helper_token);
	helper::writer request(helper_process);
	request.field(token_value).field(desktop_name_prefix);
	if (!request) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_desktop: could not write request to helper."));
		return std::nullopt;
	}

	helper::reader response(helper_process, logger, L"impersonation_desktop");
	if (!response) {
		return std::nullopt;
	}

	resolved_impersonation_desktop ret;
	std::uintptr_t window_station_info{};
	std::uintptr_t desktop_info{};
	response.field(window_station_info).field(desktop_info);
	if (!response) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_desktop: could not read desktop info from helper."));
		return std::nullopt;
	}

	if (!window_station_info || !desktop_info) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_desktop: helper returned invalid desktop info."));
		return std::nullopt;
	}

	HANDLE window_station{};
	if (!DuplicateHandle(static_cast<HANDLE>(helper_process.handle()), reinterpret_cast<HANDLE>(window_station_info), GetCurrentProcess(), &window_station, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_desktop: could not duplicate window station from helper. Last Error: %d."), err);
		return std::nullopt;
	}

	HANDLE desktop{};
	if (!DuplicateHandle(static_cast<HANDLE>(helper_process.handle()), reinterpret_cast<HANDLE>(desktop_info), GetCurrentProcess(), &desktop, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		auto const err = GetLastError();
		CloseWindowStation(reinterpret_cast<HWINSTA>(window_station));
		logger.log(logmsg::error, fztranslate("impersonation_desktop: could not duplicate desktop from helper. Last Error: %d."), err);
		return std::nullopt;
	}

	ret.window_station.reset(reinterpret_cast<HWINSTA>(window_station));
	ret.desktop.reset(reinterpret_cast<HDESK>(desktop));

	auto station_name = get_user_object_name(ret.window_station.get());
	auto desktop_name = get_user_object_name(ret.desktop.get());
	if (station_name.empty() || desktop_name.empty()) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_desktop: could not read returned desktop name."));
		return std::nullopt;
	}

	ret.name = station_name + L'\\' + desktop_name;

	return ret;
}

}

extern "C" FZ_PUBLIC_SYMBOL void CALLBACK fz_impersonation_desktop_helper(HWND, HINSTANCE, LPSTR, int)
{
	auto in_handle = GetStdHandle(STD_INPUT_HANDLE);
	auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!in_handle || in_handle == INVALID_HANDLE_VALUE || !out_handle || out_handle == INVALID_HANDLE_VALUE) {
		return;
	}
	helper::reader in(in_handle, fz::get_null_logger(), L"impersonation_desktop");
	helper::writer out(out_handle, in_handle);
	if (!in) {
		if (in.state() == helper::stream_state::invalid_data) {
			out.invalid();
		}
		return;
	}

	std::uintptr_t token_value{};
	in.field(token_value);
	if (!in) {
		return;
	}

	if (!token_value) {
		out.invalid();
		return;
	}

	fz::windows::unique_handle token(reinterpret_cast<HANDLE>(token_value));

	std::wstring desktop_name_prefix;
	in.field(desktop_name_prefix);
	if (!in) {
		if (in.state() == helper::stream_state::invalid_data) {
			out.invalid();
		}
		return;
	}

	if (!is_valid_desktop_name_prefix(desktop_name_prefix)) {
		out.error(fztranslate("Invalid desktop name prefix."));
		return;
	}

	auto desktop = create_isolated_desktop(token.get(), desktop_name_prefix);
	if (!desktop.desktop) {
		out.error(desktop.error.empty() ? fztranslate("Could not create isolated desktop.") : desktop.error);
		return;
	}

	out.success(
		reinterpret_cast<std::uintptr_t>(desktop.desktop.window_station.get()),
		reinterpret_cast<std::uintptr_t>(desktop.desktop.desktop.get())
	);
}

#endif
