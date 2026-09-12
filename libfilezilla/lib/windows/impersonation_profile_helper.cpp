#include "impersonation_profile_helper.hpp"

#ifdef FZ_WINDOWS

#include "helpers.hpp"
#include "impersonation_helper.hpp"

#include "../libfilezilla/glue/dll.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/process.hpp"
#include "../libfilezilla/translate.hpp"

#include <userenv.h>

#include <cstdint>

extern "C" FZ_PUBLIC_SYMBOL void CALLBACK fz_impersonation_profile_helper(HWND, HINSTANCE, LPSTR, int);

namespace {

namespace helper = fz::windows::impersonation_helper;

/*
Profile helper request:

  helper::header header  flags must be 0
  uintptr token          helper-local duplicated token handle
  string user            PROFILEINFOW::lpUserName
  string server          PROFILEINFOW::lpServerName
  string profile_path    PROFILEINFOW::lpProfilePath

Profile helper success response:

  helper::header header  success flag set
  uintptr profile        helper-local profile registry handle
*/
fz::dll& userenv()
{
	static fz::dll lib(L"userenv.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	return lib;
}

}

namespace fz::windows {

HANDLE load_user_profile(HANDLE token, std::wstring const &user, std::wstring const &server, std::wstring const &roaming_profile_path, logger_interface &logger)
{
	auto const dll_path = helper::current_module_path(reinterpret_cast<void const *>(&fz_impersonation_profile_helper));
	if (dll_path.empty()) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_profile: could not locate libfilezilla module. Last Error: %d."), err);
		return nullptr;
	}

	auto const &rundll32_path = helper::rundll32_path();
	if (rundll32_path.empty()) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_profile: could not locate rundll32.exe. Last Error: %d."), err);
		return nullptr;
	}

	fz::process helper_process;
	logger.log(logmsg::debug_debug, L"impersonation_profile: starting helper. Rundll32: '%s', Module: '%s', Entry point: 'fz_impersonation_profile_helper'.", rundll32_path, dll_path);
	if (!helper_process.spawn(rundll32_path, { dll_path, L"fz_impersonation_profile_helper" }, fz::process::io_redirection::redirect)) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_profile: could not start rundll32 helper."));
		return nullptr;
	}

	HANDLE helper_token{};
	if (!DuplicateHandle(GetCurrentProcess(), token, static_cast<HANDLE>(helper_process.handle()), &helper_token, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_profile: could not duplicate token into helper. Last Error: %d."), err);
		return nullptr;
	}

	auto const token_value = reinterpret_cast<std::uintptr_t>(helper_token);
	helper::writer request(helper_process);
	request.field(token_value)
		.field(user)
		.field(server)
		.field(roaming_profile_path);

	if (!request) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_profile: could not write request to helper."));
		return nullptr;
	}

	helper::reader response(helper_process, logger, L"impersonation_profile");
	if (!response) {
		return nullptr;
	}

	std::uintptr_t response_profile{};
	response.field(response_profile);
	if (!response || !response_profile) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_profile: helper returned invalid profile info."));
		return nullptr;
	}

	HANDLE profile{};
	if (!DuplicateHandle(static_cast<HANDLE>(helper_process.handle()), reinterpret_cast<HANDLE>(response_profile), GetCurrentProcess(), &profile, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_profile: could not duplicate profile handle from helper. Last Error: %d."), err);
		return nullptr;
	}

	return profile;
}

}

extern "C" FZ_PUBLIC_SYMBOL void CALLBACK fz_impersonation_profile_helper(HWND, HINSTANCE, LPSTR, int)
{
	auto in_handle = GetStdHandle(STD_INPUT_HANDLE);
	auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!in_handle || in_handle == INVALID_HANDLE_VALUE || !out_handle || out_handle == INVALID_HANDLE_VALUE) {
		return;
	}
	helper::reader in(in_handle, fz::get_null_logger(), L"impersonation_profile");
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

	std::wstring user;
	std::wstring server;
	std::wstring roaming_profile_path;
	in.field(user)
		.field(server)
		.field(roaming_profile_path);

	if (!in) {
		if (in.state() == helper::stream_state::invalid_data) {
			out.invalid();
		}
		return;
	}

	auto const privilege_error = helper::enable_process_privileges({SE_BACKUP_NAME, SE_RESTORE_NAME});
	if (privilege_error != ERROR_SUCCESS) {
		out.error(L"AdjustTokenPrivileges", privilege_error);
		return;
	}

	PROFILEINFOW info = {};
	info.dwSize = sizeof(info);
	info.dwFlags = PI_NOUI;
	info.lpUserName = user.empty() ? nullptr : user.data();
	info.lpServerName = server.empty() ? nullptr : server.data();
	info.lpProfilePath = roaming_profile_path.empty() ? nullptr : roaming_profile_path.data();

	FZ_DLL_IMPORT(userenv(), LoadUserProfileW);
	if (!LoadUserProfileW) {
		out.error(fztranslate("LoadUserProfileW is not available."));
		return;
	}

	if (!LoadUserProfileW(token.get(), &info)) {
		out.error(L"LoadUserProfileW", GetLastError());
		return;
	}

	out.success(reinterpret_cast<std::uintptr_t>(info.hProfile));
}

#endif
