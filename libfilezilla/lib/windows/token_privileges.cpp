#include "token_privileges.hpp"

#ifdef FZ_WINDOWS

#include "helpers.hpp"

#include <array>

namespace fz {
namespace {

using windows::holder;

bool same_luid(LUID const &lhs, LUID const &rhs)
{
	return lhs.LowPart == rhs.LowPart && lhs.HighPart == rhs.HighPart;
}

holder<TOKEN_PRIVILEGES> get_token_privileges(HANDLE token)
{
	DWORD needed{};
	GetTokenInformation(token, TokenPrivileges, nullptr, 0, &needed);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		auto privileges = holder<TOKEN_PRIVILEGES>::create(needed);
		if (GetTokenInformation(token, TokenPrivileges, privileges.get(), needed, &needed)) {
			return privileges;
		}
	}

	return {};
}

enum class process_privilege_state
{
	error,
	missing,
	disabled,
	enabled
};

process_privilege_state get_process_privilege_state(wchar_t const *privilege)
{
	HANDLE token{};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return process_privilege_state::error;
	}

	auto close_token = [&token] {
		if (token) {
			CloseHandle(token);
			token = nullptr;
		}
	};

	LUID luid{};
	if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
		close_token();
		return process_privilege_state::error;
	}

	auto privileges = get_token_privileges(token);
	if (!privileges) {
		close_token();
		return process_privilege_state::error;
	}

	close_token();

	for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
		auto const &entry = privileges->Privileges[i];
		if (same_luid(entry.Luid, luid)) {
			return (entry.Attributes & SE_PRIVILEGE_ENABLED) ? process_privilege_state::enabled : process_privilege_state::disabled;
		}
	}

	return process_privilege_state::missing;
}

}

bool has_process_privilege(wchar_t const *privilege)
{
	auto state = get_process_privilege_state(privilege);
	return state == process_privilege_state::enabled || state == process_privilege_state::disabled;
}

bool DropAdminPrivilegesFromToken(HANDLE h)
{
	auto privs = get_token_privileges(h);
	if (!privs) {
		return false;
	}

	std::array<LUID, 2> allowed;
	if (!LookupPrivilegeValue(nullptr, SE_INC_WORKING_SET_NAME, &allowed[0])) {
		return false;
	}
	if (!LookupPrivilegeValue(nullptr, SE_CHANGE_NOTIFY_NAME, &allowed[1])) {
		return false;
	}

	DWORD out{};
	for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
		bool found{};
		for (auto const& luid : allowed) {
			if (same_luid(luid, privs->Privileges[i].Luid)) {
				found = true;
				break;
			}
		}
		if (!found) {
			privs->Privileges[out].Luid = privs->Privileges[i].Luid;
			privs->Privileges[out].Attributes = SE_PRIVILEGE_REMOVED;
			++out;
		}
	}
	if (out) {
		privs->PrivilegeCount = out;
		if (!AdjustTokenPrivileges(h, false, privs.get(), privs.size(), nullptr, nullptr)) {
			return false;
		}
	}

	return true;
}

}

#endif
