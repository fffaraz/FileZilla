#include "impersonation_logon_helper.hpp"

#ifdef FZ_WINDOWS

#include "helpers.hpp"
#include "impersonation_helper.hpp"

#include "../libfilezilla/glue/dll.hpp"
#include "../libfilezilla/format.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/process.hpp"
#include "../libfilezilla/translate.hpp"

#include <ntsecapi.h>
#define SECURITY_WIN32
#include <secext.h>
#undef SECURITY_WIN32

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

extern "C" FZ_PUBLIC_SYMBOL void CALLBACK fz_impersonation_logon_helper(HWND, HINSTANCE, LPSTR, int);

namespace {

namespace helper = fz::windows::impersonation_helper;

/*
Logon helper request:

  helper::header header  flags must be 0
  uint32 package         0 = MSV1_0, 1 = Kerberos
  string user            user name, or UPN for Kerberos
  string domain          only present for MSV1_0

Logon helper success response:

  helper::header header  success flag set
  uintptr token          helper-local token handle
  string profile_path    profile path returned by the authentication package
*/
enum class package : std::uint32_t
{
	msv1_0,
	kerberos
};

fz::dll& secur32()
{
	static fz::dll lib(L"secur32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	return lib;
}

fz::dll& advapi32()
{
	static fz::dll lib(L"advapi32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	return lib;
}

struct lsa_handle_closer {
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle) {
			FZ_DLL_IMPORT(secur32(), LsaDeregisterLogonProcess);

			if (LsaDeregisterLogonProcess) {
				LsaDeregisterLogonProcess(handle);
			}
		}
	}
};

using unique_lsa_handle = std::unique_ptr<HANDLE, lsa_handle_closer>;

struct lsa_buffer_closer {
	using pointer = void *;
	void operator()(void *buffer) const
	{
		if (buffer) {
			FZ_DLL_IMPORT(secur32(), LsaFreeReturnBuffer);

			if (LsaFreeReturnBuffer) {
				LsaFreeReturnBuffer(buffer);
			}
		}
	}
};

using unique_lsa_buffer = std::unique_ptr<void, lsa_buffer_closer>;

LSA_STRING make_lsa_string(char *s)
{
	auto len = static_cast<USHORT>(std::strlen(s));
	return LSA_STRING{len, static_cast<USHORT>(len + 1), s};
}

std::wstring lsa_error_string(wchar_t const *what, NTSTATUS status, NTSTATUS substatus = 0)
{
	FZ_DLL_IMPORT(advapi32(), LsaNtStatusToWinError);

	if (!LsaNtStatusToWinError) {
		if (substatus) {
			return fz::sprintf(fztranslate("%s failed. NTSTATUS: 0x%08x, SubStatus: 0x%08x."), what, status, substatus);
		}

		return fz::sprintf(fztranslate("%s failed. NTSTATUS: 0x%08x."), what, status);
	}

	auto err = LsaNtStatusToWinError(status);
	auto suberr = substatus ? LsaNtStatusToWinError(substatus) : 0;

	if (substatus) {
		return fz::sprintf(fztranslate("%s failed. NTSTATUS: 0x%08x, Win32 Error: %d, SubStatus: 0x%08x, SubStatus Win32 Error: %d."), what, status, err, substatus, suberr);
	}

	return fz::sprintf(fztranslate("%s failed. NTSTATUS: 0x%08x, Win32 Error: %d."), what, status, err);
}

std::optional<std::wstring> profile_string_value(UNICODE_STRING const &string, void const *buffer, size_t buffer_length)
{
	if (!string.Length) {
		return std::wstring{};
	}

	if (!string.Buffer || string.Length % sizeof(wchar_t)) {
		return std::nullopt;
	}

	auto const begin = reinterpret_cast<uintptr_t>(buffer);
	auto const end = begin + buffer_length;
	auto const string_begin = reinterpret_cast<uintptr_t>(string.Buffer);
	auto const string_end = string_begin + string.Length;

	if (end < begin || string_end < string_begin || string_begin < begin || string_end > end) {
		return std::nullopt;
	}

	return std::wstring(string.Buffer, string.Length / sizeof(wchar_t));
}

std::optional<std::wstring> extract_profile_path_from_authentication_profile(package p, void const *buffer, size_t buffer_length)
{
	if (!buffer || buffer_length < sizeof(ULONG)) {
		return std::nullopt;
	}

	auto const message_type = *static_cast<ULONG const *>(buffer);

	if (message_type == MsV1_0InteractiveProfile || message_type == KerbInteractiveProfile) {
		if (buffer_length < sizeof(KERB_INTERACTIVE_PROFILE)) {
			return std::nullopt;
		}

		auto const &profile = *static_cast<KERB_INTERACTIVE_PROFILE const *>(buffer);
		return profile_string_value(profile.ProfilePath, buffer, buffer_length);
	}

	if (p == package::kerberos && (message_type == KerbSmartCardProfile || message_type == KerbTicketProfile)) {
		if (buffer_length < sizeof(KERB_INTERACTIVE_PROFILE)) {
			return std::nullopt;
		}

		auto const &profile = *static_cast<KERB_INTERACTIVE_PROFILE const *>(buffer);
		return profile_string_value(profile.ProfilePath, buffer, buffer_length);
	}

	if (p != package::kerberos && message_type == MsV1_0Lm20LogonProfile) {
		if (buffer_length < sizeof(MSV1_0_LM20_LOGON_PROFILE)) {
			return std::nullopt;
		}

		return std::wstring{};
	}

	return std::nullopt;
}

std::wstring logon_user(package p, std::wstring const &user, std::wstring const &domain, fz::windows::unique_handle &token, std::wstring &profile_path)
{
	FZ_DLL_IMPORT(secur32(), LsaRegisterLogonProcess);
	FZ_DLL_IMPORT(secur32(), LsaLookupAuthenticationPackage);
	FZ_DLL_IMPORT(secur32(), LsaLogonUser);

	if (!LsaRegisterLogonProcess || !LsaLookupAuthenticationPackage || !LsaLogonUser) {
		return fztranslate("Required functions are not available in secur32.dll.");
	}

	if (helper::enable_process_privileges({SE_TCB_NAME}) != ERROR_SUCCESS) {
		return fztranslate("SeTcbPrivilege could not be enabled.");
	}

	unique_lsa_handle lsa;
	LSA_OPERATIONAL_MODE security_mode{};

	char process_name[] = "libfilezilla";
	auto lsa_process_name = make_lsa_string(process_name);

	auto status = LsaRegisterLogonProcess(&lsa_process_name, fz::windows::out_ptr(lsa), &security_mode);
	if (!LSA_SUCCESS(status)) {
		return lsa_error_string(L"LsaRegisterLogonProcess", status);
	}

	char kerberos_package_name[] = MICROSOFT_KERBEROS_NAME_A;
	char msv1_package_name[] = MSV1_0_PACKAGE_NAME;
	auto *selected_package_name = p == package::kerberos ? kerberos_package_name : msv1_package_name;
	auto lsa_package_name = make_lsa_string(selected_package_name);

	ULONG auth_package{};
	status = LsaLookupAuthenticationPackage(lsa.get(), &lsa_package_name, &auth_package);
	if (!LSA_SUCCESS(status)) {
		return lsa_error_string(L"LsaLookupAuthenticationPackage", status);
	}

	char origin_name[] = "libfilezilla";
	auto lsa_origin_name = make_lsa_string(origin_name);

	TOKEN_SOURCE source{ {'F', 'i', 'l', 'e', 'Z', 'i', 'l', 'l'}, {} };
	if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
		auto const err = GetLastError();
		return fz::sprintf(fztranslate("AllocateLocallyUniqueId failed. Last Error: %d."), err);
	}

	unique_lsa_buffer profile_buffer;
	ULONG profile_buffer_length{};
	LUID logon_id{};
	QUOTA_LIMITS quotas{};
	NTSTATUS substatus{};

	if (p == package::kerberos) {
		auto user_len = user.size() * sizeof(wchar_t);
		std::vector<unsigned char> logon_buffer(sizeof(KERB_S4U_LOGON) + user_len);

		auto logon = reinterpret_cast<KERB_S4U_LOGON *>(logon_buffer.data());
		logon->MessageType = KerbS4ULogon;
		logon->Flags = 0;
		logon->ClientUpn.Length = static_cast<USHORT>(user_len);
		logon->ClientUpn.MaximumLength = logon->ClientUpn.Length;
		logon->ClientUpn.Buffer = reinterpret_cast<wchar_t *>(logon_buffer.data() + sizeof(KERB_S4U_LOGON));
		std::memcpy(logon->ClientUpn.Buffer, user.data(), user_len);

		status = LsaLogonUser(lsa.get(), &lsa_origin_name, Network, auth_package, logon_buffer.data(), static_cast<ULONG>(logon_buffer.size()), nullptr, &source, fz::windows::out_ptr(profile_buffer), &profile_buffer_length, &logon_id, fz::windows::out_ptr(token), &quotas, &substatus);
	}
	else {
		auto user_len = user.size() * sizeof(wchar_t);
		auto domain_len = domain.size() * sizeof(wchar_t);
		std::vector<unsigned char> logon_buffer(sizeof(MSV1_0_S4U_LOGON) + user_len + domain_len);

		auto logon = reinterpret_cast<MSV1_0_S4U_LOGON *>(logon_buffer.data());
		logon->MessageType = MsV1_0S4ULogon;
		logon->UserPrincipalName.Length = static_cast<USHORT>(user_len);
		logon->UserPrincipalName.MaximumLength = logon->UserPrincipalName.Length;
		logon->UserPrincipalName.Buffer = reinterpret_cast<wchar_t *>(logon_buffer.data() + sizeof(MSV1_0_S4U_LOGON));
		std::memcpy(logon->UserPrincipalName.Buffer, user.data(), user_len);

		logon->DomainName.Length = static_cast<USHORT>(domain_len);
		logon->DomainName.MaximumLength = logon->DomainName.Length;
		logon->DomainName.Buffer = reinterpret_cast<wchar_t *>(logon_buffer.data() + sizeof(MSV1_0_S4U_LOGON) + user_len);
		std::memcpy(logon->DomainName.Buffer, domain.data(), domain_len);

		status = LsaLogonUser(lsa.get(), &lsa_origin_name, Network, auth_package, logon_buffer.data(), static_cast<ULONG>(logon_buffer.size()), nullptr, &source, fz::windows::out_ptr(profile_buffer), &profile_buffer_length, &logon_id, fz::windows::out_ptr(token), &quotas, &substatus);
	}

	if (!LSA_SUCCESS(status)) {
		return lsa_error_string(L"LsaLogonUser", status, substatus);
	}

	auto path = extract_profile_path_from_authentication_profile(p, profile_buffer.get(), profile_buffer_length);
	if (!path) {
		token.reset();
		return fztranslate("LsaLogonUser returned an unsupported or malformed profile buffer.");
	}

	profile_path = std::move(*path);
	return {};
}

}

namespace fz::windows {

bool passwordless_logon_user(std::wstring const &user, std::wstring const &domain, bool use_kerberos, HANDLE &token, std::wstring &profile_path, logger_interface &logger)
{
	token = nullptr;
	profile_path.clear();

	auto const dll_path = helper::current_module_path(reinterpret_cast<void const *>(&fz_impersonation_logon_helper));
	if (dll_path.empty()) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_logon: could not locate libfilezilla module. Last Error: %d."), err);
		return false;
	}

	auto const &rundll32_path = helper::rundll32_path();
	if (rundll32_path.empty()) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_logon: could not locate rundll32.exe. Last Error: %d."), err);
		return false;
	}

	fz::process helper_process;
	logger.log(logmsg::debug_debug, L"impersonation_logon: starting helper. Rundll32: '%s', Module: '%s', Entry point: 'fz_impersonation_logon_helper'.", rundll32_path, dll_path);
	if (!helper_process.spawn(rundll32_path, { dll_path, L"fz_impersonation_logon_helper" }, fz::process::io_redirection::redirect)) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_logon: could not start rundll32 helper."));
		return false;
	}

	auto const selected_package = static_cast<std::uint32_t>(use_kerberos ? package::kerberos : package::msv1_0);
	helper::writer request(helper_process);
	request.field(selected_package).field(user);

	if (!use_kerberos) {
		request.field(domain);
	}

	if (!request) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_logon: could not write request to helper."));
		return false;
	}

	helper::reader response(helper_process, logger, L"impersonation_logon");
	if (!response) {
		return false;
	}

	std::uintptr_t response_token{};
	response.field(response_token).field(profile_path);
	if (!response || !response_token) {
		logger.log_raw(logmsg::error, fztranslate("impersonation_logon: helper returned invalid token info."));
		return false;
	}

	if (!DuplicateHandle(static_cast<HANDLE>(helper_process.handle()), reinterpret_cast<HANDLE>(response_token), GetCurrentProcess(), &token, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		auto const err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_logon: could not duplicate token from helper. Last Error: %d."), err);
		return false;
	}

	return true;
}

}

extern "C" FZ_PUBLIC_SYMBOL void CALLBACK fz_impersonation_logon_helper(HWND, HINSTANCE, LPSTR, int)
{
	auto in_handle = GetStdHandle(STD_INPUT_HANDLE);
	auto out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!in_handle || in_handle == INVALID_HANDLE_VALUE || !out_handle || out_handle == INVALID_HANDLE_VALUE) {
		return;
	}
	helper::reader in(in_handle, fz::get_null_logger(), L"impersonation_logon");
	helper::writer out(out_handle, in_handle);
	if (!in) {
		if (in.state() == helper::stream_state::invalid_data) {
			out.invalid();
		}
		return;
	}

	std::uint32_t requested_package{};
	std::wstring user;
	in.field(requested_package).field(user);
	if (!in) {
		if (in.state() == helper::stream_state::invalid_data) {
			out.invalid();
		}
		return;
	}

	if (requested_package != static_cast<std::uint32_t>(package::msv1_0) && requested_package != static_cast<std::uint32_t>(package::kerberos)) {
		out.invalid();
		return;
	}

	std::wstring domain;
	if (requested_package == static_cast<std::uint32_t>(package::msv1_0)) {
		in.field(domain);
	}

	if (!in) {
		if (in.state() == helper::stream_state::invalid_data) {
			out.invalid();
		}
		return;
	}

	fz::windows::unique_handle token;
	std::wstring profile_path;
	auto error = logon_user(static_cast<package>(requested_package), user, domain, token, profile_path);
	if (!error.empty()) {
		out.error(error);
		return;
	}

	out.success(reinterpret_cast<std::uintptr_t>(token.get()), profile_path);
}

#endif
