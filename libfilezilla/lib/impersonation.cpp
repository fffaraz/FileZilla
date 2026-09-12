#include "libfilezilla/impersonation.hpp"
#include "libfilezilla/logger.hpp"
#include "libfilezilla/translate.hpp"

namespace fz {

user::invalid::operator bool() const
{
	return false;
}

user::name::name(fz::native_string v)
	: value(std::move(v))
{}

user::name::operator bool() const
{
	return !value.empty();
}

user::id::operator bool() const
{
	return !value.empty();
}

user::user(id user_id)
	: value_(std::move(user_id))
{}

user::operator bool() const
{
	return std::visit([](const auto &v) { return static_cast<bool>(v); }, value_);
}

fz::native_string const *user::get_name() const
{
	if (auto user_name = std::get_if<name>(&value_)) {
		return &user_name->value;
	}

	return {};
}

std::string const *user::get_id() const
{
	if (auto user_id = std::get_if<id>(&value_)) {
		return &user_id->value;
	}

	return {};
}

impersonation_token::impersonation_token() = default;
impersonation_token::~impersonation_token() noexcept = default;

impersonation_token::impersonation_token(impersonation_token&&) noexcept = default;
impersonation_token& impersonation_token::operator=(impersonation_token&&) noexcept = default;

impersonation_capability_state impersonation_capabilities::operator[](impersonation_capability capability) const
{
	auto const index = static_cast<std::size_t>(capability);
	return index < states_.size() ? states_[index] : impersonation_capability_state::not_applicable;
}

impersonation_token::impersonation_token(fz::user const& user, fz::native_string const &password, fz::logger_interface& logger, impersonation_options const& opts)
	: impersonation_token(user, &password, logger, opts)
{}

impersonation_token::impersonation_token(fz::user const& user, impersonation_options::pwless_type, fz::logger_interface& logger, impersonation_options const& opts)
	: impersonation_token(user, nullptr, logger, opts)
{}

}

#if FZ_UNIX || FZ_MAC

#include <charconv>
#include <cstdint>
#include <optional>
#include <tuple>

#include "libfilezilla/buffer.hpp"

#if FZ_UNIX
#include <crypt.h>
#include <shadow.h>
#endif
#if defined(__linux__)
#include <linux/capability.h>
#include <sys/syscall.h>
#endif
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#if FZ_MAC
#include <CoreServices/CoreServices.h>
#endif
#include <cstring>

namespace fz {
namespace {
struct passwd_holder {
	passwd_holder() = default;
	passwd_holder(passwd_holder const&) = delete;
	passwd_holder(passwd_holder &&) = default;

	passwd_holder& operator=(passwd_holder const&) = delete;
	passwd_holder& operator=(passwd_holder &&) = default;

	~passwd_holder() noexcept = default;

	struct passwd* pwd_{};

	struct passwd pwd_buffer_;
	buffer buf_{};
};

passwd_holder get_passwd(native_string const& username)
{
	passwd_holder ret;

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		res = getpwnam_r(username.c_str(), &ret.pwd_buffer_, reinterpret_cast<char*>(ret.buf_.get(s)), s, &ret.pwd_);
	} while (res == ERANGE);

	if (res || !ret.pwd_) {
		ret.pwd_ = nullptr;
	}

	return ret;
}

passwd_holder get_passwd(uid_t const id)
{
	passwd_holder ret;

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		res = getpwuid_r(id, &ret.pwd_buffer_, reinterpret_cast<char*>(ret.buf_.get(s)), s, &ret.pwd_);
	} while (res == ERANGE);

	if (res || !ret.pwd_) {
		ret.pwd_ = nullptr;
	}

	return ret;
}

std::optional<gid_t> get_group(native_string const& gname)
{
	buffer buf;

	struct group g;
	struct group *pg{};

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		buf.get(s);
		res = getgrnam_r(gname.c_str(), &g, reinterpret_cast<char*>(buf.get(s)), s, &pg);
	} while (res == ERANGE);

	if (!res && pg) {
		return pg->gr_gid;
	}

	return {};
}

#if FZ_UNIX
struct shadow_holder {
	shadow_holder() = default;
	shadow_holder(shadow_holder const&) = delete;
	shadow_holder(shadow_holder &&) = default;

	shadow_holder& operator=(shadow_holder const&) = delete;
	shadow_holder& operator=(shadow_holder &&) = default;

	~shadow_holder() noexcept = default;

	struct spwd* shadow_{};

	struct spwd shadow_buffer_;
	buffer buf_{};
};

shadow_holder get_shadow(native_string const& username)
{
	shadow_holder ret;

	size_t s = 1024;
	int res{};
	do {
		s *= 2;
		ret.buf_.get(s);
		res = getspnam_r(username.c_str(), &ret.shadow_buffer_, reinterpret_cast<char*>(ret.buf_.get(s)), s, &ret.shadow_);
	} while (res == ERANGE);

	if (res) {
		ret.shadow_ = nullptr;
	}

	return ret;
}
#endif
}

class impersonation_token_impl final
{
public:
	static impersonation_token_impl* get(impersonation_token const& t) {
		return t.impl_.get();
	}

	native_string name_;
	native_string home_;
	uid_t uid_{};
	gid_t gid_{};
	std::vector<gid_t> sup_groups_;
};


namespace {
std::vector<gid_t> get_supplementary(std::string const& username, gid_t primary)
{
	std::vector<gid_t> ret;
#if FZ_IOS
	// Not supported
#else
	int size = 100;
	while (true) {
		ret.resize(size);
#if FZ_MAC
		typedef int glt;
		static_assert(sizeof(gid_t) == sizeof(glt));
#else
		typedef gid_t glt;
#endif

		int res = getgrouplist(username.c_str(), primary, reinterpret_cast<glt*>(ret.data()), &size);
		if (size < 0 || (res < 0 && static_cast<size_t>(size) <= ret.size())) {
			// Something went wrong
			ret.clear();
			break;
		}

		ret.resize(size);
		if (res >= 0) {
			break;
		}
	}
#endif
	return ret;
}

bool check_auth(native_string const& username, native_string const& password)
{
#if FZ_UNIX
	auto shadow = get_shadow(username);
	if (shadow.shadow_) {
		struct crypt_data data{};
		char* encrypted = crypt_r(password.c_str(), shadow.shadow_->sp_pwdp, &data);
		if (encrypted && !strcmp(encrypted, shadow.shadow_->sp_pwdp)) {
			return true;
		}
	}
#elif FZ_MAC && !FZ_IOS
	bool ret{};

	CFStringRef cfu = CFStringCreateWithCString(NULL, username.c_str(), kCFStringEncodingUTF8);
	if (cfu) {
		CSIdentityQueryRef q = CSIdentityQueryCreateForName(kCFAllocatorDefault, cfu, kCSIdentityQueryStringEquals, kCSIdentityClassUser, CSGetDefaultIdentityAuthority());
		if (q) {
			if (CSIdentityQueryExecute(q, kCSIdentityQueryGenerateUpdateEvents, NULL)) {
				CFArrayRef users = CSIdentityQueryCopyResults(q);
				if (users) {
					if (CFArrayGetCount(users) == 1) {
						CSIdentityRef user = (CSIdentityRef)(CFArrayGetValueAtIndex(users, 0));
						if (user) {
							CFStringRef pw = CFStringCreateWithCString(NULL, password.c_str(), kCFStringEncodingUTF8);
							if (pw) {
								ret = CSIdentityAuthenticateUsingPassword(user, pw);
								CFRelease(pw);
							}
						}
					}
					CFRelease(users);
				}
			}
			CFRelease(q);
		}
		CFRelease(cfu);
	}

	return ret;
#endif
	return false;
}

#if defined(__linux__)
uint64_t get_effective_capabilities_mask()
{
	__user_cap_header_struct header{};
	header.version = _LINUX_CAPABILITY_VERSION_3;
	header.pid = 0;  /* calling thread */

	__user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};

	if (syscall(SYS_capget, &header, data) == -1) {
		return false;
	}

	return uint64_t{data[0].effective} | (uint64_t{data[1].effective} << 32);
}

bool has_effective_capability(uint64_t capabilities_mask, unsigned cap)
{
	return (capabilities_mask & (uint64_t{1} << cap)) != 0;
}
#endif

std::unique_ptr<impersonation_token_impl> make_impersonation_token_impl(passwd_holder &pwd, native_string const &name, native_string const *password, logger_interface& logger, impersonation_options const& opts)
{
	if (password && !check_auth(pwd.pwd_->pw_name, *password)) {
		logger.log_u(logmsg::error, fztranslate("impersonation_token: invalid credentials. User: '%s'."), name);
		return {};
	}

	if (!opts.group.empty()) {
		if (auto gid = get_group(opts.group)) {
			pwd.pwd_->pw_gid = *gid;
		}
		else {
			logger.log_u(logmsg::error, fztranslate("impersonation_token: could not get GID for group '%s'. User: '%s'."), opts.group, name);
			return {};
		}
	}

	auto ret = std::make_unique<impersonation_token_impl>();
	ret->name_ = name;
	if (pwd.pwd_->pw_dir) {
		ret->home_ = pwd.pwd_->pw_dir;
	}
	ret->uid_ = pwd.pwd_->pw_uid;
	ret->gid_ = pwd.pwd_->pw_gid;
	ret->sup_groups_ = get_supplementary(name, pwd.pwd_->pw_gid);

	return ret;
}
}

impersonation_token::impersonation_token(fz::user const& user, fz::native_string const* password, logger_interface& logger, impersonation_options const& opts)
{
	if (auto username = user.get_name()) {
		auto pwd = get_passwd(*username);

		if (!pwd.pwd_) {
			logger.log_u(logmsg::error, fztranslate("impersonation_token: user '%s' not found."), *username);
			return;
		}

		impl_ = make_impersonation_token_impl(pwd, *username, password, logger, opts);
		return;
	}

	if (auto uid = user.get_id()) {
		auto id = fz::to_integral_o<uid_t>(*uid);
		if (!id) {
			logger.log_u(logmsg::error, fztranslate("impersonation_token: invalid user id '%s'."), *uid);
			return;
		}

		auto pwd = get_passwd(*id);
		if (!pwd.pwd_) {
			logger.log_u(logmsg::error, fztranslate("impersonation_token: user id '%s' not found."), *uid);
			return;
		}

		impl_ = make_impersonation_token_impl(pwd, pwd.pwd_->pw_name, password, logger, opts);
	}
}

impersonation_capabilities impersonation_token::get_capabilities(std::initializer_list<impersonation_capability> requested)
{
	impersonation_capabilities ret{};

	bool can_switch_user = geteuid() == 0;

#if defined(__linux__)
	auto const capabilities_mask = get_effective_capabilities_mask();
	can_switch_user = can_switch_user || (has_effective_capability(capabilities_mask, CAP_SETGID) && has_effective_capability(capabilities_mask, CAP_SETUID));
#endif

	for (auto requested_capability : requested) {
		switch (requested_capability) {
		case impersonation_capability::password:
		case impersonation_capability::passwordless:
			ret.states_[static_cast<std::size_t>(requested_capability)] = can_switch_user ? impersonation_capability_state::available : impersonation_capability_state::unavailable;
			break;
		case impersonation_capability::user_profile:
			ret.states_[static_cast<std::size_t>(requested_capability)] = impersonation_capability_state::available;
			break;
		}
	}

	return ret;
}

native_string impersonation_token::username() const
{
	return impl_ ? impl_->name_ : native_string();
}

std::size_t impersonation_token::hash() const noexcept
{
	using Hash = std::hash<std::optional<uid_t>>;

	return impl_ ? Hash{}(impl_->uid_) : Hash{}(std::nullopt);
}

// Note: Setuid binaries
bool set_process_impersonation(impersonation_token const& token)
{
	auto impl = impersonation_token_impl::get(token);
	if (!impl) {
		return false;
	}

	if (setgroups(std::min(impl->sup_groups_.size(), size_t(NGROUPS_MAX)), impl->sup_groups_.data()) != 0) {
		return false;
	}

	if (setgid(impl->gid_) != 0) {
		return false;
	}
	if (setuid(impl->uid_) != 0) {
		return false;
	}

	return true;
}

bool impersonation_token::operator==(impersonation_token const& op) const
{
	if (!impl_) {
		return !op.impl_;
	}
	if (!op.impl_) {
		return false;
	}

	return std::tie(impl_->name_, impl_->uid_, impl_->gid_, impl_->home_, impl_->sup_groups_) == std::tie(op.impl_->name_, op.impl_->uid_, op.impl_->gid_, op.impl_->home_, impl_->sup_groups_);
}

bool impersonation_token::operator<(impersonation_token const& op) const
{
	if (!impl_) {
		return bool(op.impl_);
	}
	if (!op.impl_) {
		return false;
	}

	return std::tie(impl_->name_, impl_->uid_, impl_->gid_, impl_->home_, impl_->sup_groups_) < std::tie(op.impl_->name_, op.impl_->uid_, op.impl_->gid_, op.impl_->home_, impl_->sup_groups_);
}

native_string impersonation_token::home() const
{
	return impl_ ? impl_->home_ : native_string();
}

native_string current_username()
{
	passwd_holder pwd = get_passwd(geteuid());
	if (!pwd.pwd_ || !pwd.pwd_->pw_name) {
		return {};
	}
	return pwd.pwd_->pw_name;
}

std::string impersonation_token::uid() const
{
	return impl_ ? fz::to_string(impl_->uid_) : std::string();
}

std::string get_user_id(native_string const& username)
{
	passwd_holder pwd = get_passwd(username);
	if (pwd.pwd_) {
		return fz::to_string(pwd.pwd_->pw_uid);
	}

	return {};
}

native_string get_user_name(std::string const& id)
{
	auto uid = fz::to_integral_o<uid_t>(id);
	if (!uid) {
		return {};
	}

	passwd_holder pwd = get_passwd(*uid);
	if (pwd.pwd_ && pwd.pwd_->pw_name) {
		return fz::native_string(pwd.pwd_->pw_name);
	}

	return {};
}

}

#elif FZ_WINDOWS

#include "libfilezilla/glue/dll.hpp"
#include "libfilezilla/glue/windows.hpp"
#include "libfilezilla/string.hpp"
#include "windows/helpers.hpp"
#include "windows/impersonation_desktop_impl.hpp"
#include "windows/impersonation_logon_helper.hpp"
#include "windows/impersonation_profile_helper.hpp"
#include "windows/security_descriptor_builder.hpp"
#include "windows/token_privileges.hpp"

#include <shlobj.h>
#include <sddl.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <secext.h>
#undef SECURITY_WIN32
#include <userenv.h>

#include <optional>
#include <vector>

namespace fz {

namespace {

using unique_handle = windows::unique_handle;

template <WELL_KNOWN_SID_TYPE Type>
std::optional<bool> process_token_has_sid(HANDLE token)
{
	auto sid = windows::holder<SID>::create(SECURITY_MAX_SID_SIZE);
	DWORD size = SECURITY_MAX_SID_SIZE;
	if (!CreateWellKnownSid(Type, nullptr, sid.get(), &size)) {
		return {};
	}

	BOOL member{};
	if (!CheckTokenMembership(token, sid.get(), &member)) {
		return {};
	}

	return member != FALSE;
}

std::optional<bool> process_is_administrator_or_local_system()
{
	unique_handle token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, windows::out_ptr(token))) {
		return {};
	}

	unique_handle impersonation_token;
	if (!DuplicateToken(token.get(), SecurityIdentification, windows::out_ptr(impersonation_token))) {
		return {};
	}

	auto administrator = process_token_has_sid<WinBuiltinAdministratorsSid>(impersonation_token.get());
	if (!administrator || *administrator) {
		return administrator;
	}

	return process_token_has_sid<WinLocalSystemSid>(impersonation_token.get());
}

struct sid_deleter {
	using pointer = PSID;
	void operator()(PSID p) const { if (p) LocalFree(p); }
};

using unique_sid = std::unique_ptr<PSID, sid_deleter>;

dll& secur32()
{
	static dll lib(L"secur32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	return lib;
}

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

enum class authentication_package
{
	negotiate,
	msv1_0,
	kerberos
};

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

std::optional<std::wstring> extract_profile_path_from_authentication_profile(authentication_package package, void const *buffer, size_t buffer_length)
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

	if (package == authentication_package::kerberos && (message_type == KerbSmartCardProfile || message_type == KerbTicketProfile)) {
		if (buffer_length < sizeof(KERB_INTERACTIVE_PROFILE)) {
			return std::nullopt;
		}

		auto const &profile = *static_cast<KERB_INTERACTIVE_PROFILE const *>(buffer);
		return profile_string_value(profile.ProfilePath, buffer, buffer_length);
	}

	if (package != authentication_package::kerberos && message_type == MsV1_0Lm20LogonProfile) {
		if (buffer_length < sizeof(MSV1_0_LM20_LOGON_PROFILE)) {
			return std::nullopt;
		}

		return std::wstring{};
	}

	return std::nullopt;
}

bool sid_to_user_and_domain(std::wstring const &sid_string, std::wstring &user, std::wstring &domain, logger_interface &logger)
{
	PSID sid_raw{};
	if (!ConvertStringSidToSidW(sid_string.c_str(), &sid_raw)) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("logon_windows_user: ConvertStringSidToSidW failed. SID: '%s'. Last Error: %d."), sid_string, err);
		return false;
	}

	unique_sid sid(sid_raw);

	DWORD user_size{};
	DWORD domain_size{};
	SID_NAME_USE sid_type{};

	if (LookupAccountSidW(nullptr, sid.get(), nullptr, &user_size, nullptr, &domain_size, &sid_type)) {
		logger.log(logmsg::error, fztranslate("logon_windows_user: LookupAccountSidW unexpectedly succeeded while probing sizes. SID: '%s'."), sid_string);
		return false;
	}

	auto err = GetLastError();
	if (err != ERROR_INSUFFICIENT_BUFFER || !user_size || !domain_size) {
		logger.log(logmsg::error, fztranslate("logon_windows_user: LookupAccountSidW failed while probing sizes. SID: '%s'. Last Error: %d."), sid_string, err);
		return false;
	}

	user.resize(user_size - 1);
	domain.resize(domain_size - 1);

	if (!LookupAccountSidW(nullptr, sid.get(), user.data(), &user_size, domain.data(), &domain_size, &sid_type)) {
		err = GetLastError();
		logger.log(logmsg::error, fztranslate("logon_windows_user: LookupAccountSidW failed. SID: '%s'. Last Error: %d."), sid_string, err);
		return false;
	}

	if (sid_type != SidTypeUser) {
		logger.log(logmsg::error, fztranslate("logon_windows_user: SID does not identify a user account. SID: '%s', Type: %d."), sid_string, sid_type);
		return false;
	}

	user.resize(std::char_traits<wchar_t>::length(user.data()));
	domain.resize(std::char_traits<wchar_t>::length(domain.data()));

	return true;
}

std::optional<bool> is_local_domain(std::wstring const &domain, logger_interface &logger)
{
	if (domain.empty() || domain == L".") {
		return true;
	}

	wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD computer_name_size = std::size(computer_name);
	if (!GetComputerNameW(computer_name, &computer_name_size)) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("logon_windows_user: GetComputerNameW failed while classifying domain '%s'. Last Error: %d."), domain, err);
		return std::nullopt;
	}

	return !fz::stricmp(domain, std::wstring_view(computer_name, computer_name_size));
}

std::optional<std::wstring> translate_domain_user_to_upn(std::wstring const &domain, std::wstring const &user, logger_interface &logger)
{
	FZ_DLL_IMPORT(secur32(), TranslateNameW);
	if (!TranslateNameW) {
		logger.log_raw(logmsg::error, fztranslate("logon_windows_user: cannot import TranslateNameW from secur32.dll."));
		return std::nullopt;
	}

	auto account = domain + L'\\' + user;
	ULONG size{};
	auto translated = TranslateNameW(account.c_str(), NameSamCompatible, NameUserPrincipal, nullptr, &size);
	auto err = translated ? ERROR_SUCCESS : GetLastError();
	if ((!translated && err != ERROR_INSUFFICIENT_BUFFER && err != ERROR_MORE_DATA) || !size) {
		logger.log(logmsg::error, fztranslate("logon_windows_user: TranslateNameW failed while probing the UPN size for '%s'. Last Error: %d."), account, err);
		return std::nullopt;
	}

	std::wstring upn(size, L'\0');
	if (!TranslateNameW(account.c_str(), NameSamCompatible, NameUserPrincipal, upn.data(), &size)) {
		err = GetLastError();
		logger.log(logmsg::error, fztranslate("logon_windows_user: TranslateNameW failed for '%s'. Last Error: %d."), account, err);
		return std::nullopt;
	}

	upn.resize(std::char_traits<wchar_t>::length(upn.data()));
	logger.log(logmsg::debug_info, L"logon_windows_user: translated domain identity [%s] to UPN [%s].", account, upn);
	return upn;
}

BOOL logon_windows_user(fz::user const &identity, std::wstring const *password, unique_handle &token, std::wstring &user, std::wstring &domain, std::wstring &profile_path, logger_interface &logger)
{
	user.clear();
	domain.clear();
	profile_path.clear();

	if (auto username = identity.get_name()) {
		if (auto backslash_pos = username->find(L'\\'); backslash_pos != username->npos) {
			user = username->substr(backslash_pos + 1);
			domain = username->substr(0, backslash_pos);
		}
		else {
			user = *username;
		}

		logger.log(logmsg::debug_debug, L"logon_windows_user: username [%s] => user[%s], domain[%s].", *username, user, domain);
	}
	else if (auto id = identity.get_id()) {
		if (!sid_to_user_and_domain(fz::to_native(*id), user, domain, logger)) {
			return FALSE;
		}

		auto local = is_local_domain(domain, logger);
		if (!local) {
			return FALSE;
		}

		if (*local) {
			domain = L".";
		}

		logger.log(logmsg::debug_debug, L"logon_windows_user: user id [%s] => user[%s], domain[%s].", *id, user, domain);
	}
	else {
		return FALSE;
	}

	if (password) {
		unique_lsa_buffer profile_buffer;
		DWORD profile_buffer_length{};
		QUOTA_LIMITS quotas{};
		if (!LogonUserExW(user.c_str(), domain.empty() ? nullptr : domain.c_str(), password->c_str(), LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, windows::out_ptr(token), nullptr, windows::out_ptr(profile_buffer), &profile_buffer_length, &quotas)) {
			auto err = GetLastError();
			logger.log(logmsg::error, fztranslate("logon_windows_user: LogonUserExW failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
			return FALSE;
		}

		auto path = extract_profile_path_from_authentication_profile(authentication_package::negotiate, profile_buffer.get(), profile_buffer_length);
		if (!path) {
			logger.log_raw(logmsg::error, fztranslate("logon_windows_user: LogonUserExW returned an unsupported or malformed profile buffer."));
			token.reset();
			return FALSE;
		}

		profile_path = std::move(*path);

		return TRUE;
	}

	bool use_kerberos{};
	if (domain.empty() && user.find(L'@') != user.npos) {
		use_kerberos = true;
	}
	else {
		auto local = is_local_domain(domain, logger);
		if (!local) {
			return FALSE;
		}

		if (*local) {
			domain = L".";
		}
		else {
			auto upn = translate_domain_user_to_upn(domain, user, logger);
			if (!upn) {
				return FALSE;
			}

			user = std::move(*upn);
			domain.clear();
			use_kerberos = true;
		}
	}

	logger.log(logmsg::debug_debug, L"logon_windows_user: resolved user[%s], domain[%s], package[%s], password[absent].", user, domain, use_kerberos ? L"Kerberos" : L"MSV1_0");

	HANDLE token_raw{};
	if (!windows::passwordless_logon_user(user, domain, use_kerberos, token_raw, profile_path, logger)) {
		return FALSE;
	}

	token.reset(token_raw);

	return TRUE;
}

}

class impersonation_token_impl final
{
public:
	impersonation_token_impl() = default;

	impersonation_token_impl(native_string name, native_string server, std::string sid, std::wstring roaming_profile_path, unique_handle h, bool load_profile, impersonation_desktop::mode desktop_mode, logger_interface &logger)
		: name_(name)
		, sid_(std::move(sid))
		, h_(std::move(h))
		, desktop_(impersonation_desktop::impl::make(desktop_mode))
	{
		if (!server.empty() && server != L".") {
			name_ += L'@';
			name_ += server;
		}

		if (!load_profile) {
			return;
		}

		logger.log(logmsg::debug_debug, L"Loading user [%s] profile [roaming: [%s]].", name_, roaming_profile_path);
		if (auto profile = windows::load_user_profile(h_.get(), name, server, roaming_profile_path, logger)) {
			profile_h_ = profile;
		}

		if (profile_h_ == INVALID_HANDLE_VALUE) {
			logger.log(logmsg::error, fztranslate("impersonation_token: could not load user profile. User: '%s', Roaming: '%s'."), name_, roaming_profile_path);
		}
	}

	static impersonation_token_impl* get(impersonation_token const& t) {
		return t.impl_.get();
	}

	~impersonation_token_impl() {
		if (h_) {
			if (profile_h_ != INVALID_HANDLE_VALUE) {
				FZ_DLL_IMPORT(userenv(), UnloadUserProfile);

				if (UnloadUserProfile) {
					UnloadUserProfile(h_.get(), profile_h_);
				}
			}
		}
	}

	static HANDLE get_handle(impersonation_token const& t) {
		return t.impl_ ? t.impl_->h_.get() : INVALID_HANDLE_VALUE;
	}

	bool has_loaded_profile() const {
		return profile_h_ != INVALID_HANDLE_VALUE;
	}

	HANDLE get_handle() {
		return h_.get();
	}

	std::optional<wchar_t *> get_desktop_name(logger_interface &logger)
	{
		if (desktop_) {
			if (!desktop_->init(h_.get(), logger)) {
				return std::nullopt;
			}

			if (auto name = desktop_->name()) {
				static thread_local std::wstring name_copy;
				name_copy = *name;
				return name_copy.data();
			}
		}

		return nullptr;
	}

	std::string const& get_sid() {
		return sid_;
	}

	native_string const& get_name() {
		return name_;
	}

	impersonation_token_impl(impersonation_token_impl const&) = delete;
	impersonation_token_impl& operator=(impersonation_token_impl const&) = delete;

private:
	native_string name_;
	std::string sid_; // SID as string
	unique_handle h_{};
	HANDLE profile_h_{INVALID_HANDLE_VALUE};
	std::unique_ptr<impersonation_desktop::impl> desktop_;

	static dll& userenv() {
		static dll lib(L"userenv.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
		return lib;
	}
};

namespace {

std::unique_ptr<impersonation_token_impl> make_impersonation_token_impl(fz::user const& identity, fz::native_string const* password, logger_interface& logger, impersonation_options const& opts)
{
	unique_handle token;
	std::wstring user;
	std::wstring domain;
	std::wstring roaming_profile_path;
	if (!logon_windows_user(identity, password, token, user, domain, roaming_profile_path, logger)) {
		return {};
	}

	std::string sid;
	if (!GetUserInfoFromToken(token.get(), sid, user, domain, logger)) {
		return {};
	}

	auto local = is_local_domain(domain, logger);
	if (!local) {
		return {};
	}

	if (*local) {
		domain = L".";
	}

	unique_handle primary;
	if (!DuplicateTokenEx(token.get(), 0, nullptr, SecurityImpersonation, TokenPrimary, windows::out_ptr(primary))) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_token: DuplicateTokenEx failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
		return {};
	}

	if (opts.drop_admin_privileges && !DropAdminPrivilegesFromToken(primary.get())) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_token: DropAdminPrivilegesFromToken failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
		return {};
	}

	auto const load_profile = opts.profile == impersonation_profile_mode::require ||
		(opts.profile == impersonation_profile_mode::require_if_roaming && !roaming_profile_path.empty());

	auto ret = std::make_unique<impersonation_token_impl>(std::move(user), std::move(domain), std::move(sid), std::move(roaming_profile_path), std::move(primary), load_profile, opts.desktop, logger);
	if (load_profile && !ret->has_loaded_profile()) {
		return {};
	}

	return ret;
}

}

impersonation_token::impersonation_token(fz::user const& user, fz::native_string const* password, logger_interface& logger, impersonation_options const& opts)
{
	impl_ = make_impersonation_token_impl(user, password, logger, opts);
}

impersonation_capabilities impersonation_token::get_capabilities(std::initializer_list<impersonation_capability> requested)
{
	impersonation_capabilities ret{};

	for (auto requested_capability : requested) {
		switch (requested_capability) {
		case impersonation_capability::password:
			ret.states_[static_cast<std::size_t>(requested_capability)] = has_process_privilege(SE_ASSIGNPRIMARYTOKEN_NAME)
				? impersonation_capability_state::available
				: impersonation_capability_state::unavailable;
			break;

		case impersonation_capability::passwordless:
			ret.states_[static_cast<std::size_t>(requested_capability)] =
				has_process_privilege(SE_ASSIGNPRIMARYTOKEN_NAME) &&
				has_process_privilege(SE_TCB_NAME)
				? impersonation_capability_state::available
				: impersonation_capability_state::unavailable;
			break;

		case impersonation_capability::user_profile: {
			auto process_identity = process_is_administrator_or_local_system();
			if (!process_identity) {
				ret.states_[static_cast<std::size_t>(requested_capability)] = impersonation_capability_state::indeterminate;
				break;
			}

			ret.states_[static_cast<std::size_t>(requested_capability)] =
				*process_identity &&
				has_process_privilege(SE_BACKUP_NAME) &&
				has_process_privilege(SE_RESTORE_NAME)
					? impersonation_capability_state::available
					: impersonation_capability_state::unavailable;
			break;
		}
		}
	}

	return ret;
}

native_string impersonation_token::username() const
{
	return impl_ ? impl_->get_name() : native_string();
}

std::size_t impersonation_token::hash() const noexcept
{
	using Hash = std::hash<std::string>;

	return impl_ ? Hash{}(impl_->get_sid()) : Hash{}(std::string());
}

bool impersonation_token::operator==(impersonation_token const& op) const
{
	if (!impl_) {
		return !op.impl_;
	}

	if (!op.impl_) {
		return false;
	}

	return impl_->get_sid() == op.impl_->get_sid();
}

bool impersonation_token::operator<(impersonation_token const& op) const
{
	if (!impl_) {
		return bool(op.impl_);
	}
	if (!op.impl_) {
		return false;
	}

	return impl_->get_sid() < op.impl_->get_sid();
}

native_string impersonation_token::home() const
{
	native_string ret;

	if (impl_) {
		// Manually define it instead of using FOLDERID_Profile as it would prevent building a DLL.
		static GUID const profile = { 0x5E6C858F, 0x0E22, 0x4760, {0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73} };

		FZ_DLL_IMPORT(shdlls::get().shell32_, SHGetKnownFolderPath);
		FZ_DLL_IMPORT(shdlls::get().ole32_, CoTaskMemFree);

		wchar_t* out{};
		if (SHGetKnownFolderPath && CoTaskMemFree && SHGetKnownFolderPath(profile, KF_FLAG_DONT_VERIFY | KF_FLAG_DEFAULT_PATH | KF_FLAG_CREATE, impl_->get_handle(), &out) == S_OK) {
			ret = out;
			CoTaskMemFree(out);
		}
	}

	return ret;
}

std::string impersonation_token::uid() const
{
	return impl_ ? impl_->get_sid() : std::string();
}

HANDLE get_handle(impersonation_token const& t) {
	return impersonation_token_impl::get_handle(t);
}

std::optional<wchar_t *> get_desktop_name(impersonation_token const& t, logger_interface &logger)
{
	if (auto impl = impersonation_token_impl::get(t)) {
		return impl->get_desktop_name(logger);
	}

	return std::nullopt;
}

native_string current_username()
{
	std::wstring username;

	username.resize(128);
	DWORD size = static_cast<DWORD>(username.size());

	while (!GetUserNameW(username.data(), &size)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			return {};
		}

		username.resize(username.size() * 2);
		size = static_cast<DWORD>(username.size());
	}

	if (!size) {
		return {};
	}

	username.resize(size -1);
	return username;
}

std::string get_user_id(native_string const& username)
{
	SID_NAME_USE use = SidTypeUnknown;
	BYTE sid[256];
	wchar_t domain[256];
	DWORD sid_size = sizeof(sid);
	DWORD domain_size = sizeof(domain);

	auto account = [&]() -> std::wstring {
		if (auto username_view = std::wstring_view(username); fz::starts_with(username_view, std::wstring_view(L".\\"))) {
			static wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1];
			DWORD computer_name_size = MAX_COMPUTERNAME_LENGTH + 1;

			auto res = GetComputerNameW(computer_name, &computer_name_size);

			if (!res) {
				return {};
			}

			auto ret = std::wstring(computer_name).append(L"\\").append(username_view.substr(2));
			return ret;
		}
		else {
			return username;
		}
	}();

	std::string ret;

	if (LookupAccountNameW(nullptr, account.c_str(), sid, &sid_size, domain, &domain_size, &use) && use == SidTypeUser) {
		LPSTR sid_str{};
		if (ConvertSidToStringSidA(sid, &sid_str)) {
			ret = sid_str;
		}

		LocalFree(sid_str);
	}

	return ret;
}

native_string get_user_name(std::string const& id)
{
	std::wstring user;
	std::wstring domain;

	if (!sid_to_user_and_domain(fz::to_native(id), user, domain, get_null_logger())) {
		return {};
	}

	auto local = is_local_domain(domain, get_null_logger());
	if (!local) {
		return {};
	}

	if (*local) {
		return std::wstring(L".\\") + user;
	}

	return user + L"@" + domain;
}

}
#endif
