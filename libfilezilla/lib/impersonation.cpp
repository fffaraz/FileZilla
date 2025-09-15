#include "libfilezilla/impersonation.hpp"
#include "libfilezilla/logger.hpp"
#include "libfilezilla/translate.hpp"

namespace fz {

impersonation_token::impersonation_token() = default;
impersonation_token::~impersonation_token() noexcept = default;

impersonation_token::impersonation_token(impersonation_token&&) noexcept = default;
impersonation_token& impersonation_token::operator=(impersonation_token&&) noexcept = default;

impersonation_token::impersonation_token(fz::native_string const& username, fz::native_string const &password, fz::logger_interface& logger, impersonation_options const& opts)
	: impersonation_token(username, &password, logger, opts)
{}

impersonation_token::impersonation_token(fz::native_string const& username, impersonation_options::pwless_type, fz::logger_interface& logger, impersonation_options const& opts)
	: impersonation_token(username, nullptr, logger, opts)
{}

}

#if FZ_UNIX || FZ_MAC

#include "libfilezilla/buffer.hpp"

#include <optional>
#include <tuple>

#if FZ_UNIX
#include <crypt.h>
#include <shadow.h>
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
#elif FZ_MAC
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
}

impersonation_token::impersonation_token(fz::native_string const& username, fz::native_string const* password, logger_interface& logger, impersonation_options const& opts)
{
	auto pwd = get_passwd(username);

	if (!pwd.pwd_) {
		logger.log_u(logmsg::error, fztranslate("impersonation_token: user '%s' not found."), username);
		return;
	}

	if (password && !check_auth(pwd.pwd_->pw_name, *password)) {
		logger.log_u(logmsg::error, fztranslate("impersonation_token: invalid credentials. User: '%s'."), username);
		return;
	}

	if (!opts.group.empty()) {
		if (auto gid = get_group(opts.group)) {
			pwd.pwd_->pw_gid = *gid;
		}
		else {
			logger.log_u(logmsg::error, fztranslate("impersonation_token: could not get GID for group '%s'. User: '%s'."), opts.group, username);
			return;
		}
	}

	impl_ = std::make_unique<impersonation_token_impl>();
	impl_->name_ = username;
	if (pwd.pwd_->pw_dir) {
		impl_->home_ = pwd.pwd_->pw_dir;
	}
	impl_->uid_ = pwd.pwd_->pw_uid;
	impl_->gid_ = pwd.pwd_->pw_gid;
	impl_->sup_groups_ = get_supplementary(username, pwd.pwd_->pw_gid);
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

std::string get_user_uid(native_string const& username)
{
	passwd_holder pwd = get_passwd(username);
	if (pwd.pwd_) {
		return fz::to_string(pwd.pwd_->pw_uid);
	}

	return {};
}

}

#elif FZ_WINDOWS

#include "libfilezilla/glue/dll.hpp"
#include "libfilezilla/glue/windows.hpp"
#include "windows/security_descriptor_builder.hpp"

#include <shlobj.h>
#include <sddl.h>
#include <dsgetdc.h>
#include <lm.h>
#include <userenv.h>

#include <tuple>

namespace {

struct handle_closer {
	using pointer = HANDLE;
	void operator()(HANDLE h) { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};

using unique_handle = std::unique_ptr<HANDLE, handle_closer>;

}

namespace fz {

class impersonation_token_impl final
{
public:
	impersonation_token_impl() = default;

	impersonation_token_impl(native_string name, native_string server, std::string sid, std::wstring roaming_profile_path, unique_handle h, logger_interface &logger)
		: name_(name)
		, sid_(std::move(sid))
		, h_(std::move(h))
	{
		if (!server.empty() && server != L".") {
			name_ += L'@';
			name_ += server;
		}

		FZ_DLL_IMPORT(userenv(), LoadUserProfileW);

		native_string profile_path;

		if (LoadUserProfileW) {
			logger.log(logmsg::debug_debug, L"Loading user [%s] profile [roaming: [%s]].", name_, roaming_profile_path);

			PROFILEINFOW info = {};
			info.dwSize = sizeof(info);
			info.dwFlags = PI_NOUI;
			info.lpUserName = name.data();
			info.lpServerName = server.empty() ? nullptr : server.data();
			info.lpProfilePath = roaming_profile_path.empty() ? nullptr : roaming_profile_path.data();

			if (LoadUserProfileW(h_.get(), &info)) {
				profile_h_ = info.hProfile;
			}
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

	HANDLE get_handle() {
		return h_.get();
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

	static dll& userenv() {
		static dll lib(L"userenv.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
		return lib;
	}
};

impersonation_token::impersonation_token(fz::native_string const& username, fz::native_string const* password, logger_interface& logger, impersonation_options const& opts)
{
	std::wstring user;
	std::wstring domain;

	if (!password) {
		logger.log_u(logmsg::error, fztranslate("impersonation_token: password-less login is not supported under Windows."));
		return;
	}

	if (auto backslash_pos = username.find(L'\\'); backslash_pos != username.npos) {
		user = username.substr(backslash_pos + 1);
		domain = username.substr(0, backslash_pos);
	}
	else {
		user = username;
	}

	logger.log(logmsg::debug_debug, L"impersonation_token: username [%s] => user[%s], domain[%s].", username, user, domain);

	HANDLE token_raw{INVALID_HANDLE_VALUE};

	if (!LogonUserW(user.c_str(), domain.empty() ? nullptr : domain.c_str(), password->c_str(), LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_PROVIDER_DEFAULT, &token_raw)) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_token: LogonUserW failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
		return;
	}

	unique_handle token(token_raw);

	std::string sid;
	std::wstring roaming_profile_path;
	if (!GetUserInfoFromToken(token.get(), sid, roaming_profile_path, user, domain, logger)) {
		return;
	}

	HANDLE primary_raw{INVALID_HANDLE_VALUE};
	if (!DuplicateTokenEx(token.get(), 0, nullptr, SecurityImpersonation, TokenPrimary, &primary_raw)) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_token: DuplicateTokenEx failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
		return;
	}

	unique_handle primary(primary_raw);

	if (opts.drop_admin_privileges && !DropAdminPrivilegesFromToken(primary.get())) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("impersonation_token: DropAdminPrivilegesFromToken failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
		return;
	}

	impl_ = std::make_unique<impersonation_token_impl>(std::move(user), std::move(domain), std::move(sid), std::move(roaming_profile_path), std::move(primary), logger);
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
	return impl_ ? fz::to_string(impl_->get_sid()) : std::string();
}

HANDLE get_handle(impersonation_token const& t) {
	return impersonation_token_impl::get_handle(t);
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

std::string get_user_uid(native_string const& username)
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

}
#endif
