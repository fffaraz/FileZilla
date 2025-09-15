#include "security_descriptor_builder.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/thread.hpp"
#include "../libfilezilla/glue/dll.hpp"
#include "../libfilezilla/translate.hpp"

#include <array>
#include <map>

#include <sddl.h>
#include <lm.h>
#include <dsgetdc.h>

namespace fz {

namespace {
template<typename T>
struct holder final
{
	holder() = default;
	~holder()
	{
		clear();
	}

	static holder create(size_t s) {
		holder h;
		h.v_ = reinterpret_cast<T*>(::operator new[](s, std::align_val_t(alignof(T))));
		h.size_ = s;
		h.delete_ = true;
		return h;
	}

	void clear()
	{
		if (delete_) {
			::operator delete[](reinterpret_cast<void*>(v_), std::align_val_t(alignof(T)));
		}
		size_ = 0;
		v_ = nullptr;
	}

	static holder create(void* v, bool del)
	{
		holder h;
		h.v_ = reinterpret_cast<T*>(v);
		h.size_ = v ? size_t(-1) : 0;
		h.delete_ = del;
		return h;
	}

	holder(holder&& h) noexcept
		: v_(h.v_)
		, size_(h.size_)
	{
		h.v_ = nullptr;
		h.size_ = 0;
		delete_ = h.delete_;
	}

	holder& operator=(holder&& h) noexcept {
		if (this != &h) {
			clear();
			v_ = h.v_;
			size_ = h.size_;
			h.v_ = nullptr;
			h.size_ = 0;
			delete_ = h.delete_;
		}
		return *this;
	}

	size_t size() const { return size_; }

	explicit operator bool() const { return v_ != nullptr; }

	holder(holder const&) = delete;
	holder& operator=(holder const&) = delete;

	T* get() { return v_; }
	T& operator*() { return *v_; }
	T* operator->() { return v_; }

private:
	bool delete_{};
	T* v_{};
	size_t size_{};
};
}

struct security_descriptor_builder::impl
{
	holder<SID> get_sid(entity e);
	bool init_user();

	std::map<entity, DWORD> rights_;

	holder<TOKEN_USER> user_;
	holder<ACL> acl_;
	SECURITY_DESCRIPTOR sd_{};
};

security_descriptor_builder::security_descriptor_builder()
	: impl_(std::make_unique<impl>())
{
}

security_descriptor_builder::~security_descriptor_builder()
{
}

void security_descriptor_builder::add(entity e, DWORD rights)
{
	impl_->acl_.clear();
	impl_->rights_[e] = rights;
}

ACL* security_descriptor_builder::get_acl(sdb_flags f)
{
	if (impl_->acl_) {
		return impl_->acl_.get();
	}

	if (!impl_->init_user()) {
		return nullptr;
	}

	DWORD const needed = static_cast<DWORD>(sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + SECURITY_MAX_SID_SIZE) * impl_->rights_.size());
	auto acl = holder<ACL>::create(needed);

	if (InitializeAcl(acl.get(), needed, ACL_REVISION)) {
		for (auto it = impl_->rights_.cbegin(); acl && it != impl_->rights_.cend(); ++it) {
			auto sid = impl_->get_sid(it->first);
			DWORD flags = (f & sdb_flags::inheritable) ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) : 0;
			if (!sid || !AddAccessAllowedAceEx(acl.get(), ACL_REVISION, flags, it->second, sid.get())) {
				return {};
			}
		}
		impl_->acl_ = std::move(acl);
	}

	if (impl_->acl_) {
		InitializeSecurityDescriptor(&impl_->sd_, SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorControl(&impl_->sd_, SE_DACL_PROTECTED, (f & sdb_flags::inherit_from_parent) ? 0 : SE_DACL_PROTECTED);
		SetSecurityDescriptorDacl(&impl_->sd_, TRUE, impl_->acl_.get(), FALSE);
		SetSecurityDescriptorOwner(&impl_->sd_, impl_->user_->User.Sid, FALSE);
		SetSecurityDescriptorGroup(&impl_->sd_, NULL, FALSE);
		SetSecurityDescriptorSacl(&impl_->sd_, FALSE, NULL, FALSE);
	}

	return impl_->acl_.get();
}

SECURITY_DESCRIPTOR* security_descriptor_builder::get_sd(sdb_flags f)
{
	if (!get_acl(f)) {
		return nullptr;
	}

	return &impl_->sd_;
}

namespace {
WELL_KNOWN_SID_TYPE GetWellKnownSidType(security_descriptor_builder::entity e)
{
	switch (e) {
		case security_descriptor_builder::administrators:
			return WinBuiltinAdministratorsSid;
		case security_descriptor_builder::authenticated_users:
			return WinAuthenticatedUserSid;
		case security_descriptor_builder::users:
			return WinBuiltinUsersSid;
		case security_descriptor_builder::system:
			return WinLocalSystemSid;
		default:
			return WinNullSid;
	}
}
}

holder<SID> security_descriptor_builder::impl::get_sid(entity e)
{
	if (e == self) {
		init_user();
		return holder<SID>::create(user_ ? user_->User.Sid : nullptr, false);
	}
	else {
		WELL_KNOWN_SID_TYPE wk = GetWellKnownSidType(e);
		if (wk == WinNullSid) {
			return {};
		}

		auto sid = holder<SID>::create(SECURITY_MAX_SID_SIZE);
		DWORD l = SECURITY_MAX_SID_SIZE;
		if (!CreateWellKnownSid(wk, nullptr, sid.get(), &l)) {
			return {};
		}
		return sid;
	}
}

namespace {
holder<TOKEN_USER> GetUserFromToken(HANDLE token)
{
	DWORD needed{};
	GetTokenInformation(token, TokenUser, NULL, 0, &needed);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		auto user = holder<TOKEN_USER>::create(needed);
		if (GetTokenInformation(token, TokenUser, user.get(), needed, &needed)) {
			return user;
		}
	}

	return {};
}
}

bool security_descriptor_builder::impl::init_user()
{
	if (user_) {
		return true;
	}

	HANDLE token{INVALID_HANDLE_VALUE};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return false;
	}
	user_ = GetUserFromToken(token);

	CloseHandle(token);

	return user_.operator bool();
}

bool GetUserAndDomainFromSid(PSID sid, std::wstring& user, std::wstring& domain)
{
	DWORD user_size = 0;
	DWORD domain_size = 0;
	SID_NAME_USE sid_type;

	if (LookupAccountSidW(nullptr, sid, nullptr, &user_size, nullptr, &domain_size, &sid_type)) {
		return false;
	}

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || user_size == 0 || domain_size == 0) {
		return false;
	}

	user.resize(user_size - 1);
	domain.resize(domain_size - 1);

	if (!LookupAccountSidW(nullptr, sid, user.data(), &user_size, domain.data(), &domain_size, &sid_type)) {
		return false;
	}

	user.resize(std::char_traits<wchar_t>::length(user.data()));
	domain.resize(std::char_traits<wchar_t>::length(domain.data()));

	return true;
}

namespace {

bool GetRoamingProfilePath(HANDLE h, std::wstring const& user, std::wstring &domain, std::wstring& roaming_profile_path, logger_interface& logger)
{
	static dll netapi32_dll(L"netapi32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);

	FZ_DLL_IMPORT(netapi32_dll, DsGetDcNameW);
	FZ_DLL_IMPORT(netapi32_dll, NetApiBufferFree);
	FZ_DLL_IMPORT(netapi32_dll, NetUserGetInfo);

	logger.log(logmsg::debug_debug, L"Entering GetRoamingProfilePath(%s, %s)", user, domain);

	if (!DsGetDcNameW || !NetApiBufferFree || !NetUserGetInfo) {
		logger.log_raw(logmsg::error, fztranslate("GetRoamingProfilePath: couldn't import netapi32.dll functions."));
		return false;
	}

	auto make_fqdn_if_necessary = [&](std::wstring &fqdn) {
		static wchar_t computer_name[MAX_COMPUTERNAME_LENGTH + 1];
		DWORD computer_name_size = MAX_COMPUTERNAME_LENGTH + 1;

		if (!GetComputerNameW(computer_name, &computer_name_size)) {
			auto err = GetLastError();
			logger.log(logmsg::error, fztranslate("GetRoamingProfilePath: GetComputerNameW failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, err);
			return false;
		}

		if (domain == computer_name) {
			domain.clear();
			fqdn.clear();
			return true;
		}

		// Resolve the domain controller name
		DOMAIN_CONTROLLER_INFOW* dc_info{};
		DWORD error = DsGetDcNameW(
			nullptr,
			domain.c_str(),
			nullptr,
			nullptr,
			DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
			&dc_info
		);

		bool success = error == ERROR_SUCCESS && dc_info && dc_info->DomainControllerName;
		if (success) {
			logger.log(logmsg::debug_debug, L"GetRoamingProfilePath(%s, %s): DC name = [%s]", user, domain, dc_info->DomainControllerName);
			fqdn = dc_info->DomainControllerName;
		}
		else {
			logger.log(logmsg::debug_debug, L"GetRoamingProfilePath(%s, %s): DsGetDcNameW failed. Error: %d.", user, domain, error);
		}

		NetApiBufferFree(dc_info);

		return success;
	};

	std::wstring fqdn;
	if (!make_fqdn_if_necessary(fqdn)) {
		return false;
	}

	thread worker;

	NET_API_STATUS netusergetinfo_status{};
	DWORD impersonateloggedonuser_err{};
	DWORD reverttoself_err{};

	worker.run([&] {
		if (!ImpersonateLoggedOnUser(h)) {
			impersonateloggedonuser_err = GetLastError();
			return;
		}

		LPBYTE buf_ptr = nullptr;
		netusergetinfo_status = NetUserGetInfo(fqdn.empty() ? nullptr : fqdn.c_str(), user.c_str(), 3, &buf_ptr);

		if (netusergetinfo_status == NERR_Success) {
			USER_INFO_3* user_info = reinterpret_cast<USER_INFO_3*>(buf_ptr);

			if (user_info->usri3_profile) {
				roaming_profile_path = user_info->usri3_profile;
			}
		}

		NetApiBufferFree(buf_ptr);

		if (!RevertToSelf()) {
			reverttoself_err = GetLastError();
		}
	});
	worker.join();

	if (impersonateloggedonuser_err) {
		logger.log(logmsg::error, fztranslate("GetRoamingProfilePath: ImpersonateLoggedOnUser failed. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, impersonateloggedonuser_err);
		return false;
	}

	if (netusergetinfo_status != NERR_Success) {
		logger.log(logmsg::error, fztranslate("GetRoamingProfilePath: NetUserGetInfo failed. User: '%s', Domain: '%s'. Status: %d."), user, domain, netusergetinfo_status);
	}

	if (reverttoself_err) {
		logger.log(logmsg::error, fztranslate("GetRoamingProfilePath: RevertToSelf failed, aborting. User: '%s', Domain: '%s'. Last Error: %d."), user, domain, reverttoself_err);
		std::fflush(nullptr);
		TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
	}

	return netusergetinfo_status == NERR_Success;
}

}

bool GetUserInfoFromToken(
	HANDLE h,
	std::string& sid_string,
	std::wstring& roaming_profile_path,
	std::wstring& username,
	std::wstring& domain,
	logger_interface& logger
)
{
	auto user = GetUserFromToken(h);
	if (!user) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("GetUserInfoFromToken: GetUserFromToken failed. Last Error: %d."), err);
		return false;
	}

	LPSTR sid{};
	if (!ConvertSidToStringSidA(user->User.Sid, &sid)) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("GetUserInfoFromToken: ConvertSidToStringSidA failed. Last Error: %d."), err);
		return false;
	}

	sid_string = sid;
	LocalFree(sid);

	if (!GetUserAndDomainFromSid(user->User.Sid, username, domain)) {
		auto err = GetLastError();
		logger.log(logmsg::error, fztranslate("GetUserInfoFromToken: GetUserAndDomainFromSid failed. Last Error: %d."), err);
		return false;
	}

	if (domain == L"NT AUTHORITY" || domain == L"BUILTIN") {
		roaming_profile_path.clear();
		domain.clear();
	}
	else
	if (!GetRoamingProfilePath(h, username, domain, roaming_profile_path, logger)) {
		return false;
	}

	return true;
}

namespace {
holder<TOKEN_PRIVILEGES> GetPrivileges(HANDLE token)
{
	DWORD needed{};
	GetTokenInformation(token, TokenPrivileges, NULL, 0, &needed);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		auto privs = holder<TOKEN_PRIVILEGES>::create(needed);
		if (GetTokenInformation(token, TokenPrivileges, privs.get(), needed, &needed)) {
			return privs;
		}
	}

	return {};
}
}

bool DropAdminPrivilegesFromToken(HANDLE h)
{
	auto privs = GetPrivileges(h);
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
			if (std::tie(luid.LowPart, luid.HighPart) == std::tie(privs->Privileges[i].Luid.LowPart, privs->Privileges[i].Luid.HighPart)) {
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
