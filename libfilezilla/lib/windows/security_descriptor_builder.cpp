#include "security_descriptor_builder.hpp"

#ifdef FZ_WINDOWS

#include "helpers.hpp"

#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/translate.hpp"

#include <map>

#include <sddl.h>

namespace fz {

namespace {
using windows::holder;
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

bool GetUserInfoFromToken(
	HANDLE h,
	std::string& sid_string,
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
		domain.clear();
	}

	return true;
}

}
#endif
