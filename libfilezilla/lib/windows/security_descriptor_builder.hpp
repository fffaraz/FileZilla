#ifndef LIBFILEZILLA_WINDOWS_SECURITY_DESCRIPTOR_BUILDER_HEADER
#define LIBFILEZILLA_WINDOWS_SECURITY_DESCRIPTOR_BUILDER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"
#include "../libfilezilla/logger.hpp"
#include <memory>

namespace fz {
enum class sdb_flags : unsigned
{
	none = 0,
	inherit_from_parent = 0x1, // ACLs from parent can be inherited
	inheritable = 0x2, // Allos ACLs to be inherited by children
};
inline bool operator&(sdb_flags lhs, sdb_flags rhs) {
	return (static_cast<std::underlying_type_t<sdb_flags>>(lhs) & static_cast<std::underlying_type_t<sdb_flags>>(rhs)) != 0;
}
inline sdb_flags operator|(sdb_flags lhs, sdb_flags rhs)
{
	return static_cast<sdb_flags>(static_cast<std::underlying_type_t<sdb_flags>>(lhs) | static_cast<std::underlying_type_t<sdb_flags>>(rhs));
}
inline sdb_flags& operator|=(sdb_flags& lhs, sdb_flags rhs)
{
	lhs = lhs | rhs;
	return lhs;
}

class security_descriptor_builder final
{
public:
	enum entity {
		self,
		administrators,
		authenticated_users,
		users,
		system
	};

	security_descriptor_builder();
	~security_descriptor_builder();

	security_descriptor_builder(security_descriptor_builder const&) = delete;
	security_descriptor_builder& operator=(security_descriptor_builder const&) = delete;

	void add(entity e, DWORD rights = GENERIC_ALL | STANDARD_RIGHTS_ALL | SPECIFIC_RIGHTS_ALL);

	ACL* get_acl(sdb_flags f);
	SECURITY_DESCRIPTOR* get_sd(sdb_flags f);

private:
	struct impl;
	std::unique_ptr<impl> impl_;
};

bool GetUserAndDomainFromSid(PSID sid, std::wstring& user, std::wstring& domain);
bool GetUserInfoFromToken(HANDLE h, std::string& sid_string, std::wstring& roaming_profile_path, std::wstring& username, std::wstring& domain, logger_interface& logger = get_null_logger());
bool DropAdminPrivilegesFromToken(HANDLE h);

}

#endif
#endif
