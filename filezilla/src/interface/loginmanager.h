#ifndef FILEZILLA_INTERFACE_LOGINMANAGER_HEADER
#define FILEZILLA_INTERFACE_LOGINMANAGER_HEADER

#include "serverdata.h"
#include "../commonui/login_manager.h"

#include <list>

// The purpose of this class is to manage some aspects of the login
// behaviour. These are:
// - Password dialog for servers with ASK or INTERACTIVE logontype
// - Storage of passwords for ASK servers for duration of current session

class CLoginManager : public login_manager
{
public:
	static CLoginManager& Get() { return m_theLoginManager; }

	bool AskDecryptor(fz::public_key const& pub, bool allowForgotten, bool allowCancel);

protected:
	bool query_unprotect_site(Site & site);
	bool query_credentials(Site & site, std::wstring const& challenge, bool otp, bool canRemember);

	static CLoginManager m_theLoginManager;
};

#endif
