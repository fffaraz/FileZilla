#ifndef FILEZILLA_COMMONUI_LOGINMANAGER_HEADER
#define FILEZILLA_COMMONUI_LOGINMANAGER_HEADER

#include "site.h"
#include "visibility.h"

#include <libfilezilla/encryption.hpp>

#include <map>
#include <list>
#include <string>
#include <vector>

// The purpose of this class is to manage some aspects of the login
// behaviour. These are:
// - Query credentials for servers with ASK or INTERACTIVE logontype
// - Storage of passwords for ASK servers for duration of current session

class FZCUI_PUBLIC_SYMBOL login_manager
{
public:
	virtual ~login_manager() = default;

	bool GetPassword(Site & site, bool silent);
	bool GetPassword(Site & site, bool silent, std::wstring const& challenge, bool otp, bool canRemember);

	void CachedPasswordFailed(CServer const& server, std::wstring const& challenge = std::wstring());

	void RememberPassword(Site & site, std::wstring const& challenge = std::wstring());

	fz::private_key GetDecryptor(fz::public_key const& pub, bool * forgotten = nullptr);
	void Remember(fz::private_key const& key, std::string_view const& pass = std::string_view());

	void RememberAsForgotten(fz::public_key const& pub_key);

protected:

	virtual bool query_unprotect_site(Site&) { return false; }
	virtual bool query_credentials(Site&, std::wstring const& /*challenge*/, bool /*otp*/, bool /*canRemember*/) { return false; }

	// Session password cache for Ask-type servers
	struct t_passwordcache final
	{
		std::wstring host;
		unsigned int port{};
		std::wstring user;
		std::wstring password;
		std::wstring challenge;
	};

	std::list<t_passwordcache>::iterator FindItem(CServer const& server, std::wstring const& challenge);

	std::list<t_passwordcache> m_passwordCache;

	std::map<fz::public_key, fz::private_key> decryptors_;
	std::vector<std::string> decryptorPasswords_;
};

#endif
