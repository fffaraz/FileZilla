
#include "serverdata.h"
#include "loginmanager.h"
#include "Options.h"

#include "../commonui/protect.h"

void protect(ProtectedCredentials& creds)
{
	protect(creds, CLoginManager::Get(), *COptions::Get());
}
