#ifndef LIBFILEZILLA_WINDOWS_IMPERSONATION_LOGON_HELPER_HEADER
#define LIBFILEZILLA_WINDOWS_IMPERSONATION_LOGON_HELPER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"

#include <string>

namespace fz {

class logger_interface;

namespace windows {

bool passwordless_logon_user(std::wstring const &user, std::wstring const &domain, bool use_kerberos, HANDLE &token, std::wstring &profile_path, logger_interface &logger);

}

}

#endif
#endif
