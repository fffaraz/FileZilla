#ifndef LIBFILEZILLA_WINDOWS_IMPERSONATION_PROFILE_HELPER_HEADER
#define LIBFILEZILLA_WINDOWS_IMPERSONATION_PROFILE_HELPER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"

#include <string>

namespace fz {

class logger_interface;

namespace windows {

HANDLE load_user_profile(HANDLE token, std::wstring const &user, std::wstring const &server, std::wstring const &roaming_profile_path, logger_interface &logger);

}

}

#endif

#endif
