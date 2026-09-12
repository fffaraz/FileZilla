#ifndef LIBFILEZILLA_WINDOWS_TOKEN_PRIVILEGES_HEADER
#define LIBFILEZILLA_WINDOWS_TOKEN_PRIVILEGES_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"

namespace fz {

bool has_process_privilege(wchar_t const *privilege);
bool DropAdminPrivilegesFromToken(HANDLE h);

}

#endif
#endif
