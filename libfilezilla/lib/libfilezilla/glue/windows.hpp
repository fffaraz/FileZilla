#ifndef LIBFILEZILLA_GLUE_WINDOWS_HEADER
#define LIBFILEZILLA_GLUE_WINDOWS_HEADER

#include "../private/defs.hpp"

#ifndef FZ_WINDOWS
#error "You included a file you should not include"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Don't let Windows headers #define min/max, clashes with std::min/max
#ifndef NOMINMAX
#define NOMINMAX
#endif

// IE 9 or higher
#ifndef _WIN32_IE
#define _WIN32_IE 0x0900
#elif _WIN32_IE <= 0x0900
#undef _WIN32_IE
#define _WIN32_IE 0x0900
#endif

// Windows 7 or higher
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#elif _WIN32_WINNT < 0x0601
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

// Windows 7 or higher
#ifndef WINVER
#define WINVER 0x0601
#elif WINVER < 0x0601
#undef WINVER
#define WINVER 0x0601
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#ifndef UNICODE
#define UNICODE
#endif

#ifndef STRICT
#define STRICT 1
#endif

#include <windows.h>
#include <shellapi.h>

#ifndef ERROR_DISK_QUOTA_EXCEEDED
#define ERROR_DISK_QUOTA_EXCEEDED 1295
#endif

#endif
