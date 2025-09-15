#ifndef LIBFILEZILLA_GLUE_WX_HEADER
#define LIBFILEZILLA_GLUE_WX_HEADER

/** \file
 * \brief Glue to handle support wxString for some functions
 */


#include "../private/defs.hpp"
#if FZ_WINDOWS
#include "windows.hpp"
#endif

#include <wx/string.h>

#include "../format.hpp"
#include "../string.hpp"

namespace fz {
template<typename T, typename std::enable_if_t<std::is_same_v<wxString, typename std::decay_t<T>>, int> = 0>
inline std::wstring to_wstring(T const& s) {
	return s.ToStdWstring();
}

template<typename T, typename std::enable_if_t<std::is_same_v<wxString, typename std::decay_t<T>>, int> = 0>
inline native_string to_native(T const& in)
{
	return to_native(in.ToStdWstring());
}

template<typename T, typename std::enable_if_t<std::is_same_v<wxString, typename std::decay_t<T>>, int> = 0>
inline std::string to_utf8(T const& s)
{
	return to_utf8(s.ToStdWstring());
}

template<typename T, typename std::enable_if_t<std::is_same_v<wxString, typename std::decay_t<T>>, int> = 0, typename... Args>
std::wstring sprintf(T const& fmt, Args&&... args)
{
	return sprintf(fmt.ToStdWstring(), std::forward<Args>(args)...);
}

}

#endif
