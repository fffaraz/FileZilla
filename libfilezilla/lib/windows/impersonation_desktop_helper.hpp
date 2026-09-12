#ifndef LIBFILEZILLA_WINDOWS_IMPERSONATION_DESKTOP_HELPER_HEADER
#define LIBFILEZILLA_WINDOWS_IMPERSONATION_DESKTOP_HELPER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"

#include <memory>
#include <optional>
#include <string>

namespace fz {

class logger_interface;

namespace windows {

struct window_station_closer {
	using pointer = HWINSTA;
	void operator()(HWINSTA h) const;
};

struct desktop_closer {
	using pointer = HDESK;
	void operator()(HDESK h) const;
};

using unique_window_station = std::unique_ptr<HWINSTA, window_station_closer>;
using unique_desktop = std::unique_ptr<HDESK, desktop_closer>;

struct resolved_impersonation_desktop final
{
	std::wstring name;
	unique_window_station window_station;
	unique_desktop desktop;
};

std::optional<resolved_impersonation_desktop> resolve_impersonation_desktop(HANDLE token, std::wstring const &desktop_name_prefix, logger_interface &logger);

}

}

#endif

#endif
