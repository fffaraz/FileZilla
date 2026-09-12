#ifndef LIBFILEZILLA_WINDOWS_IMPERSONATION_DESKTOP_IMPL_HEADER
#define LIBFILEZILLA_WINDOWS_IMPERSONATION_DESKTOP_IMPL_HEADER

#include "../libfilezilla/impersonation.hpp"

#ifdef FZ_WINDOWS

namespace fz {

class logger_interface;

namespace impersonation_desktop
{
	class impl
	{
	public:
		class named;
		class isolated;
		class inherited_or_isolated;

		virtual ~impl() = 0;
		virtual bool init(HANDLE token, logger_interface &logger) = 0;
		virtual std::wstring const *name() = 0;

		static std::unique_ptr<impl> make(const mode &m);
	};
}

}

#endif

#endif
