#ifndef LIBFILEZILLA_GLUE_WXINVOKER_HEADER
#define LIBFILEZILLA_GLUE_WXINVOKER_HEADER

/** \file
 * \brief Glue to create invokers using the event system of wxWidgets.
 */

#include "../invoker.hpp"

#include <wx/event.h>

namespace fz {

/// \private
template<typename... Args>
std::function<void(Args...)> do_make_invoker(wxEvtHandler& handler, std::function<void(Args...)> && f)
{
	return [&handler, cf = f](Args&&... args) mutable {
		auto cb = [cf, targs = std::make_tuple(std::forward<Args>(args)...)] {
			std::apply(cf, targs);
		};
		handler.CallAfter(cb);
	};
}

/// \brief Alternative version of fz::invoke that accepts wxEvtHandler
template<typename F>
auto make_invoker(wxEvtHandler& handler, F && f)
{
	return do_make_invoker(handler, decltype(get_func_type(&F::operator()))(std::forward<F>(f)));
}

/// \brief Returns an invoker factory utilizing the event system of of wx.
inline invoker_factory get_invoker_factory(wxEvtHandler& handler)
{
	return [&handler](std::function<void()> const& cb) mutable {
		handler.CallAfter(cb);
	};
}

}

#endif
