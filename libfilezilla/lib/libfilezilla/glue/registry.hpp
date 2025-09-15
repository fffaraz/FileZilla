#ifndef LIBFILEZILLA_GLUE_REGISTRY_HEADER
#define LIBFILEZILLA_GLUE_REGISTRY_HEADER

/** \file
 * \brief Declares fz::regkey to access the Windows Registry
 */

#include "../libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "windows.hpp"

#include <optional>
#include <string>

namespace fz {

/**
 * \brief Prepresents a key in the Windows registry
 *
 * Can access both the appropaire native registry view, as well
 * as explicitly the 32-bit and 64bit registry views.
 */
class FZ_PUBLIC_SYMBOL regkey final
{
public:
	regkey() = default;
	~regkey();

	enum regview {
		regview_native,
		regview_32,
		regview_64
	};


	/// See \sa regkey::open
	explicit regkey(HKEY const root, std::wstring const& subkey, bool readonly, regview v = regview_native);

	regkey(regkey const&) = delete;
	regkey& operator=(regkey const&) = delete;

	void close();

	/**
	 * \brief Opens the specified registry key
	 *
	 * If readonly is not set, missing subkeys are automatically created
	 */
	bool open(HKEY const root, std::wstring const& subkey, bool readonly, regview v = regview_native);

	bool has_value(std::wstring const& name) const;

	/// Gets the value with the given name as wstring, converting if necessary
	std::wstring value(std::wstring const& name) const;

	/// Gets the value with the given name as integer, converting if necessary
	uint64_t int_value(std::wstring const& name) const;

	bool set_value(std::wstring const& name, std::wstring const& value);
	bool set_value(std::wstring const& name, uint64_t value);

	explicit operator bool() const {
		return key_.has_value();
	}

	bool delete_value(std::wstring const& name);

private:
	mutable std::optional<HKEY> key_;
};
}

#else
#error This file is for Windows only
#endif

#endif
