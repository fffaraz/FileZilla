#ifndef LIBFILEZILLA_GLUE_DLL_HEADER
#define LIBFILEZILLA_GLUE_DLL_HEADER

#include "../libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "./windows.hpp"

namespace fz {

/**
 * \brief Encapsulates a DLL
 *
 * The DLL is loaded up on construction and freed on destruction.
 */
class FZ_PUBLIC_SYMBOL dll final
{
public:
	explicit dll()
		: h_{}
	{}

	/// Open the specified library with the passed in flags.
	explicit dll(wchar_t const* name, DWORD flags)
		: h_{LoadLibraryExW(name, nullptr, flags)}
	{}

	/// Closes the library and frees related resources
	~dll() {
		if (h_) {
			FreeLibrary(h_);
		}
	}

	template<typename T>
	static dll from_address(T const& t) {
		dll d;
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<char const*>(t), &d.h_)) {
			d.h_ = nullptr;
		}
		return d;
	}

	dll(dll const&) = delete;
	dll& operator=(dll const&) = delete;

	dll(dll && d);
	dll& operator=(dll && d);

	explicit operator bool() const {
		return h_ != nullptr;
	}

	/**
	 * \brief Retrieves the address of an exported symbol in the library
	 *
	 * Cast the address to the proper type with reinterpret_cast
	 */
	void *operator[](char const *name) const {
		return h_ ? reinterpret_cast<void*>(::GetProcAddress(h_, name)) : nullptr;
	}

private:
	mutable HMODULE h_{};
};

/**
 * \brief A collection of commonly used dlls.
 *
 */
class FZ_PUBLIC_SYMBOL shdlls final
{
protected:
	shdlls();
	~shdlls();

	shdlls(shdlls const&) = delete;
	shdlls* operator=(shdlls const&) = delete;

public:
	static shdlls& get();

	dll shell32_; ///< The Shell32 DLL
	dll ole32_;   ///< The Ole32 DLL
};

}

/**
 * \def FZ_DLL_IMPORT
 * \brief Imports a symbol from a dynamically loaded DLL.
 *
 * This macro retrieves the address of a symbol exported by a DLL and casts it to the correct type.
 * The imported symbol is stored as a static variable, ensuring it is only resolved once per translation unit.
 *
 * \param dll The instance of the \ref fz::dll class representing the loaded DLL.
 * \param symbol The name of the symbol to import, as it is exported by the DLL.
 *
 * \remark The imported symbol must be declared in the global scope as external (for variables) or
 *         as a prototype (for functions) at the point where this macro is instantiated.
 *         Additionally, this macro assumes the symbol being imported is not implemented as a macro itself.
 *         If the symbol name resolves to a macro, the behavior is undefined and may result in
 *         a compilation error, a linker error, or unexpected behavior.
 *
 * Example usage:
 * \code
 * fz::dll user32{L"user32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32};
 * FZ_DLL_IMPORT(user32, MessageBoxW);
 * if (MessageBoxW) {
 *     MessageBoxW(nullptr, L"Hello, World!", L"Example", MB_OK);
 * }
 * \endcode
 */
#define FZ_DLL_IMPORT(dll, symbol)                                                   \
	static const auto symbol = reinterpret_cast<decltype(&::symbol)>((dll)[#symbol]) \
/***/

#else
#error This file is for Windows only
#endif

#endif

