#include "../libfilezilla/glue/dll.hpp"

#include <objbase.h>

namespace fz {
namespace {
extern "C" {
typedef HRESULT (STDAPICALLTYPE *coinitex_t)(LPVOID, DWORD);
typedef HRESULT (STDAPICALLTYPE *couninit_t)();
}
}

dll::dll(dll && d)
{
	h_ = d.h_;
	d.h_ = nullptr;
}

dll& dll::operator=(dll && d)
{
	if (&d != this) {
		if (h_) {
			FreeLibrary(h_);
		}
		h_ = d.h_;
		d.h_ = nullptr;
	}
	return *this;
}

shdlls::shdlls()
	: shell32_(L"shell32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)
	, ole32_(L"ole32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32)
{
	auto const coinitex = reinterpret_cast<coinitex_t>(ole32_["CoInitializeEx"]);
	if (coinitex) {
		coinitex(NULL, COINIT_MULTITHREADED);
	}
}

shdlls::~shdlls()
{
	auto const couninit = reinterpret_cast<couninit_t>(ole32_["CoUninitialize"]);
	if (couninit) {
		couninit();
	}
}

shdlls& shdlls::get()
{
	static shdlls d;
	return d;
}
}
