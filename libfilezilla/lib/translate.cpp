#include "libfilezilla/translate.hpp"
#include "libfilezilla/string.hpp"

namespace fz {
namespace {
std::wstring default_translator(char const* const t)
{
	return fz::to_wstring(t);
}

std::wstring default_translator_pf(char const* const singular, char const* const plural, int64_t n)
{
	return fz::to_wstring((n == 1) ? singular : plural);
}

std::wstring(*translator)(char const* const) = default_translator;
std::wstring(*translator_pf)(char const* const singular, char const* const plural, int64_t n) = default_translator_pf;
}

void set_translators(
	std::wstring(*s)(char const* const t),
	std::wstring(*pf)(char const* const singular, char const* const plural, int64_t n)
)
{
	translator = s ? s : default_translator;
	translator_pf = pf ? pf : default_translator_pf;
}

std::wstring translate(char const * const t)
{
	return translator(t);
}

std::wstring translate(char const * const singular, char const * const plural, int64_t n)
{
	return translator_pf(singular, plural, n);
}
}
