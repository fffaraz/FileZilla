#ifndef LIBFILEZILLA_TRANSLATE_HEADER
#define LIBFILEZILLA_TRANSLATE_HEADER

#include "libfilezilla.hpp"

#include <string>

/** \file
 * \brief Functions to translate strings
 */
namespace fz {

/** \brief Sets translators for strings
 *
 * You could pass functions that in turn call gettext/ngettext
 */
void FZ_PUBLIC_SYMBOL set_translators(
	std::wstring(*s) (char const* const t),
	std::wstring(*pf)(char const* const singular, char const* const plural, int64_t n)
);

/** \brief Translates the input string with the configured translator.
 *
 * Returns the untranslated string is if no translator has previously been configured
 */
std::wstring FZ_PUBLIC_SYMBOL translate(char const* const source);
std::wstring FZ_PUBLIC_SYMBOL translate(char const* const singular, char const * const plural, int64_t n);
}

// Sadly xgettext cannot be used with namespaces
#define fztranslate fz::translate
#define fztranslate fz::translate
#define fztranslate_mark

#endif
