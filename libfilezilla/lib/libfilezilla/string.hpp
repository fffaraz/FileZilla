#ifndef LIBFILEZILLA_STRING_HEADER
#define LIBFILEZILLA_STRING_HEADER

#include "libfilezilla.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

template<class CharT, class BaseT>
class traits_cloner
{
public:
	using char_type = CharT;

	using base_type = BaseT;
	using base_traits = std::char_traits<base_type>;

	static std::size_t length(char_type const* s) {
		return base_traits::length(reinterpret_cast<base_type const*>(s));
	}
	static int compare(char_type const* s1, char_type const* s2, std::size_t count) {
		return base_traits::compare(reinterpret_cast<base_type const*>(s1), reinterpret_cast<base_type const*>(s2), count);
	}
	static char_type* copy(char_type* dest, char_type const* src, std::size_t count) {
		return reinterpret_cast<char_type*>(base_traits::copy(reinterpret_cast<base_type*>(dest), reinterpret_cast<base_type const*>(src), count));
	}
	static void assign( char_type& c1, char_type const& c2 ) noexcept {
	c1 = c2;
	}
	static char_type const* find(char_type const* ptr, std::size_t count, char_type const& ch) {
		return reinterpret_cast<char_type const*>(base_traits::find(reinterpret_cast<base_type const*>(ptr), count, reinterpret_cast<base_type const&>(ch)));
	}
	static bool eq(char_type a, char_type b) {
		return base_traits::eq(static_cast<base_type>(a), static_cast<base_type>(b));
	}
};

template<>
class std::char_traits<uint8_t> : public traits_cloner<uint8_t, char>
{};

/** \file
 * \brief String types and assorted functions.
 *
 * Defines the \ref fz::native_string type and offers various functions to convert between
 * different string types.
 */

namespace fz {

/** \typedef native_string
 *
 * \brief A string in the system's native character type and encoding.\n Note: This typedef changes depending on platform!
 *
 * On Windows, the system's native encoding is UTF-16, so native_string is typedef'ed to std::wstring.
 *
 * On all other platform, native_string is a typedef for std::string.
 *
 * Always using native_string has the benefit that no conversion needs to be performed which is especially useful
 * if dealing with filenames.
 */

#ifdef FZ_WINDOWS
typedef std::wstring native_string;
typedef std::wstring_view native_string_view;
#endif
#if defined(FZ_UNIX) || defined(FZ_MAC)
typedef std::string native_string;
typedef std::string_view native_string_view;
#endif

/** \brief Converts std::string to native_string.
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
native_string FZ_PUBLIC_SYMBOL to_native(std::string_view const& in);

/** \brief Convert std::wstring to native_string.
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
native_string FZ_PUBLIC_SYMBOL to_native(std::wstring_view const& in);

/// Avoid converting native_string to native_string_view and back to native_string
template<typename T, typename std::enable_if_t<std::is_same_v<native_string, typename std::decay_t<T>>, int> = 0>
inline native_string to_native(T const& in) {
	return in;
}

/** \brief Locale-sensitive stricmp
 *
 * Like std::string::compare but case-insensitive, respecting locale.
 *
 * \note does not handle embedded null
 */
int FZ_PUBLIC_SYMBOL stricmp(std::string_view const& a, std::string_view const& b);
int FZ_PUBLIC_SYMBOL stricmp(std::wstring_view const& a, std::wstring_view const& b);

/** \brief Converts ASCII uppercase characters to lowercase as if C-locale is used.

 Under some locales there is a different case-relationship
 between the letters a-z and A-Z as one expects from ASCII under the C locale.
 In Turkish for example there are different variations of the letter i,
 namely dotted and dotless. What we see as 'i' is the lowercase dotted i and
 'I' is the  uppercase dotless i. Since std::tolower is locale-aware, I would
 become the dotless lowercase i.

 This is not always what we want. FTP commands for example are case-insensitive
 ASCII strings, LIST and list are the same.

 tolower_ascii instead converts all types of 'i's to the ASCII i as well.

 \return  A-Z becomes a-z.\n In addition dotless lowercase i and dotted uppercase i also become the standard i.

 */
template<typename Char>
Char tolower_ascii(Char c) {
	if (c >= 'A' && c <= 'Z') {
		return c + ('a' - 'A');
	}
	return c;
}

template<>
std::wstring::value_type FZ_PUBLIC_SYMBOL tolower_ascii(std::wstring::value_type c);

/// \brief Converts ASCII lowercase characters to uppercase as if C-locale is used.
template<typename Char>
Char toupper_ascii(Char c) {
	if (c >= 'a' && c <= 'z') {
		return c + ('A' - 'a');
	}
	return c;
}

template<>
std::wstring::value_type FZ_PUBLIC_SYMBOL toupper_ascii(std::wstring::value_type c);

/** \brief tr_tolower_ascii does for strings what tolower_ascii does for individual characters
 */
 // Note: For UTF-8 strings it works on individual octets!
std::string FZ_PUBLIC_SYMBOL str_tolower_ascii(std::string_view const& s);
std::wstring FZ_PUBLIC_SYMBOL str_tolower_ascii(std::wstring_view const& s);

std::string FZ_PUBLIC_SYMBOL str_toupper_ascii(std::string_view const& s);
std::wstring FZ_PUBLIC_SYMBOL str_toupper_ascii(std::wstring_view const& s);

/** \brief A type trait to identify the value_type of any string-like type.
 */
template<typename T, typename = void>
struct string_value_type;

template<typename T>
struct string_value_type<T, std::void_t<typename T::value_type>> {
	using type = typename T::value_type;
};

template<typename CharT>
struct string_value_type<CharT*> {
	using type = std::remove_cv_t<CharT>;
};

template<typename CharT, std::size_t N>
struct string_value_type<CharT (&)[N]> {
	using type = std::remove_cv_t<CharT>;
};

template<typename CharT, std::size_t N>
struct string_value_type<CharT[N]> {
	using type = std::remove_cv_t<CharT>;
};

// Helper alias for easier use.
template<typename T>
using string_value_type_t = typename string_value_type<T>::type;

/** \brief Comparator to be used for std::map for case-insensitive keys
 *
 * Comparison is done locale-agnostic.
 * Useful for key-value pairs in protocols, e.g. HTTP headers.
 */
struct FZ_PUBLIC_SYMBOL less_insensitive_ascii final
{
	using is_transparent = std::true_type;

	template<typename L, typename R,
		std::enable_if_t<std::is_same_v<string_value_type_t<L>, string_value_type_t<R>>>* = nullptr>
	bool operator()(L const& lhs, R const& rhs) const {
		std::basic_string_view<string_value_type_t<L>> lv(lhs);
		std::basic_string_view<string_value_type_t<R>> rv(rhs);

		return std::lexicographical_compare(lv.begin(), lv.end(), rv.begin(), rv.end(),
			[](auto const& a, auto const& b) {
				return tolower_ascii(a) < tolower_ascii(b);
			}
		);
	}
};

/** \brief Locale-insensitive stricmp
 *
 * Equivalent to str_tolower_ascii(a).compare(str_tolower_ascii(b));
 */
template<typename A, typename B,
	std::enable_if_t<std::is_same_v<string_value_type_t<A>, string_value_type_t<B>>>* = nullptr>
inline bool equal_insensitive_ascii(A const& a, B const& b)
{
	std::basic_string_view<string_value_type_t<A>> av(a);
	std::basic_string_view<string_value_type_t<B>> bv(b);

	return std::equal(av.cbegin(), av.cend(), bv.cbegin(), bv.cend(),
		[](auto const& a, auto const& b) {
			return tolower_ascii(a) == tolower_ascii(b);
		}
	);
}

/** \brief Converts from std::string in system encoding into std::wstring
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
std::wstring FZ_PUBLIC_SYMBOL to_wstring(std::string_view const& in);

/** \brief Returns identity, that way to_wstring can be called with native_string.
 *
 * This template deals with wide string literals, std::wstring and std::wstring_view parameters.
 */
template <typename T>
inline auto to_wstring(T && in) -> decltype(std::wstring(std::forward<T>(in)))
{
	return std::wstring(std::forward<T>(in));
}

/// Converts from arithmetic type to std::wstring
template<typename Arg>
inline typename std::enable_if<std::is_arithmetic_v<std::decay_t<Arg>>, std::wstring>::type to_wstring(Arg && arg)
{
	return std::to_wstring(std::forward<Arg>(arg));
}


/** \brief Converts from std::string in UTF-8 into std::wstring
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
std::wstring FZ_PUBLIC_SYMBOL to_wstring_from_utf8(std::string_view const& in);
std::wstring FZ_PUBLIC_SYMBOL to_wstring_from_utf8(char const* s, size_t len);

class buffer;
std::wstring FZ_PUBLIC_SYMBOL to_wstring_from_utf8(fz::buffer const& in);

/** \brief Converts from std::wstring into std::string in system encoding
 *
 * \return the converted string on success. On failure an empty string is returned.
 */
std::string FZ_PUBLIC_SYMBOL to_string(std::wstring_view const& in);

/** \brief Returns identity, that way to_wstring can be called with native_string.
 *
 * This template deals with string literals, std::string and std::string_view parameters.
 */
template <typename T>
inline auto to_string(T && in) -> decltype(std::string(std::forward<T>(in)))
{
	return std::string(std::forward<T>(in));
}


/// Converts from arithmetic type to std::string
template<typename Arg>
inline typename std::enable_if<std::is_arithmetic_v<std::decay_t<Arg>>, std::string>::type to_string(Arg && arg)
{
	return std::to_string(std::forward<Arg>(arg));
}


/// Returns length of 0-terminated character sequence. Works with both narrow and wide-characters.
template<typename Char>
size_t strlen(Char const* str) {
	return std::char_traits<Char>::length(str);
}


/** \brief Converts from std::string in native encoding into std::string in UTF-8
 *
 * \return the converted string on success. On failure an empty string is returned.
 *
 * \note Does not handle embedded nulls
 */
std::string FZ_PUBLIC_SYMBOL to_utf8(std::string_view const& in);

/** \brief Converts from std::wstring in native encoding into std::string in UTF-8
 *
 * \return the converted string on success. On failure an empty string is returned.
 *
 * \note Does not handle embedded nulls
 */
std::string FZ_PUBLIC_SYMBOL to_utf8(std::wstring_view const& in);

/// Calls either fz::to_string or fz::to_wstring depending on the passed template argument
template<typename String, typename Arg>
inline auto toString(Arg&& arg) -> typename std::enable_if<std::is_same_v<String, std::string>, decltype(to_string(std::forward<Arg>(arg)))>::type
{
	return to_string(std::forward<Arg>(arg));
}

template<typename String, typename Arg>
inline auto toString(Arg&& arg) -> typename std::enable_if<std::is_same_v<String, std::wstring>, decltype(to_wstring(std::forward<Arg>(arg)))>::type
{
	return to_wstring(std::forward<Arg>(arg));
}

#if !defined(fzT) || defined(DOXYGEN)
#ifdef FZ_WINDOWS
/** \brief Macro for a string literal in system-native character type.\n Note: Macro definition changes depending on platform!
 *
 * Example: \c fzT("this string is wide on Windows and narrow elsewhere")
 */
#define fzT(x) L ## x
#else
/** \brief Macro for a string literal in system-native character type.\n Note: Macro definition changes depending on platform!
 *
 * Example: \c fzT("this string is wide on Windows and narrow elsewhere")
 */
#define fzT(x) x
#endif
#endif

 /// Returns the function argument of the type matching the template argument. \sa fzS
template<typename Char>
constexpr Char const* choose_string(char const* c, wchar_t const* w);

template<> constexpr inline char const* choose_string(char const* c, wchar_t const*) { return c; }
template<> constexpr inline wchar_t const* choose_string(char const*, wchar_t const* w) { return w; }

#if !defined(fzS) || defined(DOXYGEN)
/** \brief Macro to get const pointer to a string of the corresponding type
 *
 * Useful when using string literals in templates where the type of string
 * is a template argument:
 * \code
 *   template<typename String>
 *   String append_foo(String const& s) {
 *       s += fzS(String::value_type, "foo");
 *   }
 * \endcode
 */
#define fzS(Char, s) fz::choose_string<Char>(s, L ## s)
#endif

 /** \brief Returns \c in with all occurrences of \c find in the input string replaced with \c replacement
  *
  * \arg find If empty, no replacement takes place.
  */
std::string FZ_PUBLIC_SYMBOL replaced_substrings(std::string_view const& in, std::string_view const& find, std::string_view const& replacement);
std::wstring FZ_PUBLIC_SYMBOL replaced_substrings(std::wstring_view const& in, std::wstring_view const& find, std::wstring_view const& replacement);

/// Returns \c in with all occurrences of \c find in the input string replaced with \c replacement
std::string FZ_PUBLIC_SYMBOL replaced_substrings(std::string_view const& in, char find, char replacement);
std::wstring FZ_PUBLIC_SYMBOL replaced_substrings(std::wstring_view const& in, wchar_t find, wchar_t replacement);

/** \brief Modifies \c in, replacing all occurrences of \c find with \c replacement
 *
 * \arg find If empty, no replacement takes place.
 */
bool FZ_PUBLIC_SYMBOL replace_substrings(std::string& in, std::string_view const& find, std::string_view const& replacement);
bool FZ_PUBLIC_SYMBOL replace_substrings(std::wstring& in, std::wstring_view const& find, std::wstring_view const& replacement);

/// Modifies \c in, replacing all occurrences of \c find with \c replacement
bool FZ_PUBLIC_SYMBOL replace_substrings(std::string& in, char find, char replacement);
bool FZ_PUBLIC_SYMBOL replace_substrings(std::wstring& in, wchar_t find, wchar_t replacement);

/**
 * \brief Container-like class that can be used to iterate over tokens in a string.
 *
 * The class will keep a copy of any temporary constructor's parameter.
 * strtokenizer must live longer than the iterators created from it.
 *
 * Access through the iterators returns views, make sure non-temporary arguments
 * to strtokenizer constructur live longer than the iterators.
 *
 * Do not modify a string for which there is an strtokenizer instance.
 *
 * Always use the construction guide for this class, never explictly use the
 * template parameters.
 *
 * Usage example:
 * \code
 * for (auto t : fz::strtokenizer("foo,baz,,bar", ",", true)) {
 *   std::cout << t << "\n";
 * }
 *
 * // Will print the following:
 * //     foo
 * //     baz
 * //     bar
 * \endcode
 */
template <typename String, typename Delims>
class strtokenizer
{
	using view_type = std::basic_string_view<std::decay_t<decltype(std::declval<String>()[0])>>;

public:
	/**
	 * \brief strtokenizer class constructor.
	 *
	 * \param delims the delimiters to look for
	 * \param ignore_empty If true, empty tokens are omitted in the output
	 */
	constexpr strtokenizer(String && string, Delims &&delims, bool ignore_empty)
		: string_(std::forward<String>(string))
		, delims_(std::forward<Delims>(delims))
		, ignore_empty_(ignore_empty)
	{}

	using value_type = const view_type;
	using pointer = value_type*;
	using reference = value_type&;
	using size_type = std::size_t;
	using difference_type = std::ptrdiff_t;

	struct sentinel{};

	struct iterator
	{
		using iterator_category = std::input_iterator_tag;
		using difference_type   = strtokenizer::difference_type;
		using value_type        = strtokenizer::value_type;
		using pointer           = strtokenizer::pointer;
		using reference         = strtokenizer::reference;

		constexpr bool operator !=(sentinel) const
		{
			return !s_.empty();
		}

		constexpr bool operator ==(sentinel) const
		{
			return s_.empty();
		}

		constexpr iterator& operator =(sentinel)
		{
			s_ = {};
			return *this;
		}

		constexpr bool operator ==(iterator const& op) const
		{
			return s_.size() == op.s_.size();
		}

		constexpr bool operator !=(iterator const& op) const
		{
			return s_.size() != op.s_.size();
		}

		constexpr value_type operator*() const
		{
			return s_.substr(0, pos_);
		}

		constexpr iterator &operator++()
		{
			for (;;) {
				if (pos_ != s_.size()) {
					++pos_;
				}

				s_.remove_prefix(pos_);

				pos_ = s_.find_first_of(t_->delims_);

				if (pos_ == view_type::npos) {
					pos_ = s_.size();
					break;
				}

				if (pos_ != 0 || !t_->ignore_empty_) {
					break;
				}
			}

			return *this;
		}

	private:
		friend strtokenizer;

		constexpr iterator(const strtokenizer *t)
			: t_(t)
			, s_(view_type(t_->string_))
			, pos_(view_type::npos)
		{
			operator++();
		}

		const strtokenizer *t_;
		view_type s_;
		size_type pos_;
	};

	using const_value_type = value_type;
	using const_pointer = pointer;
	using const_reference = reference;
	using const_iterator = iterator;

	constexpr iterator begin() const
	{
		return { this };
	}

	constexpr sentinel end() const
	{
		return {};
	}

	constexpr const_iterator cbegin() const
	{
		return { this };
	}

	constexpr sentinel cend() const
	{
		return {};
	}

public:
	String string_;
	Delims delims_;
	bool ignore_empty_;
};

/**
 * \brief strtokenizer class construction-guide.
 *
 * \param delims the delimiters to look for
 * \param ignore_empty If true, empty tokens are omitted in the output
 */
template <typename String, typename Delims>
strtokenizer(String && string, Delims &&delims, bool ignore_empty) -> strtokenizer<String, Delims>;

/**
 * \brief Tokenizes string.
 *
 * \param delims the delimiters to look for
 * \param ignore_empty If true, empty tokens are omitted in the output
 */
std::vector<std::string> FZ_PUBLIC_SYMBOL strtok(std::string_view const& tokens, std::string_view const& delims, bool const ignore_empty = true);
std::vector<std::wstring> FZ_PUBLIC_SYMBOL strtok(std::wstring_view const& tokens, std::wstring_view const& delims, bool const ignore_empty = true);
inline auto FZ_PUBLIC_SYMBOL strtok(std::string_view const& tokens, char const delim, bool const ignore_empty = true) {
	return strtok(tokens, std::string_view(&delim, 1), ignore_empty);
}
inline auto FZ_PUBLIC_SYMBOL strtok(std::wstring_view const& tokens, wchar_t const delim, bool const ignore_empty = true) {
	return strtok(tokens, std::wstring_view(&delim, 1), ignore_empty);
}

/**
 * \brief Tokenizes string.
 *
 * \warning This function returns string_views, mind the lifetime of the string passed in tokens.
 *
 * \param delims the delimiters to look for
 * \param ignore_empty If true, empty tokens are omitted in the output
 */
std::vector<std::string_view> FZ_PUBLIC_SYMBOL strtok_view(std::string_view const& tokens, std::string_view const& delims, bool const ignore_empty = true);
std::vector<std::wstring_view> FZ_PUBLIC_SYMBOL strtok_view(std::wstring_view const& tokens, std::wstring_view const& delims, bool const ignore_empty = true);
inline auto FZ_PUBLIC_SYMBOL strtok_view(std::string_view const& tokens, char const delim, bool const ignore_empty = true) {
	return strtok_view(tokens, std::string_view(&delim, 1), ignore_empty);
}
inline auto FZ_PUBLIC_SYMBOL strtok_view(std::wstring_view const& tokens, wchar_t const delim, bool const ignore_empty = true) {
	return strtok_view(tokens, std::wstring_view(&delim, 1), ignore_empty);
}

/// \private
template<typename T, typename String>
bool to_integral_impl(String const& s, T & v)
{
	if constexpr (std::is_same_v<T, bool>) {
		unsigned int w{};
		if (!to_integral_impl(s, w)) {
			return false;
		}
		v = w != 0;
		return true;
	}
	else if constexpr (std::is_enum_v<T>) {
		return to_integral_impl<std::underlying_type_t<T>>(s, reinterpret_cast<std::underlying_type_t<T>&>(v));
	}
	else {
		bool negative{};

		auto it = s.cbegin();
		if (it != s.cend() && (*it == '-' || *it == '+')) {
			if (*it == '-') {
				if constexpr (std::is_signed_v<T>) {
					negative = true;
				}
				else {
					return false;
				}
			}
			++it;
		}

		if (it == s.cend()) {
			return false;
		}

		v = T{};
		if (negative) {
			auto constexpr min = std::numeric_limits<T>::min();
			auto constexpr min10 = min / 10;
			for (; it != s.cend(); ++it) {
				auto const& c = *it;
				if (c < '0' || c > '9') {
					return false;
				}
				if (v < min10) {
					return false;
				}
				v *= 10;
				auto digit = -static_cast<T>(c - '0');
				if (min - v > digit) {
					return false;
				}
				v += digit;
			}
		}
		else {
			auto constexpr max = std::numeric_limits<T>::max();
			auto constexpr max10 = max / 10;
			for (; it != s.cend(); ++it) {
				auto const& c = *it;
				if (c < '0' || c > '9') {
					return false;
				}
				if (v > max10) {
					return false;
				}
				v *= 10;
				auto digit = static_cast<T>(c - '0');
				if (max - v < digit) {
					return false;
				}
				v += digit;
			}
		}
	}
	return true;
}

/// Converts string to integral type T. If string is not convertible, errorval is returned.
template<typename T>
T to_integral(std::string_view const& s, T const errorval = T()) {
	T out{};
	if (!to_integral_impl<T>(s, out)) {
		out = errorval;
	}
	return out;
}

template<typename T>
T to_integral(std::wstring_view const& s, T const errorval = T()) {
	T out{};
	if (!to_integral_impl<T>(s, out)) {
		out = errorval;
	}
	return out;
}

template<typename T, typename StringType>
T to_integral(std::basic_string_view<StringType> const& s, T const errorval = T()) {
	T out{};
	if (!to_integral_impl<T>(s, out)) {
		out = errorval;
	}
	return out;
}

/// Converts string to integral type T. If string is not convertible, nullopt
template<typename T>
std::optional<T> to_integral_o(std::string_view const& s) {
	std::optional<T> ret;
	T out{};
	if (to_integral_impl<T>(s, out)) {
		ret = out;
	}
	return ret;
}

template<typename T>
std::optional<T> to_integral_o(std::wstring_view const& s) {
	std::optional<T> ret;
	T out{};
	if (to_integral_impl<T>(s, out)) {
		ret = out;
	}
	return ret;
}

template<typename T, typename StringType>
std::optional<T> to_integral_o(std::basic_string_view<StringType> const& s) {
	std::optional<T> ret;
	T out{};
	if (to_integral_impl<T>(s, out)) {
		ret = out;
	}
	return ret;
}


/// \brief Returns true iff the string only has characters in the 7-bit ASCII range
template<typename String>
bool str_is_ascii(String const& s) {
	for (auto const& c : s) {
		if (static_cast<std::make_unsigned_t<typename String::value_type>>(c) > 127) {
			return false;
		}
	}

	return true;
}

/// \private
template<typename String, typename Chars>
void trim_impl(String & s, Chars const& chars, bool fromLeft, bool fromRight) {
	size_t const first = fromLeft ? s.find_first_not_of(chars) : 0;
	if (first == String::npos) {
		s = String();
		return;
	}

	size_t const last = fromRight ? s.find_last_not_of(chars) : s.size();
	if (last == String::npos) {
		s = String();
		return;
	}

	// Invariant: If first exists, then last >= first
	s = s.substr(first, last - first + 1);
}

/// \brief Return passed string with all leading and trailing whitespace removed
inline std::string FZ_PUBLIC_SYMBOL trimmed(std::string_view s, std::string_view const& chars = " \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
	return std::string(s);
}

inline std::wstring FZ_PUBLIC_SYMBOL trimmed(std::wstring_view s, std::wstring_view const& chars = L" \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
	return std::wstring(s);
}

inline std::string FZ_PUBLIC_SYMBOL ltrimmed(std::string_view s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, true, false);
	return std::string(s);
}

inline std::wstring FZ_PUBLIC_SYMBOL ltrimmed(std::wstring_view s, std::wstring_view const& chars = L" \r\n\t")
{
	trim_impl(s, chars, true, false);
	return std::wstring(s);
}

inline std::string FZ_PUBLIC_SYMBOL rtrimmed(std::string_view s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, false, true);
	return std::string(s);
}

inline std::wstring FZ_PUBLIC_SYMBOL rtrimmed(std::wstring_view s, std::wstring_view const& chars = L" \r\n\t")
{
	trim_impl(s, chars, false, true);
	return std::wstring(s);
}


/// \brief Remove all leading and trailing whitespace from string
template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, char>, int> = 0>
inline void trim(String & s, std::string_view const& chars = " \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, wchar_t>, int> = 0>
inline void trim(String & s, std::wstring_view const& chars = L" \r\n\t", bool fromLeft = true, bool fromRight = true)
{
	trim_impl(s, chars, fromLeft, fromRight);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, char>, int> = 0>
inline void ltrim(String& s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, true, false);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, wchar_t>, int> = 0>
inline void ltrim(String& s, std::wstring_view  const& chars = L" \r\n\t")
{
	trim_impl(s, chars, true, false);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, char>, int> = 0>
inline void rtrim(String& s, std::string_view const& chars = " \r\n\t")
{
	trim_impl(s, chars, false, true);
}

template<typename String, typename std::enable_if_t<std::is_same_v<typename String::value_type, wchar_t>, int> = 0>
inline void rtrim(String & s, std::wstring_view const& chars = L" \r\n\t")
{
	trim_impl(s, chars, false, true);
}

/** \brief Tests whether the first string starts with the second string
 *
 * \tparam insensitive_ascii If true, comparison is case-insensitive
 */
template<bool insensitive_ascii = false, typename String, typename Beginning>
	std::enable_if_t<std::is_same_v<string_value_type_t<String>, string_value_type_t<Beginning>>,
bool> starts_with(String const& s, Beginning const& beginning)
{
	std::basic_string_view<string_value_type_t<String>> sv(s);
	std::basic_string_view<string_value_type_t<Beginning>> beginningv(beginning);

	if (beginningv.size() > sv.size()) {
		return false;
	}

	if constexpr (insensitive_ascii) {
		return std::equal(beginningv.begin(), beginningv.end(), sv.begin(), [](auto const& a, auto const& b) {
			return tolower_ascii(a) == tolower_ascii(b);
		});
	} else {
		return std::equal(beginningv.begin(), beginningv.end(), sv.begin());
	}
}

/** \brief Tests whether the first string ends with the second string
 *
 * \tparam insensitive_ascii If true, comparison is case-insensitive
 */
template<bool insensitive_ascii = false, typename String, typename Ending>
	std::enable_if_t<std::is_same_v<string_value_type_t<String>, string_value_type_t<Ending>>,
bool> ends_with(String const& s, Ending const& ending)
{
	std::basic_string_view<string_value_type_t<String>> sv(s);
	std::basic_string_view<string_value_type_t<Ending>> endingv(ending);

	if (endingv.size() > sv.size()) {
		return false;
	}

	if constexpr (insensitive_ascii) {
		return std::equal(endingv.rbegin(), endingv.rend(), sv.rbegin(), [](auto const& a, auto const& b) {
			return tolower_ascii(a) == tolower_ascii(b);
		});
	}
	else {
		return std::equal(endingv.rbegin(), endingv.rend(), sv.rbegin());
	}
}

/**
 * Normalizes various hyphens, dashes and minuses to just hyphen-minus.
 *
 * The narrow version assumes UTF-8 as encoding.
 */
std::string FZ_PUBLIC_SYMBOL normalize_hyphens(std::string_view const& in);
std::wstring FZ_PUBLIC_SYMBOL normalize_hyphens(std::wstring_view const& in);

/// Verifies that the input data is valid UTF-8.
bool FZ_PUBLIC_SYMBOL is_valid_utf8(std::string_view s);

/**
 * \brief Verifies that the input data is valid UTF-8.
 *
 * The verfication state is exposed, you can use this function to verify
 * data to be in UTF-8 in a piecewise fashion.
 * When starting verification, initialize state with 0 and call the function
 * for as many blocks of data as needed, each time passing the previously
 * updated state along.
 *
 * If the input data on any particular call ends in the midlde of a UTF-8
 * sequence, state is updated, so that the the check can continue with the
 * next block of data.
 *
 * Once you have no data left to verify, check that the state is zero. If it
 * is non-zero, the input data was prematurely terminated in the middle of a
 * UTF-8 sequence.
 *
 * If the input data is invalid, the function returns false and state is
 * updated with the offset of the offending input byte.
 */
bool FZ_PUBLIC_SYMBOL is_valid_utf8(std::string_view s, size_t & state);

/**
 * \brief Encodes a valid Unicode codepoint as UTF-8 and appends it to the passed string
 *
 * Undefined if not passed a valid codepoint.
 */
void FZ_PUBLIC_SYMBOL unicode_codepoint_to_utf8_append(std::string& result, uint32_t codepoint);

/**
 * \brief Converts from UTF-16-BE and appends it to the passed string
 *
 * The conversion state is exposed, you can use this function to convert
 * data to UTF-8 in a piecewise fashion.
 * When starting conversion, initialize state with 0 and call the function
 * for as many blocks of data as needed, each time passing the previously
 * updated state along.
 *
 * If the input data on any particular call ends in the midlde of a UTF-16
 * sequence, state is updated, so that the conversion can continue at the next
 * iteration.
 *
 * Once you have no data left to convert, check that the state is zero. If it
 * is non-zero, the input data was prematurely terminated in the middle of a
 * UTF-16 sequence.
 *
 * If the input data is invalid, the function returns false and state is
 * updated with the offset of the offending input byte.
 */
bool FZ_PUBLIC_SYMBOL utf16be_to_utf8_append(std::string & result, std::string_view data, uint32_t & state);

/// Just as utf16be_to_utf8_append but for little-endian UTF-16.
bool FZ_PUBLIC_SYMBOL utf16le_to_utf8_append(std::string & result, std::string_view data, uint32_t & state);

inline native_string to_native_from_utf8(std::string_view s) {
#ifdef FZ_WINDOWS
	return to_wstring_from_utf8(s);
#else
	return to_string(to_wstring_from_utf8(s));
#endif
}

FZ_PUBLIC_SYMBOL void wipe_conversion_cache();

}

#endif
