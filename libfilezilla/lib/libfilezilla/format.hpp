#ifndef LIBFILEZILLA_FORMAT_HEADER
#define LIBFILEZILLA_FORMAT_HEADER

#include "encode.hpp"
#include "string.hpp"

#include <cstdlib>
#include <type_traits>

#ifdef LFZ_FORMAT_DEBUG
#include <assert.h>
#define format_assert(pred) assert((pred))
#else
#define format_assert(pred)
#endif

/** \file
* \brief Header for the \ref fz::sprintf "sprintf" string formatting function
*/

namespace fz {

/// \cond
namespace detail {

// Get flags
enum : char {
	pad_0 = 1,
	pad_blank = 2,
	with_width = 4,
	left_align = 8,
	always_sign = 16
};

struct field final {
	size_t width{};
	char flags{};
	char type{};

	explicit operator bool() const { return type != 0; }
};

template<typename Arg>
bool is_negative([[maybe_unused]] Arg && v)
{
	if constexpr (std::is_signed_v<std::decay_t<Arg>>) {
		return v < 0;
	}
	else {
		return false;
	}
}

// Converts integral type to desired string type...
// ... basic case: simple unsigned value
template<typename String, bool Unsigned, typename Arg>
typename std::enable_if_t<std::is_integral_v<std::decay_t<Arg>> && !std::is_enum_v<std::decay_t<Arg>>, String> integral_to_string(field const& f, Arg && arg)
{
	std::decay_t<Arg> v = arg;

	char lead{};

	format_assert(!Unsigned || !std::is_signed_v<std::decay_t<Arg>> || arg >= 0);

	if (is_negative(arg)) {
		lead = '-';
	}
	else if (f.flags & always_sign) {
		lead = '+';
	}
	else if (f.flags & pad_blank) {
		lead = ' ';
	}

	// max decimal digits in b-bit integer is floor((b-1) * log_10(2)) + 1 < b * 0.5 + 1
	typename String::value_type buf[sizeof(v) * 4 + 1];
	auto *const end = buf + sizeof(v) * 4 + 1;
	auto *p = end;

	do {
		int const mod = std::abs(static_cast<int>(v % 10));
		*(--p) = '0' + mod;
		v /= 10;
	} while (v);

	auto width = f.width;
	if (f.flags & with_width) {
		if (lead && width > 0) {
			--width;
		}

		String ret;

		if (f.flags & pad_0) {
			if (lead) {
				ret += lead;
			}
			if (static_cast<size_t>(end - p) < width) {
				ret.append(width - (end - p), '0');
			}
			ret.append(p, end);
		}
		else {
			if (static_cast<size_t>(end - p) < width && !(f.flags & left_align)) {
				ret.append(width - (end - p), ' ');
			}
			if (lead) {
				ret += lead;
			}
			ret.append(p, end);
			if (static_cast<size_t>(end - p) < width && f.flags & left_align) {
				ret.append(width - (end - p), ' ');
			}
		}

		return ret;
	}
	else {
		if (lead) {
			*(--p) = lead;
		}
		return String(p, end);
	}
}

// ... for strongly typed enums
template<typename String, bool Unsigned, typename Arg>
typename std::enable_if_t<std::is_enum_v<std::decay_t<Arg>>, String> integral_to_string(field const& f, Arg && arg)
{
	return integral_to_string<String, Unsigned>(f, static_cast<std::underlying_type_t<std::decay_t<Arg>>>(arg));
}

// ... assert otherwise
template<typename String, bool Unsigned, typename Arg>
typename std::enable_if_t<!std::is_integral_v<std::decay_t<Arg>> && !std::is_enum_v<std::decay_t<Arg>>, String> integral_to_string(field const&, Arg &&)
{
	format_assert(0);
	return String();
}

template<typename String, class Arg, typename = void>
struct has_toString : std::false_type {};

template<typename String, class Arg>
struct has_toString<String, Arg, std::void_t<decltype(toString<String>(std::declval<Arg>()))>> : std::true_type {};

template <int N>
struct argument
{
	template <class Arg>
	struct of_type
	{
		template <typename String>
		static constexpr bool is_formattable_as = std::disjunction<
			std::is_enum<std::decay_t<Arg>>,
			std::is_arithmetic<std::decay_t<Arg>>,
			std::is_pointer<std::decay_t<Arg>>,
			std::is_same<String, std::decay_t<Arg>>,
			has_toString<String, Arg>
		>::value;
	};
};

// Converts integral type to hex string with desired string type
template<typename String, bool Lowercase, typename Arg>
String integral_to_hex_string(Arg && arg) noexcept
{
	if constexpr (std::is_enum_v<std::decay_t<Arg>>) {
		// Special handling for enum, cast to underlying type
		return integral_to_hex_string<String, Lowercase>(static_cast<std::underlying_type_t<std::decay_t<Arg>>>(arg));
	}
	else if constexpr (std::is_signed_v<std::decay_t<Arg>>) {
		return integral_to_hex_string<String, Lowercase>(static_cast<std::make_unsigned_t<std::decay_t<Arg>>>(arg));
	}
	else if constexpr (std::is_integral_v<std::decay_t<Arg>>) {
		std::decay_t<Arg> v = arg;
		typename String::value_type buf[sizeof(v) * 2];
		auto* const end = buf + sizeof(v) * 2;
		auto* p = end;

		do {
			*(--p) = fz::int_to_hex_char<typename String::value_type, Lowercase>(v & 0xf);
			v >>= 4;
		} while (v);

		return String(p, end);
	}
	else {
		format_assert(0);
		return String();
	}
}

// Converts pointer to hex string
template<typename String, typename Arg>
String pointer_to_string(Arg&& arg) noexcept
{
	if constexpr (std::is_pointer_v<std::decay_t<Arg>>) {
		return String({'0', 'x'}) + integral_to_hex_string<String, true>(reinterpret_cast<uintptr_t>(arg));
	}
	else {
		format_assert(0);
		return String();
	}
}

template<typename String, typename Arg>
String char_to_string(Arg&& arg)
{
	if constexpr (std::is_integral_v<std::decay_t<Arg>>) {
		return String({static_cast<typename String::value_type>(static_cast<unsigned char>(arg))});
	}
	else {
		format_assert(0);
		return String();
	}
}


template<typename String>
void pad_arg(String& s, field const& f)
{
	if (f.flags & with_width && s.size() < f.width) {
		if (f.flags & left_align) {
			s += String(f.width - s.size(), ' ');
		}
		else {
			s = String(f.width - s.size(), (f.flags & pad_0) ? '0' : ' ') + s;
		}
	}
}

template<typename String, typename Arg>
String format_arg(field const& f, Arg&& arg)
{
	String ret;
	if (f.type == 's') {
		if constexpr (std::is_same_v<String, std::decay_t<Arg>>) {
			ret = arg;
		}
		else if constexpr (has_toString<String, Arg>::value) {
			// Converts argument to string
			// if toString(arg) is valid expression
			ret = toString<String>(std::forward<Arg>(arg));
		}
		else {
			// Otherwise assert
			format_assert(0);
		}
		pad_arg(ret, f);
	}
	else if (f.type == 'd' || f.type == 'i') {
		ret = integral_to_string<String, false>(f, std::forward<Arg>(arg));
	}
	else if (f.type == 'u') {
		ret = integral_to_string<String, true>(f, std::forward<Arg>(arg));
	}
	else if (f.type == 'x') {
		ret = integral_to_hex_string<String, true>(std::forward<Arg>(arg));
		pad_arg(ret, f);
	}
	else if (f.type == 'X') {
		ret = integral_to_hex_string<String, false>(std::forward<Arg>(arg));
		pad_arg(ret, f);
	}
	else if (f.type == 'p') {
		ret = pointer_to_string<String>(std::forward<Arg>(arg));
		pad_arg(ret, f);
	}
	else if (f.type == 'c') {
		ret = char_to_string<String>(std::forward<Arg>(arg));
	}
	else {
		format_assert(0);
	}
	return ret;
}

template<typename String, typename... Args>
String extract_arg(field const&, size_t)
{
	return String();
}


template<typename String, typename Arg, typename... Args>
String extract_arg(field const& f, size_t arg_n, Arg&& arg, Args&&...args)
{
	String ret;

	if (!arg_n) {
		ret = format_arg<String>(f, std::forward<Arg>(arg));
	}
	else {
		ret = extract_arg<String>(f, arg_n - 1, std::forward<Args>(args)...);
	}

	return ret;
}

template<typename InString, typename OutString>
field get_field(InString const& fmt, typename InString::size_type & pos, size_t& arg_n, OutString & ret)
{
	field f;
	if (++pos >= fmt.size()) {
		format_assert(0);
		return f;
	}

	// Get literal percent out of the way
	if (fmt[pos] == '%') {
		ret += '%';
		++pos;
		return f;
	}

parse_start:
	while (true) {
		if (fmt[pos] == '0') {
			f.flags |= pad_0;
		}
		else if (fmt[pos] == ' ') {
			f.flags |= pad_blank;
		}
		else if (fmt[pos] == '-') {
			f.flags &= ~pad_0;
			f.flags |= left_align;
		}
		else if (fmt[pos] == '+') {
			f.flags &= ~pad_blank;
			f.flags |= always_sign;
		}
		else {
			break;
		}
		if (++pos >= fmt.size()) {
			format_assert(0);
			return f;
		}
	}

	// Field width
	while (fmt[pos] >= '0' && fmt[pos] <= '9') {
		f.flags |= with_width;
		f.width *= 10;
		f.width += fmt[pos] - '0';
		if (++pos >= fmt.size()) {
			format_assert(0);
			return f;
		}
	}
	if (f.width > 10000) {
		format_assert(0);
		f.width = 10000;
	}

	if (fmt[pos] == '$') {
		// Positional argument, start over
		arg_n = f.width - 1;
		if (++pos >= fmt.size()) {
			format_assert(0);
			return f;
		}
		goto parse_start;
	}

	// Ignore length modifier
	while (true) {
		auto c = fmt[pos];
		if (c == 'h' || c == 'l' || c == 'L' || c == 'j' || c == 'z' || c == 't') {
			if (++pos >= fmt.size()) {
				format_assert(0);
				return f;
			}
		}
		else {
			break;
		}
	}

	f.type = static_cast<char>(fmt[pos++]);
	return f;
}

template<typename String, typename Arg, int N>
constexpr bool check_argument()
{
	static_assert(
		argument<N>::template of_type<Arg>::template is_formattable_as<String>,
		"Argument cannot be formatted by fz::sprintf()"
	);

	return argument<N>::template of_type<Arg>::template is_formattable_as<String>;
}

template<typename String, typename... Args, std::size_t... Is>
constexpr bool check_arguments(std::index_sequence<Is...>)
{
	return (check_argument<String, Args, Is>() && ...);
}

template<typename InString, typename CharType = typename InString::value_type, typename OutString = std::basic_string<CharType>, typename... Args>
OutString do_sprintf(InString const& fmt, Args&&... args)
{
	OutString ret;

	// Find % characters
	typename InString::size_type start = 0, pos;

	size_t arg_n{};
	while ((pos = fmt.find('%', start)) != InString::npos) {

		// Copy segment preceding the %
		ret += fmt.substr(start, pos - start);

		field f = detail::get_field(fmt, pos, arg_n, ret);
		if (f) {
			format_assert(arg_n < sizeof...(args));
			ret += detail::extract_arg<OutString>(f, arg_n++, std::forward<Args>(args)...);
		}

		start = pos;
	}

	// Copy remainder of string
	ret += fmt.substr(start);

	return ret;
}
}
/// \endcond

/** \brief A simple type-safe sprintf replacement
*
* Only partially implements the format specifiers for the printf family of C functions:
*
* \li Positional arguments
* \li Supported flags: 0, ' ', -, +
* \li Field widths are supported as decimal integers not exceeding 10k, longer widths are truncated
* \li precision is ignored
* \li Supported types: d, i, u, s, x, X, p
*
* For string arguments, mixing char*, wchar_t*, std::string and std::wstring is allowed. Converstion
* to/from narrow strings is using the locale's encoding.
*
* Asserts if unsupported types are passed or if the types don't match the arguments. Fails gracefully with NDEBUG.
*
* Example:
*
* \code
* std::string s = fz::printf("%2$s %1$s", "foo", std::wstring("bar");
* assert(s == "bar foo"); // This is true
* \endcode
*/
template<typename... Args>
std::string sprintf(std::string_view const& fmt, Args&&... args)
{
	detail::check_arguments<std::string, Args...>(std::index_sequence_for<Args...>());

	return detail::do_sprintf(fmt, std::forward<Args>(args)...);
}

template<typename... Args>
std::wstring sprintf(std::wstring_view const& fmt, Args&&... args)
{
	detail::check_arguments<std::wstring, Args...>(std::index_sequence_for<Args...>());

	return detail::do_sprintf(fmt, std::forward<Args>(args)...);
}

}

#endif
