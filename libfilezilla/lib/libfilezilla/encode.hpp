#ifndef LIBFILEZILLA_ENCODE_HEADER
#define LIBFILEZILLA_ENCODE_HEADER

#include "libfilezilla.hpp"

#include <string>
#include <vector>

/** \file
 * \brief Functions to encode/decode strings
 *
 * Defines functions to deal with hex, base64 and percent encoding.
 */

namespace fz {
class buffer;

/** \brief Converts a hex digit to decimal int
 *
 * Example: '9' becomes 9, 'b' becomes 11, 'D' becomes 13
 *
 * Returns -1 if input is not a valid hex digit.
 */
template<typename Char>
int hex_char_to_int(Char c)
{
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	else if (c >= '0' && c <= '9') {
		return c - '0';
	}
	return -1;
}

/// \private
template<typename OutString, typename String>
OutString hex_decode_impl(String const& in)
{
	OutString ret;
	if (!(in.size() % 2)) {
		ret.reserve(in.size() / 2);
		for (size_t i = 0; i < in.size(); i += 2) {
			int high = hex_char_to_int(in[i]);
			int low = hex_char_to_int(in[i + 1]);
			if (high == -1 || low == -1) {
				return OutString();
			}
			ret.push_back(static_cast<typename OutString::value_type>((high << 4) + low));
		}
	}

	return ret;
}

template<typename OutString = std::vector<uint8_t>>
OutString hex_decode(std::string_view const& in)
{
	return hex_decode_impl<OutString>(in);
}

template<typename OutString = std::vector<uint8_t>>
OutString hex_decode(std::wstring_view const& in)
{
	return hex_decode_impl<OutString>(in);
}

/** \brief Converts an integer to the corresponding lowercase hex digit
*
* Example: 9 becomes '9', 11 becomes 'b'
*
* Undefined output if input is less than 0 or larger than 15
*/
template<typename Char = char, bool Lowercase = true>
Char int_to_hex_char(int d)
{
	if (d > 9) {
		return static_cast<Char>((Lowercase ? 'a' : 'A') + d - 10);
	}
	else {
		return static_cast<Char>('0' + d);
	}
}

template<typename String, typename InString, bool Lowercase = true>
String hex_encode(InString const& data)
{
	static_assert(sizeof(typename InString::value_type) == 1, "Input must be a container of 8 bit values");
	String ret;
	ret.reserve(data.size() * 2);
	for (auto const& c : data) {
		ret.push_back(int_to_hex_char<typename String::value_type, Lowercase>(static_cast<unsigned char>(c) >> 4));
		ret.push_back(int_to_hex_char<typename String::value_type, Lowercase>(static_cast<unsigned char>(c) & 0xf));
	}

	return ret;
}

/**
 * \brief Alphabet variations for base64
 *
 * - standard: Alphabet with / and + as chars 62 and 63
 * - url: - and _
 */
enum class base64_type {
	standard,
	url
};

/// \brief Encodes raw input string to base64
std::string FZ_PUBLIC_SYMBOL base64_encode(std::string_view const& in, base64_type type = base64_type::standard, bool pad = true);
std::string FZ_PUBLIC_SYMBOL base64_encode(std::vector<uint8_t> const& in, base64_type type = base64_type::standard, bool pad = true);
std::string FZ_PUBLIC_SYMBOL base64_encode(fz::buffer const& in, base64_type type = base64_type::standard, bool pad = true);

/**
 * \brief base64-encodes input and appends it to result.
 *
 * Multiple inputs concatenated this way cannot be passed to a single base64_decode. The parts need to be
 * individually decoded.
 */
void FZ_PUBLIC_SYMBOL base64_encode_append(std::string& result, std::string_view const& in, base64_type type = base64_type::standard, bool pad = true);

/**
 * \brief Decodes base64, ignores whitespace. Returns empty string on invalid input.
 *
 * Padding is optional, alphabet is auto-detected.
 */
std::vector<uint8_t> FZ_PUBLIC_SYMBOL base64_decode(std::string_view const& in);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL base64_decode(std::wstring_view const& in);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL base64_decode(fz::buffer const& in);
std::string FZ_PUBLIC_SYMBOL base64_decode_s(std::string_view const& in);
std::string FZ_PUBLIC_SYMBOL base64_decode_s(std::wstring_view const& in);
std::string FZ_PUBLIC_SYMBOL base64_decode_s(fz::buffer const& in);


/**
 * \brief Alphabet variations for base32
 * - standard: A-Z2-7 as per RFC4648
 * - base32hex: Tricontakaidecimal, natural extension of hex with letters G through V
 * - locale_safe: Does not contain the letter i
 */
enum class base32_type {
	standard,
	base32hex,
	locale_safe
};

/// \brief Encodes raw input string to base32
std::string FZ_PUBLIC_SYMBOL base32_encode(std::string_view const& in, base32_type type = base32_type::standard, bool pad = true);
std::string FZ_PUBLIC_SYMBOL base32_encode(std::vector<uint8_t> const& in, base32_type type = base32_type::standard, bool pad = true);
std::string FZ_PUBLIC_SYMBOL base32_encode(fz::buffer const& in, base32_type type = base32_type::standard, bool pad = true);

/**
 * \brief Decodes base32, ignores whitespace. Returns empty string on invalid input.
 *
 * Padding is optional.
 */
std::vector<uint8_t> FZ_PUBLIC_SYMBOL base32_decode(std::string_view const& in, base32_type type = base32_type::standard);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL base32_decode(std::wstring_view const& in, base32_type type = base32_type::standard);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL base32_decode(fz::buffer const& in, base32_type type = base32_type::standard);
std::string FZ_PUBLIC_SYMBOL base32_decode_s(std::string_view const& in, base32_type type = base32_type::standard);
std::string FZ_PUBLIC_SYMBOL base32_decode_s(std::wstring_view const& in, base32_type type = base32_type::standard);
std::string FZ_PUBLIC_SYMBOL base32_decode_s(fz::buffer const& in, base32_type type = base32_type::standard);

/**
 * \brief Percent-encodes string.
 *
 * The characters A-Z, a-z, 0-9, hyphen, underscore, period, tilde are not percent-encoded, optionally slashes aren't encoded either.
 * Every other character is encoded.
 *
 * \param keep_slashes If set, slashes are not encoded.
 */
std::string FZ_PUBLIC_SYMBOL percent_encode(std::string_view const& s, bool keep_slashes = false);
std::string FZ_PUBLIC_SYMBOL percent_encode(std::wstring_view const& s, bool keep_slashes = false);

/**
 * \brief Percent-encodes wide-character. Non-ASCII characters are converted to UTF-8 before they are encoded.
 *
 * \sa \ref fz::percent_encode
 */
std::wstring FZ_PUBLIC_SYMBOL percent_encode_w(std::wstring_view const& s, bool keep_slashes = false);

/**
 * \brief Percent-decodes string.
 *
 * If the string cannot be decoded, an empty string is returned.
 */
std::vector<uint8_t> FZ_PUBLIC_SYMBOL percent_decode(std::string_view const& s, bool allow_embedded_null = false, bool plus_is_space = false);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL percent_decode(std::wstring_view const& s, bool allow_embedded_null = false, bool plus_is_space = false);
std::string FZ_PUBLIC_SYMBOL percent_decode_s(std::string_view const& s, bool allow_embedded_null = false, bool plus_is_space = false);
std::string FZ_PUBLIC_SYMBOL percent_decode_s(std::wstring_view const& s, bool allow_embedded_null = false, bool plus_is_space = false);

}

#endif
