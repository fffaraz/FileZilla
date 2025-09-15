#include "libfilezilla/buffer.hpp"
#include "libfilezilla/util.hpp"
#include "libfilezilla/string.hpp"

#ifdef FZ_WINDOWS
#include <string.h>

#include "libfilezilla/glue/windows.hpp"
#else
#include <iconv.h>
#include <strings.h>

#include <memory>
#include <type_traits>
#endif

#include <cstdlib>

static_assert('a' + 25 == 'z', "We only support systems running with an ASCII-based character set. Sorry, no EBCDIC.");

// char may be unsigned, yielding stange results if subtracting characters. To work around it, expect a particular order of characters.
static_assert('A' < 'a', "We only support systems running with an ASCII-based character set. Sorry, no EBCDIC.");

namespace fz {

#ifdef FZ_WINDOWS
native_string to_native(std::string_view const& in)
{
	return to_wstring(in);
}

native_string to_native(std::wstring_view const& in)
{
	return std::wstring(in);
}

#else
native_string to_native(std::string_view const& in)
{
	return std::string(in);
}

native_string to_native(std::wstring_view const& in)
{
	return to_string(in);
}
#endif

int stricmp(std::string_view const& a, std::string_view const& b)
{
#ifdef FZ_WINDOWS
	int ret = _strnicmp(a.data(), b.data(), std::min(a.size(), b.size()));
#else
	int ret = strncasecmp(a.data(), b.data(), std::min(a.size(), b.size()));
#endif
	if (!ret) {
		if (a.size() < b.size()) {
			ret = -1;
		}
		else if (a.size() > b.size()) {
			ret = 1;
		}
	}
	return ret;
}

int stricmp(std::wstring_view const& a, std::wstring_view const& b)
{
#ifdef FZ_WINDOWS
	int ret = _wcsnicmp(a.data(), b.data(), std::min(a.size(), b.size()));
#else
	int ret = wcsncasecmp(a.data(), b.data(), std::min(a.size(), b.size()));
#endif
	if (!ret) {
		if (a.size() < b.size()) {
			ret = -1;
		}
		else if (a.size() > b.size()) {
			ret = 1;
		}
	}
	return ret;
}

template<>
std::wstring::value_type tolower_ascii(std::wstring::value_type c)
{
	if (c >= 'A' && c <= 'Z') {
		return c + ('a' - 'A');
	}
	else if (c == 0x130 || c == 0x131) {
		c = 'i';
	}
	return c;
}

template<>
std::wstring::value_type toupper_ascii(std::wstring::value_type c)
{
	if (c >= 'a' && c <= 'z') {
		return c + ('A' - 'a');
	}
	else if (c == 0x130 || c == 0x131) {
		c = 'I';
	}
	return c;
}

namespace {
template<typename Out, bool lower, typename String>
Out str_case_ascii_impl(String const& s)
{
	Out ret;
	ret.resize(s.size());
	for (size_t i = 0; i < s.size(); ++i) {
		if constexpr (lower) {
			ret[i] = tolower_ascii(s[i]);
		}
		else {
			ret[i] = toupper_ascii(s[i]);
		}
	}
	return ret;
}
}

std::string str_tolower_ascii(std::string_view const& s)
{
	return str_case_ascii_impl<std::string, true>(s);
}

std::wstring str_tolower_ascii(std::wstring_view const& s)
{
	return str_case_ascii_impl<std::wstring, true>(s);
}

std::string str_toupper_ascii(std::string_view const& s)
{
	return str_case_ascii_impl<std::string, false>(s);
}

std::wstring str_toupper_ascii(std::wstring_view const& s)
{
	return str_case_ascii_impl<std::wstring, false>(s);
}

std::wstring to_wstring(std::string_view const& in)
{
	std::wstring ret;

	if (!in.empty()) {
#if FZ_WINDOWS
		char const* const in_p = in.data();
		size_t const len = in.size();
		int const out_len = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, in_p, static_cast<int>(len), nullptr, 0);
		if (out_len > 0) {
			ret.resize(out_len);
			wchar_t* out_p = ret.data();
			MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, in_p, static_cast<int>(len), out_p, out_len);
		}
#else
		size_t start = 0;
		while (start < in.size()) {
			// Run in a loop to handle embedded null chars
			size_t pos = in.find(char{}, start);
			size_t inlen;
			if (pos == std::string::npos) {
				inlen = in.size() - start;
			}
			else {
				inlen = pos - start;
			}

			std::mbstate_t ps{};
			char const* in_p = in.data() + start;
			size_t len = mbsnrtowcs(nullptr, &in_p, inlen, 0, &ps);
			if (len != static_cast<size_t>(-1)) {
				size_t old = ret.size();
				if (start) {
					++old;
				}
				ret.resize(old + len);
				wchar_t* out_p = &ret[old];

				in_p = in.data() + start; // Some implementations of wcsrtombs change src even on null dst
				mbsnrtowcs(out_p, &in_p, inlen, len, &ps);
			}
			else {
				ret.clear();
				break;
			}

			start += inlen + 1;
			if (start >= in.size()) {
				if (pos != std::string::npos) {
					ret += wchar_t{};
				}
				break;
			}
		}
#endif
	}

	return ret;
}

#ifndef FZ_WINDOWS
// On some platforms, e.g. NetBSD, the second argument to iconv is const.
// Depending which one is used, declare iconv_second_arg_type as either char* or char const*
extern "C" typedef size_t (*iconv_prototype_with_const)(iconv_t, char const**, size_t *, char**, size_t *);
typedef std::conditional<std::is_same_v<decltype(&iconv), iconv_prototype_with_const>, char const*, char*>::type iconv_second_arg_type;

namespace {
// On some platforms, e.g. those derived from SunOS, iconv does not understand "WCHAR_T", so we
// need to guess an encoding.
// On other platforms, WCHAR_T results in iconv() doing endless loops, such as OS X.
char const* calc_wchar_t_encoding()
{
	auto try_encoding = [](char const* const encoding) -> bool {
		iconv_t cd = iconv_open(encoding, "UTF-8");
		if (cd == reinterpret_cast<iconv_t>(-1)) {
			return false;
		}
		iconv_close(cd);
		return true;
	};

	// Explicitly specify endianess, otherwise we'll get a BOM prefixed to everything
	int const i = 1;
	char const* p = reinterpret_cast<char const*>(&i);
	bool const little_endian = p[0] == 1;

	if (sizeof(wchar_t) == 4) {
		if (little_endian && try_encoding("UTF-32LE")) {
			return "UTF-32LE";
		}
		if (!little_endian && try_encoding("UTF-32BE")) {
			return "UTF-32BE";
		}
	}
	else if (sizeof(wchar_t) == 2) {
		if (little_endian && try_encoding("UTF-16LE")) {
			return "UTF-16LE";
		}
		if (!little_endian && try_encoding("UTF-16BE")) {
			return "UTF-16BE";
		}
	}

	// Oh dear...
	// WCHAR_T is our last, best hope.
	return "WCHAR_T";
}

char const* wchar_t_encoding()
{
	static char const* const encoding = calc_wchar_t_encoding();
	return encoding;
}

class iconv_t_holder
{
public:
	iconv_t_holder(char const* to, char const* from)
		: to_(to)
		, from_(from)
	{
		reinit();
	}

	~iconv_t_holder()
	{
		close();
	}

	void close()
	{
		if (cd != reinterpret_cast<iconv_t>(-1)) {
			iconv_close(cd);
			outbuf_.wipe();
		}
	}

	void reinit()
	{
		close();
		cd = iconv_open(to_, from_);
	}

	explicit operator bool() const {
		return cd != reinterpret_cast<iconv_t>(-1);
	}

	iconv_t_holder(iconv_t_holder const&) = delete;
	iconv_t_holder& operator=(iconv_t_holder const&) = delete;

	char const* const to_;
	char const* const from_;

	iconv_t cd{reinterpret_cast<iconv_t>(-1)};
	fz::buffer outbuf_;
};
}
#endif

std::wstring to_wstring_from_utf8(std::string_view const& in)
{
	return to_wstring_from_utf8(in.data(), in.size());
}

std::wstring to_wstring_from_utf8(fz::buffer const& in)
{
	return to_wstring_from_utf8(reinterpret_cast<char const*>(in.get()), in.size());
}

#if FZ_WINDOWS
void wipe_conversion_cache()
{
}
#else
namespace {
iconv_t_holder& get_to_wide_iconv_holder()
{
	static thread_local iconv_t_holder holder(wchar_t_encoding(), "UTF-8");
	return holder;
}
iconv_t_holder& get_to_utf8_iconv_holder()
{
	static thread_local iconv_t_holder holder("UTF-8", wchar_t_encoding());
	return holder;
}
}

void wipe_conversion_cache()
{
	auto & w = get_to_wide_iconv_holder();
	w.reinit();
	auto & u = get_to_utf8_iconv_holder();
	u.reinit();
}
#endif

std::wstring to_wstring_from_utf8(char const* s, size_t len)
{
	std::wstring ret;

	if (len != 0) {
#if FZ_WINDOWS
		char const* const in_p = s;
		int const out_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in_p, static_cast<int>(len), nullptr, 0);
		if (out_len > 0) {
			ret.resize(out_len);
			wchar_t* out_p = ret.data();
			MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in_p, static_cast<int>(len), out_p, out_len);
		}
#else

		auto & holder = get_to_wide_iconv_holder();
		if (holder && iconv(holder.cd, nullptr, nullptr, nullptr, nullptr) != static_cast<size_t>(-1)) {
			auto in_p = const_cast<iconv_second_arg_type>(s);
			size_t out_len = len * sizeof(wchar_t) * 2;
			char* out_p = reinterpret_cast<char*>(holder.outbuf_.get(out_len));

			size_t r = iconv(holder.cd, &in_p, &len, &out_p, &out_len);

			if (r != static_cast<size_t>(-1)) {
				ret.assign(reinterpret_cast<wchar_t*>(holder.outbuf_.get()), reinterpret_cast<wchar_t*>(out_p));
			}

			// Our buffer should big enough as well, so we can ignore errors such as E2BIG.
		}
#endif
	}

	return ret;
}

std::string to_string(std::wstring_view const& in)
{
	std::string ret;

	if (!in.empty()) {
#if FZ_WINDOWS
		wchar_t const* const in_p = in.data();
		BOOL usedDefault = FALSE;
		int const len = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, in_p, static_cast<int>(in.size()), nullptr, 0, nullptr, &usedDefault);
		if (len > 0 && !usedDefault) {
			ret.resize(len);
			char* out_p = ret.data();
			WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, in_p, static_cast<int>(in.size()), out_p, len, nullptr, nullptr);
		}
#else
		size_t start = 0;
		while (true) {
			// Run in a loop to handle embedded null chars
			size_t pos = in.find(wchar_t{}, start);
			size_t inlen;
			if (pos == std::wstring::npos) {
				inlen = in.size() - start;
			}
			else {
				inlen = pos - start;
			}

			std::mbstate_t ps{};
			wchar_t const* in_p = in.data() + start;
			size_t len = wcsnrtombs(nullptr, &in_p, inlen, 0, &ps);
			if (len != static_cast<size_t>(-1)) {
				size_t old = ret.size();
				if (start) {
					++old;
				}
				ret.resize(old + len);
				char* out_p = &ret[old];

				in_p = in.data() + start; // Some implementations of wcsrtombs change src even on null dst
				wcsnrtombs(out_p, &in_p, inlen, len, &ps);
			}
			else {
				ret.clear();
				break;
			}

			start += inlen + 1;
			if (start >= in.size()) {
				if (pos != std::wstring::npos) {
					ret += char{};
				}
				break;
			}
		}
#endif
	}

	return ret;
}

std::string FZ_PUBLIC_SYMBOL to_utf8(std::string_view const& in)
{
	return to_utf8(to_wstring(in));
}

std::string FZ_PUBLIC_SYMBOL to_utf8(std::wstring_view const& in)
{
	std::string ret;

	if (!in.empty()) {
#if FZ_WINDOWS
		wchar_t const* const in_p = in.data();
		int const len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, in_p, static_cast<int>(in.size()), nullptr, 0, nullptr, nullptr);
		if (len > 0) {
			ret.resize(len);
			char* out_p = ret.data();
			WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, in_p, static_cast<int>(in.size()), out_p, len, nullptr, nullptr);
		}
#else
		auto & holder = get_to_utf8_iconv_holder();
		if (holder && iconv(holder.cd, nullptr, nullptr, nullptr, nullptr) != static_cast<size_t>(-1)) {
			auto in_p = reinterpret_cast<iconv_second_arg_type>(const_cast<wchar_t*>(in.data()));
			size_t in_len = in.size() * sizeof(wchar_t);

			size_t out_len = in.size() * 4;
			char* out_p = reinterpret_cast<char*>(holder.outbuf_.get(out_len));

			size_t r = iconv(holder.cd, &in_p, &in_len, &out_p, &out_len);

			if (r != static_cast<size_t>(-1)) {
				ret.assign(reinterpret_cast<char*>(holder.outbuf_.get()), out_p);
			}
		}
#endif
	}

	return ret;
}

namespace {
template<typename String, typename View>
inline bool do_replace_substrings(String& in, View const& find, View const& replacement)
{
	if (find.empty()) {
		return false;
	}
	bool ret = false;
	size_t pos = in.find(find);
	while (pos != std::string::npos) {
		in.replace(pos, find.size(), replacement);
		pos = in.find(find, pos + replacement.size());
		ret = true;
	}
	return ret;
}
}

std::string replaced_substrings(std::string_view const& in, std::string_view const& find, std::string_view const& replacement)
{
	std::string ret(in.data(), in.size());
	do_replace_substrings(ret, find, replacement);
	return ret;
}

std::wstring replaced_substrings(std::wstring_view const& in, std::wstring_view const& find, std::wstring_view const& replacement)
{
	std::wstring ret(in.data(), in.size());
	do_replace_substrings(ret, find, replacement);
	return ret;
}

std::string replaced_substrings(std::string_view const& in, char find, char replacement)
{
	std::string ret(in.data(), in.size());
	do_replace_substrings(ret, std::string_view(&find, 1), std::string_view(&replacement, 1));
	return ret;
}

std::wstring replaced_substrings(std::wstring_view const& in, wchar_t find, wchar_t replacement)
{
	std::wstring ret(in.data(), in.size());
	do_replace_substrings(ret, std::wstring_view(&find, 1), std::wstring_view(&replacement, 1));
	return ret;
}


bool replace_substrings(std::string& in, std::string_view const& find, std::string_view const& replacement)
{
	return do_replace_substrings(in, find, replacement);
}

bool replace_substrings(std::wstring& in, std::wstring_view const& find, std::wstring_view const& replacement)
{
	return do_replace_substrings(in, find, replacement);
}

bool replace_substrings(std::string& in, char find, char replacement)
{
	return do_replace_substrings(in, std::string_view(&find, 1), std::string_view(&replacement, 1));
}

bool replace_substrings(std::wstring& in, wchar_t find, wchar_t replacement)
{
	return do_replace_substrings(in, std::wstring_view(&find, 1), std::wstring_view(&replacement, 1));
}


namespace {
template<typename Ret, typename String>
std::vector<Ret> strtok_impl(String && s, String && delims, bool const ignore_empty)
{
	std::vector<Ret> ret;

	for (auto t: strtokenizer(s, delims, ignore_empty)) {
		ret.push_back(Ret(t));
	}

	return ret;
}
}

std::vector<std::string> strtok(std::string_view const& tokens, std::string_view const& delims, bool const ignore_empty)
{
	return strtok_impl<std::string>(tokens, delims, ignore_empty);
}

std::vector<std::wstring> strtok(std::wstring_view const& tokens, std::wstring_view const& delims, bool const ignore_empty)
{
	return strtok_impl<std::wstring>(tokens, delims, ignore_empty);
}

std::vector<std::string_view> strtok_view(std::string_view const& tokens, std::string_view const& delims, bool const ignore_empty)
{
	return strtok_impl<std::string_view>(tokens, delims, ignore_empty);
}

std::vector<std::wstring_view> strtok_view(std::wstring_view const& tokens, std::wstring_view const& delims, bool const ignore_empty)
{
	return strtok_impl<std::wstring_view>(tokens, delims, ignore_empty);
}

std::string normalize_hyphens(std::string_view const& in)
{
	std::string ret(in.data(), in.size());

	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2010"), "-"); // Hyphen
	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2011"), "-"); // Non-Breaking-Hyphen
	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2012"), "-"); // Figure Dash
	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2013"), "-"); // En Dash
	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2014"), "-"); // Em Dash
	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2015"), "-"); // Horizontal Bar
	fz::replace_substrings(ret, reinterpret_cast<char const*>(u8"\u2212"), "-"); // Minus Sign

	return ret;
}

std::wstring normalize_hyphens(std::wstring_view const& in)
{
	std::wstring ret(in.data(), in.size());

	fz::replace_substrings(ret, L"\u2010", L"-"); // Hyphen
	fz::replace_substrings(ret, L"\u2011", L"-"); // Non-Breaking-Hyphen
	fz::replace_substrings(ret, L"\u2012", L"-"); // Figure Dash
	fz::replace_substrings(ret, L"\u2013", L"-"); // En Dash
	fz::replace_substrings(ret, L"\u2014", L"-"); // Em Dash
	fz::replace_substrings(ret, L"\u2015", L"-"); // Horizontal Bar
	fz::replace_substrings(ret, L"\u2212", L"-"); // Minus Sign

	return ret;
}

bool is_valid_utf8(std::string_view s, size_t & state)
{
	if (!s.size()) {
		return true;
	}

	int const instate = state;
	state = 0;

	enum states : size_t {
		valid,
		cont3_3,
		cont3_2,
		cont3_1,
		cont2_2,
		cont2_1,
		cont1
	};

	auto p = s.data();
	auto const end = p + s.size();
	auto const max = s.size() >= 8 ? p + s.size() - 8 : p;
	unsigned char c{};

	switch (instate) {
	default:
		break;
	case cont3_3:
		goto cont3_3;
	case cont3_2:
		goto cont3_2;
	case cont3_1:
		goto cont3_1;
	case cont2_2:
		goto cont2_2;
	case cont2_1:
		goto cont2_1;
	case cont1:
		goto cont1;
	}

	while (p != end) {
		// If aligned on 8 byte boundary, look at 8 bytes at a time
		if (!(uintptr_t(p) % 8)) {
			while (p < max) {
				uint64_t const *v = reinterpret_cast<uint64_t const*>(p);
				// Look for any byte with highest most bit set
				if (*v & 0x8080808080808080ull) {
					break;
				}
				p += 8;
			}
		}

		// Either not aligned, or a high bit found. Look at the data in detail.
		c = *p++;
		if (c < 0x80) {
			continue;
		}
		if (c >= 0xf5u) {
			state = p - s.data() - 1;
			return false;
		}
		else if (c >= 0xf0u) {
			// 3 continuation bytes
			if (p == end) {
				state = cont3_3;
				return true;
			}
cont3_3:

			if (c == 0xf0u) {
				// Check for overlong
				c = *p++;
				if (c < 0x90u || c > 0xbfu) {
					state = p - s.data() - 1;
					return false;
				}
			}
			else if (c == 0xf4u) {
				// Check for > U+10FFFF
				c = *p++;
				if (c < 0x80u || c > 0x8fu) {
					state = p - s.data() - 1;
					return false;
				}
			}
			else if ((*p++ & 0xc0u) != 0x80u) {
				state = p - s.data() - 1;
				return false;
			}

			if (p == end) {
				state = cont3_2;
				return true;
			}
cont3_2:
			if ((*p++ & 0xc0u) != 0x80u) {
				state = p - s.data() - 1;
				return false;
			}

			if (p == end) {
				state = cont3_1;
				return true;
			}
cont3_1:
			if ((*p++ & 0xc0u) != 0x80u) {
				state = p - s.data() - 1;
				return false;
			}
		}
		else if (c >= 0xe0u) {
			// 2 continuation bytes
			if (p == end) {
				state = cont2_2;
				return true;
			}
cont2_2:

			if (c == 0xe0u) {
				// Check for overlong
				c = *p++;
				if (c < 0xa0u || c > 0xbfu) {
					state = p - s.data() - 1;
					return false;
				}
			}
			else if (c == 0xedu) {
				// Check for surrogates
				c = *p++;
				if (c < 0x80u || c > 0x9fu) {
					state = p - s.data() - 1;
					return false;
				}
			}
			else if ((*p++ & 0xc0u) != 0x80u) {
				state = p - s.data() - 1;
				return false;
			}

			if (p == end) {
				state = cont2_1;
				return true;
			}
cont2_1:
			if ((*p++ & 0xc0u) != 0x80u) {
				state = p - s.data() - 1;
				return false;
			}
		}
		else if (c >= 0xc2u) {
			// 1 continuation byte
			if (p == end) {
				state = cont1;
				return true;
			}
cont1:

			if ((*p++ & 0xc0u) != 0x80u) {
				state = p - s.data() - 1;
				return false;
			}
		}
		else if (c >= 0x80u) {
			state = p - s.data() - 1;
			return false;
		}
	}
	return true;
}

bool is_valid_utf8(std::string_view s)
{
	size_t state{};
	return is_valid_utf8(s, state) && !state;
}

void unicode_codepoint_to_utf8_append(std::string& result, uint32_t cp)
{
	if (cp <= 0x7f) {
		result += static_cast<char>(cp);
	}
	else if (cp <= 0x7ff) {
		result += static_cast<char>(0xc0u | ((cp >> 6u) & 0x1fu));
		result += static_cast<char>(0x80u | (cp & 0x3fu));
	}
	else if (cp <= 0xffff) {
		result += static_cast<char>(0xe0u | ((cp >> 12u) & 0x0fu));
		result += static_cast<char>(0x80u | ((cp >> 6u) & 0x3fu));
		result += static_cast<char>(0x80u | (cp & 0x3fu));
	}
	else {
		result += static_cast<char>(0xf0u | ((cp >> 18u) & 0x07u));
		result += static_cast<char>(0x80u | ((cp >> 12u) & 0x3fu));
		result += static_cast<char>(0x80u | ((cp >> 6u) & 0x3fu));
		result += static_cast<char>(0x80u | (cp & 0x3fu));
	}
}

bool utf16be_to_utf8_append(std::string & result, std::string_view data, uint32_t & state)
{
	if (data.empty()) {
		return true;
	}

	auto const* p = reinterpret_cast<unsigned char const*>(&data[0]);
	auto const* end = p + data.size();

	if (state & 0x80000000u) {
		goto utf16_be_cont;
	}

	while (p < end) {
		state |= static_cast<uint32_t>(*p++) << 8;
		if (p == end) {
			state |= 0x80000000u;
			break;
		}
utf16_be_cont:
		state |= static_cast<unsigned char>(*p++);
		state &= ~0x80000000u;
		if (state & 0x40000000u) {
			// Expect low surrogate
			auto low = state & 0xffffu;
			if (low < 0xdc00u || low > 0xdfffu) {
				state = p - reinterpret_cast<unsigned char const*>(data.data()) - 1;
				return false;
			}
			auto codepoint = (state & 0x3ff0000u) >> 6;
			codepoint |= low & 0x3ffu;
			codepoint += 0x10000u;

			fz::unicode_codepoint_to_utf8_append(result, codepoint);
			state = 0;
		}
		else if (state >= 0xd800u && state <= 0xdbffu) {
			// High surrogate
			state = 0x40000000u | (state & 0x3ffu) << 16;
		}
		else if (state >= 0xdc00u && state <= 0xdfffu) {
			state = p - reinterpret_cast<unsigned char const*>(data.data()) - 1;
			return false;
		}
		else {
			unicode_codepoint_to_utf8_append(result, state);
			state = 0;
		}
	}

	return true;
}


bool utf16le_to_utf8_append(std::string & result, std::string_view data, uint32_t & state)
{
	if (data.empty()) {
		return true;
	}

	auto const* p = reinterpret_cast<unsigned char const*>(&data[0]);
	auto const* end = p + data.size();

	if (state & 0x80000000u) {
		goto utf16_le_cont;
	}

	while (p < end) {
		state |= *p++;
		if (p == end) {
			state |= 0x80000000u;
			break;
		}
utf16_le_cont:
		state |= static_cast<uint32_t>(*p++) << 8;
		state &= ~0x80000000u;
		if (state & 0x40000000u) {
			// Expect low surrogate
			auto low = state & 0xffffu;
			if (low < 0xdc00u || low > 0xdfffu) {
				state = p - reinterpret_cast<unsigned char const*>(data.data()) - 1;
				return false;
			}
			auto codepoint = (state & 0x3ff0000u) >> 6;
			codepoint |= low & 0x3ffu;
			codepoint += 0x10000u;

			fz::unicode_codepoint_to_utf8_append(result, codepoint);
			state = 0;
		}
		else if (state >= 0xd800u && state <= 0xdbffu) {
			// High surrogate
			state = 0x40000000u | (state & 0x3ffu) << 16;
		}
		else if (state >= 0xdc00u && state <= 0xdfffu) {
			state = p - reinterpret_cast<unsigned char const*>(data.data()) - 1;
			return false;
		}
		else {
			unicode_codepoint_to_utf8_append(result, state);
			state = 0;
		}
	}

	return true;
}

}
