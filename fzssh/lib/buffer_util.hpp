#ifndef FZSSH_BUFFER_UTIL_HEADER
#define FZSSH_BUFFER_UTIL_HEADER

#include "fzssh/visibility.hpp"

#include <libfilezilla/buffer.hpp>

#include <optional>

namespace fz {
class logger_interface;
}

namespace fz::ssh {

template<typename Char>
void write_uint32(Char * data, uint32_t v)
{
	data[3] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[2] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[1] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[0] = static_cast<Char>(v);
}

template<typename Char>
void write_uint64(Char * data, uint64_t v)
{
	data[7] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[6] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[5] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[4] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[3] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[2] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[1] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[0] = static_cast<Char>(v);
}

void FZSSH_PUBLIC_SYMBOL write_uint32(buffer & buf, uint32_t c);
void FZSSH_PUBLIC_SYMBOL write_uint64(buffer & buf, uint64_t c);

template<typename String>
void write_string(buffer& buf, String const& s)
{
	write_uint32(buf, s.size());
	buf.append(s);
}

template<typename Char>
uint32_t read_uint32(Char const* data)
{
	uint32_t ret{};
	for (size_t i = 0; i < 4; ++i) {
		ret <<= 8;
		ret += static_cast<unsigned char>(*(data++));
	}
	return ret;
}

template<typename Char>
uint64_t read_uint64(Char const* data)
{
	uint64_t ret{};
	for (size_t i = 0; i < 8; ++i) {
		ret <<= 8;
		ret += static_cast<unsigned char>(*(data++));
	}
	return ret;
}

bool FZSSH_PUBLIC_SYMBOL extract_uint32(std::string_view & packet, uint32_t & out);
bool FZSSH_PUBLIC_SYMBOL extract_uint64(std::string_view & packet, uint64_t & out);

struct extract_fail_t final {} const extract_fail;
class extracted_string final
{
public:
	constexpr extracted_string() noexcept = default;

	constexpr explicit extracted_string(std::string_view v) noexcept
		: v_(v)
		, valid_(true)
	{}

	constexpr extracted_string(extract_fail_t const&, std::string_view v) noexcept
		: v_(v)
	{}

	constexpr explicit operator bool() const {
		return valid_;
	}

	constexpr std::string_view const& operator*() const {
		return v_;
	}
	constexpr std::string_view & operator*() {
		return v_;
	}
	constexpr std::string_view const* operator->() const {
		return &v_;
	}
	constexpr std::string_view * operator->() {
		return &v_;
	}

	constexpr extracted_string& operator=(std::string_view const& v) {
		v_ = v;
		valid_ = true;
		return *this;
	}

private:
	std::string_view v_;
	bool valid_{};
};

constexpr bool operator==(std::string_view const& l, extracted_string const& r) {
	return r && l == *r;
}
constexpr bool operator==(extracted_string const& l, std::string_view const& r) {
	return l && *l == r;
}
constexpr bool operator!=(std::string_view const& l, extracted_string const& r) {
	return !(l == r);
}
constexpr bool operator!=(extracted_string const& l, std::string_view const& r) {
	return !(l == r);
}

extracted_string FZSSH_PUBLIC_SYMBOL extract_blob(std::string_view & packet);

enum class string_type : unsigned {
	ascii,
	ascii_noquotes,
	multiline_ascii,
	utf8,
	text,
	blob
};


extracted_string FZSSH_PUBLIC_SYMBOL extract_string(std::string_view & packet, string_type t, bool allow_empty);

bool FZSSH_PUBLIC_SYMBOL extract_namelist(std::string_view & packet, std::string_view & out, logger_interface & logger);
bool FZSSH_PUBLIC_SYMBOL is_namelist(std::string_view const& names, logger_interface & logger);

void FZSSH_PUBLIC_SYMBOL write_mpint(fz::buffer & buf, std::string_view v);
inline void write_mpint(fz::buffer & buf, fz::buffer const& v) {
	write_mpint(buf, v.to_view());
}

inline void append_comma_sep(std::string & s, std::string_view const& v)
{
	if (!s.empty()) {
		s += ',';
	}
	s += v;
}

std::optional<bool> FZSSH_PUBLIC_SYMBOL extract_bool(std::string_view & packet);

}

#endif
