#include "buffer_util.hpp"

#include <libfilezilla/logger.hpp>

using namespace std::literals;

namespace fz::ssh {

void write_uint32(buffer & buf, uint32_t c)
{
	write_uint32(buf.get(4), c);
	buf.add(4);
}

void write_uint64(buffer & buf, uint64_t c)
{
	write_uint64(buf.get(8), c);
	buf.add(8);
}

void write_mpint(fz::buffer & buf, std::string_view v)
{
	bool zeropad{};
	while (!v.empty() && !v[0]) {
		v.remove_prefix(1);
	}
	if (!v.empty() && static_cast<unsigned char>(v[0]) & 0x80u) {
		zeropad = true;
	}
	write_uint32(buf, v.size() + (zeropad ? 1 : 0));
	if (zeropad) {
		buf.append('\0');
	}
	buf.append(v);
}

bool extract_uint32(std::string_view & packet, uint32_t & out)
{
	if (packet.size() < 4) {
		return false;
	}
	out = read_uint32(packet.data());
	packet.remove_prefix(4);
	return true;
}

bool extract_uint64(std::string_view & packet, uint64_t & out)
{
	if (packet.size() < 8) {
		return false;
	}
	out = read_uint64(packet.data());
	packet.remove_prefix(8);
	return true;
}

extracted_string extract_blob(std::string_view & packet)
{
	uint32_t s{};
	if (!extract_uint32(packet, s)) {
		return {extract_fail, "Bad length"sv};
	}
	if (s > packet.size()) {
		return {extract_fail, "Bad length"sv};
	}
	auto ret = packet.substr(0, s);
	packet.remove_prefix(s);
	return extracted_string{ret};
}

extracted_string extract_string(std::string_view & packet, string_type t, bool allow_empty)
{
	auto s = extract_blob(packet);
	if (!s) {
		return s;
	}

	if (t != string_type::blob) {
		while (!s->empty() && s->back() == '\0') {
			s->remove_suffix(1);
		}
	}

	if (!allow_empty && s->empty()) {
		return {extract_fail, "String cannot be empty"sv};
	}

	switch (t) {
		case string_type::ascii_noquotes:
			for (auto const c : *s) {
				if (c == '\'' || c == '"' || c == '`') {
					return {extract_fail, "Bad character in string"sv};
				}
			}
			[[fallthrough]];
		case string_type::ascii:
			for (auto const c : *s) {
				if (c == '\t') {
					continue;
				}
				if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 127) {
					return {extract_fail, "Bad character in string"sv};
				}
			}
			break;
		case string_type::multiline_ascii:
			for (auto const c : *s) {
				if (c == '\r' || c == '\n' || c == '\t') {
					continue;
				}
				if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 127) {
					return {extract_fail, "Bad character in string"sv};
				}
			}
			break;
		case string_type::utf8:
			if (!is_valid_utf8(*s)) {
				return {extract_fail, "String is not UTF-8"sv};
			}
			[[fallthrough]];
		case string_type::text:
			for (auto const c : *s) {
				if (c == '\r' || c == '\n' || c == '\t') {
					continue;
				}
				if (static_cast<unsigned char>(c) < 32) {
					return {extract_fail, "Bad character in string"sv};
				}
			}
			break;
	    case string_type::blob:
			break;
	}

	return s;
}

bool extract_namelist(std::string_view & packet, std::string_view & out, logger_interface & logger)
{
	if (packet.size() < 4) {
		logger.log(logmsg::error, "Cannot parse namelist length: Packet too short"sv);
		return false;
	}
	size_t s = read_uint32(packet.data());
	packet.remove_prefix(4);
	if (s > packet.size()) {
		logger.log(logmsg::error, "Cannot parse namelist: length larger than packet"sv);
		return false;
	}

	auto names = packet.substr(0, s);
	if (!is_namelist(names, logger)) {
		return false;
	}

	out = names;
	packet.remove_prefix(s);
	return true;
}

bool is_namelist(std::string_view const& names, logger_interface & logger)
{
	for (auto const& name : strtokenizer(names, ',', false)) {
		if (name.empty()) {
			logger.log(logmsg::error, "Cannot parse namelist: found empty name"sv);
			return false;
		}
		for (auto const c : name) {
			if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 127) {
				logger.log(logmsg::error, "Cannot parse namelist: Invalid character in name"sv);
				return false;
			}
		}
	}
	return true;
}

std::optional<bool> extract_bool(std::string_view & packet)
{
	if (packet.empty()) {
		return {};
	}

	std::optional<bool> ret = packet[0];
	packet.remove_prefix(1);
	return ret;
}

}
