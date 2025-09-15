#include "libfilezilla/encode.hpp"
#include "libfilezilla/format.hpp"
#include "libfilezilla/xml.hpp"

#include <map>
#include <string.h>

using namespace std::literals;

namespace {
constexpr bool is_xml_ws(char c)  {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

constexpr bool is_all_xml_ws(std::string_view value)
{
	for (auto c : value) {
		if (!is_xml_ws(c)) {
			return false;
		}
	}
	return true;
}

constexpr bool true_cb(fz::xml::callback_event, std::string_view, std::string_view, std::string &&) {
	return true;
}
constexpr bool raw_true_cb(fz::xml::callback_event, std::string_view, std::string_view, std::string_view) {
	return true;
}
}

namespace fz {

namespace xml {

parser::parser()
	: cb_(&true_cb)
{}

parser::parser(callback_t const& cb)
	: cb_(cb ? cb : &true_cb)
{
}

parser::parser(callback_t && cb)
	: cb_(cb ? std::move(cb) : &true_cb)
{
}

void parser::set_callback(callback_t && cb) {
	cb_ = cb ? std::move(cb) : &true_cb;
}

void parser::set_callback(callback_t const& cb) {
	cb_ = cb ? cb : &true_cb;
}

bool parser::finalize()
{
	if (s_ == state::error) {
		return false;
	}
	switch (encoding_) {
	case encoding::unknown:
		set_error("Premature end of document"sv, value_.size());
		return false;
	case encoding::utf8:
		if (utf8_state_) {
			set_error("Premature end of document"sv, 0);
			return false;
		}
		break;
	case encoding::utf16be:
	case encoding::utf16le:
		if (utf16_state_) {
			set_error("Premature end of document"sv, 0);
			return false;
		}
		break;
	}

	if (s_ != state::content || !path_.empty()) {
		set_error("Premature end of document"sv, 0);
		return false;
	}
	else if (!got_element_) {
		set_error("Missing root element"sv, 0);
		return false;
	}
	for (auto c : value_) {
		if (!is_xml_ws(c)) {
			set_error("PCDATA past root element"sv, 0);
			return false;
		}
	}
	s_ = state::done;
	return true;
}

bool parser::deduce_encoding(std::string_view & data)
{
	if (data.size() + value_.size() < 4) {
		value_.append(data);
		data = std::string_view();
		return true;
	}

	size_t prev_size = value_.size();
	value_.append(data.substr(0, 4 - prev_size));
	data = data.substr(4 - prev_size);

	size_t bom_size{};
	if (value_[0] == '\x00' && value_[1] == '\x00' && value_[2] == '\xfe' && value_[3] == '\xff') {
		value_ = "Unsupported encoding: UCS-4-BE BOM"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\xff' && value_[1] == '\xfe' && value_[2] == '\x00' && value_[3] == '\x00') {
		value_ = "Unsupported encoding: UCS-4-LE BOM"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\x00' && value_[1] == '\x00' && value_[2] == '\xff' && value_[3] == '\xfe') {
		value_ = "Unsupported encoding: UCS-4 BOM with unusual byte order"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\xfe' && value_[1] == '\xff' && value_[2] == '\x00' && value_[3] == '\x00') {
		value_ = "Unsupported encoding: UCS-4 BOM with unusual byte order"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\x00' && value_[1] == '\x00' && value_[2] == '\x00' && value_[3] == '\x3c') {
		value_ = "Unsupported encoding: UCS-4-BE"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\x3c' && value_[1] == '\x00' && value_[2] == '\x00' && value_[3] == '\x00') {
		value_ = "Unsupported encoding: UCS-4-LE"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\x00' && value_[1] == '\x00' && value_[2] == '\x3c' && value_[3] == '\x00') {
		value_ = "Unsupported encoding: UCS-4 with unusual byte order"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\x00' && value_[1] == '\x3c' && value_[2] == '\x00' && value_[3] == '\x00') {
		value_ = "Unsupported encoding: UCS-4 with unusual byte order"sv;
		s_ = state::error;
		return false;
	}
	else if (value_[0] == '\xef' && value_[1] == '\xbb' && value_[2] == '\xbf') {
		// UTF-8 with BOM
		bom_size = 3;
		encoding_ = encoding::utf8;
	}
	else if (value_[0] == '\xfe' && value_[1] == '\xff') {
		// UTF-16-BE with BOM
		bom_size = 2;
		encoding_ = encoding::utf16be;
	}
	else if (value_[0] == '\xff' && value_[1] == '\xfe') {
		// UTF-16-LE with BOM
		bom_size = 2;
		encoding_ = encoding::utf16le;
	}
	else if (value_[0] == '\x00' && value_[1] == '\x3c' && value_[2] == '\x00' && value_[3] == '\x3f') {
		// UTF-16-BE without BOM
		encoding_ = encoding::utf16be;
	}
	else if (value_[0] == '\x3c' && value_[1] == '\x00' && value_[2] == '\x3f' && value_[3] == '\x00') {
		// UTF-16-LE without BOM
		encoding_ = encoding::utf16le;
	}
	else {
		// Assume UTF-8.
		encoding_ = encoding::utf8;
	}
	std::string v = value_;
	value_.clear();
	return parse(std::string_view(v).substr(bom_size));
}

bool parser::parse(std::string_view data)
{
	if (s_ == state::error) {
		return false;
	}
	if (s_ == state::done) {
		if (!data.empty()) {
			set_error("Already finalized"sv, 0);
			return false;
		}
		return true;
	}
	if (encoding_ == encoding::unknown) {
		if (!deduce_encoding(data)) {
			return false;
		}
	}

	if (encoding_ == encoding::utf8) {
		if (!is_valid_utf8(data, utf8_state_)) {
			set_error("Invalid UTF-8"sv, utf8_state_);
			return false;
		}
		return parse_valid_utf8(data);
	}
	else {
		bool converted = (encoding_ == encoding::utf16be)
				? utf16be_to_utf8_append(converted_, data, utf16_state_)
				: utf16le_to_utf8_append(converted_, data, utf16_state_);
		if (!converted) {
			s_ = state::error;
			value_ = fz::sprintf("Could not convert from %s to UTF-8"sv, (encoding_ == encoding::utf16be) ? "UTF-16-BE"sv : "UTF-16-LE"sv);
			return false;
		}

		bool ret = parse_valid_utf8(converted_);
		converted_.clear();
		return ret;
	}
}

bool parser::parse_valid_utf8(std::string_view data)
{
	// Precondition: Data is valid UTF-8.

	if (data.empty()) {
		return true;
	}

	// Check for null bytes
	auto slen = strnlen(data.data(), data.size());
	if (slen != data.size()) {
		set_error("Null character"sv, slen);
		return false;
	}

	char const* p = &data[0];
	char const* end = p + data.size();
	if (!parse(p, end)) {
		if (s_ != state::error) {
			s_ = state::error;
			value_.clear();
		}
		return false;
	}
	processed_ += data.size();

	if (path_.size() > path_size_limit_) {
		set_error("Path too long"sv, 0);
		return false;
	}
	if (value_.size() > value_size_limit_) {
		set_error("Value too long"sv, 0);
		return false;
	}

	return true;
}

bool parser::decode_ref()
{
	std::string_view ref = std::string_view(path_).substr(nodes_.back());
	if (ref.empty() || ref.size() > 8) {
		return false;
	}
	else if (ref[0] == '#') {
		uint32_t v{};
		if (ref.size() > 1 && ref[1] == 'x') {
			for (size_t i = 2; i < ref.size(); ++i) {
				v <<= 4;
				int digit = hex_char_to_int(ref[i]);
				if (digit < 0) {
					return false;
				}
				v += digit;
			}
		}
		else {
			v = to_integral(ref.substr(1), 0);
		}
		if (!v || v > 0x10FFFF) {
			return false;
		}
		else if (v == 0xfffe || v == 0xffff) {
			return false;
		}
		else if (v >= 0xd800 && v <= 0xDFFF) {
			// No surrogates allowed.
			return false;
		}
		unicode_codepoint_to_utf8_append(value_, v);
	}
	else {
		// In C++20 switch to unordered_map
		static std::map<std::string_view, char> const entities{
			{"lt"sv, '<'},
			{"gt"sv, '>'},
			{"quot"sv, '"'},
			{"apos"sv, '\''},
			{"amp"sv, '&'},
		};
		auto it = entities.find(ref);
		if (it == entities.end()) {
			return false;
		}
		value_.push_back(it->second);
	}

	return true;
}

bool parser::is_valid_tag_or_attr(std::string_view) const
{
	return true;
}

bool parser::normalize_value()
{
	// Look for first UTF-8 bytes of U+000D, U+2028 (0xe2 0x80 0xa8) and U+0085 (0xc2 0x85)
	// Intentionally avoiding std::string::find_first_of here, as it's turns out to be
	// slow, see GCC bug 103798
	char * start = value_.data();
	while (auto const c = *start) {
		if (c == '\r' || c == '\xe2' || c == '\xc2') {
			break;
		}
		++start;
	}
	if (*start) {
		char const* in = start;
		char* out = start;
		char prev{};

		while (auto const c = *in++) {
			switch (c) {
			case '\r':
				*out++ = '\n';
				break;
			case '\n':
				if (prev != '\r') {
					*out++ ='\n';
				}
				break;
			case '\xe2': // U+2028
				if (in[0] == '\x80' && in[1] == '\xa8') {
					in += 2;
					*out++ = '\n';
				}
				else {
					*out++ = c;
				}
				break;
			case '\xc2': // U+85
				if (in[0] == '\x85') {
					++in;
					if (prev != '\r') {
						*out++ = '\n';
						break;
					}
				}
				else {
					*out++ = c;
				}
				break;
			default:
				*out++ = c;
				break;
			}
			prev = c;
		}
		value_.resize(out - value_.data());
	}
	return true;
}

bool parser::parse(char const* const begin, char const* const end)
{
	char const* p = begin;

	switch (s_) {
	case state::content:
	state_content: {
		char const* const start = p;
		while (p < end) {
			char const c = *p++;
			if (c == '<') {
				value_.append(start, p - start - 1);
				if (path_.empty()) {
					// Ignore whitespace, disallow the rest.
					for (auto c : value_) {
						if (!is_xml_ws(c)) {
							set_error("PCDATA outside root element"sv, p - begin);
							return false;
						}
					}
					value_.clear();
				}
				else {
					if (!value_.empty()) {
						if (!normalize_value()) {
							set_error("Invalid character in text"sv, p - begin);
							return false;
						}
						if (!cb_(callback_event::value, path_, {}, std::move(value_))) {
							return false;
						}
						value_.clear();
					}
				}
				nodes_.push_back(path_.size());
				goto state_tag_start;
			}
			else if (c == '&') {
				value_.append(start, p - start - 1);
				nodes_.push_back(path_.size());
				goto state_reference;
			}
		}
		value_.append(start, p - start);
		s_ = state::content;
		break;
	}
	case state::tag_start:
	state_tag_start: {
		if (p == end) {
			s_ = state::tag_start;
			break;
		}
		char const c = *p++;
		if (c == '>') {
			set_error("Empty tag name"sv, p - begin);
			return false;
		}
		else if (is_xml_ws(c)) {
			set_error("Whitespace after opening bracket"sv, p - begin);
			return false;
		}
		else if (c == '!') {
			nodes_.pop_back();
			dashes_ = 0;
			goto state_comment_start;
		}
		else if (c == '?') {
			path_.push_back(c);
			goto state_pi;
		}
		else if (c == '/') {
			// Closing tag
			nodes_.pop_back();
			if (nodes_.empty()) {
				set_error("Closing element without open element"sv, p - begin);
				return false;
			}
			tag_match_pos_ = nodes_.back();
			if (tag_match_pos_) {
				++tag_match_pos_;
			}
			goto state_tag_closing;
		}
		else {
			if (got_element_ && path_.empty()) {
				set_error("Extra element after root element"sv, p - begin);
				return false;
			}
			if (!path_.empty()) {
				path_.push_back('<');
			}
			got_element_ = true;
			path_.push_back(c);
			goto state_tag_name;
		}
		s_ = state::tag_start;
		break;
	}
	case state::tag_name:
	state_tag_name: {
		char const* const start = p;
		while (p < end) {
			char const c = *p++;
			if (c == '>') {
				path_.append(start, p - start - 1);
				auto tag = std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : nodes_.back());
				if (!is_valid_tag_or_attr(tag)) {
					set_error("Invalid tag name"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::open, nodes_.back() ? std::string_view(path_).substr(0, nodes_.back()) : std::string_view(), tag, std::string())) {
					return false;
				}
				goto state_content;
			}
			else if (is_xml_ws(c)) {
				path_.append(start, p - start - 1);
				auto tag = std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : nodes_.back());
				if (!is_valid_tag_or_attr(tag)) {
					set_error("Invalid tag name"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::open, nodes_.back() ? std::string_view(path_).substr(0, nodes_.back()) : std::string_view(), tag, std::string())) {
					return false;
				}
				goto state_attributes;
			}
			else if (c == '/') {
				path_.append(start, p - start - 1);
				auto tag = std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : nodes_.back());
				if (!is_valid_tag_or_attr(tag)) {
					set_error("Invalid tag name"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::open, nodes_.back() ? std::string_view(path_).substr(0, nodes_.back()) : std::string_view(), tag, std::string())) {
					return false;
				}
				if (!cb_(callback_event::close, nodes_.back() ? std::string_view(path_).substr(0, nodes_.back()) : std::string_view(), tag, std::string())) {
					return false;
				}
				goto state_tag_end;
			}
		}
		path_.append(start, p - start);
		s_ = state::tag_name;
		break;
	}
	case state::comment_start:
	state_comment_start: {
		while (p < end) {
			char const c = *p++;
			if (c == '-') {
				if (dashes_ == 1) {
					dashes_ = 0;
					goto state_comment_end;
				}
				++dashes_;
			}
			else if (c == '[' && !dashes_) {
				goto state_cdata_start;
			}
			else if (c == 'D' && !dashes_ && got_xmldecl_ && !got_doctype_ && !got_element_) {
				got_doctype_ = true;
				goto state_doctype_start;
			}
			else {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
		}
		s_ = state::comment_start;
		break;
	}
	case state::comment_end:
	state_comment_end: {
		while (p < end) {
			char const c = *p++;
			if (c == '-') {
				++dashes_;
				if (dashes_ > 2) {
					set_error("Triple dashes in comment"sv, p - begin);
					return false;
				}
				continue;
			}
			else if (c == '>') {
				if (dashes_ == 2) {
					goto state_content;
				}
			}
			dashes_ = 0;
		}
		s_ = state::comment_end;
		break;
	}
	case state::doctype_start:
	state_doctype_start: {
		while (p < end) {
			char const c = *p++;
			constexpr auto doctype_header = "OCTYPE ";
			if (c != doctype_header[dashes_++]) {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
			if (dashes_ == 7) {
				nodes_.push_back(path_.size());
				goto state_doctype_name;
			}
		}
		s_ = state::doctype_start;
		break;
	}
	case state::doctype_name:
	state_doctype_name: {
		char const* const start = p;
		while (p < end) {
			char const c = *p++;
			if (c == ' ') {
				path_.append(start, p - start - 1);
				if (path_.size() == nodes_.back()) {
					set_error("Empty doctype name"sv, p - begin);
					return false;
				}
				quotes_ = 0;
				goto state_doctype_value;
			}
			else if (c == '>') {
				path_.append(start, p - start - 1);
				if (path_.size() == nodes_.back()) {
					set_error("Empty doctype name"sv, p - begin);
					return false;
				}
				cb_(callback_event::doctype, {}, path_.substr(nodes_.back()), std::string());
				path_.resize(nodes_.back());
				nodes_.pop_back();
				goto state_content;
			}
		}
		path_.append(start, p - start);
		s_ = state::doctype_name;
		break;
	}
	case state::doctype_value:
	state_doctype_value: {
		char const* const start = p;
		while (p < end) {
			char const c = *p++;
			if (c == quotes_) {
				quotes_ = 0;
			}
			else if (!quotes_) {
				if (c == '\'') {
					quotes_ = '\'';
				}
				else if (c == '"') {
					quotes_ = '"';
				}
				else if (c == '[') {
					set_error("Doctypes with internal subset not supported", p - begin);
					return false;
				}
				else if (c == '>') {
					value_.append(start, p - start - 1);
					cb_(callback_event::doctype, {}, path_.substr(nodes_.back()), std::move(value_));
					value_.clear();
					path_.resize(nodes_.back());
					nodes_.pop_back();
					goto state_content;
				}
			}
		}
		value_.append(start, p - start);
		s_ = state::doctype_value;
		break;
	}
	case state::cdata_start:
	state_cdata_start: {
		while (p < end) {
			char const c = *p++;
			constexpr auto cdata_header = "CDATA[";
			if (c != cdata_header[dashes_++]) {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
			if (dashes_ == 6) {
				dashes_ = 0;
				goto state_cdata_end;
			}
		}
		s_ = state::cdata_start;
		break;
	}
	case state::cdata_end:
	state_cdata_end: {
		while (p < end) {
			char const c = *p++;
			value_ += c;
			if (c == ']') {
				if (dashes_ < 2) {
					++dashes_;
				}
				continue;
			}
			else if (c == '>') {
				if (dashes_ == 2) {
					value_.resize(value_.size() - 3);
					goto state_content;
				}
			}
			dashes_ = 0;
		}
		s_ = state::cdata_end;
		break;
	}
	case state::pi:
	state_pi: {
		while (p < end) {
			char const c = *p++;
			if (c == '?') {
				if (path_.size() == nodes_.back() + 1) {
					set_error("Empty parsing instruction"sv, p - begin);
					return false;
				}
				if (equal_insensitive_ascii(std::string_view(path_).substr(nodes_.back()), "?xml"sv)) {
					if (got_xmldecl_ || got_element_) {
						set_error("Misplaced xmldecl"sv, p - begin);
						return false;
					}
					got_xmldecl_ = true;
				}
				if (!is_valid_tag_or_attr(value_)) {
					set_error("Invalid parsing instruction"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::parsing_instruction, {}, std::string_view(path_).substr(nodes_.back() + 1), std::move(value_))) {
					return false;
				}
				value_.clear();
				goto state_tag_end;
			}
			else if (is_xml_ws(c)) {
				if (path_.size() + 1 == nodes_.back()) {
					set_error("Parsing instruction starting with whitespace"sv, p - begin);
					return false;
				}
				if (equal_insensitive_ascii(std::string_view(path_).substr(nodes_.back()), "?xml"sv)) {
					if (got_xmldecl_ || got_element_) {
						set_error("Misplaced xmldecl"sv, p - begin);
						return false;
					}
					got_xmldecl_ = true;
				}
				goto state_pi_value;
			}
			else {
				path_.push_back(c);
			}
		}
		s_ = state::pi;
		break;
	}
	case state::pi_value:
	state_pi_value: {
		while (p < end) {
			char const c = *p++;
			if (c == '?') {
				if (!is_valid_tag_or_attr(value_)) {
					set_error("Invalid parsing instruction"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::parsing_instruction, {}, std::string_view(path_).substr(nodes_.back() + 1), std::move(value_))) {
					return false;
				}
				value_.clear();
				goto state_tag_end;
			}
			else {
				value_.push_back(c);
			}
		}
		s_ = state::pi_value;
		break;
	}
	case state::tag_closing:
	state_tag_closing: {
		while (p < end) {
			char const c = *p++;
			if (c == '>') {
				if (tag_match_pos_ != path_.size()) {
					set_error("Mismatched element tags"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::close, nodes_.back() ? std::string_view(path_).substr(0, nodes_.back()) : std::string_view(), std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : nodes_.back()), std::string())) {
					return false;
				}
				path_.resize(nodes_.back());
				nodes_.pop_back();
				goto state_content;
			}
			else if (is_xml_ws(c)) {
				if (tag_match_pos_ != path_.size()) {
					set_error("Mismatched element tags"sv, p - begin);
					return false;
				}
			}
			else if (tag_match_pos_ >= path_.size() || c != path_[tag_match_pos_++]) {
				set_error("Mismatched element tags"sv, p - begin);
				return false;
			}
		}
		s_ = state::tag_closing;
		break;
	}
	case state::tag_end:
	state_tag_end: {
		if (p == end) {
			s_ = state::tag_end;
			break;
		}
		char const c = *p++;
		if (c != '>') {
			set_error("Invalid character"sv, p - begin);
			return false;
		}
		path_.resize(nodes_.back());
		nodes_.pop_back();
		goto state_content;
	}
	case state::attributes:
	state_attributes: {
		while (p < end) {
			char const c = *p++;
			if (is_xml_ws(c)) {
				continue;
			}
			else if (c == '=') {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
			if (c == '/') {
				if (!cb_(callback_event::close, nodes_.back() ? std::string_view(path_).substr(0, nodes_.back()) : std::string_view(), std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : nodes_.back()), std::string())) {
					return false;
				}
				goto state_tag_end;
			}
			else if (c == '>') {
				goto state_content;
			}
			else {
				name_.push_back(c);
				goto state_attribute_name;
			}
		}
		s_ = state::attributes;
		break;
	}
	case state::attribute_name:
	state_attribute_name: {
		while (p < end) {
			char const c = *p++;
			if (is_xml_ws(c)) {
				if (!is_valid_tag_or_attr(name_)) {
					set_error("Invalid attribute name"sv, p - begin);
					return false;
				}
				goto state_attribute_equal;
			}
			else if (c == '=') {
				if (!is_valid_tag_or_attr(name_)) {
					set_error("Invalid attribute name"sv, p - begin);
					return false;
				}
				goto state_attribute_quote;
			}
			else if (c == '/' || c == '>' || c == '\'' || c == '"' || c == '&') {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
			else {
				name_.push_back(c);
			}
		}
		s_ = state::attribute_name;
		break;
	}
	case state::attribute_equal:
	state_attribute_equal: {
		while (p < end) {
			char const c = *p++;
			if (c == '=') {
				goto state_attribute_quote;
			}
			else if (!is_xml_ws(c)) {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
		}
		s_ = state::attribute_equal;
		break;
	}
	case state::attribute_quote:
	state_attribute_quote: {
		while (p < end) {
			char const c = *p++;
			if (c == '\'' || c == '"') {
				quotes_ = c;
				goto state_attribute_value;
			}
			else if (!is_xml_ws(c)) {
				set_error("Invalid character"sv, p - begin);
				return false;
			}
		}
		s_ = state::attribute_quote;
		break;
	}
	case state::attribute_value:
	state_attribute_value: {
		char const* const start = p;
		while (p < end) {
			char const c = *p++;
			if (c == quotes_) {
				value_.append(start, p - start - 1);
				if (!is_valid_tag_or_attr(value_)) {
					set_error("Invalid attribute value"sv, p - begin);
					return false;
				}
				if (!cb_(callback_event::attribute, path_, name_, std::move(value_))) {
					return false;
				}
				name_.clear();
				value_.clear();
				goto state_attributes;
			}
			else if (c == '&') {
				value_.append(start, p - start - 1);
				nodes_.push_back(path_.size());
				goto state_attrvalue_reference;
			}
		}
		value_.append(start, p - start);
		s_ = state::attribute_value;
		break;
	}
	case state::reference:
	state_reference: {
		while (p < end) {
			char const c = *p++;
			if (c == ';') {
				if (!decode_ref()) {
					set_error("Could not decode reference"sv, p - begin);
					return false;
				}
				path_.resize(nodes_.back());
				nodes_.pop_back();
				goto state_content;
			}
			else {
				// A more than generous limit
				if (path_.size() - nodes_.back() > 10) {
					set_error("Could not decode reference, too long."sv, p - begin);
				}
				path_.push_back(c);
			}
		}
		s_ = state::reference;
		break;
	}
	case state::attrvalue_reference:
	state_attrvalue_reference: {
		while (p < end) {
			char const c = *p++;
			if (c == ';') {
				if (!decode_ref()) {
					set_error("Could not decode reference"sv, p - begin);
					return false;
				}
				path_.resize(nodes_.back());
				nodes_.pop_back();
				goto state_attribute_value;
			}
			else {
				// A more than generous limit
				if (path_.size() - nodes_.back() > 10) {
					set_error("Could not decode reference, too long."sv, p - begin);
				}
				path_.push_back(c);
			}
		}
		s_ = state::attrvalue_reference;
		break;
	}
	default:
		set_error("Bad state"sv, p - begin);
		return false;

	}

	return true;
}

std::string parser::get_error() const
{
	return (s_ == state::error) ? value_ : std::string();
}

void parser::set_error(std::string_view msg, size_t offset)
{
	s_ = state::error;
	if (offset) {
		--offset;
	}
	value_ = sprintf("%s at offset %d", msg, offset + processed_);
}

void parser::set_limits(size_t path_size_limit, size_t value_size_limit)
{
	path_size_limit_ = path_size_limit;
	value_size_limit_ = value_size_limit;
}

namespace_parser::namespace_parser()
	: parser_([this](callback_event type, std::string_view path, std::string_view name, std::string && value) { return on_callback(type, path, name, std::move(value)); })
	, cb_(&true_cb)
	, raw_cb_(&raw_true_cb)
{
}

namespace_parser::namespace_parser(parser::callback_t const& cb)
	: parser_([this](callback_event type, std::string_view path, std::string_view name, std::string && value) { return on_callback(type, path, name, std::move(value)); })
	, cb_(cb ? cb : &true_cb)
	, raw_cb_(&raw_true_cb)
{
}

namespace_parser::namespace_parser(parser::callback_t && cb)
	: parser_([this](callback_event type, std::string_view path, std::string_view name, std::string && value) { return on_callback(type, path, name, std::move(value)); })
	, cb_(cb ? std::move(cb) : &true_cb)
	, raw_cb_(&raw_true_cb)
{
}

void namespace_parser::set_callback(parser::callback_t && cb) {
	cb_ = cb ? std::move(cb) : &true_cb;
}

void namespace_parser::set_callback(parser::callback_t const& cb) {
	cb_ = cb ? cb : &true_cb;
}

void namespace_parser::set_raw_callback(raw_callback_t && cb) {
	raw_cb_ = cb ? std::move(cb) : &raw_true_cb;
}

void namespace_parser::set_raw_callback(raw_callback_t const& cb) {
	raw_cb_ = cb ? cb : &raw_true_cb;
}

bool namespace_parser::parse(std::string_view data)
{
	return parser_.parse(data);
}

bool namespace_parser::finalize()
{
	return parser_.finalize();
}

bool namespace_parser::apply_namespace_to_path()
{
	auto in = applied_.to_view();
	size_t pos = in.find(':');
	if (pos != std::string::npos) {
		auto inprefix = in.substr(0, pos);
		// This handles all non-empty prefixes
		for (auto it = namespaces_.crbegin(); it != namespaces_.crend(); ++it) {
			auto const& prefix = std::get<1>(*it);
			if (prefix == inprefix) {
				auto const& name = std::get<2>(*it);
				if (name.empty()) {
					error_ = true;
					path_ = sprintf("Use of explicitly undeclared namespace prefix '%s'"sv, inprefix);
					return false;
				}

				path_.append(name);
				path_.append(in.substr(pos + 1));
				return true;
			}
		}

		// No namespace found for prefix
		error_ = true;
		path_ = sprintf("No namespace declared for prefix '%s'"sv, inprefix);
		return false;
	}
	else {
		// This handles all empty prefixes, aka default namspaces.
		for (auto it = namespaces_.crbegin(); it != namespaces_.crend(); ++it) {
			auto const& prefix = std::get<1>(*it);
			auto const& name = std::get<2>(*it);
			if (!prefix.empty()) {
				continue;
			}
			if (!name.empty()) {
				path_.append(name);
			}
			break;
		}
		path_.append(applied_.to_view());
		return true;
	}
}

std::string_view namespace_parser::apply_namespaces(std::string_view in)
{
	size_t pos = in.find(':');
	if (pos != std::string::npos) {
		auto inprefix = in.substr(0, pos);
		// This handles all non-empty prefixes
		for (auto it = namespaces_.crbegin(); it != namespaces_.crend(); ++it) {
			auto const& prefix = std::get<1>(*it);
			if (prefix == inprefix) {
				auto const& name = std::get<2>(*it);
				if (name.empty()) {
					error_ = true;
					path_ = sprintf("Use of explicitly undeclared namespace prefix '%s'"sv, inprefix);
					return {};
				}

				applied_.clear();
				applied_.append(name);
				applied_.append(in.substr(pos + 1));
				return applied_.to_view();
			}
		}

		// No namespace found for prefix
		error_ = true;
		path_ = sprintf("No namespace declared for prefix '%s'"sv, inprefix);
		return {};
	}
	else {
		return in;
	}
}

bool namespace_parser::on_callback(callback_event type, std::string_view path, std::string_view name, std::string && value)
{
	if (!raw_cb_(type, path, name, value)) {
		return false;
	}
	if (type == callback_event::parsing_instruction) {
		return cb_(type, path, name, std::move(value));
	}

	if (type == callback_event::attribute) {
		if (attributes_.size() > 50) {
			error_ = true;
			path_ = "Too many attributes"sv;
			return false;
		}
		if (name == "xmlns"sv) {
			if (!value.empty() && value.back() != ':') {
				value += ':';
			}
			namespaces_.emplace_back(nodes_.size(), std::string(), std::move(value));
			return true;
		}
		size_t pos = name.find(':');
		if (pos != std::string::npos) {
			auto prefix = name.substr(pos + 1);
			name = name.substr(0, pos);
			if (name == "xmlns"sv) {
				if (prefix.empty()) {
					error_ = true;
					path_ = "Empty namespace prefix"sv;
					return false;
				}
				if (!value.empty() && value.back() != ':') {
					value += ':';
				}
				namespaces_.emplace_back(nodes_.size(), prefix, std::move(value));
				return true;
			}
		}

		attributes_.emplace_back(std::make_pair(name, std::move(value)));
		return true;
	}

	if (needs_namespace_expansion_) {
		if (!apply_namespace_to_path()) {
			return false;
		}
		needs_namespace_expansion_ = false;

		auto tag = std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : 0);
		if (!cb_(callback_event::open, std::string_view(path_).substr(0, nodes_.back()), tag, std::string())) {
			return false;
		}

		for (auto & a : attributes_) {
			auto tag = apply_namespaces(a.first);
			if (tag.empty()) {
				return false;
			}
			if (!cb_(callback_event::attribute, path_, tag, std::move(a.second))) {
				return false;
			}
		}
		attributes_.clear();
	}

	if (type == callback_event::open) {
		needs_namespace_expansion_ = true;
		applied_.clear();
		applied_.append(name);
		nodes_.push_back(path_.size());
		if (!path_.empty()) {
			path_ += '<';
		}
		return true;
	}
	else if (type == callback_event::close) {
		if (!cb_(type, std::string_view(path_).substr(0, nodes_.back()), std::string_view(path_).substr(nodes_.back() ? nodes_.back() + 1 : 0), std::move(value))) {
			return false;
		}
		path_.resize(nodes_.back());
		nodes_.pop_back();
		while (!namespaces_.empty()) {
			if (std::get<0>(namespaces_.back()) <= nodes_.size()) {
				break;
			}
			namespaces_.pop_back();
		}
		return true;
	}
	else {
		return cb_(type, path_, name, std::move(value));
	}
}

std::string namespace_parser::get_error() const
{
	if (error_) {
		return path_;
	}
	return parser_.get_error();
}


pretty_printer::~pretty_printer()
{
}

void pretty_printer::finish_line()
{
	bool open = !line_.empty();
	if (!value_.empty()) {
		if (!is_all_xml_ws(value_)) {
			if (open) {
				line_ += '>';
				open = false;
			}
			line_ += value_;
		}
		value_.clear();
	}
	if (open) {
		line_ += '>';
		open = false;
	}
	print_line();
}

void pretty_printer::print_line()
{
	auto const tokens = strtok_view(line_, '\n', true);
	for (auto const t : tokens) {
		on_line(t);
	}
	line_.clear();
}

namespace {
void append_escaped(std::string & result, std::string_view value)
{
	char c{};
	size_t i = 0;
	while (i < value.size()) {
		size_t start = i;
		for (; i < value.size(); ++i) {
			c = value[i];
			if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '&') {
				break;
			}
		}
		result += value.substr(start, i - start);
		if (i != value.size()) {
			++i;
			switch (c) {
			case '<':
				result += "&lt;"sv;
				break;
			case '>':
				result += "&gt;"sv;
				break;
			case '"':
				result += "&quot;"sv;
				break;
			case '\'':
				result += "&apos;"sv;
				break;
			case '&':
				result += "&amp;"sv;
				break;
			}
		}
	}
}
}

void pretty_printer::log(callback_event type, std::string_view, std::string_view name, std::string_view value)
{
	if (type == callback_event::value) {
		append_escaped(value_, value);
	}
	else if (type == callback_event::parsing_instruction) {
		finish_line();
		line_.assign(depth_ * 2, ' ');
		line_ += "<?"sv;
		line_ += name;
		if (!value.empty()) {
			line_ += ' ';
		}
		line_ += value;
		line_ += "?>"sv;
		print_line();
	}
	else if (type == callback_event::doctype) {
		line_ += "<!DOCTYPE "sv;
		line_ += name;
		if (!value.empty()) {
			line_ += ' ';
		}
		line_ += value;
		line_ += ">"sv;
		print_line();
	}
	else if (type == callback_event::attribute) {
		line_ += ' ';
		line_ += name;
		line_ += "=\""sv;
		append_escaped(line_, value);
		line_ += '"';
	}
	else if (type == callback_event::open) {
		finish_line();

		line_.assign(depth_++ * 2, ' ');
		line_ += '<';
		line_ += name;
	}
	else if (type == callback_event::close) {
		--depth_;
		if (!value_.empty() && !is_all_xml_ws(value_)) {
			if (!line_.empty()) {
				line_ += '>';
			}
			line_ += value_;
			line_ += "</"sv;
			line_ += name;
			line_ += '>';
		}
		else {
			if (!line_.empty()) {
				line_ += "/>"sv;
			}
			else {
				line_.assign(depth_ * 2, ' ');
				line_ += "</"sv;
				line_ += name;
				line_ += '>';
			}
		}
		value_.clear();
		print_line();
	}
}

pretty_logger::pretty_logger(logger_interface & logger, logmsg::type level)
	: level_(level)
	, logger_(logger)
{}

void pretty_logger::on_line(std::string_view line)
{
	logger_.log_u_raw(level_, line);
}

}
}
