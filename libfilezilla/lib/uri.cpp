#include "libfilezilla/uri.hpp"
#include "libfilezilla/encode.hpp"
#include "libfilezilla/iputils.hpp"

namespace fz {

namespace uri_chars {
constexpr std::string_view alpha{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" };
constexpr std::string_view digit{ "01234567890" };
constexpr std::string_view scheme{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-." };
}

uri::uri(std::string_view const& in, uri_parsing_flags flags)
{
	if (!parse(in, flags)) {
		clear();
	}
}

void uri::clear()
{
	*this = uri();
}

bool uri::parse(std::string_view in, uri_parsing_flags flags)
{
	// Look for fragment
	size_t pos = in.find('#');
	if (pos != std::string::npos) {
		fragment_ = in.substr(pos + 1);
		in = in.substr(0, pos);
	}

	// Look for query
	pos = in.find('?');
	if (pos != std::string::npos) {
		query_ = in.substr(pos + 1);
		in = in.substr(0, pos);
	}

	// Do we have a scheme?
	if (!in.empty() && uri_chars::alpha.find(in[0]) != std::string::npos) {
		size_t scheme_delim = in.find_first_not_of(uri_chars::scheme, 1);
		if (scheme_delim != std::string::npos && in[scheme_delim] == ':') {
			scheme_ = in.substr(0, scheme_delim);
			in = in.substr(scheme_delim + 1);
		}
	}

	// Do we have authority?
	if (!in.empty()) {
		bool has_authority{};
		if (in.size() >= 2 && in[0] == '/' && in[1] == '/') {
			in = in.substr(2);
			has_authority = true;
		}
		else if (flags == uri_parsing_flags::assume_authority) {
			has_authority = true;
		}

		if (has_authority) {
			size_t auth_delim = in.find('/');
			std::string_view authority;
			if (auth_delim != std::string::npos) {
				authority = in.substr(0, auth_delim);
				in = in.substr(auth_delim);
			}
			else {
				authority = in;
				in = std::string_view();
			}
			if (!parse_authority(authority)) {
				return false;
			}
		}
	}

	if (!in.empty()) {
		path_ = percent_decode_s(in);
		if (path_.empty()) {
			return false;
		}
	}

	return true;
}

bool uri::parse_authority(std::string_view authority)
{
	// Do we have userinfo?
	size_t pos = authority.find('@');
	if (pos != std::string::npos) {
		std::string_view userinfo = authority.substr(0, pos);
		authority = authority.substr(pos + 1);
		pos = userinfo.find(':');
		if (pos != std::string::npos) { // Slight inaccuracy: Empty password isn't handled well
			user_ = percent_decode_s(userinfo.substr(0, pos));
			if (user_.empty() && pos != 0) {
				return false;
			}
			pass_ = percent_decode_s(userinfo.substr(pos + 1));
			if (pass_.empty() && pos + 1 != userinfo.size()) {
				return false;
			}
		}
		else {
			user_ = userinfo;
		}
	}

	// Do we have port?
	pos = authority.rfind(':');
	if (pos != std::string::npos) {
		if (authority.find_first_not_of(uri_chars::digit, pos + 1) == std::string::npos) {
			port_ = to_integral<unsigned short>(authority.substr(pos + 1), 0);
			if (!port_) {
				return false;
			}
			authority = authority.substr(0, pos);
		}
	}

	if (!authority.empty() && authority[0] == '[') {
		if (authority.back() != ']') {
			return false;
		}
		if (get_address_type(authority) != address_type::ipv6) {
			return false;
		}
	}
	host_ = percent_decode_s(authority);
	if (host_.empty() && !authority.empty()) {
		return false;
	}
	return true;
}

std::string uri::to_string(bool with_query) const
{
	std::string ret;
	if (!scheme_.empty()) {
		ret += scheme_ + ":";
	}
	if (!host_.empty()) {
		ret += "//";
		ret += get_authority(true);
	}
	ret += percent_encode(path_, true);

	if (with_query) {
		if (!query_.empty()) {
			ret += "?" + query_;
		}
		if (!fragment_.empty()) {
			ret += "#" + fragment_;
		}
	}

	return ret;
}

std::string uri::get_request(bool with_query) const
{
	std::string ret = percent_encode(path_, true);
	if (!ret.empty() && !query_.empty() && with_query) {
		ret += "?";
		ret += query_;
	}

	return ret;
}

std::string uri::get_authority(bool with_userinfo) const
{
	std::string ret;
	if (!host_.empty()) {
		if (with_userinfo) {
			ret += percent_encode(user_);
			if (!pass_.empty()) {
				ret += ":";
				ret += percent_encode(pass_);
			}
			if (!user_.empty() || !pass_.empty()) {
				ret += "@";
			}
		}
		ret += percent_encode(host_);
		if (port_ != 0) {
			ret += ":";
			ret += fz::to_string(port_);
		}
	}

	return ret;
}

void uri::resolve(uri const& base)
{
	if (!scheme_.empty() && scheme_ != base.scheme_) {
		return;
	}
	scheme_ = base.scheme_;

	if (!host_.empty()) {
		return;
	}

	host_ = base.host_;
	port_ = base.port_;
	user_ = base.user_;
	pass_ = base.pass_;

	if (path_.empty()) {
		path_ = base.path_;
		if (query_.empty()) {
			query_ = base.query_;
		}
	}
	else {
		if (path_[0] != '/') {
			if (base.path_.empty() && !base.host_.empty()) {
				path_ = "/" + path_;
			}
			else {
				size_t pos = base.path_.rfind('/');
				if (pos != std::string::npos) {
					path_ = base.path_.substr(0, pos) + path_;
				}
			}
		}
	}
}

bool uri::empty() const
{
	return host_.empty() && path_.empty();
}


bool uri::operator==(uri const& arg) const
{
	return std::tie(scheme_, user_, pass_, host_, port_, path_, query_, fragment_) == std::tie(arg.scheme_, arg.user_, arg.pass_, arg.host_, arg.port_, arg.path_, arg.query_, arg.fragment_);
}


query_string::query_string(std::string_view const& raw, bool plus_is_space)
{
	set(raw, plus_is_space);
}

query_string::query_string(std::pair<std::string, std::string> const& segment)
{
	segments_[segment.first] = segment.second;
}

query_string::query_string(std::initializer_list<std::pair<std::string, std::string>> const& segments)
{
	for (auto const& segment : segments) {
		if (!segment.first.empty()) {
			segments_[segment.first] = segment.second;
		}
	}
}

bool query_string::set(std::string_view const& raw, bool plus_is_space)
{
	segments_.clear();

	auto const tokens = strtok_view(raw, "&");
	for (auto const& token : tokens) {
		size_t pos = token.find('=');
		if (!pos) {
			segments_.clear();
			return false;
		}

		std::string key = percent_decode_s(token.substr(0, pos), false, plus_is_space);
		if (key.empty()) {
			segments_.clear();
			return false;
		}
		std::string value;
		if (pos != std::string::npos) {
			value = percent_decode_s(token.substr(pos + 1), false, plus_is_space);
			if (value.empty() && pos + 1 != token.size()) {
				segments_.clear();
				return false;
			}
		}
		segments_[key] = value;
	}

	return true;
}

std::string& query_string::operator[](std::string const& key)
{
	return segments_[key];
}

void query_string::remove(std::string const& key)
{
	auto it = segments_.find(key);
	if (it != segments_.end()) {
		segments_.erase(key);
	}
}

std::string query_string::to_string(bool encode_slashes) const
{
	std::string ret;
	if (!segments_.empty()) {
		for (auto const& segment : segments_) {
			ret += percent_encode(segment.first, !encode_slashes);
			ret += '=';
			ret += percent_encode(segment.second, !encode_slashes);
			ret += '&';
		}
		ret.pop_back();
	}
	return ret;
}

}
