#include "../libfilezilla/http/headers.hpp"
#include "../libfilezilla/uri.hpp"

using namespace std::literals;

namespace fz::http {

with_headers::~with_headers()
{
}

std::optional<uint64_t> with_headers::get_content_length() const
{
	auto it = headers_.find("Content-Length"s);
	if (it == headers_.end()) {
		return {};
	}

	return to_integral_o<uint64_t>(it->second);
}

void with_headers::set_content_length(uint64_t l)
{
	headers_["Content-Length"s] = fz::to_string(l);
	headers_.erase("Transfer-Encoding"s);
}

void with_headers::set_chunked_encoding()
{
	headers_["Transfer-Encoding"s] = "chunked";
	headers_.erase("Content-Length"s);
}

bool with_headers::chunked_encoding() const
{
	auto it = headers_.find("Transfer-Encoding"s);
	if (it == headers_.end()) {
		return false;
	}
	return fz::equal_insensitive_ascii(it->second, "chunked"s);
}

void with_headers::set_content_type(std::string content_type)
{
	if (content_type.empty()) {
		headers_.erase("Content-Type"s);
	}
	else {
		headers_["Content-Type"s] = std::move(content_type);
	}
}


std::string with_headers::get_header(std::string const& key) const
{
	auto it = headers_.find(key);
	if (it != headers_.end()) {
		return it->second;
	}
	return std::string();
}

bool with_headers::keep_alive() const
{
	auto it = headers_.find("Connection");
	if (it != headers_.end()) {
		auto tokens = strtok_view(it->second, ", "sv);
		for (auto const& token : tokens) {
			if (equal_insensitive_ascii(token, "close"sv)) {
				return false;
			}
		}
	}

	return true;
}

std::string get_canonical_host(uri const& u)
{
	if (u.port_ == 0) {
		return u.host_;
	}
	else if (u.port_ == 443 && equal_insensitive_ascii(u.scheme_, "https")) {
		return u.host_;
	}
	else if (u.port_ == 80 && equal_insensitive_ascii(u.scheme_, "http")) {
		return u.host_;
	}

	return u.host_ + ":" + fz::to_string(u.port_);
}

}
