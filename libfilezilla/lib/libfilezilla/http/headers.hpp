#ifndef LIBFILEZILLA_HTTP_HEADERS_HEADER
#define LIBFILEZILLA_HTTP_HEADERS_HEADER

/** \file
 * \brief Declares \ref fz::with_headers as base for HTTP requests/responses
 */

#include <map>
#include <optional>

#include "../string.hpp"

namespace fz {

class uri;

namespace http {

enum class continuation
{
	next,
	wait,
	done,
	error
};

typedef std::map<std::string, std::string, less_insensitive_ascii> headers;

class FZ_PUBLIC_SYMBOL with_headers
{
public:
	virtual ~with_headers();

	std::optional<uint64_t> get_content_length() const;

	/// Sets Content-Lenght. Also clears Transfer-Encoding
	void set_content_length(uint64_t l);

	/// Sets Transfer-Encoding to chunked. Also clears Content-Length
	void set_chunked_encoding();

	/// Whether chunked encoding is used
	bool chunked_encoding() const;

	void set_content_type(std::string content_type);

	std::string get_header(std::string const& key) const;

	bool keep_alive() const;

	headers headers_;
};

/// Canonicalizes the URI for use in the Host: header
std::string FZ_PUBLIC_SYMBOL get_canonical_host(uri const& uri);

}
}

#endif
