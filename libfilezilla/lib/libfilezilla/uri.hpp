#ifndef LIBFILEZILLA_URI_HEADER
#define LIBFILEZILLA_URI_HEADER

#include "libfilezilla.hpp"

#include <initializer_list>
#include <map>
#include <string>

/** \file
 * \brief Declares fz::uri for (de)composing URIs.
 */

namespace fz {

enum class uri_parsing_flags
{
	normal,

	/// If parsing a schemeless URI, assume it has an authority, otherwise it's all seen as path
	assume_authority
};

/**
 * \brief The uri class is used to decompose URIs into their individual components.
 *
 * Implements Uniform Resource Identifiers as described in RFC 3986
 */
class FZ_PUBLIC_SYMBOL uri final
{
public:
	uri() noexcept = default;
	explicit uri(std::string_view const& in, uri_parsing_flags flags = {});

	void clear();

	/**
	 * \brief Splits uri into components.
	 *
	 * Percent-decodes username, pass, host and path
	 * Does not decode query and fragment.
	 **/
	bool parse(std::string_view in, uri_parsing_flags flags = {});

	/**
	 * \brief Assembles components into string
	 *
	 * Percent-encodes username, pass, host and path
	 * Does not encode query and fragment.
	 */
	std::string to_string(bool with_query = true) const;

	/// \brief Returns path and query, separated by question mark.
	std::string get_request(bool with_query = true) const;

	/// \brief Returns [user[:pass]@]host[:port]
	std::string get_authority(bool with_userinfo) const;

	bool empty() const;
	explicit operator bool() const { return !empty(); }

	/// Often referred to as the protocol prefix, e.g. ftp://
	std::string scheme_;

	/// Optional user part of the authority
	std::string user_;

	/// Optional password part of the authority
	std::string pass_;

	/// Hostname, or IP address literal
	std::string host_;

	/// Optional Port if non-zero
	unsigned short port_{};

	/// Optional path, must start with a slash if set
	std::string path_;

	/**
	 * \brief The part of a URI after ? but before #
	 *
	 * The query string is not encoded when building the URI, neither is it decoded when parsing a URI.
	 *
	 * \sa \c fz::query_string
	 */
	std::string query_;

	/**
	 * \brief The part of a URI after #
	 *
	 * The fragment is not encoded when building the URI, neither is it decoded when parsing a URI.
	 */
	std::string fragment_;

	/// \brief Checks that the URI is absolute, that is the path starting with a slash.
	bool is_absolute() const { return path_[0] == '/'; }

	/**
	 * \brief Resolve a relative URI reference into an absolute URI given a base URL.
	 *
	 * If the URI is not relative or from a different scheme, it is not changed.
	 */
	void resolve(uri const& base);

	bool operator==(uri const& arg) const;

	bool operator!=(uri const& arg) const { return !(*this == arg); }

private:
	bool FZ_PRIVATE_SYMBOL parse_authority(std::string_view authority);
};

/**
 * \brief Class for parsing a URI's query string.
 *
 * Assumes the usual semantics of key-value pairs separated by ampersands.
 */
class FZ_PUBLIC_SYMBOL query_string final
{
public:
	explicit query_string() = default;
	explicit query_string(std::string_view const& raw, bool plus_is_space = false);
	explicit query_string(std::pair<std::string, std::string> const& segment);
	explicit query_string(std::initializer_list<std::pair<std::string, std::string>> const& segments);
	bool set(std::string_view const& raw, bool plus_is_space = false);

	std::string to_string(bool encode_slashes) const;

	void remove(std::string const& key);
	std::string& operator[](std::string const& key);

	std::map<std::string, std::string, less_insensitive_ascii> const& pairs() const { return segments_; }

	bool empty() const { return segments_.empty(); }

private:
	std::map<std::string, std::string, less_insensitive_ascii> segments_;
};

}

#endif
