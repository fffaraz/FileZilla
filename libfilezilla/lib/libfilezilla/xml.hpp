#ifndef LIBFILEZILLA_XML_HEADER
#define LIBFILEZILLA_XML_HEADER

/** \file
 * \brief Streaming XML parser, including a parser with namespace support.
 *
 * Also includes a pretty printer and associated logger for the processed XML.
 */

#include <functional>
#include <string>
#include <tuple>
#include <vector>

#include "buffer.hpp"
#include "logger.hpp"

namespace fz {

namespace xml {

/// Types of callbacks when parsing XML
enum class callback_event
{
	/// An element is opened, passed name
	open,

	/// An element is closed, passed name
	close,

	/// Attribute in name and value
	attribute,

	/// An element's value. name empty, full element in path.
	/// Element can have multiple values if they have child elements.
	value,

	/// Parsing instruction, includes the <?xml?> declaration. Until first space in name, rest in value.
	parsing_instruction,

	doctype,
};

/**
 * \brief A streaming XML parser
 *
 * Supports input data in UTF-8, UTF-16-BE and UTF-16-LE, detected
 * automatically.
 *
 * Can parse XML in chunks of any size, including bytewise in all supported
 * character sets.
 */
class FZ_PUBLIC_SYMBOL parser final
{
public:
	/**
	 * Callbacks return whether parsing should continue.
	 *
	 * \arg path is the full path of the parent element, which is formed
	 * by concatenating all parent elements' names, separated by <
	 */
	typedef std::function<bool(callback_event type, std::string_view path, std::string_view name, std::string && value)> callback_t;

	parser();
	parser(callback_t const& cb);
	parser(callback_t && cb);

	/// The passed callback function will be invoked for each event during the parse.
	/// Don't call any parser function from a callback.
	void set_callback(callback_t && cb);
	void set_callback(callback_t const& cb);

	/// Processes the block of data. Can be partial.
	bool parse(std::string_view data);

	/// After parsing all data, finalize the document to check that it
	/// is terminated properly.
	bool finalize();

	/// Returns an error description. Empty if parsing was stopped by a callback.
	std::string get_error() const;

	/// These limits are checked after processing a block of input data. They
	/// may be temporarily exceeded by the size of the last block of input data.
	void set_limits(size_t value_size_limit, size_t path_size_limit);

private:
	bool FZ_PRIVATE_SYMBOL decode_ref();
	bool FZ_PRIVATE_SYMBOL is_valid_tag_or_attr(std::string_view s) const;
	bool FZ_PRIVATE_SYMBOL normalize_value();

	bool FZ_PRIVATE_SYMBOL parse_valid_utf8(std::string_view data);
	bool FZ_PRIVATE_SYMBOL parse(char const* const begin, char const* const end);
	void FZ_PRIVATE_SYMBOL set_error(std::string_view msg, size_t offset);

	bool FZ_PRIVATE_SYMBOL deduce_encoding(std::string_view & data);

	enum class state {
		content,
		tag_start, // Just after reading <
		tag_name, // Reading tag name
		tag_closing, // In a closing tag, matching the tag name
		tag_end, // Just before reading >

		attributes,
		attribute_name,
		attribute_equal,
		attribute_quote,
		attribute_value,

		// <?xml and other parsing intructions
		pi,
		pi_value,

		// entity and character references
		reference,
		attrvalue_reference,

		comment_start,
		comment_end,

		doctype_start,
		doctype_name,
		doctype_value,

		cdata_start,
		cdata_end,

		done,
		error
	};

	callback_t cb_;

	std::string path_;
	std::vector<size_t> nodes_;
	std::string name_;
	std::string value_;
	size_t processed_{};
	std::string converted_{};

	size_t path_size_limit_{1024*1024};
	size_t value_size_limit_{10*1024*1024};

	union {
		size_t utf8_state_{};
		uint32_t utf16_state_;
	};

	state s_{ state::content };

	enum class encoding {
		unknown,
		utf8,
		utf16le,
		utf16be
	};
	encoding encoding_{};

	union {
		size_t tag_match_pos_{};
		char quotes_;
		unsigned char dashes_;
	};

	bool got_xmldecl_{};
	bool got_doctype_{};
	bool got_element_{};
};

/**
 * \brief A stremable XML parser that resolves namespace declarations
 * and namespace prefixes.
 *
 * Works like fz::xml::parser, but replaces namespace prefixes in element and
 * attribute names with the corresponding namespace name and applies default namespaces
 * to element names.
 *
 * Namespace delcarations are omitted from attribute callbacks.
 *
 * Limitation: Does not support more than 50 attributes per element.
 */
class FZ_PUBLIC_SYMBOL namespace_parser final
{
public:
	namespace_parser();
	namespace_parser(parser::callback_t const& cb);
	namespace_parser(parser::callback_t && cb);

	void set_callback(parser::callback_t && cb);
	void set_callback(parser::callback_t const& cb);

	bool parse(std::string_view data);
	bool finalize();

	std::string get_error() const;

	/// Additional raw callback to look at events before namespace processing takes place.
	typedef std::function<bool(callback_event type, std::string_view path, std::string_view name, std::string_view value)> raw_callback_t;
	void set_raw_callback(raw_callback_t && cb);
	void set_raw_callback(raw_callback_t const& cb);
private:
	std::string_view FZ_PRIVATE_SYMBOL apply_namespaces(std::string_view in);
	bool FZ_PRIVATE_SYMBOL apply_namespace_to_path();

	bool FZ_PRIVATE_SYMBOL on_callback(callback_event type, std::string_view path, std::string_view name, std::string && value);

	parser parser_;

	parser::callback_t cb_;
	raw_callback_t raw_cb_;

	std::string path_;
	fz::buffer applied_;
	std::vector<size_t> nodes_;
	std::vector<std::pair<std::string, std::string>> attributes_;
	std::vector<std::tuple<size_t, std::string, std::string>> namespaces_;
	bool needs_namespace_expansion_{};
	bool error_{};
};

/// A slow pretty printer for XML as it is being parsed.
class FZ_PUBLIC_SYMBOL pretty_printer
{
public:
	pretty_printer() = default;
	virtual ~pretty_printer();

	void log(callback_event type, std::string_view, std::string_view name, std::string_view value);

protected:
	virtual void on_line(std::string_view line) = 0;

private:
	void FZ_PRIVATE_SYMBOL finish_line();
	void FZ_PRIVATE_SYMBOL print_line();

	size_t depth_{};
	std::string value_;
	std::string line_;
};

/// Pretty-prints XML as it is being parsed to a logger.
class FZ_PUBLIC_SYMBOL pretty_logger final : public pretty_printer
{
public:
	pretty_logger(logger_interface & logger, logmsg::type level);

protected:
	virtual void on_line(std::string_view line) override;

	logmsg::type level_;
	logger_interface & logger_;
};


}
}

#endif
