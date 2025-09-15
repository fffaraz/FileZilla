#ifndef LIBFILEZILLA_AIO_XML_WRITER_HEADER
#define LIBFILEZILLA_AIO_XML_WRITER_HEADER

/** \file
 * \brief Special writers to directly forward data to an XML streaming parser
 */

#include "writer.hpp"
#include "../xml.hpp"

#include <optional>

namespace fz {
/// Forwards received data directly into an XML parser
class FZ_PUBLIC_SYMBOL xml_parser_writer final : public writer_base
{
public:
	xml_parser_writer(xml::parser::callback_t && cb, std::wstring const& name, aio_buffer_pool & pool, progress_cb_t && progress_cb = nullptr);

	void enable_pretty_log(logmsg::type t);

private:
	virtual aio_result FZ_PRIVATE_SYMBOL do_add_buffer(scoped_lock &, buffer_lease && b) override;
	virtual aio_result FZ_PRIVATE_SYMBOL do_finalize(scoped_lock &) override;

	xml::parser parser_;
	xml::parser::callback_t cb_;
	std::optional<xml::pretty_logger> logger_;
};

/// Similar to \sa xml_parser_writer, but with namespace support
class FZ_PUBLIC_SYMBOL xml_namespace_parser_writer final : public writer_base
{
public:
	xml_namespace_parser_writer(xml::parser::callback_t && cb, std::wstring const& name, aio_buffer_pool & pool, progress_cb_t && progress_cb = nullptr);

	void enable_pretty_log(logmsg::type t);

private:
	virtual aio_result FZ_PRIVATE_SYMBOL do_add_buffer(scoped_lock &, buffer_lease && b) override;
	virtual aio_result FZ_PRIVATE_SYMBOL do_finalize(scoped_lock &) override;

	xml::namespace_parser parser_;
	std::optional<xml::pretty_logger> logger_;
};
}

#endif
