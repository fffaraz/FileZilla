#include "../libfilezilla/aio/xml_writer.hpp"

namespace fz {

xml_parser_writer::xml_parser_writer(xml::parser::callback_t && cb, std::wstring const& name, aio_buffer_pool & pool, progress_cb_t && progress_cb)
	: writer_base(name, pool, std::move(progress_cb), 1)
	, cb_(std::move(cb))
{
	parser_.set_callback([this](xml::callback_event t, std::string_view path, std::string_view name, std::string && value) {
		if (logger_) {
			logger_->log(t, path, name, value);
		}
		return cb_ ? cb_(t, path, name, std::move(value)) : true;
	});
}

void xml_parser_writer::enable_pretty_log(logmsg::type t)
{
	logger_.emplace(buffer_pool_.logger(), t);
}

aio_result xml_parser_writer::do_add_buffer(scoped_lock &, buffer_lease && b)
{
	bool ret = parser_.parse(b->to_view());
	b.release();
	if (!ret) {
		auto error = parser_.get_error();
		if (!error.empty()) {
			buffer_pool_.logger().log(logmsg::error, "Could not parse XML: %s", error);
		}
		return aio_result::error;
	}
	return aio_result::ok;
}

aio_result xml_parser_writer::do_finalize(scoped_lock &)
{
	if (!parser_.finalize()) {
		auto error = parser_.get_error();
		if (!error.empty()) {
			buffer_pool_.logger().log(logmsg::error, "Could not parse XML: %s", error);
		}
		return aio_result::error;
	}
	return aio_result::ok;
}


xml_namespace_parser_writer::xml_namespace_parser_writer(xml::parser::callback_t && cb, std::wstring const& name, aio_buffer_pool & pool, progress_cb_t && progress_cb)
	: writer_base(name, pool, std::move(progress_cb), 1)
{
	parser_.set_callback(std::move(cb));
}

void xml_namespace_parser_writer::enable_pretty_log(logmsg::type t)
{
	logger_.emplace(buffer_pool_.logger(), t);
	parser_.set_raw_callback([this](xml::callback_event t, std::string_view path, std::string_view name, std::string_view value) { logger_->log(t, path, name, value); return true; });
}

aio_result xml_namespace_parser_writer::do_add_buffer(scoped_lock &, buffer_lease && b)
{
	bool ret = parser_.parse(b->to_view());
	b.release();
	if (!ret) {
		auto error = parser_.get_error();
		if (!error.empty()) {
			buffer_pool_.logger().log(logmsg::error, "Could not parse XML: %s", error);
		}
		return aio_result::error;
	}
	return aio_result::ok;
}

aio_result xml_namespace_parser_writer::do_finalize(scoped_lock &)
{
	if (!parser_.finalize()) {
		auto error = parser_.get_error();
		if (!error.empty()) {
			buffer_pool_.logger().log(logmsg::error, "Could not parse XML: %s", error);
		}
		return aio_result::error;
	}
	return aio_result::ok;}

}
