#include "../fzssh/sftp/sftp_client.hpp"
#include "../fzssh/ssh.hpp"

#include "../buffer_util.hpp"

#include "../sftp.hpp"

#include <libfilezilla/logger.hpp>

using namespace std::literals;

namespace fz::ssh::sftp {

using fz::ssh::extract_uint32;
using fz::ssh::extract_uint64;
using fz::ssh::extract_string;

namespace {
size_t constexpr max_in_payload_size{256*1024};
}

class sftp_client_impl final : public sftp_base
{
public:
	sftp_client_impl(std::unique_ptr<socket_interface> && channel, event_handler & handler, logger_interface & logger, sftp_client* c);

	virtual ~sftp_client_impl();

	virtual void stop(bool send_done) override;
	void unblock_read();

private:
	friend class sftp_client;

	sftp_client* const c_{};

	struct dequeue_on_unblock_read_event_type;
	typedef simple_event<dequeue_on_unblock_read_event_type> dequeue_on_unblock_read_event;
	void on_dequeue_on_unblock_read_event();

	virtual void operator()(event_base const & ev) override;
	virtual void on_connect() override;
	virtual void on_can_send_packets() override;

	virtual continuation process_packet(message_type type, uint32_t id, std::string_view data) override;
	continuation process_packet(response_handler* handler, message_type request_type, message_type response_type, std::string_view data);

	continuation process_version(std::string_view data);
	continuation process_handle(response_handler* handler, std::string_view data);
	continuation process_data(response_handler* handler, std::string_view data);
	continuation process_status(response_handler* handler, std::string_view data);
	continuation process_names(response_handler* handler, message_type request_type, std::string_view data);
	continuation process_attributes(response_handler* handler, std::string_view data);

	continuation process_pending_responses();

	uint32_t next_id_{};

	struct pending
	{
		pending(uint32_t id, message_type type, response_handler* handler)
			: id_(id)
			, request_type_(type)
			, handler_(handler)
		{}

		uint32_t id_{};
		message_type request_type_{};
		message_type response_type_{};
		response_handler* handler_{};
		std::string data_;
	};

	std::deque<pending> pending_;

	event_handler* waiting_for_on_can_send_{};
	bool is_retrying_process_in_queue_{};

	friend class request_builder;
};


class request_builder
{
public:
	request_builder(sftp_client_impl & s, response_handler* handler, message_type type, std::string_view const& description = {});
	request_builder(sftp_client_impl & s, message_type type, std::string_view const& description = {});
	~request_builder();


	request_builder(request_builder const&) = delete;

	buffer& buf_;

private:
	sftp_client_impl & s_;
	response_handler* const handler_{};
	message_type const type_;
	size_t old_size_{};
};

request_builder::request_builder(sftp_client_impl & s, response_handler* handler, message_type type, std::string_view const& description)
	: buf_(s.outbuf_)
	, s_(s)
	, handler_(handler)
	, type_(type)
	, old_size_(buf_.size())
{
	if (description.empty()) {
		s_.logger_.log(logmsg::debug_info, "Sending %s"sv, to_string(type));
	}
	else {
		s_.logger_.log(logmsg::debug_info, "Sending %s (%s)"sv, to_string(type), description);
	}
	buf_.append(4, 0);
	buf_.append(static_cast<uint8_t>(type));
	write_uint32(buf_, ++s_.next_id_);
}

request_builder::request_builder(sftp_client_impl & s, message_type type, std::string_view const& description)
	: buf_(s.outbuf_)
	, s_(s)
	, type_(type)
	, old_size_(buf_.size())
{
	if (description.empty()) {
		s_.logger_.log(logmsg::debug_info, "Sending %s"sv, to_string(type));
	}
	else {
		s_.logger_.log(logmsg::debug_info, "Sending %s (%s)"sv, to_string(type), description);
	}
	buf_.append(4, 0);
	buf_.append(static_cast<uint8_t>(type));
}

request_builder::~request_builder()
{
	size_t const payload_size = buf_.size() - old_size_ - 4;

	if (payload_size > max_out_payload_size) {
		buf_.resize(old_size_);
		s_.logger_.log(logmsg::error, "Payload size %u exceeds max payload size %u", payload_size, max_out_payload_size);
	}

	write_uint32(buf_.get() + old_size_, payload_size);

	if (!old_size_ && !s_.wait_write_) {
		s_.do_send();
	}

	if (type_ != message_type::SSH_FXP_INIT) {
		s_.pending_.emplace_back(s_.next_id_, type_, handler_);
	}
}

namespace {
bool is_allowed_response(message_type cmd, message_type response)
{
	if (response == message_type::SSH_FXP_STATUS) {
		return true;
	}
	switch (cmd) {
	case message_type::SSH_FXP_REALPATH:
	case message_type::SSH_FXP_READDIR:
		return response == message_type::SSH_FXP_NAME;
	case message_type::SSH_FXP_OPENDIR:
	case message_type::SSH_FXP_OPEN:
		return response == message_type::SSH_FXP_HANDLE;
	case message_type::SSH_FXP_READ:
		return response == message_type::SSH_FXP_DATA;
	case message_type::SSH_FXP_FSTAT:
	case message_type::SSH_FXP_STAT:
		return response == message_type::SSH_FXP_ATTRS;
	default:
		break;
	}

	return false;
}
}

sftp_client_impl::sftp_client_impl(std::unique_ptr<socket_interface> && channel, event_handler & handler, logger_interface & logger, sftp_client* c)
	: sftp_base(std::move(channel), handler, logger, max_in_payload_size, true)
	, c_(c)
{
}

sftp_client_impl::~sftp_client_impl()
{
	stop(false);
}

void sftp_client_impl::stop(bool send_done)
{
	remove_handler();

	auto event_filter = [&](event_handler* /*h*/, event_base& ev) -> bool {
		if (ev.derived_type() == outbuf_empty_event::type()) {
			return std::get<0>(static_cast<outbuf_empty_event const&>(ev).v_) == c_;
		}
		else if (ev.derived_type() == sftp_client::ready_event::type()) {
			return std::get<0>(static_cast<sftp_client::ready_event const&>(ev).v_) == c_;
		}
		return false;
	};
	event_loop_.filter_events(event_filter);

	if (send_done && socket_) {
		event_handler_.send_event<sftp_client::done_event>(c_);
	}
	disconnecting_ = true;
	socket_.reset();
}

void sftp_client_impl::unblock_read()
{
	if (wait_read_) {
		if (!pending_.empty() && pending_.front().response_type_ != message_type::none) {
			send_event<dequeue_on_unblock_read_event>();
			return;
		}

		sftp_base::unblock_read();
	}
}

void sftp_client_impl::on_dequeue_on_unblock_read_event()
{
	is_retrying_process_ = is_retrying_process_in_queue_;
	is_retrying_process_in_queue_ = false;

	auto c = process_pending_responses();

	is_retrying_process_ = false;

	if (c == continuation::next) {
		sftp_base::unblock_read();
		return;
	}

	if (c == continuation::error) {
		stop(true);
		return;
	}

	// Else, keep waiting.
}

void sftp_client_impl::operator()(const event_base &ev)
{
	if (dispatch<dequeue_on_unblock_read_event>(ev, this, &sftp_client_impl::on_dequeue_on_unblock_read_event)) {
		return;
	}
	sftp_base::operator()(ev);
}

void sftp_client_impl::on_connect()
{
	if (!peer_version_) {
		request_builder b(*this, message_type::SSH_FXP_INIT);
		write_uint32(b.buf_, 3);
	}
	sftp_base::on_connect();
}

continuation sftp_client_impl::process_packet(message_type type, uint32_t id, std::string_view data)
{
	if (type == message_type::SSH_FXP_VERSION) {
		if (peer_version_) {
			logger_.log(logmsg::error, "Got SSH_FXP_VERSION multiple times"sv);
			return continuation::error;
		}
		else {
			return process_version(data);
		}
	}
	else if (!peer_version_) {
		logger_.log(logmsg::error, "Got a different packet prior to SSH_FXP_VERSION"sv);
		return continuation::error;
	}

	if (type == message_type::SSH_FXP_INIT) {
		logger_.log(logmsg::error, "Got SSH_FXP_INIT from server"sv);
		return continuation::error;
	}

	// Re-order responses to match request order

	if (pending_.empty()) {
		logger_.log(logmsg::error, "Got a response of type %u despite there being no pending reuqest"sv, type);
		return continuation::error;
	}
	size_t i = 0;
	for (; i < pending_.size(); ++i) {
		if (pending_[i].id_ == id) {
			break;
		}
	}
	if (i == pending_.size()) {
		logger_.log(logmsg::error, "Got response without matching request"sv);
		return continuation::error;
	}

	pending& p = pending_[i];
	if (!p.data_.empty()) {
		logger_.log(logmsg::error, "Got two responses for the same packet "sv);
		return continuation::error;
	}
	if (!is_allowed_response(p.request_type_, type)) {
		logger_.log(logmsg::error, "Got response not matching request type"sv);
		return continuation::error;
	}

	if (!i) {
		response_handler* handler = p.handler_;
		message_type req_type = p.request_type_;
		pending_.pop_front();
		if (handler) {
			auto ret = process_packet(handler, req_type, type, data);
			if (ret == continuation::wait_and_retry) {
				pending_.emplace_front(id, req_type, handler);
			}
			if (ret != continuation::next) {
				return ret;
			}
		}
		auto ret = process_pending_responses();
		if (ret == continuation::wait_and_retry) {
			// The original packet process_packet has been called with got
			// processed already, hence convert wait_and_retry into wait
			// so that the buffer gets properly consumed.
			ret = continuation::wait;
		}
		return ret;
	}
	else {
		p.data_ = data;
		p.response_type_ = type;
		return continuation::next;
	}

}

continuation sftp_client_impl::process_packet(response_handler* handler, message_type request_type, message_type response_type, std::string_view data)
{
	switch (response_type) {
	case message_type::SSH_FXP_HANDLE:
		return process_handle(handler, data);
	case message_type::SSH_FXP_DATA:
		return process_data(handler, data);
	case message_type::SSH_FXP_STATUS:
		return process_status(handler, data);
	case message_type::SSH_FXP_NAME:
		return process_names(handler, request_type, data);
	case message_type::SSH_FXP_ATTRS:
		return process_attributes(handler, data);
	default:
		logger_.log(logmsg::error, "Internal error, cannot process packet of type %u"sv, request_type);
		return continuation::error;
	}
}

continuation sftp_client_impl::process_names(response_handler* handler, message_type request_type, std::string_view data)
{
	uint32_t count;
	if (!extract_uint32(data, count)) {
		logger_.log(logmsg::error, "Could not extract count of names from received SSH_FXP_NAME packet"sv);
		return handler->failure();
	}

	if (count > data.size() / 12) {
		logger_.log(logmsg::error, "Nonsensical name count in received SSH_FXP_NAME packet"sv);
		return handler->failure();
	}

	if (request_type == message_type::SSH_FXP_REALPATH && count != 1) {
		logger_.log(logmsg::error, "Received a SSH_FXP_NAME packet with a name count different from 1 in a reply to a SSH_FXP_REALPATH packet"sv);
		return handler->failure();
	}

	for (size_t i = 0; i < count; ++i) {
		entry e;
		auto name = extract_string(data, string_type::text, false);
		if (!name) {
			logger_.log(fz::logmsg::error, "Could not extract name %u from received SSH_FXP_NAME packet: %s"sv, i, *name);
			return handler->failure();
		}
		e.name_ = *name;

		auto longname = extract_string(data, string_type::text, true);
		if (!longname) {
			logger_.log(fz::logmsg::error, "Could not extract longname %u from received SSH_FXP_NAME packet: %s"sv, i, *longname);
			return handler->failure();
		}
		e.longname_ = *longname;

		auto attrs = extract_attributes(data, logger_);
		if (!attrs) {
			return handler->failure();
		}
		static_cast<attributes&>(e) = *attrs;

		auto ret = handler->process_name(e, i != count - 1);
		if (ret != continuation::next) {
			return ret;
		}
	}

	return continuation::next;
}

continuation sftp_client_impl::process_attributes(response_handler* handler, std::string_view data)
{
	auto attrs = extract_attributes(data, logger_);
	if (!attrs) {
		return handler->failure();
	}

	return handler->process_attributes(*attrs);
}

continuation sftp_client_impl::process_pending_responses()
{
	auto ret = continuation::next;

	while (ret == continuation::next && !pending_.empty()) {
		if (pending_.front().response_type_ == message_type::none) {
			break;
		}

		auto p = std::move(pending_.front());
		pending_.pop_front();

		if (!p.handler_) {
			is_retrying_process_ = false;
			continue;
		}

		ret = process_packet(p.handler_, p.request_type_, p.response_type_, p.data_);
		is_retrying_process_ = false;
		if (ret == continuation::wait_and_retry) {
			is_retrying_process_in_queue_ = true;
			pending_.push_front(std::move(p));
		}
	}

	return ret;
}

continuation sftp_client_impl::process_version(std::string_view data)
{
	if (!extract_uint32(data, peer_version_)) {
		logger_.log(logmsg::error, "Could not read peer SFTP version"sv);
		return continuation::error;
	}
	if (peer_version_ != 3) {
		logger_.log(logmsg::error, "Unsupported peer SFTP version %u"sv, peer_version_);
		return continuation::error;
	}
	logger_.log(logmsg::debug_info, "Peer SFTP version is %u"sv, peer_version_);

	while (!data.empty()) {
		auto name = extract_string(data, string_type::ascii, false);
		auto extdata = extract_string(data, string_type::blob, true);
		if (!name || !extdata) {
			logger_.log(logmsg::error, "Could not extract SFTP extension data"sv);
			return continuation::error;
		}
		logger_.log(logmsg::debug_info, "Peer SFTP supports extension %s", *name);
	}

	event_handler_.send_event<sftp_client::ready_event>(c_);
	return continuation::next;
}

continuation sftp_client_impl::process_handle(response_handler* handler, std::string_view data)
{
	auto h = extract_blob(data);
	if (!h || h->size() > 256) {
		logger_.log(logmsg::error, "Could not extract handle"sv);
		return handler->failure();
	}

	logger_.log(logmsg::debug_info, "Handle is %s", fz::hex_encode<std::string>(*h));
	return handler->process_handle(*h);
}

continuation sftp_client_impl::process_data(response_handler* handler, std::string_view data)
{
	auto d = extract_string(data, string_type::blob, true);
	if (!d) {
		logger_.log(logmsg::error, "Could not extract data"sv);
		return handler->failure();
	}
	return handler->process_data(*d);
}

continuation sftp_client_impl::process_status(response_handler* handler, std::string_view data)
{
	uint32_t rawcode{};
	extract_uint32(data, rawcode);
	if (rawcode > static_cast<size_t>(status_code::MAX)) {
		logger_.log(logmsg::error, "Could not extract status"sv);
		return handler->failure();
	}

	auto code = static_cast<status_code>(rawcode);

	auto s = extract_string(data, string_type::utf8, true);
	if (!s) {
		logger_.log(logmsg::error, "Could not extract description"sv);
		return handler->failure();
	}

	if (!s->empty()) {
		logger_.log(code == status_code::SSH_FX_OK ? logmsg::debug_info : logmsg::debug_warning, "Got status %s: %s"sv, to_string(code), *s);
	}
	else {
		logger_.log(code == status_code::SSH_FX_OK ? logmsg::debug_info : logmsg::debug_warning, "Got status %s"sv, to_string(code));
	}

	return handler->process_status(code, *s);
}

void sftp_client_impl::on_can_send_packets()
{
	if (waiting_for_on_can_send_) {
		waiting_for_on_can_send_->send_event<outbuf_empty_event>(c_);
		waiting_for_on_can_send_ = nullptr;
	}
}

bool sftp_client::can_send_packets(event_handler & waiter)
{
	bool ret = impl_->can_send_packets(true);
	if (!ret) {
		impl_->waiting_for_on_can_send_ = &waiter;
	}
	return ret;
}


// sftp_client

sftp_client::sftp_client(std::unique_ptr<socket_interface> && channel, event_handler & h, logger_interface & logger)
	: impl_(std::make_unique<sftp_client_impl>(std::move(channel), h, logger, this))
{
}

sftp_client::~sftp_client()
{
	if (impl_) {
		if (impl_->pending_.empty()) {
			impl_->disconnect();
		}
		impl_->stop(false);

		auto event_filter = [&](event_handler* /*h*/, event_base& ev) -> bool {
			if (ev.derived_type() == sftp_client::done_event::type()) {
				return std::get<0>(static_cast<sftp_client::done_event const&>(ev).v_) == this;
			}
			return false;
		};
		impl_->event_loop_.filter_events(event_filter);
	}
}

void sftp_client::unblock_read()
{
	return impl_->unblock_read();
}

bool sftp_client::is_retrying_process()
{
	return impl_->is_retrying_process();
}

bool sftp_client::can_send_packets()
{
	return impl_->can_send_packets();
}

void sftp_client::cancel_wait(event_handler* handler)
{
	if (impl_->waiting_for_on_can_send_ == handler) {
		auto event_filter = [&](event_base& ev) -> bool {
			if (ev.derived_type() == outbuf_empty_event::type()) {
				return std::get<0>(static_cast<outbuf_empty_event const&>(ev).v_) == this;
			}
			return false;
		};
		handler->filter_events(event_filter);
		impl_->waiting_for_on_can_send_ = nullptr;
	}
}

size_t sftp_client::pending_requests()
{
	return impl_->pending_.size();
}

void sftp_client::cancel(response_handler* handler)
{
	for (auto & p : impl_->pending_) {
		if (p.handler_ == handler) {
			p.handler_ = nullptr;
		}
	}
}

void sftp_client::realpath(response_handler* handler, std::string_view name)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_REALPATH, name);
	write_string(b.buf_, name);
}

void sftp_client::close(response_handler* handler, std::string_view handle)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_CLOSE);
	write_string(b.buf_, handle);
}

void sftp_client::opendir(response_handler* handler, std::string_view name)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_OPENDIR);
	write_string(b.buf_, name);
}

void sftp_client::readdir(response_handler* handler, std::string_view handle)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_READDIR);
	write_string(b.buf_, handle);
}

void sftp_client::open(response_handler* handler, std::string_view name, file_flags flags, std::optional<attributes> const& initial_attributes)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_OPEN);
	write_string(b.buf_, name);
	write_uint32(b.buf_, static_cast<uint32_t>(flags));

	if (initial_attributes) {
		write_attributes(b.buf_, *initial_attributes);
	}
	else {
		write_uint32(b.buf_, 0);
	}
}

void sftp_client::read(response_handler* handler, std::string_view handle, uint64_t offset, uint32_t size)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_READ);
	write_string(b.buf_, handle);
	write_uint64(b.buf_, offset);
	write_uint32(b.buf_, size);
}

void sftp_client::write(response_handler* handler, std::string_view handle, uint64_t offset, std::string_view data)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_WRITE);
	write_string(b.buf_, handle);
	write_uint64(b.buf_, offset);
	write_string(b.buf_, data);
}

void sftp_client::stat(response_handler* handler, std::string_view name)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_STAT);
	write_string(b.buf_, name);
}

void sftp_client::fstat(response_handler* handler, std::string_view handle)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_FSTAT);
	write_string(b.buf_, handle);
}

void sftp_client::setstat(response_handler* handler, std::string_view name, attributes const& attrs)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_SETSTAT);
	write_string(b.buf_, name);
	write_attributes(b.buf_, attrs);
}

void sftp_client::fsetstat(response_handler* handler, std::string_view handle, attributes const& attrs)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_FSETSTAT);
	write_string(b.buf_, handle);
	write_attributes(b.buf_, attrs);
}

void sftp_client::remove(response_handler* handler, std::string_view name)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_REMOVE);
	write_string(b.buf_, name);
}

void sftp_client::rename(response_handler* handler, std::string_view oldname, std::string_view newname)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_RENAME);
	write_string(b.buf_, oldname);
	write_string(b.buf_, newname);
}

void sftp_client::mkdir(response_handler* handler, std::string_view name, attributes const& attrs)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_MKDIR);
	write_string(b.buf_, name);
	write_attributes(b.buf_, attrs);
}

void sftp_client::rmdir(response_handler* handler, std::string_view name)
{
	if (impl_->disconnecting_) {
		return;
	}
	request_builder b(*impl_, handler, message_type::SSH_FXP_RMDIR);
	write_string(b.buf_, name);
}

void sftp_client::disconnect()
{
	impl_->disconnect();
}

}
