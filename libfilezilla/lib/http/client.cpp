#include "../libfilezilla/http/client.hpp"
#include "../libfilezilla/event_handler.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/socket.hpp"
#include "../libfilezilla/translate.hpp"

#include "throttler.hpp"

#include <cstring>

using namespace std::literals;

namespace fz::http::client {

class client::impl final : public event_handler
{
public:
	impl(client & c, aio_buffer_pool * buffer_pool, event_handler & handler, logger_interface & logger, std::string && user_agent);

	virtual ~impl();

	bool add_request(shared_request_response const& srr);
	void next();
	void stop(bool send_done, bool keep_alive);

private:
	void destroy_socket();

	virtual void operator()(event_base const& ev) override;
	void on_buffer_availability(aio_waitable const* w);
	void on_timer(timer_id);
	void on_socket_event(fz::socket_event_source*, fz::socket_event_flag type, int error);
	void send_loop();
	void read_loop();

	continuation on_send();
	continuation on_read();

	client & client_;
	event_handler & handler_;
	aio_buffer_pool * buffer_pool_{};
	logger_interface & logger_;

	fz::buffer send_buffer_;

	continuation parse_header();
	continuation process_complete_header();
	continuation finalize_response();
	continuation process_receive_buffer_for_response_body();
	continuation read_response_body();
	continuation prepare_response_body_buffer();
	continuation parse_chunk_header();

	bool waiting_for_read_{true};
	bool waiting_for_send_{};
	bool wait_for_response_before_send_{};

	// The state of sending requests_[send_pos_]
	enum class request_send_state
	{
		none = 0,
		header,
		pre_body,
		body,
		finalizing
	};
	request_send_state request_send_state_{};

	std::deque<shared_request_response> requests_;
	fz::buffer_lease body_buffer_;
	std::optional<uint64_t> dataToSend_{};

	size_t send_pos_{};


	enum transferEncodings
	{
		identity,
		chunked,
		none
	};

	fz::buffer recv_buffer_;
	struct read_state
	{
		transferEncodings transfer_encoding_{identity};

		std::optional<uint64_t> responseContentLength_{};

		fz::buffer_lease writer_buffer_;

		bool more_{true};

		enum class state {
			header,
			on_header,
			body,
			chunk_header,
			chunk_trailer,
			finalizing
		};
		state state_{state::header};

		bool keep_alive_{};
		bool eof_{};
	};
	read_state read_state_;

#if FZ_WINDOWS
	timer_id buffer_tuning_timer_{};
#endif

	std::string canonical_host_;
	socket_interface* socket_{};

	std::string agent_;

	uint64_t request_id_counter_{};

	static request_throttler throttler_;
	timer_id throttle_timer_{};
};

request_throttler client::impl::throttler_;


client::client(event_handler & handler, aio_buffer_pool & buffer_pool, logger_interface & logger, std::string user_agent)
	: impl_(std::make_unique<impl>(*this, &buffer_pool, handler, logger, std::move(user_agent)))
{
}

client::client(event_handler & handler, logger_interface & logger, std::string user_agent)
	: impl_(std::make_unique<impl>(*this, nullptr, handler, logger, std::move(user_agent)))
{
}

client::~client()
{
	if (impl_) {
		impl_->stop(false, false);
	}
}


bool client::add_request(shared_request_response const& srr)
{
	return impl_ && impl_->add_request(srr);
}

void client::stop(bool keep_alive)
{
	if (impl_) {
		impl_->stop(false, keep_alive);
	}
}

void client::destroy()
{
	if (impl_) {
		impl_->remove_handler();
		impl_->stop(false, false);
	}
}

client::impl::impl(client & c, aio_buffer_pool * buffer_pool, event_handler & handler, logger_interface & logger, std::string && user_agent)
	: event_handler(handler.event_loop_)
	, client_(c)
	, handler_(handler)
	, buffer_pool_(buffer_pool)
	, logger_(logger)
	, agent_(std::move(user_agent))
{
}

client::impl::~impl()
{
	remove_handler();
}

void client::impl::stop(bool send_done, bool keep_alive)
{
	if (!requests_.empty() || read_state_.eof_) {
		keep_alive = false;
	}

	for (auto & srr : requests_) {
		if (srr) {
			if (srr->req().body_) {
				srr->req().body_->remove_waiter(*this);
			}
			if (send_done) {
				handler_.send_event<done_event>(srr->request_id_, false);
			}
		}
	}
	if (!requests_.empty() && requests_.front() && requests_.front()->res().writer_) {
		requests_.front()->res().writer_->remove_waiter(*this);
	}
	if (buffer_pool_) {
		buffer_pool_->remove_waiter(*this);
	}

	if (!socket_ && waiting_for_send_) {
		waiting_for_send_ = false;
		remove_socket_events(this, nullptr);
	}

	if (!keep_alive) {
		destroy_socket();
	}

	stop_timer(throttle_timer_);
	throttle_timer_ = 0;
	requests_.clear();
	send_pos_ = 0;
	request_send_state_ = request_send_state::none;
	wait_for_response_before_send_ = false;
	read_state_ = read_state();
}

bool client::impl::add_request(shared_request_response const& srr)
{
	logger_.log(logmsg::debug_verbose, "Adding a request"sv);
	if (!srr) {
		return false;
	}

	auto & req = srr->req();
	if (req.uri_.host_.empty()) {
		logger_.log(logmsg::error, fztranslate("Request has no host"));
		return false;
	}
	if (!is_valid_utf8(req.uri_.host_)) {
		logger_.log(logmsg::error, fztranslate("Hostname not in UTF-8"));
		return false;
	}
	if (!is_valid_utf8(req.uri_.path_)) {
		logger_.log(logmsg::error, fztranslate("Path not in UTF-8"));
		return false;
	}
	if (req.uri_.path_.empty()) {
		req.uri_.path_ = "/";
	}
	if (req.verb_.empty()) {
		req.verb_ = "GET";
	}

	if (send_pos_ >= requests_.size() && !wait_for_response_before_send_) {
		if (!waiting_for_send_) {
			waiting_for_send_ = true;
			send_event<socket_event>(socket_, fz::socket_event_flag::write, 0);
		}
		if (requests_.empty() && !waiting_for_read_) {
			waiting_for_read_ = true;
			send_event<socket_event>(socket_, fz::socket_event_flag::read, 0);
		}
	}

	srr->request_id_ = ++request_id_counter_;
	srr->res().flags_ = 0;
	requests_.push_back(srr);
	return true;
}

continuation client::impl::on_send()
{
	if (wait_for_response_before_send_) {
		return continuation::wait;
	}

	if (send_pos_ >= requests_.size()) {
		return continuation::done;
	}

	auto & srr = requests_[send_pos_];
	if (!srr) {
		logger_.log(logmsg::debug_warning, "Null request in request_send state."sv);
		return continuation::error;
	}

	auto & rr = *srr;
	auto & req = rr.req();

	if (request_send_state_ == request_send_state::none) {
		logger_.log(logmsg::debug_verbose, "Starting request processing");

		// Check backoff
		fz::duration backoff = throttler_.get_throttle(req.uri_.host_);
		if (backoff) {
			if (backoff >= fz::duration::from_seconds(10)) {
				logger_.log(logmsg::status, fztranslate("Server instructed client to wait %d seconds before sending next request"), backoff.get_seconds());
			}
			waiting_for_send_ = true;
			throttle_timer_ = add_timer(backoff, true);
			return continuation::wait;
		}

		if (!req.reset()) {
			return continuation::error;
		}

		if (!rr.res().reset()) {
			return continuation::error;
		}

		if (req.verb_.empty()) {
			logger_.log(logmsg::debug_warning, "No request verb"sv);
			return continuation::error;
		}

		auto canonical_host = get_canonical_host(req.uri_);
		req.headers_["Host"] = canonical_host;
		auto pos = req.headers_.find("Connection");
		if (pos == req.headers_.end()) {
			// TODO: consider making keep-alive the default
			req.headers_["Connection"] = "close";
		}
		req.headers_["User-Agent"] = agent_;

		if (socket_ && canonical_host_ == canonical_host) {
			request_send_state_ = request_send_state::header;
			logger_.log(logmsg::debug_verbose, "Re-using existing connection."sv);
			return continuation::next;
		}

		if (send_pos_) {
			wait_for_response_before_send_ = true;
			logger_.log(logmsg::debug_info, "Next request has different host. Need to wait for response to finish before continuing with next request.");
			return continuation::next;
		}

		request_send_state_ = request_send_state::header;
		canonical_host_ = std::move(canonical_host);

		logger_.log(logmsg::debug_verbose, "Creating socket interface for connecting to %s"sv, canonical_host_);

		bool https = equal_insensitive_ascii(req.uri_.scheme_, "https");
		unsigned short port = req.uri_.port_ ? req.uri_.port_ : (https ? 443 : 80);

		auto const host = to_native_from_utf8(req.uri_.host_);
		socket_ = client_.create_socket(host, port, https);
		if (!socket_) {
			logger_.log(logmsg::error, fztranslate("Could not connect to '%s'"), req.uri_.host_);
			return continuation::error;
		}
		socket_->set_event_handler(this);

		auto af = address_type::unknown;
		if (req.flags_ & request::flag_force_ipv6) {
			af = address_type::ipv6;
		}
		else if (req.flags_ & request::flag_force_ipv4) {
			af = address_type::ipv4;
		}

		if (socket_->connect(host, port, af)) {
			logger_.log(logmsg::error, fztranslate("Could not connect to '%s'"), req.uri_.host_);
			return continuation::error;
		}

		auto root = dynamic_cast<fz::socket*>(socket_->root());
		if (root) {
			root->set_flags(fz::socket::flag_nodelay, true);
		}

		waiting_for_send_ = true;
		return continuation::wait;
	}

	while (!send_buffer_.empty()) {
		int error{};
		int written = socket_->write(send_buffer_.get(), send_buffer_.size(), error);
		if (written < 0) {
			if (error != EAGAIN) {
				logger_.log(logmsg::error, fztranslate("Could not write to socket: %s"), fz::socket_error_description(error));
				return continuation::error;
			}
			waiting_for_send_ = true;
			return continuation::wait;
		}
		else {
			client_.on_alive();
			send_buffer_.consume(static_cast<size_t>(written));
		}
	}

	if (request_send_state_ == request_send_state::header) {
		dataToSend_ = req.update_content_length_from_body();

		// Assemble request and headers
		std::string request_line = fz::sprintf("%s %s HTTP/1.1"sv, req.verb_, req.uri_.get_request());
		send_buffer_.append(request_line);
		if (req.flags_ & request::flag_confidential_path) {
			logger_.log(logmsg::command, "%s <confidential> HTTP/1.1"sv, req.verb_);
		}
		else if (req.flags_ & request::flag_confidential_querystring) {
			logger_.log(logmsg::command, "%s %s HTTP/1.1"sv, req.verb_, req.uri_.get_request(false));
		}
		else {
			logger_.log(logmsg::command, "%s"sv, request_line);
		}
		send_buffer_.append("\r\n"sv);

		for (auto const& header : req.headers_) {
			std::string line = fz::sprintf("%s: %s"sv, header.first, header.second);
			if (header.first == "Authorization") {
				logger_.log(logmsg::command, "%s: %s"sv, header.first, std::string(header.second.size(), '*'));
			}
			else {
				logger_.log(logmsg::command, "%s"sv, line);
			}
			send_buffer_.append(line);
			send_buffer_.append("\r\n"sv);
		}

		send_buffer_.append("\r\n"sv);
		request_send_state_ = request_send_state::pre_body;

		return continuation::next;
	}
	else if (request_send_state_ == request_send_state::pre_body) {
		if (!req.body_) {
			logger_.log(logmsg::debug_info, "Finished sending request header. Request has no body"sv);
			request_send_state_ = request_send_state::finalizing;
			return continuation::next;
		}
		request_send_state_ = request_send_state::body;

		logger_.log(logmsg::debug_info, "Finished sending request header.");

		// Enable Nagle's algorithm if we have a beefy body
		if (req.body_->size() > 536) { // TCPv4 minimum required MSS
			auto root = dynamic_cast<fz::socket*>(socket_->root());
			if (root) {
				root->set_flags(fz::socket::flag_nodelay, false);
			}
		}
#if FZ_WINDOWS
		// TCP send buffer autotuning
		if (!buffer_tuning_timer_) {
			buffer_tuning_timer_ = add_timer(fz::duration::from_seconds(1), false);
		}
#endif
		return continuation::next;
	}
	else if (request_send_state_ == request_send_state::body) {
		if (body_buffer_->empty()) {
			auto [r, buffer] = req.body_->get_buffer(*this);
			if (r == fz::aio_result::wait) {
				return continuation::wait;
			}
			else if (r == fz::aio_result::error) {
				return continuation::error;
			}
			body_buffer_ = std::move(buffer);

			if (dataToSend_) {
				if (body_buffer_->empty()) {
					if (*dataToSend_) {
						logger_.log(logmsg::error, fztranslate("Unexpected end-of-file on '%s'"), req.body_->name());
						return continuation::error;
					}
					logger_.log(logmsg::debug_info, "Finished sending request body"sv);
					request_send_state_ = request_send_state::finalizing;
					return continuation::next;
				}
				else if (body_buffer_->size() > *dataToSend_) {
					logger_.log(logmsg::error, fztranslate("Excess data read from '%s'"), req.body_->name());
					return continuation::error;
				}
			}
			else {
				if (body_buffer_->empty()) {
					send_buffer_.append("0\r\n\r\n\r\n"sv);
					request_send_state_ = request_send_state::finalizing;
				}
				else {
					// Send chunk-size
					auto chunk = fz::sprintf("%X\r\n", body_buffer_->size());
					send_buffer_.append(chunk);
				}
				return continuation::next;
			}
		}

		int error;
		int written = socket_->write(body_buffer_->get(), body_buffer_->size(), error);
		if (written < 0) {
			if (error != EAGAIN) {
				logger_.log(logmsg::error, fztranslate("Could not write to socket: %s"), fz::socket_error_description(error));
				logger_.log(logmsg::error, fztranslate("Disconnected from server"));
				return continuation::error;
			}
			waiting_for_send_ = true;
			return continuation::wait;
		}
		else if (written) {
			client_.on_alive();
			body_buffer_->consume(static_cast<size_t>(written));
			if (body_buffer_->empty()) {
				body_buffer_.release();
				if (!dataToSend_) {
					send_buffer_.append("\r\n"sv);
				}
			}
			if (dataToSend_) {
				*dataToSend_ -= written;
			}
			if (req.on_body_sending_progress_) {
				req.on_body_sending_progress_(srr, written);
			}
		}
		return continuation::next;
	}

#if FZ_WINDOWS
	stop_timer(buffer_tuning_timer_);
#endif
	auto root = dynamic_cast<fz::socket*>(socket_->root());
	if (root) {
		root->set_flags(fz::socket::flag_nodelay, false);
	}

	++send_pos_;
	request_send_state_ = request_send_state::none;

	if (!req.keep_alive()) {
		wait_for_response_before_send_ = true;
		logger_.log(logmsg::debug_info, "Request did not ask for keep-alive. Waiting for response to finish before sending next request with a new connection."sv);
	}
	return continuation::next;
}

continuation client::impl::finalize_response()
{
	logger_.log(logmsg::debug_verbose, "Finalizing response");
	auto & srr = requests_.front();
	if (srr) {
		auto & res = srr->res();
		if (!(res.flags_ & response::flag_no_body)) {
			res.flags_ |= response::flag_got_body;
			if (res.success() && res.writer_) {
				auto r = res.writer_->add_buffer(std::move(read_state_.writer_buffer_), *this);
				if (r == fz::aio_result::ok) {
					r = res.writer_->finalize(*this);
				}
				switch (r) {
				case fz::aio_result::ok:
					break;
				case fz::aio_result::wait:
					return continuation::wait;
				default:
					return continuation::error;
				}
			}
		}

		auto & req = srr->req();
		if (req.body_) {
			req.body_->remove_waiter(*this);
		}
		if (res.writer_) {
			res.writer_->remove_waiter(*this);
		}
		handler_.send_event<done_event>(srr->request_id_, true);
	}
	if (read_state_.eof_ || !read_state_.keep_alive_ || !send_pos_) {
		destroy_socket();
	}

	requests_.pop_front();
	read_state_ = read_state();
	if (send_pos_) {
		if (!socket_ && (send_pos_ > 1 || request_send_state_ != request_send_state::none)) {
			logger_.log(logmsg::debug_warning, "Server refused keep-alive, but we already sent the next request(s). Must fail the other requests now."sv);
			return continuation::error;
		}
		--send_pos_;
	}

	if (wait_for_response_before_send_) {
		wait_for_response_before_send_ = false;
		if (!requests_.empty() && !waiting_for_send_) {
			waiting_for_send_ = true;
			send_event<socket_event>(socket_, fz::socket_event_flag::write, 0);
		}
	}

	return continuation::next;
}

continuation client::impl::on_read()
{
	if (!socket_) {
		return continuation::wait;
	}

	if (read_state_.state_ == read_state::state::body) {
		continuation c = prepare_response_body_buffer();
		if (c != continuation::next) {
			return c;
		}

		c = read_response_body();
		if (c != continuation::next) {
			return c;
		}

		if (read_state_.responseContentLength_) {
			if (!*read_state_.responseContentLength_) {
				if (read_state_.transfer_encoding_ == chunked) {
					read_state_.state_ = read_state::state::chunk_header;
				}
				else {
					read_state_.state_ = read_state::state::finalizing;
				}
			}
			else if (read_state_.eof_) {
				logger_.log(logmsg::error, fztranslate("HTTP connection closed prematurely"));
				return continuation::error;
			}
		}
		else if (read_state_.eof_) {
			read_state_.state_ = read_state::state::finalizing;
		}

		if (read_state_.state_ == read_state::state::body) {
			auto & srr = requests_.front();
			if (srr && !read_state_.writer_buffer_) {
				auto & res = srr->res();
				if (res.body_.size() == res.max_body_size_) {
					logger_.log(logmsg::error, fztranslate("Response too large"));
					return continuation::error;
				}
			}
		}
		return continuation::next;
	}

	// Response headers, chunk framing
	if (!read_state_.eof_ && read_state_.more_) {
		int error;
		size_t const recv_size = 1024 * 64;
		int read = socket_->read(recv_buffer_.get(recv_size), recv_size, error);
		if (read <= -1) {
			if (error != EAGAIN) {
				logger_.log(logmsg::error, fztranslate("Could not read from socket: %s"), fz::socket_error_description(error));
				destroy_socket();
				return requests_.empty() ? continuation::wait : continuation::error;
			}
			waiting_for_read_ = true;
			return continuation::wait;
		}

		if (read) {
			read_state_.more_ = false;
			recv_buffer_.add(static_cast<size_t>(read));
			client_.on_alive();
		}
		else {
			read_state_.eof_ = true;
		}
	}

	if (requests_.empty()) {
		if (!recv_buffer_.empty()) {
			logger_.log(logmsg::debug_warning, "Server sent data without pending request"sv);
		}
		else {
			logger_.log(logmsg::debug_info, "Idle connection closed"sv);
		}
		return continuation::error;
	}

	if (read_state_.more_ && read_state_.eof_) {
		logger_.log(logmsg::error, fztranslate("HTTP connection closed prematurely"));
		return continuation::error;
	}

	switch (read_state_.state_) {
	case read_state::state::header:
		return parse_header();
	case read_state::state::on_header: {
		if (read_state_.transfer_encoding_ == none) {
			read_state_.state_ = read_state::state::finalizing;
		}
		else if (read_state_.transfer_encoding_ == chunked) {
			read_state_.state_ = read_state::state::chunk_header;
		}
		else {
			if (read_state_.responseContentLength_ && !*read_state_.responseContentLength_) {
				read_state_.state_ = read_state::state::finalizing;
			}
			else {
				read_state_.state_ = read_state::state::body;
			}
		}
		return continuation::next;
	}
	case read_state::state::finalizing:
		return finalize_response();
	case read_state::state::chunk_header:
	case read_state::state::chunk_trailer:
		return parse_chunk_header();
	default:
		logger_.log(logmsg::error, fztranslate("Internal error, bad state"));
		return continuation::error;
	}
}

continuation client::impl::parse_header()
{
	logger_.log(logmsg::debug_verbose, "fz::http::client::impl::parse_header"sv);

	// Parse the recv buffer into the HTTP header.
	// We do just the neccessary parsing and silently ignore most header fields
	// The calling operation is responsible for things like redirect parsing.
	for (;;) {
		// Find line ending
		size_t i = 0;
		for (i = 0; (i + 1) < recv_buffer_.size(); ++i) {
			if (recv_buffer_[i] == '\r') {
				if (recv_buffer_[i + 1] != '\n') {
					logger_.log(logmsg::error, fztranslate("Malformed response header: %s"), fztranslate("Server not sending proper line endings"));
					return continuation::error;
				}
				break;
			}
			if (!recv_buffer_[i]) {
				logger_.log(logmsg::error, fztranslate("Malformed response header: %s"), fztranslate("Null character in line"));
				return continuation::error;
			}
		}

		constexpr size_t const max_line_size = 8192;
		if ((i + 1) >= recv_buffer_.size()) {
			if (recv_buffer_.size() >= max_line_size) {
				logger_.log(logmsg::error, fztranslate("Too long header line"));
				return continuation::error;
			}
			break;
		}

		std::wstring wline = fz::to_wstring_from_utf8(reinterpret_cast<char const*>(recv_buffer_.get()), i);
		if (wline.empty()) {
			wline = fz::to_wstring(std::string(recv_buffer_.get(), recv_buffer_.get() + i));
		}
		if (!wline.empty()) {
			logger_.log_raw(logmsg::reply, wline);
		}

		auto & res = requests_.front()->res();
		if (!res.got_code()) {
			if (recv_buffer_.size() < 15 || memcmp(recv_buffer_.get(), "HTTP/1.", 7)) {
				// Invalid HTTP Status-Line
				logger_.log(logmsg::error, fztranslate("Invalid HTTP Response"));
				return continuation::error;
			}

			if (recv_buffer_[9] < '1' || recv_buffer_[9] > '5' ||
				recv_buffer_[10] < '0' || recv_buffer_[10] > '9' ||
				recv_buffer_[11] < '0' || recv_buffer_[11] > '9')
			{
				// Invalid response code
				logger_.log(logmsg::error, fztranslate("Invalid response code"));
				return continuation::error;
			}

			unsigned int code = res.code_ = (recv_buffer_[9] - '0') * 100 + (recv_buffer_[10] - '0') * 10 + recv_buffer_[11] - '0';
			if (code != 100) {
				res.code_ = code;
				res.reason_ = recv_buffer_.to_view().substr(13, i - 13);
				res.flags_ |= response::flag_got_code;
			}

			if (!send_pos_) {
				if (res.success()) {
					logger_.log(logmsg::error, fztranslate("Broken server, it claims to have processed a request before it got fully set"));
					return continuation::error;
				}
				else {
					logger_.log(logmsg::debug_info, "Premature error response");
				}
			}
		}
		else {
			if (!i) {
				recv_buffer_.consume(2);

				// End of header
				return process_complete_header();
			}

			std::string line(recv_buffer_.get(), recv_buffer_.get() + i);

			auto delim_pos = line.find(':');
			if (delim_pos == std::string::npos || !delim_pos) {
				logger_.log(logmsg::error, fztranslate("Malformed response header: %s"), fztranslate("Invalid line"));
				return continuation::error;
			}

			std::string value;
			auto value_start = line.find_first_not_of(" \t", delim_pos + 1);
			if (value_start != std::string::npos) {
				int value_stop = line.find_last_not_of(" \t"); // Cannot fail
				value = line.substr(value_start, value_stop - value_start + 1);
			}

			auto & header = res.headers_[line.substr(0, delim_pos)];
			if (header.empty()) {
				header = value;
			}
			else if (!value.empty()) {
				if (header.size() + 2 + value.size() > max_line_size) {
					logger_.log(logmsg::error, fztranslate("Too long header line"));
					return continuation::error;
				}
				header += ", " + value;
			}
			if (res.headers_.size() >= 4096) {
				logger_.log(logmsg::error, fztranslate("Too many header lines"));
				return continuation::error;
			}
		}

		recv_buffer_.consume(i + 2);

		if (recv_buffer_.empty()) {
			break;
		}
	}

	read_state_.more_ = true;
	return continuation::next;
}

continuation client::impl::process_complete_header()
{
	logger_.log(logmsg::debug_verbose, "Processing completed header"sv);

	auto & srr = requests_.front();
	auto & req = srr->req();
	auto & res = srr->res();

	res.flags_ |= response::flag_got_header;
	if (req.verb_ == "HEAD" || res.code_prohobits_body()) {
		res.flags_ |= response::flag_no_body;
	}

	auto const te = fz::str_tolower_ascii(res.get_header("Transfer-Encoding"));
	if (te == "chunked") {
		read_state_.transfer_encoding_ = chunked;
	}
	else if (te.empty() || te == "identity") {
		read_state_.transfer_encoding_ = identity;
	}
	else {
		logger_.log(logmsg::error, fztranslate("Malformed response header: %s"), fztranslate("Unknown transfer encoding"));
		return continuation::error;
	}

	if (!res.keep_alive()) {
		wait_for_response_before_send_ = true;
	}

	auto retry = res.get_header("Retry-After");
	if (res.code_ >= 400 && !retry.empty()) {
		// TODO: Retry-After for redirects
		auto const now = fz::datetime::now();

		fz::duration d;
		int seconds = fz::to_integral<int>(retry, -1);
		if (seconds > 0) {
			d = fz::duration::from_seconds(seconds);
		}
		else {
			fz::datetime t;
			if (t.set_rfc822(retry)) {
				if (t > now) {
					d = t - now;
				}
			}
		}

		if (!d && res.code_ == 429) {
			d = fz::duration::from_seconds(1);
		}
		if (d) {
			logger_.log(logmsg::debug_verbose, "Got Retry-After with %d", d.get_seconds());
			throttler_.throttle(req.uri_.host_, now + d);
		}
	}

	read_state_.responseContentLength_ = std::nullopt;
	if (res.no_body()) {
		read_state_.transfer_encoding_ = none;
	}
	else if (read_state_.transfer_encoding_ == identity) {
		uint64_t length{};
		auto const cl = res.get_header("Content-Length");
		if (!cl.empty()) {
			length = fz::to_integral<uint64_t>(cl, uint64_t(-1));
			if (length == uint64_t(-1)) {
				logger_.log(logmsg::error, fztranslate("Malformed response header: %s"), fztranslate("Invalid Content-Length"));
				return continuation::error;
			}
			read_state_.responseContentLength_ = length;
		}
	}

	read_state_.keep_alive_ = res.keep_alive() && req.keep_alive();

	continuation cont = continuation::next;
	read_state_.state_ = read_state::state::on_header;
	if (res.on_header_) {
		// Get current id, on_header_ might requeue which updates the id
		auto id = srr->request_id_;
		cont = res.on_header_(srr);
		if (srr->request_id_ != id) {
			if (cont == continuation::wait || cont == continuation::next) {
				cont = continuation::error;
			}
		}
		if (cont == continuation::wait) {
			return continuation::wait;
		}

		if (cont == continuation::done || srr->request_id_ != id) {
			if (req.body_) {
				req.body_->remove_waiter(*this);
			}
			handler_.send_event<done_event>(id, cont != continuation::error);
			if (send_pos_) {
				// Clear the pointer, we no longer need the request to finish, all needed information is in read_state_.
				srr.reset();
				if (cont != continuation::error) {
					cont = continuation::next;
				}
			}
			else {
				// Gotta abort this request the hard way.
				requests_.pop_front();
				destroy_socket();
				request_send_state_ = request_send_state::none;

				if (wait_for_response_before_send_) {
					wait_for_response_before_send_ = false;
					if (!requests_.empty() && cont != continuation::error) {
						waiting_for_send_ = true;
						send_event<socket_event>(socket_, fz::socket_event_flag::write, 0);
					}
				}
				if (cont != continuation::error) {
					cont = continuation::wait;
				}
			}
			return cont;
		}
	}

	return cont;
}

continuation client::impl::prepare_response_body_buffer()
{
	if (requests_.empty()) {
		return continuation::error;
	}
	if (!requests_.front()) {
		return continuation::next;
	}

	auto & res = requests_.front()->res();
	if (res.success() && res.writer_) {
		if (read_state_.writer_buffer_ && read_state_.writer_buffer_->size() == read_state_.writer_buffer_->capacity()) {
			auto r = res.writer_->add_buffer(std::move(read_state_.writer_buffer_), *this);
			if (r == aio_result::wait) {
				return continuation::wait;
			}
			else if (r != aio_result::ok) {
				return continuation::error;
			}
		}
		if (!read_state_.writer_buffer_) {
			if (!buffer_pool_) {
				logger_.log(logmsg::error, fztranslate("Cannot use writers without buffer pool"));
				return continuation::error;
			}
			read_state_.writer_buffer_ = buffer_pool_->get_buffer(*this);
			if (!read_state_.writer_buffer_) {
				return continuation::wait;
			}
		}
	}

	return continuation::next;
}

continuation client::impl::parse_chunk_header()
{
	if (read_state_.responseContentLength_) {
		// Trailing CRLF of previous chunk
		if (recv_buffer_.size() < 2) {
			read_state_.more_ = true;
			return continuation::next;
		}
		if (recv_buffer_[0] != '\r' || recv_buffer_[1] != '\n') {
			logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Chunk data improperly terminated"));
			return continuation::error;
		}
		recv_buffer_.consume(2);
		read_state_.responseContentLength_ = std::nullopt;
	}

	// Find line ending
	size_t i = 0;
	for (i = 0; (i + 1) < recv_buffer_.size(); ++i) {
		if (recv_buffer_[i] == '\r') {
			if (recv_buffer_[i + 1] != '\n') {
				logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Wrong line endings"));
				return continuation::error;
			}
			break;
		}
		if (!recv_buffer_[i]) {
			logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Null character in line"));
			return continuation::error;
		}
	}
	if ((i + 1) >= recv_buffer_.size()) {
		size_t const max_line_size = 8192;
		if (recv_buffer_.size() >= max_line_size) {
			logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Line length exceeded"));
			return continuation::error;
		}
		read_state_.more_ = true;
		return continuation::next;
	}

	if (read_state_.state_ == read_state::state::chunk_trailer) {
		if (!i) {
			// We're done
			recv_buffer_.consume(2);
			read_state_.state_ = read_state::state::finalizing;
			return continuation::next;
		}

		// Ignore the trailer
	}
	else {
		// Read chunk size
		uint64_t size{};
		unsigned char const* end = recv_buffer_.get() + i;
		unsigned char* q;
		for (q = recv_buffer_.get(); q != end && *q != ';' && *q != ' '; ++q) {
			if (size & 0xf000000000000000ull) {
				// Invalid size
				logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Invalid chunk size"));
				return continuation::error;
			}
			size *= 16;
			if (*q >= '0' && *q <= '9') {
				size += *q - '0';
			}
			else if (*q >= 'A' && *q <= 'F') {
				size += *q - 'A' + 10;
			}
			else if (*q >= 'a' && *q <= 'f') {
				size += *q - 'a' + 10;
			}
			else {
				// Invalid size
				logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Invalid chunk size"));
				return continuation::error;
			}
		}
		if (q == recv_buffer_.get()) {
			logger_.log(logmsg::error, fztranslate("Malformed chunk data: %s"), fztranslate("Invalid chunk size"));
			return continuation::error;
		}

		if (!size) {
			read_state_.state_ = read_state::state::chunk_trailer;
		}
		else {
			read_state_.responseContentLength_ = size;
			read_state_.state_ = read_state::state::body;
		}
	}

	recv_buffer_.consume(i + 2);
	return continuation::next;
}

continuation client::impl::process_receive_buffer_for_response_body()
{
	size_t s = recv_buffer_.size();
	if (read_state_.responseContentLength_) {
		if (read_state_.responseContentLength_ < s) {
			s = *read_state_.responseContentLength_;
		}
	}

	if (read_state_.writer_buffer_) {
		size_t rem = read_state_.writer_buffer_->capacity() - read_state_.writer_buffer_->size();
		if (rem < s) {
			s = rem;
		}
		read_state_.writer_buffer_->append(recv_buffer_.get(), s);
	}
	else {
		auto & srr = requests_.front();
		if (srr) {
			auto & res = srr->res();
			auto rem = res.max_body_size_ - res.body_.size();
			if (rem < s) {
				s = rem;
			}
			res.body_.append(recv_buffer_.get(), s);
		}
	}

	recv_buffer_.consume(s);
	if (read_state_.responseContentLength_) {
		*read_state_.responseContentLength_ -= s;
	}

	return continuation::next;
}

continuation client::impl::read_response_body()
{
	if (!recv_buffer_.empty()) {
		return process_receive_buffer_for_response_body();
	}

	unsigned char* target{};
	size_t recv_size = read_state_.responseContentLength_ ? *read_state_.responseContentLength_ : size_t(-1);
	if (read_state_.writer_buffer_) {
		size_t rem = read_state_.writer_buffer_->capacity() - read_state_.writer_buffer_->size();
		if (rem < recv_size) {
			recv_size = rem;
		}
		target = read_state_.writer_buffer_->get(recv_size);
	}
	else if (auto & srr = requests_.front()) {
		auto & res = srr->res();
		size_t rem = res.max_body_size_ - res.body_.size();
		if (rem < recv_size) {
			recv_size = rem;
		}
		target = res.body_.get(recv_size);
	}
	else {
		size_t rem = 64 * 1024;
		if (rem < recv_size) {
			recv_size = rem;
		}
		target = recv_buffer_.get(recv_size);
	}

	int error;
	int read = socket_->read(target, recv_size, error);
	if (read <= -1) {
		if (error != EAGAIN) {
			logger_.log(logmsg::error, fztranslate("Could not read from socket: %s"), fz::socket_error_description(error));
			destroy_socket();
			return requests_.empty() ? continuation::wait : continuation::error;
		}
		waiting_for_read_ = true;
		return continuation::wait;
	}

	if (read) {
		client_.on_alive();

		if (read_state_.responseContentLength_) {
			*read_state_.responseContentLength_ -= read;
		}

		if (read_state_.writer_buffer_) {
			read_state_.writer_buffer_->add(read);
		}
		else if (auto & srr = requests_.front()) {
			auto & res = srr->res();
			res.body_.add(read);
		}
	}
	else {
		read_state_.eof_ = true;
	}

	return continuation::next;
}

void client::impl::operator()(event_base const& ev)
{
	dispatch<socket_event, aio_buffer_event, timer_event>(ev, this, &client::impl::on_socket_event, &client::impl::on_buffer_availability, &client::impl::on_timer);
}

void client::impl::on_socket_event(socket_event_source*, socket_event_flag type, int error)
{
	if (error) {
		logger_.log(logmsg::error, fztranslate("Socket error: %s"), fz::socket_error_description(error));
		stop(true, false);
	}
	else if (type == socket_event_flag::read) {
		waiting_for_read_ = false;
		read_loop();
	}
	else if (type == socket_event_flag::connection || type == socket_event_flag::write) {
		waiting_for_send_ = false;
		send_loop();
	}
}

void client::impl::read_loop()
{
	for (int i = 0; i < 100; ++i) { // Limit loop iterations to avoid potential livelock
		continuation c = on_read();
		if (c == continuation::done || c == continuation::wait) {
			return;
		}
		else if (c == continuation::error) {
			stop(true, false);
			return;
		}
	}
	waiting_for_read_ = true;
	send_event<socket_event>(socket_, fz::socket_event_flag::read, 0);
}

void client::impl::send_loop()
{
	for (int i = 0; i < 100; ++i) { // Limit loop iterations to avoid potential livelock
		continuation c = on_send();
		if (c == continuation::done || c == continuation::wait) {
			return;
		}
		else if (c == continuation::error) {
			stop(true, false);
			return;
		}
	}
	waiting_for_send_ = true;
	send_event<socket_event>(socket_, fz::socket_event_flag::write, 0);
}

void client::impl::on_buffer_availability(aio_waitable const* w)
{
	if (!requests_.empty()) {
		if (send_pos_ < requests_.size() && requests_[send_pos_]) {
			auto & rr = *requests_[send_pos_];
			auto & req = rr.req();
			if (req.body_.get() == w) {
				if (request_send_state_ == request_send_state::body) {
					send_loop();
					return;
				}
			}
		}

		if ((buffer_pool_ && buffer_pool_ == w) || requests_.back()->res().writer_.get() == w) {
			read_loop();
			return;
		}
	}
	logger_.log(logmsg::debug_warning, "Stale buffer_availability_event"sv);
}

void client::impl::on_timer(fz::timer_id id)
{
	if (id == throttle_timer_) {
		throttle_timer_ = 0;
		waiting_for_send_ = false;
		send_loop();
		return;
	}
#if FZ_WINDOWS
	if (id == buffer_tuning_timer_ && socket_) {
		auto root = dynamic_cast<fz::socket*>(socket_->root());
		if (root && root->is_connected()) {
			int const ideal_send_buffer = root->ideal_send_buffer_size();
			if (ideal_send_buffer != -1) {
				root->set_buffer_sizes(-1, ideal_send_buffer);
			}
		}
	}
#endif
}

void client::impl::destroy_socket()
{
	waiting_for_read_ = true;
	waiting_for_send_ = false;
	if (socket_) {
		socket_ = nullptr;
		client_.destroy_socket();
	}
	send_buffer_.clear();
	recv_buffer_.clear();
	body_buffer_.release();
#if FZ_WINDOWS
	stop_timer(buffer_tuning_timer_);
	buffer_tuning_timer_ = 0;
#endif
}

void client::impl::next()
{
	if (read_state_.state_ == read_state::state::on_header) {
		send_event<socket_event>(socket_, fz::socket_event_flag::read, 0);
	}
}

}
