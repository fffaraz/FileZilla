#include "libfilezilla/ascii_layer.hpp"

namespace fz {
ascii_layer::ascii_layer(event_loop& loop, event_handler* handler, socket_interface& next_layer)
	: socket_layer{handler, next_layer, false}
	, event_handler(loop)
{
	next_layer.set_event_handler(this);
}

ascii_layer::~ascii_layer()
{
	remove_handler();
}

int ascii_layer::read(void *buffer, unsigned int size, int &error)
{
	if (!buffer || !size) {
		error = EINVAL;
		return -1;
	}

repeat_read:
	auto *begin = reinterpret_cast<uint8_t*>(buffer);

	int read;
	if (tmp_read_.has_value()) {
		*begin = *tmp_read_;

		if (size == 1) {
			// Corner-case: Caller is reading bytewise from layer.

			uint8_t ch{};
			read = next_layer_.read(&ch, 1, error);

			if (read < 0) {
				if (error == EAGAIN) {
					waiting_read_ = true;
				}
				return read;
			}

			if (!read) {
				tmp_read_.reset();
			}
			else {
				if (ch == '\n' && *begin == '\r') {
					*begin = '\n';

					tmp_read_.reset();
				}
				else {
					tmp_read_.emplace(ch);
				}
			}

			return 1;
		}

		read = next_layer_.read(begin + 1, size - 1, error);
		if (read < 0) {
			if (error == EAGAIN) {
				waiting_read_ = true;
			}
			return read;
		}

		if (!read ) {
			tmp_read_.reset();
			return 1;
		}
		read += 1;
	}
	else {
		read = next_layer_.read(begin, size, error);
		if (read <= 0) {
			if (read < 0 && error == EAGAIN) {
				waiting_read_ = true;
			}
			return read;
		}
	}

	// Invariant: read > 0

	auto end = begin + read;

	// Use std algos to eliminate CRs followed by LF. Stray CRs are kept.

	static constexpr uint8_t const crlf_begin[] = { '\r', '\n' };
	static constexpr uint8_t const* const crlf_end = crlf_begin + 2;
	int crlf_count{};

	if (auto crlf_it1 = std::search(begin, end, crlf_begin, crlf_end); crlf_it1 != end) {
		do {
			auto crlf_it2 = std::search(crlf_it1 + 2, end, crlf_begin, crlf_end);
			std::copy(crlf_it1 + 1, crlf_it2, crlf_it1 - crlf_count++);
			crlf_it1 = crlf_it2;
		} while (crlf_it1 != end);
	}

	read -= crlf_count;

	// Invariant: read > 0, still, because crlf_count <= read/2

	if (begin[read - 1] == '\r') {
		--read;
		tmp_read_.emplace(begin[read]);
		if (!read) {
			// If caller is reading bytewise and we got a \r, repeat reading, we don't want to return 0 as that signals EOF.
			goto repeat_read;
		}
	}
	else {
		tmp_read_.reset();
	}

	return read;
}

int ascii_layer::write(void const* buffer, unsigned int size, int& error)
{
	if (!buffer || !size) {
		error = EINVAL;
		return -1;
	}

	if (write_blocked_by_send_buffer_) {
		error = EAGAIN;
		return -1;
	}

	while (!buffer_.empty()) {
		int written = next_layer_.write(buffer_.get(), buffer_.size(), error);
		if (written <= 0) {
			if (error == EAGAIN) {
				write_blocked_by_send_buffer_ = true;
			}
			return written;
		}
		buffer_.consume(written);
	}

	auto const* in = reinterpret_cast<uint8_t const*>(buffer);
	auto const* end = in + size;
	auto * out = buffer_.get(size * 2);
	while (in != end) {
		auto const ch = *in++;
		if (ch == '\n' && was_cr_) {
			*out++ = '\r';
		}
		was_cr_ = ch == '\r';

		*out++ = ch;
	}
	buffer_.add(out - buffer_.get());

	while (!buffer_.empty()) {
		int written = next_layer_.write(buffer_.get(), buffer_.size(), error);
		if (written <= 0) {
			if (error == EAGAIN) {
				write_blocked_by_send_buffer_ = true;
				return size;
			}
			return -1;
		}
		buffer_.consume(written);
	}

	return size;
}

int ascii_layer::shutdown()
{
	if (write_blocked_by_send_buffer_) {
		return EAGAIN;
	}
	while (!buffer_.empty()) {
		int error;
		int written = next_layer_.write(buffer_.get(), buffer_.size(), error);
		if (written <= 0) {
			if (error == EAGAIN) {
				write_blocked_by_send_buffer_ = true;
			}
			return error;
		}
		buffer_.consume(written);
	}
	int ret = next_layer_.shutdown();
	if (ret == EAGAIN) {
		write_blocked_by_send_buffer_ = true;
	}
	return ret;
}

void ascii_layer::operator()(event_base const& ev)
{
	dispatch<socket_event, hostaddress_event>(ev, this
		, &ascii_layer::on_socket_event
		, &ascii_layer::forward_hostaddress_event);
}

void ascii_layer::on_socket_event(socket_event_source*, socket_event_flag t, int error)
{
	if (error) {
		if (event_handler_) {
			event_handler_->send_event<fz::socket_event>(this, t, error);
		}
		return;
	}

	if (t == socket_event_flag::write) {
		while (!buffer_.empty()) {
			int error;
			int written = next_layer_.write(buffer_.get(), buffer_.size(), error);
			if (written <= 0) {
				if (error != EAGAIN && event_handler_) {
					event_handler_->send_event<fz::socket_event>(this, socket_event_flag::write, error);
				}
				return;
			}
			buffer_.consume(written);
		}
		if (write_blocked_by_send_buffer_) {
			write_blocked_by_send_buffer_ = false;
			event_handler_->send_event<fz::socket_event>(this, socket_event_flag::write, 0);
		}
	}
	else {
		if (t == socket_event_flag::read) {
			waiting_read_ = false;
		}
		event_handler_->send_event<fz::socket_event>(this, t, 0);
	}
}

void ascii_layer::set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block)
{
	auto old = event_handler_;
	event_handler_ = handler;
	socket_event_flag const pending = change_socket_event_handler(old, handler, this, retrigger_block);
	if (handler) {
		auto s = get_state();
		if (!write_blocked_by_send_buffer_ && (s == socket_state::connected || s == socket_state::shutting_down) && !(pending & (socket_event_flag::write | socket_event_flag::connection)) && !(retrigger_block & socket_event_flag::write)) {
			handler->send_event<socket_event>(this, socket_event_flag::write, 0);
		}
		if (!waiting_read_ && (s == socket_state::connected || s == socket_state::shutting_down || s == socket_state::shut_down)) {
			if (!(pending & socket_event_flag::read) && !(retrigger_block & socket_event_flag::read)) {
				handler->send_event<socket_event>(this, socket_event_flag::read, 0);
			}
		}
	}
}
}
