#include "fzssh/channel.hpp"

#include "buffer_util.hpp"
#include "sftp.hpp"

#include <libfilezilla/logger.hpp>

using namespace std::literals;

namespace fz::ssh::sftp {

#define idtos(id) \
	case message_type:: id: \
		return #id ""sv \

std::string_view FZSSH_PUBLIC_SYMBOL to_string(message_type id)
{
	switch (id) {
		idtos(SSH_FXP_INIT);
		idtos(SSH_FXP_VERSION);
		idtos(SSH_FXP_OPEN);
		idtos(SSH_FXP_CLOSE);
		idtos(SSH_FXP_READ);
		idtos(SSH_FXP_WRITE);
		idtos(SSH_FXP_LSTAT);
		idtos(SSH_FXP_FSTAT);
		idtos(SSH_FXP_SETSTAT);
		idtos(SSH_FXP_FSETSTAT);
		idtos(SSH_FXP_OPENDIR);
		idtos(SSH_FXP_READDIR);
		idtos(SSH_FXP_REMOVE);
		idtos(SSH_FXP_MKDIR);
		idtos(SSH_FXP_RMDIR);
		idtos(SSH_FXP_REALPATH);
		idtos(SSH_FXP_STAT);
		idtos(SSH_FXP_RENAME);
		idtos(SSH_FXP_READLINK);
		idtos(SSH_FXP_SYMLINK);
		idtos(SSH_FXP_STATUS);
		idtos(SSH_FXP_HANDLE);
		idtos(SSH_FXP_DATA);
		idtos(SSH_FXP_NAME);
		idtos(SSH_FXP_ATTRS);
		idtos(SSH_FXP_EXTENDED);
		idtos(SSH_FXP_EXTENDED_REPLY);
	default:
		return {};
	}
}

#undef idtos

#define idtos(id) \
	case status_code:: id: \
		return #id ""sv \

std::string_view to_string(status_code id)
{
	switch (id) {
		idtos(SSH_FX_OK);
		idtos(SSH_FX_EOF);
		idtos(SSH_FX_NO_SUCH_FILE);
		idtos(SSH_FX_PERMISSION_DENIED);
		idtos(SSH_FX_FAILURE);
		idtos(SSH_FX_BAD_MESSAGE);
		idtos(SSH_FX_NO_CONNECTION);
		idtos(SSH_FX_CONNECTION_LOST);
		idtos(SSH_FX_OP_UNSUPPORTED);
	default:
		return {};
	}
}

#undef idtos

bool attributes::is_directory() const
{
	// Intentionally not using S_IFDIR
	return perms_ && (*perms_ & 040000);
}

bool attributes::is_symlink() const
{
	// Intentionally not using S_IFLNK
	return perms_ && (*perms_ & 0120000);
}

sftp_base::sftp_base(std::unique_ptr<socket_interface> && channel, event_handler & handler, logger_interface & logger, size_t max_in_payload_size, bool server)
	: event_handler(handler, child_event_handler)
	, event_handler_(handler)
	, logger_(logger)
	, socket_(std::move(channel))
	, max_in_payload_size_(max_in_payload_size)
	, server_(server)
{
	socket_->set_event_handler(this);
	channel_is_fzssh_ = dynamic_cast<ssh_channel*>(socket_.get()) != nullptr;
}

void sftp_base::dump()
{
	auto [type, len] = in_packet_ ? std::pair((int)in_packet_->type, in_packet_->len) : std::pair(-1, size_t{});
	if (channel_is_fzssh_) {
		logger_.log(logmsg::error, "wait_read_=%u wait_write_=%u outbuf_.size()=%u", wait_read_, wait_write_, outbuf_.size());
	}
	else {
		logger_.log(logmsg::error, "wait_read_=%u inbuf_.size()=%u wait_write_=%u outbuf_.size()=%u", wait_read_, inbuf_.size(), wait_write_, outbuf_.size());
	}
	logger_.log(logmsg::error, "%d %u", type, len);
}

void sftp_base::operator()(event_base const& ev)
{
	fz::dispatch<socket_event>(ev, this,
		&sftp_base::on_socket_event);
}

void sftp_base::on_socket_event(socket_event_source */*s*/, socket_event_flag type, int error)
{
	if (!socket_) {
		return;
	}

	if (error) {
		logger_.log(logmsg::error, "The channel has failed with error code %d", error);
		stop(true);
		return;
	}

	if (type == socket_event_flag::read) {
		on_read();
	}
	else if (type == socket_event_flag::write) {
		on_send();
	}
	else if (type == socket_event_flag::connection) {
		on_connect();
	}
}

void sftp_base::on_read()
{
	wait_read_ = false;

	if (!in_packet_) {
		in_packet_.emplace();
	}

	std::string_view packet;

	if (channel_is_fzssh_) {
		logger_.log(logmsg::debug_debug, "sftp_base::on_read"sv);
		int err{};
		int res = static_cast<ssh_channel&>(*socket_).inbuf(packet, err);
		if (res < 0) {
			if (err == EAGAIN) {
				wait_read_ = true;
			}
			else {
				if (!disconnecting_ && !server_) {
					logger_.log(logmsg::error, "SSH channel got unexpectedly closed by server"sv);
				}
				else {
					logger_.log(logmsg::debug_info, "SSH channel closed by peer"sv);
				}
				stop(true);
			}
			return;
		}
		else if (!res) {
			disconnect();
			return;
		}

		if (disconnecting_) {
			static_cast<ssh_channel&>(*socket_).consume_inbuf(packet.size());
			resend_current_event();
			return;
		}
	}
	else {
		bool need_recv = disconnecting_ || inbuf_.size() < (in_packet_->len + 4);
		logger_.log(logmsg::debug_debug, "sftp_base::on_read (need_recv=%d)"sv, need_recv);
		if (need_recv) {
			int err{};
			int res = socket_->read(inbuf_.get(max_in_payload_size_ + 5), max_in_payload_size_ + 5, err);
			if (res > 0 && !disconnecting_) {
				inbuf_.add(res);
			}
			else if (res < 0) {
				if (err == EAGAIN) {
					wait_read_ = true;
				}
				else {
					if (!disconnecting_ && !server_) {
						logger_.log(logmsg::error, "SSH channel got unexpectedly closed by server"sv);
					}
					else {
						logger_.log(logmsg::debug_info, "SSH channel closed by peer"sv);
					}
					stop(true);
				}
				return;
			}
			if (!res) {
				disconnect();
				return;
			}
		}

		if (disconnecting_) {
			resend_current_event();
			return;
		}

		packet = inbuf_.to_view();
	}

	std::string_view payload;
	if (!is_retrying_process_) {
		// Fetch the type
		if (in_packet_->len == 0) {
			if (packet.size() < 5) {
				if (channel_is_fzssh_) {
					static_cast<ssh_channel&>(*socket_).want_more();
				}
				else {
					resend_current_event();
				}
				return;
			}
			in_packet_->len = read_uint32(packet.data());
			in_packet_->type = static_cast<message_type>(packet[4]);
			if (!in_packet_->len || in_packet_->len > max_in_payload_size_) {
				logger_.log(logmsg::error, "Received SFTP packet header with invalid length %u for packet type %u"sv, in_packet_->len, in_packet_->type);
				stop(true);
				return;
			}
		}

		// Do we have full packet?
		if (packet.size() < (4 + in_packet_->len)) {
			if (channel_is_fzssh_) {
				static_cast<ssh_channel&>(*socket_).want_more();
			}
			else {
				resend_current_event();
			}
			return;
		}

		payload = packet.substr(5, in_packet_->len - 1);

		auto t = to_string(in_packet_->type);
		if (t.empty()) {
			logger_.log(logmsg::error, "Received SFTP packet of unknown type %u", in_packet_->type);
			stop(true);
			return;
		}
		else {
			if (in_packet_->type > message_type::SSH_FXP_VERSION) {
				if (!extract_uint32(payload, in_packet_->id)) {
					logger_.log(logmsg::error, "Could not extract id from incoming %s packet"sv, t);
					stop(true);
					return;
				}
				else {
					logger_.log(logmsg::debug_verbose, "Processing %s, id=%u, len=%u"sv, t, in_packet_->id, in_packet_->len);
				}
			}
			else {
				logger_.log(logmsg::debug_verbose, "Processing %s, len=%u"sv, t, in_packet_->len);
			}
		}
	}
	else {
		payload = packet.substr(in_packet_->type > message_type::SSH_FXP_VERSION ? 5+4 : 5);

		logger_.log(logmsg::debug_verbose, L"Retrying %s, id=%u, len=%u"sv, to_string(in_packet_->type), in_packet_->id, in_packet_->len);
	}

	auto consume_buffer = [&] {
		if (channel_is_fzssh_) {
			if (socket_) {
				static_cast<ssh_channel&>(*socket_).consume_inbuf(in_packet_->len + 4);
			}
		}
		else {
			inbuf_.consume(in_packet_->len + 4);
		}

		in_packet_.reset();
		is_retrying_process_ = false;
	};

	continuation c = process_packet(in_packet_->type, in_packet_->id, payload);

	if (c == continuation::wait) {
		consume_buffer();

		wait_read_ = true;
	}
	else if (c == continuation::wait_and_retry) {
		wait_read_ = true;
		is_retrying_process_ = true;
	}
	else if (c == continuation::next) {
		consume_buffer();

		if (!server_ || outbuf_.empty()) {
			// Server-side, send out what we have before reading more.
			resend_current_event();
		}
	}
	else {
		stop(true);
	}
}

void sftp_base::do_send()
{
	if (!socket_) {
		return;
	}

	while (!outbuf_.empty()) {
		int error;
		int sent = socket_->write(outbuf_.get(), outbuf_.size(), error);
		if (!sent) {
			if (!disconnecting_) {
				logger_.log(logmsg::error, "Could not write to SSH channel, got eof"sv);
			}
			stop(true);
			return;
		}
		else if (sent < 0) {
			if (error == EAGAIN) {
				wait_write_ = true;
			}
			else {
				if (!disconnecting_) {
					logger_.log(logmsg::error, "Could not write to SSH channel, error %d"sv, error);
				}
				stop(true);
			}
			break;
		}
		outbuf_.consume(sent);
	}
	if (wait_outbuf_empty_) {
		wait_outbuf_empty_ = false;
		on_can_send_packets();
	}
}

void sftp_base::on_connect()
{
	on_send();
}

void sftp_base::on_send()
{
	logger_.log(logmsg::debug_debug, "sftp_base::on_send");
	wait_write_ = false;

	if (outbuf_.empty()) {
		if (disconnecting_) {
			disconnect();
		}
		return;
	}

	do_send();

	if (outbuf_.empty() && disconnecting_) {
		disconnect();
		return;
	}

	if (!outbuf_.empty()) {
		if (!wait_write_) {
			resend_current_event();
		}
	}
	else {
		if (server_ && !wait_read_ && socket_) {
			wait_read_ = true;
			send_event<socket_event>(socket_.get(), socket_event_flag::read, 0);
		}
	}
}

void sftp_base::disconnect()
{
	if (!socket_) {
		return;
	}
	disconnecting_ = true;
	if (outbuf_.empty() && !wait_write_) {
		if (socket_->shutdown() == EAGAIN) {
			wait_write_ = true;
			return;
		}
		stop(true);
	}
}

bool sftp_base::can_send_packets()
{
	return can_send_packets(false);
}

bool sftp_base::can_send_packets(bool wait)
{
	bool can_send = outbuf_.empty();
	if (!can_send && wait) {
		wait_outbuf_empty_ = true;
	}
	return can_send;
}

void sftp_base::unblock_read()
{
	if (wait_read_ && socket_) {
		send_event<socket_event>(socket_.get(), socket_event_flag::read, 0);
	}
}

bool sftp_base::is_retrying_process()
{
	return is_retrying_process_;
}

void write_attributes(buffer& buf, attributes const& attrs)
{
	attribute_flags flags{};
	if (attrs.size_) {
		flags |= attribute_flags::SSH_FILEXFER_ATTR_SIZE;
	}
	if (attrs.uid_) {
		flags |= attribute_flags::SSH_FILEXFER_ATTR_UIDGID;
	}
	if (attrs.perms_) {
		flags |= attribute_flags::SSH_FILEXFER_ATTR_PERMISSIONS;
	}
	if (attrs.modified_) {
		flags |= attribute_flags::SSH_FILEXFER_ATTR_ACMODTIME;
	}
	write_uint32(buf, static_cast<uint32_t>(flags));

	if (attrs.size_) {
		write_uint64(buf, *attrs.size_);
	}
	if (attrs.uid_) {
		write_uint32(buf, *attrs.uid_);
		write_uint32(buf, attrs.gid_ ? *attrs.gid_ : *attrs.uid_);
	}
	if (attrs.perms_) {
		write_uint32(buf, *attrs.perms_);
	}
	// Revisit this eventually, Y2K38...
	if (attrs.modified_) {
		write_uint32(buf, attrs.modified_->get_time_t());
		write_uint32(buf, (attrs.accessed_ ? attrs.accessed_ : attrs.modified_)->get_time_t());
	}
}

std::optional<attributes> extract_attributes(std::string_view & data, fz::logger_interface & logger)
{
	attributes attrs;

	attribute_flags flags;
	{
		uint32_t f;
		if (!extract_uint32(data, f)) {
			logger.log(fz::logmsg::error, "Could not extract flags"sv);
			return {};
		}
		flags = static_cast<attribute_flags>(f);
	}

	if (flags & attribute_flags::SSH_FILEXFER_ATTR_SIZE) {
		uint64_t size;
		if (!extract_uint64(data, size)) {
			logger.log(fz::logmsg::error, "Could not extract size"sv);
			return {};
		}
		attrs.size_ = size;
	}

	if (flags & attribute_flags::SSH_FILEXFER_ATTR_UIDGID) {
		uint32_t uid, gid;
		if (!extract_uint32(data, uid) || !extract_uint32(data, gid)) {
			logger.log(fz::logmsg::error, "Could not extract uidgid"sv);
			return {};
		}
		attrs.uid_ = uid;
		attrs.gid_ = gid;
	}

	if (flags & attribute_flags::SSH_FILEXFER_ATTR_PERMISSIONS) {
		uint32_t perms;
		if (!extract_uint32(data, perms)) {
			logger.log(fz::logmsg::error, "Could not extract permissions"sv);
			return {};
		}
		attrs.perms_ = perms;
	}

	if (flags & attribute_flags::SSH_FILEXFER_ATTR_ACMODTIME) {
		uint32_t atime, mtime;
		if (!extract_uint32(data, atime) || !extract_uint32(data, mtime)) {
			logger.log(fz::logmsg::error, "Could not extract acmodtime"sv);
			return {};
		}
		attrs.accessed_ = fz::datetime(atime, fz::datetime::seconds);
		attrs.modified_ = fz::datetime(mtime, fz::datetime::seconds);
	}

	if (flags & attribute_flags::SSH_FILEXFER_ATTR_EXTENDED) {
		uint32_t extended_count;
		if (!extract_uint32(data, extended_count)) {
			logger.log(fz::logmsg::error, "Could not extract extended attribute count"sv);
			return {};
		}
		for (uint32_t j = 0; j < extended_count; ++j) {
			if (!extract_string(data, string_type::ascii, false) || !extract_string(data, string_type::blob, true)) {
				logger.log(fz::logmsg::error, "Could not extract extended attribute %u"sv, j);
				return {};
			}
		}
	}

	return attrs;
}

}
