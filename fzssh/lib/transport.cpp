#include "buffer_util.hpp"
#include "cipher.hpp"
#include "connection_protocol.hpp"
#include "dh.hpp"
#include "mac.hpp"
#include "transport.hpp"
#include "userauth.hpp"

#include "fzssh/pubkey.hpp"
#include "fzssh/ssh.hpp"

#include "config.hpp"

#include <libfilezilla/format.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/util.hpp>
#include <libfilezilla/translate.hpp>

#include <string.h>

using namespace std::literals;

namespace fz::ssh {

#undef DEBUG_DUMP_SECRETS
#undef DEBUG_DUMP_UNIMPLEMENTED
//#define DEBUG_DUMP_SECRETS 1

#define idtos(id) \
	case message_id:: id: \
	    return #id ""sv \

std::string_view to_string(message_id id)
{
	switch (id) {
		idtos(SSH_MSG_DISCONNECT);
		idtos(SSH_MSG_IGNORE);
		idtos(SSH_MSG_UNIMPLEMENTED);
		idtos(SSH_MSG_DEBUG);
		idtos(SSH_MSG_SERVICE_REQUEST);
		idtos(SSH_MSG_SERVICE_ACCEPT);
		idtos(SSH_MSG_EXT_INFO);

		idtos(SSH_MSG_KEXINIT);
		idtos(SSH_MSG_NEWKEYS);

		idtos(SSH_MSG_KEXDH_INIT);
		idtos(SSH_MSG_KEXDH_REPLY);

		idtos(SSH_MSG_KEX_ECDH_INIT);
		idtos(SSH_MSG_KEX_ECDH_REPLY);

		idtos(SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
		idtos(SSH_MSG_KEX_DH_GEX_REQUEST);
		idtos(SSH_MSG_KEX_DH_GEX_GROUP);
		idtos(SSH_MSG_KEX_DH_GEX_INIT);
		idtos(SSH_MSG_KEX_DH_GEX_REPLY);

		idtos(SSH_MSG_KEX_HYBRID_INIT);
		idtos(SSH_MSG_KEX_HYBRID_REPLY);

		// Userauth protocol
		idtos(SSH_MSG_USERAUTH_REQUEST);
		idtos(SSH_MSG_USERAUTH_FAILURE);
		idtos(SSH_MSG_USERAUTH_SUCCESS);
		idtos(SSH_MSG_USERAUTH_BANNER);
		idtos(SSH_MSG_USERAUTH_PK_OK);
		idtos(SSH_MSG_USERAUTH_INFO_REQUEST);
		idtos(SSH_MSG_USERAUTH_INFO_RESPONSE);

		// Connection protocol
		idtos(SSH_MSG_GLOBAL_REQUEST);
		idtos(SSH_MSG_REQUEST_SUCCESS);
		idtos(SSH_MSG_REQUEST_FAILURE);
		idtos(SSH_MSG_CHANNEL_OPEN);
		idtos(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
		idtos(SSH_MSG_CHANNEL_OPEN_FAILURE);
		idtos(SSH_MSG_CHANNEL_WINDOW_ADJUST);
		idtos(SSH_MSG_CHANNEL_DATA);
		idtos(SSH_MSG_CHANNEL_EXTENDED_DATA);
		idtos(SSH_MSG_CHANNEL_EOF);
		idtos(SSH_MSG_CHANNEL_CLOSE);
		idtos(SSH_MSG_CHANNEL_REQUEST);
		idtos(SSH_MSG_CHANNEL_SUCCESS);
		idtos(SSH_MSG_CHANNEL_FAILURE);
	default:
		return {};
	}
}
#undef idtos

message_type get_type(message_id id)
{
	id &= message_id::WIRE_MASK;
	if (id >= message_id::SSH_MSG_KEX_MIN && id <= message_id::SSH_MSG_KEX_MAX) {
		return message_type::transport_kex;
	}
	else if (id >= message_id::SSH_MSG_TRANSPORT_MIN && id <= message_id::SSH_MSG_TRANSPORT_MAX) {
		return message_type::transport;
	}
	else if (id >= message_id::SSH_MSG_USERAUTH_METHOD_MIN && id <= message_id::SSH_MSG_USERAUTH_METHOD_MAX) {
		return message_type::userauth_method;
	}
	else if (id >= message_id::SSH_MSG_USERAUTH_MIN && id <= message_id::SSH_MSG_USERAUTH_MAX) {
		return message_type::userauth;
	}
	else if (id >= message_id::SSH_MSG_CONNECTION_MIN && id <= message_id::SSH_MSG_CONNECTION_MAX) {
		return message_type::connection;
	}
	return message_type::unknown;
}

#define idtos(id) \
	case disconnect_reason:: id: \
		return #id ""sv \

std::string_view to_string(disconnect_reason reason)
{
	switch (reason) {
		idtos(SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT);
		idtos(SSH_DISCONNECT_PROTOCOL_ERROR);
		idtos(SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
		idtos(SSH_DISCONNECT_RESERVED);
		idtos(SSH_DISCONNECT_MAC_ERROR);
		idtos(SSH_DISCONNECT_COMPRESSION_ERROR);
		idtos(SSH_DISCONNECT_SERVICE_NOT_AVAILABLE);
		idtos(SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED);
		idtos(SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE);
		idtos(SSH_DISCONNECT_CONNECTION_LOST);
		idtos(SSH_DISCONNECT_BY_APPLICATION);
		idtos(SSH_DISCONNECT_TOO_MANY_CONNECTIONS);
		idtos(SSH_DISCONNECT_AUTH_CANCELLED_BY_USER);
		idtos(SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
		idtos(SSH_DISCONNECT_ILLEGAL_USER_NAME);
	default:
		{
			static thread_local std::string buf;
			buf = fz::to_string(static_cast<std::underlying_type_t<disconnect_reason>>(reason));
			return buf;
		}
	}
}

#undef idtos

namespace {
struct exclusive_buffer_event_type;
// Can be received in two situations:
// - If waiting for the buffer: The buffer has been obtained
// - Already holding the buffer: Another session also waits. You must release the buffer once the deadline has been reached.
typedef simple_event<exclusive_buffer_event_type, fz::monotonic_clock> exclusive_buffer_event;

class rekey_buffer_mutex final
{
public:
	static rekey_buffer_mutex& get()
	{
		static rekey_buffer_mutex ret;
		return ret;
	}

	bool obtain(fz::event_handler & h);
	void release(event_handler& h);
private:
	fz::mutex m_;
	std::list<event_handler*> waiting_;
	fz::monotonic_clock obtained_;
	rekey_buffer_mutex() = default;
};


bool rekey_buffer_mutex::obtain(fz::event_handler & h)
{
	fz::scoped_lock l(m_);
	waiting_.push_back(&h);

	auto s = waiting_.size();
	if (s == 1) {
		obtained_ = monotonic_clock::now();
		return true;
	}
	else if (s == 2) {
		waiting_.front()->send_event<exclusive_buffer_event>(obtained_ + duration::from_seconds(3));
	}

	return false;
}

void rekey_buffer_mutex::release(event_handler & h)
{
	fz::scoped_lock l(m_);
	auto it = std::find(waiting_.begin(), waiting_.end(), &h);
	if (it == waiting_.end()) {
		return;
	}
	bool first = it == waiting_.begin();
	waiting_.erase(it);

	if (first) {
		h.remove_events<exclusive_buffer_event>();

		size_t s = waiting_.size();
		if (s) {
			obtained_ = monotonic_clock::now();
			waiting_.front()->send_event<exclusive_buffer_event>((s > 1) ? (obtained_ + duration::from_seconds(3)) : fz::monotonic_clock());
		}
	}
}
}

transport::transport(session &sess, parameters const& params, socket_interface & s, bool server, event_handler & h, logger_interface & logger)
    : event_handler(h, child_event_handler)
    , session_(sess)
    , logger_(logger)
    , handler_(h)
    , s_(s)
    , server_(server)
    , compatibility_flags_(params.compatibility_flags_)
    , read_event_(&s_, socket_event_flag::read, 0)
    , write_event_(&s_, socket_event_flag::write, 0)
{
	own_version_ = "SSH-2.0-fzssh_";
	own_version_ += replaced_substrings(PACKAGE_VERSION_S, '-', '_');

	auto softwareversion = trimmed(params.softwareversion_, " _-,/");
	if (!softwareversion.empty()) {
		own_version_ += '_';
		for (auto c : softwareversion) {
			if (c < 32 || static_cast<unsigned char>(c) > 127) {
				continue;
			}
			if (c == '-' || c == ' ') {
				c = '_';
			}
			own_version_ += c;
		}
	}

	outbuf_.append(own_version_);
	outbuf_.append("\r\n"sv);
	s_.set_event_handler(this);

	own_kex_init_data_.kex_ = params.kex_;
	own_kex_init_data_.enc_c2s_ = params.cipher_;
	own_kex_init_data_.mac_c2s_ = params.mac_;
	own_kex_init_data_.hostkey_ = params.hostkey_signatures_;

	own_kex_init_data_.enc_s2c_ = own_kex_init_data_.enc_c2s_;
	own_kex_init_data_.mac_s2c_ = own_kex_init_data_.mac_c2s_;

	append_comma_sep(own_kex_init_data_.comp_c2s_, "none"sv);
	append_comma_sep(own_kex_init_data_.comp_s2c_, "none"sv);

	append_comma_sep(own_kex_init_data_.kex_, server_ ? "kex-strict-s-v00@openssh.com"sv : "kex-strict-c-v00@openssh.com"sv);
	append_comma_sep(own_kex_init_data_.kex_, server_ ? "ext-info-s"sv : "ext-info-c"sv);
	in_.allow_ext_info_ = true;

	initial_kex_ = true;

	in_.enc_ = create_cipher("none"sv);
	in_.mac_ = create_mac("none"sv, {});
	out_.enc_ = create_cipher("none"sv);
	out_.mac_ = create_mac("none"sv, {});
}

transport::~transport()
{
	stop(false);
	send_disconnect(disconnect_reason::SSH_DISCONNECT_BY_APPLICATION, {});
	if (wait_send_ != wait_mode::socket && wait_send_ != wait_mode::socket_failed) {
		do_send();
		if (outbuf_.empty()) {
			s_.shutdown();
		}
	}

	handler_.remove_events(&session_);
}

void transport::stop(bool send_done)
{
	remove_handler();
	s_.set_event_handler(nullptr);

	if (send_done) {
		handler_.send_event<session_done_event>(&session_);
	}
}

void transport::dump()
{
	logger_.log(logmsg::error, "Transport status: inbuf %u, queued %u, outbuf %u, queued_outbuf %u, wait_recv %u, wait_send %u, keying=%u",
	            inbuf_.size(), queued_inbuf_.size(), outbuf_.size(), queued_outbuf_.size(), wait_recv_, wait_send_, keying_);
	if (connection_protocol_) {
		connection_protocol_->dump();
	}
}

void transport::operator()(event_base const& ev)
{
	fz::dispatch<socket_event, exclusive_buffer_event, timer_event>(ev, this,
		&transport::on_socket_event,
		&transport::on_exclusive_buffer,
		&transport::on_timer);
}

void transport::on_socket_event(fz::socket_event_source*, fz::socket_event_flag type, int error)
{
	if (error) {
		if (!disconnecting_) {
			std::string_view name = [&](){
				switch (type) {
					case socket_event_flag::read:
						return "read"sv;
					case socket_event_flag::write:
					case socket_event_flag::connection:
						return "write"sv;
					default:
						return "unexpected"sv;
				}
			}();

			logger_.log(logmsg::error, "Got %s socket error: %s"sv, name, fz::socket_error_string(error));
		}
		stop();
		return;
	}

	if (type == fz::socket_event_flag::read) {
		on_recv();
	}
	else if (type == fz::socket_event_flag::write || type == fz::socket_event_flag::connection) {
		on_send();
	}
}

void transport::on_exclusive_buffer(fz::monotonic_clock const& deadline)
{
	if (rekey_buffer_state_ == rekey_buffer_state::waiting) {
		logger_.log(logmsg::debug_info, "Obtained exclusive right to queue more than 1M of data during re-key");
		rekey_buffer_state_ = rekey_buffer_state::exclusive;
		unblock_read();
	}
	if (deadline && rekey_buffer_state_ == rekey_buffer_state::exclusive) {
		auto now = fz::monotonic_clock::now();
		if (now >= deadline) {
			send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Persistent high memory usage remains after re-keying."sv);
		}
		else {
			if (!rekey_timer_) {
				logger_.log(logmsg::debug_warning, "A different session has to queue much data during to re-key while this session still holds exclusive usage. If issue persists, connection will be dropped in %ums"sv, (deadline - now).get_milliseconds());
				rekey_timer_ = add_timer(deadline);
			}
		}
	}
}

void transport::on_timer(timer_id t)
{
	if (t == rekey_timer_) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Persistent high memory usage remains after re-keying."sv);
	}
}


void transport::on_recv()
{
	wait_recv_ = false;

	if (!skip_recv_ || disconnecting_) {
		int error{};
		int to_read = max_packet_size - inbuf_.size();
		int read = s_.read(inbuf_.get(to_read), to_read, error);
		if (!read) {
			if (!disconnecting_) {
				auto level = logmsg::error;
				if (server_ && service_ == service_type::connection && !connection_protocol_->channel_count()) {
					level = logmsg::status;
				}
				logger_.log(level, fztranslate("Could not read from socket, socket unexpectedly closed"));
			}
			stop();
			return;
		}
		if (read < 0) {
			if (error == EAGAIN) {
				wait_recv_ = true;
			}
			else {
				if (!disconnecting_) {
					logger_.log(logmsg::error, fztranslate("Could not read from socket: %s"), fz::socket_error_string(error));
				}
				stop();
			}
			return;
		}

		if (!disconnecting_) {
			inbuf_.add(read);
		}
	}

	if (disconnecting_) {
		resend_current_event();
		return;
	}

	continuation c;
	if (!queued_inbuf_.empty() && keying_ == keying_state::no) {
		c = process_queued_input();
	}
	else {
		c = process_raw_input();
	}
	if (c == continuation::next) {
		resend_current_event();
	}
	else if (c == continuation::wait) {
		skip_recv_ = true;
	}
}

namespace {
bool could_be_telnet(fz::buffer const& in)
{
	if (in.size() < 3) {
		return false;
	}
	if (in[0] != 0xffu) {
		return false;
	}
	return in[1] >= 251u && in[1] <= 254u;
}
}

continuation transport::read_version()
{
	size_t max_preamble = server_ ? 0 : 4096;
	size_t constexpr max_verlen = 255;

	size_t max = std::min(std::max(max_verlen, max_preamble), inbuf_.size());
	bool was_cr{};
	for (size_t i = 0; i < max; ++i) {
		auto c = inbuf_[i];
		if (c == '\n') {
			std::string_view line = inbuf_.to_view().substr(0, i);
			if (!starts_with(line, "SSH-")) {
				if (!is_valid_utf8(line)) {
					// While this is only a SHOULD in the RFC, we still reject it
					return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, bad encoding in preceeding lines"sv);
				}
				was_cr = false;
				decrypted_ += i + 1;
				if (decrypted_ >= max_preamble) {
					return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, too many preceeding lines"sv);
				}
				inbuf_.consume(i + 1);
				continue;
			}
			else {
				if (was_cr) {
					line.remove_suffix(1);
				}

				if (line.size() > max_verlen) {
					return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, too long"sv);
				}

				if (!was_cr && !starts_with(line, "SSH-1.99-"sv)) {
					if (compatibility_flags_ & compatibility_flags::identification_string_not_terminated_by_crlf) {
						logger_.log(logmsg::error, "%s is in violation of the SSH specifications, it does not terminate its identification string with CRLF. As per RFC 4253 section 4.2 it MUST be terminated by CRLF."sv, server_ ? "Client"sv : "Server");
						used_compatibility_flags_ |= compatibility_flags::identification_string_not_terminated_by_crlf;
					}
					else {
						return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Identification string not terminated by CRLF"sv);
					}
				}
				if (!str_is_ascii(line)) {
					return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Peer identification string is not in ASCII"sv);
				}

				if (!starts_with(line, "SSH-2.0-"sv) && !starts_with(line, "SSH-1.99-"sv)) {
					return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Unsupported protoversion"sv);
				}

				// Could verify/parse the rest here.

				peer_version_ = line;
				logger_.log(logmsg::debug_info, "Received protover: %s"sv, peer_version_);
				inbuf_.consume(i + 1);
				decrypted_ = 0;
				read_version_ = false;
				if (!inbuf_.empty()) {
					skip_recv_ = true;
				}
				if (!send_kexinit()) {
					return continuation::error;
				}
				return continuation::next;
			}
		}
		else if (was_cr) {
			// Disallow cr not followed by lf
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, got CR not followed by LF"sv);
		}
		else if (c == '\r') {
			was_cr = true;
		}
		else if (c < 32) {
			if (could_be_telnet(inbuf_)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, got inadmissable control characters. Are you trying to connect with a telnet client to an SSH server or vice-versa? That cannot possibly work."sv);
			}
			else {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, got inadmissable control characters"sv);
			}
		}
	}
	if (inbuf_.size() >= std::max(max_verlen, max_preamble)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not read identification string, line too long"sv);
	}
	return continuation::next;
}

continuation transport::process_raw_input()
{
	skip_recv_ = false;

	if (read_version_) {
		return read_version();
	}

	size_t const block_size = in_.enc_->block_size();
	if (inbuf_.size() < std::max(size_t(8), block_size)) {
		return continuation::next;
	}

	size_t const mac_size = in_.mac_->size();
	uint32_t packet_length{};
	size_t total_size{};

	bool const etm = in_.mac_->etm();
	if (etm) {
		// verify mac than decrypt

		// Length decryption not supported by our ciphers, always assume plain
		packet_length = read_uint32(inbuf_.get());
		if (packet_length > max_packet_size) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Packet too big"sv);
		}

		total_size = 4 + packet_length + mac_size;
		if (inbuf_.size() < total_size) {
			return continuation::next;
		}

		if (decrypted_ != std::numeric_limits<size_t>::max()) {
			// Check MAC first
			if (!in_.mac_->verify(in_.seq_, inbuf_.get(), packet_length + 4, inbuf_.get() + packet_length + 4)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_MAC_ERROR, "MAC failed"sv);
			}

			// Then decrypt
			if (!in_.enc_->decrypt(inbuf_.get() + 4, packet_length, inbuf_.get() + 4 + packet_length, mac_size)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Decryption failed"sv);
			}
		}
	}
	else if (in_.cbc_) {
		// CBC requires special care.
		// Cite: Albrecht, Martin R. et al. "Plaintext Recovery Attacks against SSH." 2009 30th IEEE Symposium on Security and Privacy (2009): 16-26
		//
		// The mitigation stratety: https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/ssh2-cbc-pktlen-weakness.html
		// Start blockwise,
		while (decrypted_ != std::numeric_limits<size_t>::max()) {
			if (inbuf_.size() < decrypted_ + in_.mac_->size()) {
				return continuation::next;
			}

			// Check MAC
			if (decrypted_ && in_.mac_->verify(in_.seq_, inbuf_.get(), decrypted_, inbuf_.get() + decrypted_)) {
				break;
			}

			if (decrypted_ >= max_packet_size) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Packet too big or MAC failure"sv);
			}

			// Get one more block
			if (inbuf_.size() < decrypted_ + block_size) {
				return continuation::next;
			}

			if (!in_.enc_->decrypt(inbuf_.get() + decrypted_, block_size, inbuf_.get() + decrypted_ + block_size, mac_size)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Decryption failed"sv);
			}
			decrypted_ += block_size;
		}
		packet_length = read_uint32(inbuf_.get());
		if (packet_length > max_packet_size) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Packet too big"sv);
		}

		if (packet_length + 4 != decrypted_) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Invalid packet length"sv);
		}
		total_size = 4 + packet_length + mac_size;
	}
	else {
		if (!decrypted_) {
			if (!in_.enc_->decrypt_length(inbuf_.get(), block_size)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Length decryption failed"sv);
			}
			decrypted_ += block_size;
		}

		packet_length = read_uint32(inbuf_.get());
		if (packet_length > max_packet_size) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Packet too big"sv);
		}

		total_size = 4 + packet_length + mac_size;
		if (inbuf_.size() < total_size) {
			return continuation::next;
		}

		if (decrypted_ != std::numeric_limits<size_t>::max()) {
			if (!in_.enc_->decrypt(inbuf_.get() + decrypted_, 4 + packet_length - decrypted_, inbuf_.get() + 4 + packet_length, mac_size)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Decryption failed"sv);
			}

			// Check MAC
			if (!in_.mac_->verify(in_.seq_, inbuf_.get(), packet_length + 4, inbuf_.get() + packet_length + 4)) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_MAC_ERROR, "MAC failed"sv);
			}
		}
	}

	// Check padding
	unsigned char padding = inbuf_[4];
	if (padding < 4) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Invalid padding: Too small"sv);
	}
	if ((packet_length + (etm ? 0 : 4)) % std::max(size_t(8), block_size)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Invalid padding: Not aligned with blocksize"sv);
	}
	if (padding >= packet_length) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Invalid padding: Larger than packet_length"sv);
	}

	uint32_t payload_size = packet_length - padding - 1;
	if (!payload_size) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Empty payload"sv);
	}
	if (payload_size > 32768) {
#if DEBUG_DUMP_UNIMPLEMENTED
		logger_.log(logmsg::debug_verbose, "Packet contents are %s"sv, hex_encode<std::string>(inbuf_.to_view().substr(6, 256)));
#endif
		logger_.log(logmsg::error, "Excessive payload size of %u. total_size=%u, packet_length=%u, padding=%u"sv, payload_size, total_size, packet_length, padding);
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Payload too big"sv);
	}

	if (decrypted_ != std::numeric_limits<size_t>::max()) {
		decrypted_ = std::numeric_limits<size_t>::max();
		in_.payload_ += total_size;
	}

	// Augment message id based on kex or auth type
	auto id = static_cast<message_id>(inbuf_[5]);
	auto type = get_type(id);
	if (type == message_type::transport_kex) {
		if (!kex_type_) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got KEX-specific message id without having negotiated a KEX algorithm"sv);
		}
		switch (*kex_type_) {
		case kex_type::dh:
			id |= message_id::FLAG_KEX_DH;
			break;
		case kex_type::ecdh:
			id |= message_id::FLAG_KEX_ECDH;
			break;
		case kex_type::dhge:
			id |= message_id::FLAG_KEX_DHGE;
			break;
		case kex_type::pqth:
			id |= message_id::FLAG_KEX_PQTH;
			break;
		}
	}
	else if (type == message_type::userauth_method) {
		id |= auth_->get_method_flag();
	}

	auto c = process_binary_packet(in_.seq_, type, id, inbuf_.to_view().substr(6, payload_size - 1), false);
	if (c != continuation::wait && !disconnecting_) {
		inbuf_.consume(total_size);
		decrypted_ = 0;
		++in_.seq_;
		++in_.packets_;

		if (c == continuation::consume_and_wait) {
			return continuation::wait;
		}

		if (!check_rekey()) {
			return continuation::error;
		}

		if (!inbuf_.empty() || (!queued_inbuf_.empty() && keying_ == keying_state::no)) {
			skip_recv_ = true;
		}
	}
	return c;
}

continuation transport::process_queued_input()
{
	if (keying_ != keying_state::no) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Internal error"sv);
	}

	skip_recv_ = false;
	if (queued_inbuf_.empty()) {
		return continuation::next;
	}

	if (queued_inbuf_.size() < 9) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Internal error"sv);
	}

	uint32_t in_seq = read_uint32(queued_inbuf_.get());
	message_id id = static_cast<message_id>(queued_inbuf_[4]);
	uint32_t packet_length = read_uint32(queued_inbuf_.get() + 5);

	auto packet = queued_inbuf_.to_view().substr(9, packet_length);
	if (packet.size() != packet_length) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Internal error"sv);
	}

	auto c = process_binary_packet(in_seq, get_type(id), id, packet, true);
	if (c != continuation::wait && !disconnecting_) {
		queued_inbuf_.consume(packet_length + 9);

		if (queued_inbuf_.empty()) {
			release_buffer_usage_rights();
		}

		if (!inbuf_.empty() || (!queued_inbuf_.empty() && keying_ == keying_state::no)) {
			skip_recv_ = true;
		}
	}
	return c;
}

continuation transport::process_binary_packet(uint32_t in_seq, message_type type, message_id id, std::string_view packet, bool from_queue)
{
	auto name = to_string(id);
	if (!name.empty()) {

		// If channel packet, snoop channel id for better log readability
		if (id >= message_id::SSH_MSG_CHANNEL_OPEN_CONFIRMATION && id <= message_id::SSH_MSG_CHANNEL_FAILURE && packet.size() >= 4) {
			uint32_t channel = read_uint32(packet.data());
			logger_.log(logmsg::debug_info, "Processing %s, channel=%s, size=%u"sv, name, channel, packet.size() - 4);
		}
		else {
			logger_.log(logmsg::debug_info, "Processing %s, size=%u"sv, name, packet.size());
		}
	}
	else {
		logger_.log(logmsg::debug_warning, "Received binary packet with unimplemented type %d and size %u"sv, id, packet.size());
#if DEBUG_DUMP_UNIMPLEMENTED
		logger_.log(logmsg::debug_verbose, "Packet contents are %s"sv, hex_encode<std::string>(packet));
#endif

		if (initial_kex_ && strict_kex_extension_) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Strict key exchange extension in use, but received unexpected packet during initial kex"sv);
		}

		packet_builder b(*this, message_id::SSH_MSG_UNIMPLEMENTED);
		write_uint32(b.buf_, in_seq);
		if (!b.commit()) {
			return continuation::error;
		}
		return continuation::next;
	}

	auto dispatch = [&]() {
		switch (id) {
		case message_id::SSH_MSG_DISCONNECT:
			return process_disconnect(packet);
		case message_id::SSH_MSG_KEXINIT:
			return process_kexinit(packet);
		case message_id::SSH_MSG_KEXDH_INIT:
		case message_id::SSH_MSG_KEX_ECDH_INIT:
		case message_id::SSH_MSG_KEX_DH_GEX_INIT:
		case message_id::SSH_MSG_KEX_HYBRID_INIT:
			return process_dh_init(name, packet);
		case message_id::SSH_MSG_KEX_DH_GEX_REQUEST:
			return process_dh_gex_request(packet);
		case message_id::SSH_MSG_KEX_DH_GEX_GROUP:
			return process_dh_gex_group(packet);
		case message_id::SSH_MSG_KEXDH_REPLY:
		case message_id::SSH_MSG_KEX_ECDH_REPLY:
		case message_id::SSH_MSG_KEX_DH_GEX_REPLY:
		case message_id::SSH_MSG_KEX_HYBRID_REPLY:
			return process_dh_reply(name, packet);
		case message_id::SSH_MSG_NEWKEYS:
			return process_newkeys(packet);
		default:
			break;
		}

		if (initial_kex_ && strict_kex_extension_) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Strict key exchange extension in use, but received unexpected packet during initial kex"sv);
		}

		switch (id) {
		case message_id::SSH_MSG_IGNORE:
			return process_ignore(packet);
		case message_id::SSH_MSG_DEBUG:
			return process_debug(packet);
		case message_id::SSH_MSG_UNIMPLEMENTED:
			return process_unimplemented(packet);
		default:
			break;
		}

		if (!from_queue && (keying_ >= keying_state::kex_init_received || in_.enc_next_)) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Non-key-exchange packet from peer during a key exchange initiated or acknowledged by peer"sv);
		}

		if (keying_ != keying_state::no) {
			if (initial_kex_) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received non-key-exchange packet during initial key exchange"sv);
			}

			if (queued_inbuf_.size() + packet.size() > 1024 * 1024 * 128) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "Out of memory, cannot continue this connection"sv);
			}
			else if (queued_inbuf_.size() + packet.size() > 1024 * 1024) {
				// Only allow one session at a time doing re-keying with large amount of queued input
				if (!obtain_buffer_usage_rights()) {
					return continuation::wait;
				}
			}

			write_uint32(queued_inbuf_, in_seq);
			queued_inbuf_.append(static_cast<unsigned char>(id));
			write_uint32(queued_inbuf_, packet.size());
			queued_inbuf_.append(packet);

			return continuation::next;
		}

		if (type == message_type::transport) {
			switch (id) {
			case message_id::SSH_MSG_SERVICE_REQUEST:
				return process_service_request(packet);
			case message_id::SSH_MSG_SERVICE_ACCEPT:
				return process_service_accept(packet);
			case message_id::SSH_MSG_EXT_INFO:
				return process_ext_info(packet);
			default:
				break;
			}
		}
		else if (type == message_type::userauth || type == message_type::userauth_method) {
			return auth_->process_binary_packet(id, packet);
		}
		else if (type == message_type::connection) {
			return connection_protocol_->process_binary_packet(id, packet);
		}
		return continuation::next;
	};

	auto c = dispatch();
	if (c == continuation::error_badside) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Received %s when not running as %s"sv, name, server_ ? "client"sv : "server"sv));
	}
	if (c == continuation::error_unimplemented) {
		packet_builder b(*this, message_id::SSH_MSG_UNIMPLEMENTED);
		write_uint32(b.buf_, in_seq);
		if (!b.commit()) {
			return continuation::error;
		}
		return continuation::next;
	}

	return c;
}

continuation transport::process_disconnect(std::string_view packet)
{
	uint32_t raw_code{};
	extracted_string reason;
	if (!extract_uint32(packet, raw_code) || !(reason = extract_string(packet, string_type::utf8, true)) || !extract_string(packet, string_type::ascii, true)) {
		logger_.log(logmsg::error, "Received malformed SSH_MSG_DISCONNECT"sv);
	}
	else {
		auto code = static_cast<disconnect_reason>(raw_code);
		if (code == disconnect_reason::SSH_DISCONNECT_BY_APPLICATION && outbuf_.empty() && service_ == service_type::connection && !connection_protocol_->channel_count()) {
			logger_.log(logmsg::status, "Connection closed by peer"sv);
		}
		else if (reason->empty()) {
			logger_.log(logmsg::error, "Received SSH_MSG_DISCONNECT with code %s and without additional description."sv, to_string(code));
		}
		else {
			logger_.log(logmsg::error, "Received SSH_MSG_DISCONNECT with code %s. Description: %s"sv, to_string(code), *reason);
		}
	}

	stop();
	return continuation::error;
}

continuation transport::process_ignore(std::string_view packet)
{
	auto data = extract_blob(packet);
	if (!data || !packet.empty()) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_IGNORE"sv);
	}

	// We ignore it.

	return continuation::next;
}

continuation transport::process_unimplemented(std::string_view packet)
{
	uint32_t seq{};
	if (!extract_uint32(packet, seq) || !packet.empty()) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_UNIMPLEMENTED"sv);
	}

	logger_.log(logmsg::debug_warning, "Sequence number of unimplemented packet was %u"sv, seq);

	return continuation::next;
}

continuation transport::process_debug(std::string_view packet)
{
	auto always_display = extract_bool(packet);
	auto message = extract_string(packet, string_type::utf8, false);
	auto langtag = extract_string(packet, string_type::ascii, true);
	if (!always_display || !message || !langtag || !packet.empty()) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_DEBUG"sv);
	}

	// We ignore it.

	return continuation::next;
}

namespace {
std::string_view first_match(std::string_view const& lhs, std::string_view const& rhs, bool * preferred_by_both = 0)
{
	strtokenizer l(lhs, ',', true);
	strtokenizer r(rhs, ',', true);
	for (auto lit = l.begin(); lit != l.end(); ++lit) {
		for (auto rit = r.begin(); rit != r.end(); ++rit) {
			if (*lit == *rit) {
				if (preferred_by_both) {
					*preferred_by_both = lit == l.begin() && rit == r.begin();
				}
				return *lit;
			}
		}
	}

	return {};
}
}

continuation transport::process_kexinit(std::string_view packet)
{
	if (keying_ != keying_state::no && keying_ != keying_state::kex_init_sent) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Got extra SSH_MSG_KEXINIT during an ongoing key exchange"sv);
	}
	if (in_.enc_next_ || in_.mac_next_) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Peer sent SSH_MSG_KEXINIT when SSH_MSG_NEWKEYS was expected."sv);
	}

	if (packet.size() < 16 + 10 * 4 + 1 + 4) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "SSH_MSG_KEXINIT packet too small"sv);
	}

	peer_kex_payload_.clear();
	peer_kex_payload_.append(static_cast<uint8_t>(message_id::SSH_MSG_KEXINIT));
	peer_kex_payload_.append(packet);

	packet.remove_prefix(16);
	std::string_view dummy;
	kex_init_data<std::string_view> peer_kex_init_data;
	if (!extract_namelist(packet, peer_kex_init_data.kex_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.hostkey_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.enc_c2s_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.enc_s2c_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.mac_c2s_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.mac_s2c_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.comp_c2s_, logger_) ||
	    !extract_namelist(packet, peer_kex_init_data.comp_s2c_, logger_) ||
	    !extract_namelist(packet, dummy, logger_) || /// ignored lang c2s
	    !extract_namelist(packet, dummy, logger_)) /// ignored lang s2c
	{
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_KEXINIT"sv);
	}
	if (packet.size() < 5) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_KEXINIT, packet too small"sv);
	}
	if (packet.size() > 5) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_KEXINIT, packet too big"sv);
	}
	peer_kex_init_data.guessed_kex_ = packet[0];
	packet.remove_prefix(1);

	uint32_t reserved{};
	if (!extract_uint32(packet, reserved)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_KEXINIT, could not extract reserved field"sv);
	}

	logger_.log(logmsg::debug_info, "Kex algorithms offered by peer: %s"sv, peer_kex_init_data.kex_);
	logger_.log(logmsg::debug_info, "Host key signature algorithms offered by peer: %s"sv, peer_kex_init_data.hostkey_);
	logger_.log(logmsg::debug_info, "Ciphers c2s offered by peer: %s"sv, peer_kex_init_data.enc_c2s_);
	logger_.log(logmsg::debug_info, "Ciphers s2c offered by peer: %s"sv, peer_kex_init_data.enc_s2c_);
	logger_.log(logmsg::debug_info, "Mac algorithms c2s offered by peer: %s"sv, peer_kex_init_data.mac_c2s_);
	logger_.log(logmsg::debug_info, "Mac algorithms s2c offered by peer: %s"sv, peer_kex_init_data.mac_s2c_);
	logger_.log(logmsg::debug_info, "Compression algorithms c2s offered by peer: %s"sv, peer_kex_init_data.comp_c2s_);
	logger_.log(logmsg::debug_info, "Compression algorithms s2c offered by peer: %s"sv, peer_kex_init_data.comp_s2c_);

	bool strict{};
	bool ext_info{};
	for (auto const& kex : strtokenizer(peer_kex_init_data.kex_, ',', false)) {
		if (kex == "kex-strict-c-v00@openssh.com"sv) {
			if (!server_) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Was offered kex-strict-c-v00@openssh.com when running as client"sv);
			}
			strict = true;
		}
		else if (kex == "kex-strict-s-v00@openssh.com"sv) {
			if (server_) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Was offered kex-strict-s-v00@openssh.com when running as server"sv);
			}
			strict = true;
		}
		else if (kex == "ext-info-c"sv) {
			if (!server_) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Was offered ext-info-c when running as client"sv);
			}
			ext_info = true;
		}
		else if (kex == "ext-info-s"sv) {
			if (server_) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Was offered ext-info-s when running as server"sv);
			}
			ext_info = true;
		}
	}

	// During initial kexinit, check for strict kex extension
	if (initial_kex_) {
		strict_kex_extension_ = strict;
		out_.allow_ext_info_ = ext_info;

		if (strict_kex_extension_ && in_.seq_) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Strict key exchange extension in use, but SSH_MSG_KEXINIT not first packet"sv);
		}
	}

	bool guessable_kex{};
	bool guessable_hostkey{};

	auto match = [&](auto const& client_data, auto const& server_data) {
		// We only deal with signature-capable host keys, so conditions
		// two and three in kex_algorithm selection in section 7.1 of
		// RFC 4253 can be ignored.
		algorithms_next_.kex_ = first_match(client_data.kex_, server_data.kex_, &guessable_kex);
		algorithms_next_.hostkey_signature_ = first_match(client_data.hostkey_, server_data.hostkey_, &guessable_hostkey);
		algorithms_next_.cipher_c2s_ = first_match(client_data.enc_c2s_, server_data.enc_c2s_);
		algorithms_next_.cipher_s2c_ = first_match(client_data.enc_s2c_, server_data.enc_s2c_);
		algorithms_next_.mac_c2s_ = first_match(client_data.mac_c2s_, server_data.mac_c2s_);
		algorithms_next_.mac_s2c_ = first_match(client_data.mac_s2c_, server_data.mac_s2c_);
		std::string_view comp_c2s = first_match(client_data.comp_c2s_, server_data.comp_c2s_);
		std::string_view comp_s2c = first_match(client_data.comp_s2c_, server_data.comp_s2c_);

		if (algorithms_next_.kex_.empty()) {
			logger_.log(logmsg::status, "Our kex algorithms offer: %s"sv, own_kex_init_data_.kex_);
			logger_.log(logmsg::status, "Peer kex algorithms offer: %s"sv, peer_kex_init_data.kex_);
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching kex algorithm"sv);
		}
		if (algorithms_next_.hostkey_signature_.empty()) {
			logger_.log(logmsg::status, "Our host key signature algorithms offer: %s"sv, own_kex_init_data_.hostkey_);
			logger_.log(logmsg::status, "Peer host key signature algorithms offer: %s"sv, peer_kex_init_data.hostkey_);
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching hostkey signature algorithm"sv);
		}
		if (algorithms_next_.cipher_c2s_.empty()) {
			logger_.log(logmsg::status, "Our c2s cipher offer: %s"sv, own_kex_init_data_.enc_c2s_);
			logger_.log(logmsg::status, "Peer c2s cipher offer: %s"sv, peer_kex_init_data.enc_c2s_);
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching client-to-server encryption algorithm"sv);
		}
		if (algorithms_next_.cipher_s2c_.empty()) {
			logger_.log(logmsg::status, "Our s2c cipher offer: %s"sv, own_kex_init_data_.enc_s2c_);
			logger_.log(logmsg::status, "Peer s2c cipher offer: %s"sv, peer_kex_init_data.enc_s2c_);
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching server-to-client encryption algorithm"sv);
		}

		if (algorithms_next_.cipher_c2s_ == "aes256-gcm@openssh.com"sv) {
			algorithms_next_.mac_c2s_ = algorithms_next_.cipher_c2s_;
		}
		if (algorithms_next_.cipher_s2c_ == "aes256-gcm@openssh.com"sv) {
			algorithms_next_.mac_s2c_ = algorithms_next_.cipher_s2c_;
		}

		if (algorithms_next_.mac_c2s_.empty()) {
			logger_.log(logmsg::status, "Our c2s MAC algorithms offer: %s"sv, own_kex_init_data_.mac_c2s_);
			logger_.log(logmsg::status, "Peer c2s MAC algorithms offer: %s"sv, peer_kex_init_data.mac_c2s_);
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching client-to-server MAC algorithm"sv);
		}
		if (algorithms_next_.mac_s2c_.empty()) {
			logger_.log(logmsg::status, "Our s2c MAC algorithms offer: %s"sv, own_kex_init_data_.mac_s2c_);
			logger_.log(logmsg::status, "Peer s2c MAC algorithms offer: %s"sv, peer_kex_init_data.mac_s2c_);
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching server-to-client MAC algorithm"sv);
		}

		if (comp_c2s.empty()) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching client-to-server compression algorithm"sv);
		}
		if (comp_s2c.empty()) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "No matching server-to-client compression algorithm"sv);
		}
		return continuation::next;
	};

	continuation r = server_ ? match(peer_kex_init_data, own_kex_init_data_) : match(own_kex_init_data_, peer_kex_init_data);
	if (r != continuation::next) {
		return r;
	}

	logger_.log(logmsg::debug_info, "Negotiated kex %s with hostkey signature %s, c2s cipher %s with mac %s, s2c cipher %s with mac %s", algorithms_next_.kex_, algorithms_next_.hostkey_signature_, algorithms_next_.cipher_c2s_, algorithms_next_.mac_c2s_, algorithms_next_.cipher_s2c_, algorithms_next_.mac_s2c_);

	if (!setup_hostkey()) {
		return continuation::error;
	}

	if (!send_kexinit()) {
		return continuation::error;
	}
	keying_ = keying_state::kex_init_received;
	kex_type_ = get_kex_type(algorithms_next_.kex_);

	if (initial_kex_) {
		// Remove extensions only used during first kex
		std::string kex;
		for (auto const& k : strtokenizer(own_kex_init_data_.kex_, ',', false)) {
			if (k == "kex-strict-c-v00@openssh.com"sv) {
				continue;
			}
			else if (k == "kex-strict-s-v00@openssh.com"sv) {
				continue;
			}
			else if (k == "ext-info-c"sv) {
				continue;
			}
			else if (k == "ext-info-s"sv) {
				continue;
			}
			append_comma_sep(kex, k);
		}
		own_kex_init_data_.kex_ = std::move(kex);
	}

	return finalize_kexinit(peer_kex_init_data.hostkey_, peer_kex_init_data.guessed_kex_ && (!guessable_hostkey || !guessable_kex));
}

size_t transport::kex_needed_bits_hint() const
{
	// It could be argued that it's the minimum of cipher and hash.
	// I think it's better to overestimate the hint, so use max.
	size_t bits_hint = get_digest_size(exchange_hash_alg_) * 8;
	bits_hint = std::max(bits_hint, get_cipher_bits(algorithms_next_.cipher_s2c_));
	bits_hint = std::max(bits_hint, get_cipher_bits(algorithms_next_.cipher_c2s_));
	bits_hint = std::max(bits_hint, mac_key_size(algorithms_next_.mac_s2c_));
	bits_hint = std::max(bits_hint, mac_key_size(algorithms_next_.mac_c2s_));

	return bits_hint;
}

namespace {
std::string_view short_name(kex_type type)
{
	switch (type) {
	case kex_type::ecdh:
		return "ECDH"sv;
	case kex_type::pqth:
		return "PQ/T hybrid"sv;
	default:
		return "DH"sv;
	}
}
}

bool transport::create_dh_keys(std::string_view kex)
{
	exchange_hash_alg_ = get_exchange_hash(kex);
	if (!peer_dh_) {
		peer_dh_ = create_dh_pubkey(kex);
	}
	if (!own_dh_) {
		own_dh_ = create_dh_privkey(kex, server_);
	}
	if (!peer_dh_ || !own_dh_) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Unsupported key exchange method"sv);
		return false;
	}

	if (!own_dh_->generate(kex_needed_bits_hint())) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, sprintf("Could not initialize ephemeral %s privkey"sv, short_name(*kex_type_)));
		return false;
	}

	return true;
}

bool transport::check_rekey()
{
	if (keying_ != keying_state::no || disconnecting_) {
		return true;
	}

	bool need_rekey{};
	if (out_.packets_ >= (1ull << 31) - 4) { // Take rekey packets into account
		need_rekey = true;
	}
	else if (out_.payload_ >= out_.max_payload_) {
		need_rekey = true;
	}

	if (!in_.enc_next_) {
		if (in_.packets_ >= (1ull << 31)) {
			need_rekey = true;
		}
		else if (in_.payload_ >= in_.max_payload_) {
			need_rekey = true;
		}
	}

	if (!need_rekey) {
		return true;
	}

	return send_kexinit();
}

bool transport::send_kexinit()
{
	if (keying_ != keying_state::no || disconnecting_) {
		return true;
	}

	keying_ = keying_state::kex_init_sent;

	own_kex_payload_.clear();
	own_kex_payload_.append(static_cast<uint8_t>(message_id::SSH_MSG_KEXINIT));
	random_bytes(16, own_kex_payload_);
	write_string(own_kex_payload_, own_kex_init_data_.kex_);
	write_string(own_kex_payload_, own_kex_init_data_.hostkey_);
	write_string(own_kex_payload_, own_kex_init_data_.enc_c2s_);
	write_string(own_kex_payload_, own_kex_init_data_.enc_s2c_);
	write_string(own_kex_payload_, own_kex_init_data_.mac_c2s_);
	write_string(own_kex_payload_, own_kex_init_data_.mac_s2c_);
	write_string(own_kex_payload_, own_kex_init_data_.comp_c2s_);
	write_string(own_kex_payload_, own_kex_init_data_.comp_s2c_);
	own_kex_payload_.append(4+4+1+4, '\0');

	packet_builder b(*this, message_id::SSH_MSG_KEXINIT);
	b.buf_.append(own_kex_payload_.to_view().substr(1));

	return b.commit();
}

namespace {
template<typename T>
void feed_exchange_hash(hash_accumulator & acc, T const& data)
{
	acc.update_uint32_be(data.size());
	acc.update(data);
}

template<typename T>
void feed_exchange_hash(hash_accumulator & acc, bool server, T const& own, T const& peer)
{
	feed_exchange_hash(acc, server ? peer : own);
	feed_exchange_hash(acc, server ? own : peer);
}
}

bool transport::init_out()
{
	{
		packet_builder b(*this, message_id::SSH_MSG_NEWKEYS);
		if (!b.commit()) {
			return false;
		}
	}

	out_.enc_ = std::move(out_.enc_next_);
	out_.mac_ = std::move(out_.mac_next_);
	if (strict_kex_extension_) {
		out_.seq_ = 0;
	}
	out_.cbc_ = ends_with(out_.enc_->name(), "-cbc"sv);

	out_.packets_ = 0;
	out_.payload_ = 0;
	if (out_.enc_->block_size() >= 16) {
		out_.max_payload_ = (1ull << 36) - 1024;
	}
	else {
		out_.max_payload_ = (1ull << 30) - 1024;
	}

	keying_ = keying_state::no;
	kex_type_.reset();
	peer_dh_.reset();
	own_dh_.reset();
	gex_info_ = {};

	// Checking keying state just in case the amount of queued packets results in another keying operation being started.
	while (!queued_outbuf_.empty() && keying_ == keying_state::no) {
		if (queued_outbuf_.size() < 5) {
			queued_outbuf_.clear();
			send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Internal error"sv);
			return false;
		}
		uint32_t size = read_uint32(queued_outbuf_.get());
		if (queued_outbuf_.size() < size + 5) {
			queued_outbuf_.clear();
			send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Internal error"sv);
			return false;
		}

		packet_builder b(*this, queued_outbuf_.to_view().substr(5, size));
		if (!b.commit()) {
			return false;
		}
		queued_outbuf_.consume(size + 5);
	}

	bool changed{};
	auto update = [&](std::string& s, std::string const& next) {
		if (s != next) {
			changed = true;
			s = next;
		}
	};
	update(algorithms_.kex_, algorithms_next_.kex_);
	update(algorithms_.hostkey_signature_, algorithms_next_.hostkey_signature_);
	if (server_) {
		update(algorithms_.cipher_s2c_, algorithms_next_.cipher_s2c_);
		update(algorithms_.mac_s2c_, algorithms_next_.mac_s2c_);
	}
	else {
		update(algorithms_.cipher_c2s_, algorithms_next_.cipher_c2s_);
		update(algorithms_.mac_c2s_, algorithms_next_.mac_c2s_);
	}
	if (changed) {
		handler_.send_event<algorithms_changed_event>(&session_, algorithms_);
	}

	return true;
}

std::tuple<buffer, std::vector<uint8_t>> transport::compute_exchange_hash()
{
	auto raw_shared_secret = own_dh_->shared_secret(peer_dh_);
	if (raw_shared_secret.empty()) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not get shared secret"sv);
		return {};
	}

	fz::buffer shared_secret;

	// K as mpint or string depending on kex type
	if (kex_type_ == kex_type::pqth) {
		write_string(shared_secret, raw_shared_secret);
	}
	else {
		write_mpint(shared_secret, raw_shared_secret);
	}
	wipe(raw_shared_secret);

#if DEBUG_DUMP_SECRETS
	logger_.log(logmsg::debug_debug, "Shared secret is %s"sv, fz::hex_encode<std::string>(shared_secret.to_view()));
#endif

	auto const pubhk = host_pubkey();

	hash_accumulator h(exchange_hash_alg_);
	feed_exchange_hash(h, server_, own_version_, peer_version_);
	feed_exchange_hash(h, server_, own_kex_payload_, peer_kex_payload_);
	h.update_with_length(pubhk);

	if (kex_type_ == kex_type::dhge) {
		if (gex_info_.min_) {
			h.update_uint32_be(gex_info_.min_);
		}
		h.update_uint32_be(gex_info_.n_);
		if (gex_info_.max_) {
			h.update_uint32_be(gex_info_.max_);
		}
		h.update(gex_info_.group_);
	}
	feed_exchange_hash(h, server_, own_dh_->pubkey(), peer_dh_->key());

	h.update(shared_secret);

	auto exchange_hash = h.digest();
#if DEBUG_DUMP_SECRETS
	logger_.log(logmsg::debug_debug, "Exchange hash is %s"sv, fz::hex_encode<std::string>(exchange_hash));
#endif

	return {std::move(shared_secret), std::move(exchange_hash)};
}

namespace {
std::vector<uint8_t> derive_key(hash_algorithm alg, buffer const& shared_secret, std::vector<uint8_t> const& exchange_hash, std::vector<uint8_t> const& session_id, unsigned char type, size_t bytes)
{
	if (!bytes) {
		return {};
	}

	std::vector<uint8_t> ret;
	ret.reserve(bytes);

	while (true) {
		hash_accumulator h(alg);
		h.update(shared_secret);
		h.update(exchange_hash);
		if (ret.empty()) {
			h.update(type);
			h.update(session_id);
		}
		else {
			h.update(ret);
		}

		auto digest = h.digest();
		if (digest.size() < bytes) {
			ret.insert(ret.cend(), digest.cbegin(), digest.cend());
			bytes -= digest.size();
		}
		else {
			ret.insert(ret.cend(), digest.cbegin(), digest.cbegin() + bytes);
			break;
		}
	}
	return ret;
}
}

bool transport::derive_keys(buffer const& shared_secret, std::vector<uint8_t> const& exchange_hash)
{
	logger_.log(logmsg::debug_info, "Deriving keys and setting up algorithms"sv);

	auto enc_c2s = create_cipher(algorithms_next_.cipher_c2s_);
	if (!enc_c2s) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not initialize new c2s cipher"sv);
		return false;
	}
	auto enc_s2c = create_cipher(algorithms_next_.cipher_s2c_);
	if (!enc_s2c) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not initialize new s2c cipher"sv);
		return false;
	}

	auto c2s_iv = derive_key(exchange_hash_alg_, shared_secret, exchange_hash, session_id_, 'A', enc_c2s->iv_size());
	auto s2c_iv = derive_key(exchange_hash_alg_, shared_secret, exchange_hash, session_id_, 'B', enc_s2c->iv_size());
	auto c2s_enc_key = derive_key(exchange_hash_alg_, shared_secret, exchange_hash, session_id_, 'C', enc_c2s->key_size());
	auto s2c_enc_key = derive_key(exchange_hash_alg_, shared_secret, exchange_hash, session_id_, 'D', enc_s2c->key_size());
	auto c2s_mac_key = derive_key(exchange_hash_alg_, shared_secret, exchange_hash, session_id_, 'E', mac_key_size(algorithms_next_.mac_c2s_));
	auto s2c_mac_key = derive_key(exchange_hash_alg_, shared_secret, exchange_hash, session_id_, 'F', mac_key_size(algorithms_next_.mac_s2c_));

	auto mac_c2s = create_mac(algorithms_next_.mac_c2s_, c2s_mac_key);
	if (!mac_c2s) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not initialize new c2s MAC"sv);
		return false;
	}

	auto mac_s2c = create_mac(algorithms_next_.mac_s2c_, s2c_mac_key);
	if (!mac_s2c) {
		send_disconnect(disconnect_reason::SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Could not initialize new s2c MAC"sv);
		return false;
	}

#if DEBUG_DUMP_SECRETS
	logger_.log(logmsg::debug_debug, "Next c2s enc iv: %s"sv, fz::hex_encode<std::string>(c2s_iv));
	logger_.log(logmsg::debug_debug, "Next c2s enc key: %s"sv, fz::hex_encode<std::string>(c2s_enc_key));
#endif

	enc_c2s->set_key(c2s_enc_key);
	enc_s2c->set_key(s2c_enc_key);
	enc_c2s->set_iv(std::move(c2s_iv));
	enc_s2c->set_iv(std::move(s2c_iv));

	out_.enc_next_ = std::move(server_ ? enc_s2c : enc_c2s);
	in_.enc_next_ = std::move(server_ ? enc_c2s : enc_s2c);
	out_.mac_next_ = std::move(server_ ? mac_s2c : mac_c2s);
	in_.mac_next_ = std::move(server_ ? mac_c2s : mac_s2c);

	return true;
}

continuation transport::process_newkeys(std::string_view packet)
{
	if (!packet.empty()) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_NEWKEYS, packet too big"sv);
	}

	if (!in_.enc_next_ || !in_.mac_next_ || keying_ == keying_state::signing) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Received SSH_MSG_NEWKEYS when not keying."sv);
	}
	in_.enc_ = std::move(in_.enc_next_);
	in_.mac_ = std::move(in_.mac_next_);
	if (strict_kex_extension_) {
		in_.seq_ = uint32_t(-1);
	}
	in_.cbc_ = ends_with(in_.enc_->name(), "-cbc"sv);

	bool changed{};
	auto update = [&](std::string& s, std::string const& next) {
		if (s != next) {
			changed = true;
			s = next;
		}
	};
	if (server_) {
		update(algorithms_.cipher_c2s_, algorithms_next_.cipher_c2s_);
		update(algorithms_.mac_c2s_, algorithms_next_.mac_c2s_);
	}
	else {
		update(algorithms_.cipher_s2c_, algorithms_next_.cipher_s2c_);
		update(algorithms_.mac_s2c_, algorithms_next_.mac_s2c_);
	}
	if (changed) {
		handler_.send_event<algorithms_changed_event>(&session_, algorithms_);
	}

	initial_kex_ = false;

	in_.packets_ = 0;
	in_.payload_ = 0;
	if (in_.enc_->block_size() >= 16) {
		in_.max_payload_ = (1ull << 36) - 1024;
	}
	else {
		in_.max_payload_ = (1ull << 30) - 1024;
	}

	return continuation::next;
}

bool transport::send_ext_info()
{
	if (!out_.allow_ext_info_ || own_ext_info_.empty()) {
		return true;
	}

	packet_builder b(*this, message_id::SSH_MSG_EXT_INFO);
	write_uint32(b.buf_, own_ext_info_.size());

	for (auto const& p : own_ext_info_) {
		write_string(b.buf_, p.first);
		write_string(b.buf_, p.second);
	}
	return b.commit();
}

continuation transport::process_ext_info(std::string_view packet)
{
	if (initial_kex_) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_EXT_INFO prior to initial SSH_MSG_NEWKEYS"sv);
	}

	if (!in_.allow_ext_info_) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_EXT_INFO when not advertised support for it."sv);
	}

	// Slightly more lenient than the RFC calls for wrt. _immediately_ following SSH_MSG_NEWKEYS
	if (server_ && service_ != service_type::none) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_EXT_INFO not immediately following initial SSH_MSG_NEWKEYS"sv);
	}
	// Slightly more lenient than the RFC calls for wrt. _immediately_ preceeding SSH_MSG_USERAUTH_SUCCESS
	if (!server_ && service_ > service_type::userauth) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Got SSH_MSG_EXT_INFO after accepted userauth"sv);
	}

	uint32_t count{};
	if (!extract_uint32(packet, count)) {
		return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_EXT_INFO, could not extract number of extensions"sv);
	}

	connection_protocol_->no_flow_control_ = false;
	for (size_t i = 0; i < count; ++i) {
		auto name = extract_string(packet, string_type::ascii, false);
		auto value = extract_blob(packet);
		if (!name || !value) {
			return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_EXT_INFO, could not extract extension data"sv);
		}

		logger_.log(logmsg::debug_info, "Got extension name '%s'"sv, *name);
		if (name == "no-flow-control"sv) {
			if (value != "s"sv && value != "p"sv) {
				return send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Malformed SSH_MSG_EXT_INFO, no-flow-control extension has unsupported value"sv);
			}
			if (out_.allow_ext_info_) {
				auto it = own_ext_info_.find("no-flow-control"sv);
				if (it != own_ext_info_.end()) {
					if (it->second == "p"sv || value == "p"sv) {
						logger_.log(logmsg::debug_info, "Peer no-flow-control value is %s, our value is %s, enabling no-flow-control"sv, *value, it->second);
						connection_protocol_->no_flow_control_ = true;
					}
					else {
						logger_.log(logmsg::debug_info, "Peer no-flow-control value is %s, our value is %s, not enabling no-flow-control"sv, *value, it->second);
					}
				}
				else {
					logger_.log(logmsg::debug_info, "Peer no-flow-control value is %s, we don't want to support no-flow-control"sv, *value);
				}
			}
		}
		else {
			auto res = process_ext_info(*name, *value);
			if (res != continuation::next) {
				return res;
			}
		}
	}

	return continuation::next;
}

void transport::on_send()
{
	wait_send_ = wait_mode::none;

	continuation res = do_send();
	if (res == continuation::error) {
		stop();
		return;
	}
	else if (res == continuation::wait) {
		return;
	}

	if (outbuf_.empty() && disconnecting_) {
		stop();
		return;
	}


	if (!outbuf_.empty()) {
		resend_current_event();
	}
	else if (keying_ == keying_state::no) {
		if (service_ == service_type::connection && connection_protocol_) {
			connection_protocol_->send_data();
		}
	}
}

continuation transport::do_send()
{
	if (outbuf_.empty()) {
		return disconnecting_ ? continuation::error : continuation::next;
	}

	int error;
	int sent = s_.write(outbuf_.get(), outbuf_.size(), error);
	if (!sent) {
		if (!disconnecting_) {
			logger_.log(logmsg::error, fztranslate("Could not write to socket, socket unexpectedly closed"));
		}
		return continuation::error;
	}
	else if (sent < 0) {
		if (error == EAGAIN) {
			wait_send_ = wait_mode::socket;
			return continuation::wait;
		}
		else {
			wait_send_ = wait_mode::socket_failed;
			if (!disconnecting_) {
				logger_.log(logmsg::error, fztranslate("Could not write to socket: %s"), fz::socket_error_string(error));
			}
			return continuation::error;
		}
	}
	outbuf_.consume(sent);

	return continuation::next;
}

continuation transport::send_disconnect(disconnect_reason reason_code, std::string_view msg)
{
	if (!msg.empty()) {
		logger_.log_raw(logmsg::error, msg);
	}

	if (disconnecting_) {
		stop();
		return continuation::error;
	}
	disconnecting_ = true;

	inbuf_.clear();
	queued_inbuf_.clear();
	queued_outbuf_.clear();
	release_buffer_usage_rights();

	keying_ = keying_state::no;
	kex_type_.reset();
	peer_dh_.reset();
	own_dh_.reset();
	gex_info_ = {};

	packet_builder b(*this, message_id::SSH_MSG_DISCONNECT);
	write_uint32(b.buf_, static_cast<uint32_t>(reason_code));
	write_string(b.buf_, msg);
	write_string(b.buf_, "en"sv);
	if (!b.commit()) {
		stop();
	}
	unblock_read();
	return continuation::error;
}

bool transport::protect_packet(size_t offset, uint32_t payload_size)
{
	if (outbuf_.size() < offset + payload_size + 5) {
		return false;
	}

	bool const etm = out_.mac_->etm();
	size_t const block_size = out_.enc_->block_size();
	size_t padding = 4 + block_size - (payload_size + 1 + (etm ? 0 : 4) + 4) % block_size;

	size_t const mac_size = out_.mac_->size();

	auto *p = outbuf_.get(padding + mac_size);
	outbuf_.add(padding + mac_size);

	if (out_.enc_->requires_random_padding()) {
		random_bytes(padding, p);
	}
	else {
		memset(p, 0, padding);
	}
	outbuf_[offset + 4] = padding;
	auto total = uint32_t(payload_size + padding + 1);
	write_uint32(outbuf_.get() + offset, total);

	size_t to_encrypt = total + (etm ? 0 : 4);

	if (!etm) {
		out_.mac_->generate(out_.seq_, outbuf_.get() + offset, total + 4, outbuf_.get() + offset + 4 + total);
	}

	if (!out_.enc_->encrypt(outbuf_.get() + offset + (etm ? 4 : 0), to_encrypt, outbuf_.get() + offset + 4 + total, mac_size)) {
		return false;
	}

	if (etm) {
		out_.mac_->generate(out_.seq_, outbuf_.get() + offset, total + 4, outbuf_.get() + offset + 4 + total);
	}
	++out_.seq_;
	++out_.packets_;
	out_.payload_ += to_encrypt;
	return check_rekey();
}

void transport::unblock_read()
{
	if (wait_recv_) {
		return;
	}
	wait_recv_ = true;
	send_persistent_event(&read_event_);
}

bool transport::service_can_send() const
{
	return outbuf_.empty() && keying_ == keying_state::no;
}

bool transport::obtain_buffer_usage_rights()
{
	if (rekey_buffer_state_ == rekey_buffer_state::normal) {
		if (rekey_buffer_mutex::get().obtain(*this)) {
			logger_.log(logmsg::debug_info, "Obtained exclusive right to queue more than 1M of data during re-key");
			rekey_buffer_state_ = rekey_buffer_state::exclusive;
			return true;
		}
		else {
			logger_.log(logmsg::debug_info, "Waiting for exclusive right to queue more than 1M of data during re-key");
			rekey_buffer_state_ = rekey_buffer_state::waiting;
			return false;
		}
	}
	return rekey_buffer_state_ == rekey_buffer_state::exclusive;
}

void transport::release_buffer_usage_rights()
{
	if (rekey_buffer_state_ != rekey_buffer_state::normal) {
		rekey_buffer_mutex::get().release(*this);
		queued_inbuf_.clear_and_free();
		rekey_buffer_state_ = rekey_buffer_state::normal;
		stop_timer(rekey_timer_);
		rekey_timer_ = 0;
		logger_.log(logmsg::debug_info, "Released exclusive use of rekeying memory"sv);
	}
}

namespace {
bool must_queue_due_to_keying(message_id id, keying_state k)
{
	id &= message_id::WIRE_MASK;
	if (id <= message_id::SSH_MSG_TRANSPORT_MAX && id != message_id::SSH_MSG_SERVICE_REQUEST && id != message_id::SSH_MSG_SERVICE_ACCEPT) {
		return false;
	}

	return k != keying_state::no;
}
}

packet_builder::packet_builder(transport & s, message_id id, std::string_view const& description)
    : buf_(must_queue_due_to_keying(id, s.keying_) ? s.queued_outbuf_ : s.outbuf_)
    , s_(s)
    , old_size_(buf_.size())
{
	if (s_.out_.cbc_ && buf_.empty() && &buf_ != &s.queued_outbuf_ && id != message_id::SSH_MSG_IGNORE) {
		packet_builder b(s, message_id::SSH_MSG_IGNORE, "due to CBC"sv);
		write_uint32(b.buf_, 0);
		b.commit();
		old_size_ = buf_.size();
	}
	if (&buf_ == &s.queued_outbuf_) {
		if (description.empty()) {
			s_.logger_.log(logmsg::debug_info, "Queuing %s"sv, to_string(id));
		}
		else {
			s_.logger_.log(logmsg::debug_info, "Queuing %s (%s)"sv, to_string(id), description);
		}
	}
	else {
		if (description.empty()) {
			s_.logger_.log(logmsg::debug_info, "Sending %s, seq=%u"sv, to_string(id), s_.out_.seq_);
		}
		else {
			s_.logger_.log(logmsg::debug_info, "Sending %s (%s), seq=%u"sv, to_string(id), description, s_.out_.seq_);
		}
	}
	buf_.append(5, 0);
	buf_.append(static_cast<uint8_t>(id));
}

packet_builder::packet_builder(transport & s, std::string_view data)
    : buf_(s.outbuf_)
    , s_(s)
    , old_size_(buf_.size())
{
	buf_.append(5, 0);
	buf_.append(data);
}

packet_builder::~packet_builder()
{
	if (!committed_) {
		buf_.resize(old_size_);
	}
}

bool packet_builder::commit()
{
	if (committed_) {
		return true;
	}
	committed_ = true;
	if (s_.disconnecting_) {
		// Discard packet, unless it's a disconnect message
		if (buf_.size() <= old_size_ + 5 || buf_[old_size_ + 5] != static_cast<uint8_t>(message_id::SSH_MSG_DISCONNECT)) {
			buf_.resize(old_size_);
			return false;
		}
	}

	size_t const payload_size = buf_.size() - old_size_ - 5;

	if (!payload_size) {
		buf_.resize(old_size_);
		s_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Cannot send packet: Empty binary packet payload"sv);
		return false;
	}
	if (payload_size > max_payload_size) {
		buf_.resize(old_size_);
		s_.logger_.log(logmsg::error, "Payload size %u exceeds max payload size %u"sv, payload_size, max_payload_size);
		s_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Cannot send packet: Too big binary packet payload"sv);
		return false;
	}

	if (&buf_ == &s_.queued_outbuf_) {
		// Cannot yet encrypt. Must remember size for later.
		write_uint32(buf_.get() + old_size_, payload_size);
		return true;
	}

	if (!s_.protect_packet(old_size_, payload_size)) {
		buf_.resize(old_size_);
		s_.send_disconnect(disconnect_reason::SSH_DISCONNECT_PROTOCOL_ERROR, "Could not send packet: Encryption failed"sv);
		return false;
	}

	if (!old_size_ && s_.wait_send_ == wait_mode::none) {
		s_.wait_send_ = wait_mode::internal;
		s_.send_persistent_event(&s_.write_event_);
	}

	return true;
}
}
