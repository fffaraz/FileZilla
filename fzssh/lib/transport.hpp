#ifndef FZSSH_TRANSPORT_HEADER
#define FZSSH_TRANSPORT_HEADER

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/hash.hpp>
#include <libfilezilla/socket.hpp>

#include "fzssh/visibility.hpp"
#include "fzssh/ssh.hpp"

#include "dh.hpp"

#include <map>

size_t constexpr max_packet_size{35000};
size_t constexpr max_payload_size{32768};

namespace fz {

class logger_interface;

namespace ssh {

class cipher_base;
class mac_base;
class public_key;
class private_key;

enum class message_type
{
	unknown,
	transport,
	transport_kex, // A subset of transport
	userauth,
	userauth_method, // A subset of userauth
	connection,
};

enum class message_id : unsigned
{
	// Not actual message IDs, but grouping flags to disambiguate
	FLAG_KEX_DH = 0x100,
	FLAG_KEX_ECDH = 0x200,
	FLAG_KEX_DHGE = 0x400,
	FLAG_KEX_PQTH = 0x800,
	FLAG_USERAUTH_PK = 0x1000,
	FLAG_USERAUTH_KEYBOARD_INTERACTIVE = 0x2000,
	WIRE_MASK = 0xffu,

	// Transport protocol
	SSH_MSG_DISCONNECT = 1,
	SSH_MSG_IGNORE = 2,
	SSH_MSG_UNIMPLEMENTED = 3,
	SSH_MSG_DEBUG = 4,
	SSH_MSG_SERVICE_REQUEST = 5,
	SSH_MSG_SERVICE_ACCEPT = 6,
	SSH_MSG_EXT_INFO = 7,

	SSH_MSG_KEXINIT = 20,
	SSH_MSG_NEWKEYS = 21,

	SSH_MSG_KEXDH_INIT = 30 | FLAG_KEX_DH,
	SSH_MSG_KEXDH_REPLY = 31 | FLAG_KEX_DH,

	SSH_MSG_KEX_ECDH_INIT = 30 | FLAG_KEX_ECDH,
	SSH_MSG_KEX_ECDH_REPLY = 31 | FLAG_KEX_ECDH,

	SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30 | FLAG_KEX_DHGE,
	SSH_MSG_KEX_DH_GEX_REQUEST = 34 | FLAG_KEX_DHGE,
	SSH_MSG_KEX_DH_GEX_GROUP = 31 | FLAG_KEX_DHGE,
	SSH_MSG_KEX_DH_GEX_INIT = 32 | FLAG_KEX_DHGE,
	SSH_MSG_KEX_DH_GEX_REPLY = 33 | FLAG_KEX_DHGE,

	SSH_MSG_KEX_HYBRID_INIT = 30 | FLAG_KEX_PQTH,
	SSH_MSG_KEX_HYBRID_REPLY = 31 | FLAG_KEX_PQTH,

	SSH_MSG_KEX_MIN = 30,
	SSH_MSG_KEX_MAX = 49,

	SSH_MSG_TRANSPORT_MIN = 0,
	SSH_MSG_TRANSPORT_MAX = 49,

	// Userauth protocol
	SSH_MSG_USERAUTH_REQUEST = 50,
	SSH_MSG_USERAUTH_FAILURE = 51,
	SSH_MSG_USERAUTH_SUCCESS = 52,
	SSH_MSG_USERAUTH_BANNER = 53,

	SSH_MSG_USERAUTH_PK_OK = 60 | FLAG_USERAUTH_PK,

	SSH_MSG_USERAUTH_INFO_REQUEST = 60 | FLAG_USERAUTH_KEYBOARD_INTERACTIVE,
	SSH_MSG_USERAUTH_INFO_RESPONSE = 61 | FLAG_USERAUTH_KEYBOARD_INTERACTIVE,

	SSH_MSG_USERAUTH_METHOD_MIN = 60,
	SSH_MSG_USERAUTH_METHOD_MAX = 79,

	SSH_MSG_USERAUTH_MIN = 50,
	SSH_MSG_USERAUTH_MAX = 79,

	// Connection protocol
	SSH_MSG_GLOBAL_REQUEST = 80,
	SSH_MSG_REQUEST_SUCCESS = 81,
	SSH_MSG_REQUEST_FAILURE = 82,
	SSH_MSG_CHANNEL_OPEN = 90,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
	SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
	SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
	SSH_MSG_CHANNEL_DATA = 94,
	SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
	SSH_MSG_CHANNEL_EOF = 96,
	SSH_MSG_CHANNEL_CLOSE = 97,
	SSH_MSG_CHANNEL_REQUEST = 98,
	SSH_MSG_CHANNEL_SUCCESS = 99,
	SSH_MSG_CHANNEL_FAILURE = 100,

	SSH_MSG_CONNECTION_MIN = 80,
	SSH_MSG_CONNECTION_MAX = 127,
};

inline message_id operator&(message_id lhs, message_id rhs) {
	return static_cast<message_id>(static_cast<std::underlying_type_t<message_id>>(lhs) & static_cast<std::underlying_type_t<message_id>>(rhs));
}
inline message_id& operator&=(message_id & lhs, message_id rhs) {
	lhs = lhs & rhs;
	return lhs;
}
inline message_id operator|(message_id lhs, message_id rhs) {
	return static_cast<message_id>(static_cast<std::underlying_type_t<message_id>>(lhs) | static_cast<std::underlying_type_t<message_id>>(rhs));
}
inline message_id& operator|=(message_id & lhs, message_id rhs) {
	lhs = lhs | rhs;
	return lhs;
}

message_type get_type(message_id id);

std::string_view FZSSH_PUBLIC_SYMBOL to_string(message_id id);

enum class disconnect_reason : uint32_t
{
	SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
	SSH_DISCONNECT_PROTOCOL_ERROR = 2,
	SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
	SSH_DISCONNECT_RESERVED = 4,
	SSH_DISCONNECT_MAC_ERROR = 5,
	SSH_DISCONNECT_COMPRESSION_ERROR = 6,
	SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
	SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
	SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
	SSH_DISCONNECT_CONNECTION_LOST = 10,
	SSH_DISCONNECT_BY_APPLICATION = 11,
	SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
	SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
	SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
	SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
};

std::string_view to_string(disconnect_reason reason);

enum class continuation {
	next,
	wait,
	error,
	error_badside,
	error_unimplemented,
	consume_and_wait,
};

enum class keying_state {
	no,
	kex_init_sent,
	kex_init_received, // Received implies sent.
	gex,
	diffie_hellman,
	signing,
	hostkey
};

template<typename T>
class kex_init_data final
{
public:
	T kex_;
	T hostkey_;
	T enc_c2s_;
	T enc_s2c_;
	T mac_c2s_;
	T mac_s2c_;
	T comp_c2s_;
	T comp_s2c_;
	bool guessed_kex_{};
};

enum class service_type {
	none,
	userauth_requested,
	userauth,
	connection
};

class connection_protocol;
struct parameters;
class session;
class userauth;

enum class wait_mode {
	none,
	socket,
	internal,

	socket_failed
};

enum class rekey_buffer_state {
	normal,
	waiting,
	exclusive
};

class FZSSH_PUBLIC_SYMBOL transport : public event_handler
{
public:
	transport(session& sess, parameters const& params, socket_interface & s, bool server, event_handler & h, logger_interface & logger);
	virtual ~transport();

	void stop(bool send_done = true);

	// Always returns continuation::error.
	continuation send_disconnect(disconnect_reason reason_code, std::string_view msg);

	void unblock_read();

	bool service_can_send() const;

	void dump();

	std::string peer_version() const { return peer_version_; }

	virtual continuation on_auth_success() = 0;

	session & session_;

	logger_interface & logger_;
	event_handler & handler_;
	socket_interface & s_;

	std::vector<uint8_t> session_id_;

	service_type service_{};
	std::unique_ptr<userauth> auth_;
	std::unique_ptr<connection_protocol> connection_protocol_;

	algorithm_info algorithms_;
	algorithm_info algorithms_next_;

	bool disconnecting_{};

private:
	void on_socket_event(fz::socket_event_source*, fz::socket_event_flag type, int error);

	void on_recv();
	void on_send();

	continuation do_send();

	continuation read_version();
	continuation process_raw_input();
	continuation process_queued_input();
	continuation process_binary_packet(uint32_t in_seq, message_type type, message_id id, std::string_view packet, bool from_queue);

	continuation process_disconnect(std::string_view packet);
	continuation process_ignore(std::string_view packet);
	continuation process_unimplemented(std::string_view packet);
	continuation process_debug(std::string_view packet);
	continuation process_kexinit(std::string_view packet);
	virtual continuation process_dh_gex_request(std::string_view /*packet*/) { return continuation::error_badside; }
	virtual continuation process_dh_gex_group(std::string_view /*packet*/) { return continuation::error_badside; }
	virtual continuation process_dh_init(std::string_view /*name*/, std::string_view /*packet*/) { return continuation::error_badside; }
	virtual continuation process_dh_reply(std::string_view /*name*/, std::string_view /*packet*/) { return continuation::error_badside; }
	continuation process_newkeys(std::string_view packet);

	virtual continuation process_service_request(std::string_view /*packet*/) { return continuation::error_badside; }
	virtual continuation process_service_accept(std::string_view /*packet*/) { return continuation::error_badside; }

	continuation process_ext_info(std::string_view packet);
	virtual continuation process_ext_info(std::string_view /*name*/, std::string_view /*value*/) { return continuation::next; }

	virtual bool setup_hostkey() = 0;
	virtual std::string_view host_pubkey() const = 0;

	virtual continuation finalize_kexinit(std::string_view peer_hostkeys, bool bad_guess) = 0;
	bool check_rekey();
	bool send_kexinit();

	bool protect_packet(size_t offset, uint32_t payload_size);

	size_t kex_needed_bits_hint() const;

	buffer inbuf_;
	buffer outbuf_;

	bool obtain_buffer_usage_rights();
	void release_buffer_usage_rights();
	rekey_buffer_state rekey_buffer_state_{};
	timer_id rekey_timer_{};

	buffer queued_inbuf_;
	buffer queued_outbuf_;

	bool const server_{};

protected:
	virtual void operator()(event_base const& ev) override;
	void on_exclusive_buffer(monotonic_clock const& deadline);
	void on_timer(timer_id t);

	bool create_dh_keys(std::string_view kex);
	std::tuple<buffer, std::vector<uint8_t>> compute_exchange_hash();
	bool derive_keys(buffer const& shared_secret, std::vector<uint8_t> const& exchange_hash);
	bool init_out();
	bool send_ext_info();

	keying_state keying_{};
	bool initial_kex_{};
	struct gex {
		uint32_t min_{}, n_{}, max_{};
		buffer group_;
	} gex_info_;

	std::unique_ptr<dh_privkey_base> own_dh_;
	std::unique_ptr<dh_pubkey_base> peer_dh_;
	std::optional<kex_type> kex_type_;

	std::map<std::string, std::string, std::less<>> own_ext_info_;

	compatibility_flags compatibility_flags_{};
	compatibility_flags used_compatibility_flags_{};

private:
	friend class packet_builder;

	socket_event read_event_;
	socket_event write_event_;

	hash_algorithm exchange_hash_alg_{};
	buffer peer_kex_payload_;
	buffer own_kex_payload_;
	std::string own_version_;
	std::string peer_version_;
	kex_init_data<std::string> own_kex_init_data_;

	bool strict_kex_extension_{};

	struct state
	{
		uint32_t seq_{};
		std::unique_ptr<cipher_base> enc_;
		std::unique_ptr<mac_base> mac_;

		std::unique_ptr<cipher_base> enc_next_;
		std::unique_ptr<mac_base> mac_next_;

		// For triggering rekeying
		uint64_t payload_{};
		uint64_t max_payload_{uint64_t(-1)};
		uint64_t packets_{};

		bool allow_ext_info_{};
		bool cbc_{};
	};

	state in_;
	state out_;

	bool wait_recv_{true};
	bool skip_recv_{false};

	bool read_version_{true};
	size_t decrypted_{};

	wait_mode wait_send_{wait_mode::socket};
};

class FZSSH_PUBLIC_SYMBOL packet_builder final
{
public:
	packet_builder(transport & s, message_id id, std::string_view const& description = {});
	packet_builder(transport & s, std::string_view data);
	~packet_builder();

	bool commit();

	packet_builder(packet_builder const&) = delete;

	buffer& buf_;

private:
	transport & s_;

	size_t old_size_{};
	bool committed_{};
};

}
}

#endif
