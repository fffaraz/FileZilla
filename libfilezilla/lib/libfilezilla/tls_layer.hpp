#ifndef LIBFILEZILLA_TLS_LAYER_HEADER
#define LIBFILEZILLA_TLS_LAYER_HEADER

/** \file
 * \brief A Transport Layer Security (TLS) layer
 */

#include "socket.hpp"
#include "tls_params.hpp"
#include "logger.hpp"

namespace fz {
class tls_system_trust_store;
class tls_session_info;

class tls_layer;
class tls_layer_impl;

struct certificate_verification_event_type;

/** \brief This event gets sent during the handshake with details about the session and the used certificate
 *
 * After receiving this event, \ref tls_layer::set_verification_result needs to be called eventually.
 */
typedef simple_event<certificate_verification_event_type, tls_layer*, tls_session_info> certificate_verification_event;

enum class tls_ver
{
	v1_0,
	v1_1,
	v1_2,
	v1_3
};

enum class tls_server_flags : unsigned int
{
	none = 0,

	/// In TLS 1.3, do not automatically send PSKs after finishing handshake. Ignored if not TLS 1.3
	no_auto_ticket = 0x1,

	/// Used in unit tests. Don't use in production.
	debug_no_tickets = 0x2
};

inline bool operator&(tls_server_flags lhs, tls_server_flags rhs) {
	return (static_cast<std::underlying_type_t<tls_server_flags>>(lhs) & static_cast<std::underlying_type_t<tls_server_flags>>(rhs)) != 0;
}
inline tls_server_flags operator|(tls_server_flags lhs, tls_server_flags rhs) {
	return static_cast<tls_server_flags>(static_cast<std::underlying_type_t<tls_server_flags>>(lhs) | static_cast<std::underlying_type_t<tls_server_flags>>(rhs));
}
inline tls_server_flags& operator|=(tls_server_flags & lhs, tls_server_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}


enum class tls_client_flags : unsigned int
{
	none = 0,

	/// Used in unit tests. Don't use in production.
	debug_no_tickets = 0x1
};

inline bool operator&(tls_client_flags lhs, tls_client_flags rhs) {
	return (static_cast<std::underlying_type_t<tls_client_flags>>(lhs) & static_cast<std::underlying_type_t<tls_client_flags>>(rhs)) != 0;
}
inline tls_client_flags operator|(tls_client_flags lhs, tls_client_flags rhs) {
	return static_cast<tls_client_flags>(static_cast<std::underlying_type_t<tls_client_flags>>(lhs) | static_cast<std::underlying_type_t<tls_client_flags>>(rhs));
}
inline tls_client_flags& operator|=(tls_client_flags & lhs, tls_client_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}

/**
 * \brief A Transport Layer Security (TLS) layer
 *
 * Can be used both for client- and server-side TLS.
 *
 * This class also supports TLS session resumption. Resumption has to be requested
 * explicitly, there is no shared state between unrelated sessions.
 *
 * Two trust models are possible with this class for client-side TLS: Certificates
 * can either be evaluated against the system trust store, or you can implement a
 * custom trust model such as TOFU.
 */
class FZ_PUBLIC_SYMBOL tls_layer final : protected event_handler, public socket_layer
{
public:
	tls_layer(event_loop& event_loop, event_handler* evt_handler, socket_interface& layer, tls_system_trust_store * system_trust_store, logger_interface& logger);
	virtual ~tls_layer() override;

	/**
	 * \brief Starts shaking hands for a new TLS session as client.
	 *
	 * Returns true if the handshake has started, false on error.
	 *
	 * If the handshake is started, wait for a connection event for the result.
	 *
	 * The certificate that eventually gets negotiated for the session
	 * must match the passed \c required_certificate, either in DER or PEM,
	 * or the handshake will fail.
	 */
	bool client_handshake(std::vector<uint8_t> const& required_certificate, std::vector<uint8_t> const& session_to_resume = std::vector<uint8_t>(), native_string const& session_hostname = native_string(), tls_client_flags flags = {});

	/**
	 * \brief Starts shaking hands for a new TLS session as client.
	 *
	 * Returns true if the handshake has started, false on error.
	 *
	 * If the handshake is started, wait for a connection event for the result.
	 *
	 * If no verification handler is passed, verification is done solely using the system
	 * trust store.
	 *
	 * If a verification handler is passed, it will receive a
	 * \ref certificate_verification_event event upon which the handshake is paused until
	 * \ref set_verification_result gets called including a \ref tls_session_info structure.
	 * The handler is called even for certificates not trusted by the system trust store, allowing
	 * the following impairments: Unknown issuer, wrong hostname and certificates used outside their validity time.
	 */
	bool client_handshake(event_handler *const verification_handler, std::vector<uint8_t> const& session_to_resume = std::vector<uint8_t>(), native_string const& session_hostname = native_string(), tls_client_flags flags = {});

	/**
	 * \brief Starts shaking hand for a new TLS session as server.
	 *
	 * Returns true if the handshake has started, false on error.
	 *
	 * If the handshake is started, wait for a connection event for the result.
	 *
	 * Before calling server_handshake, a valid certificate and key must be passed
	 * in through \ref set_certificate.
	 *
	 * Session parameters of an existing session can be passed to allow session resumption. Check after handshake completion
	 * with resumed_session()
	 *
	 * The preamble is sent out after setting up all the parameters, but before the first handshake message
	 */
	bool server_handshake(std::vector<uint8_t> const& session_to_resume = {}, std::string_view const& preamble = {}, tls_server_flags flags = {});

	/// Gets session parameters for resumption
	std::vector<uint8_t> get_session_parameters() const;

	/// Gets the session's peer certificate in DER
	std::vector<uint8_t> get_raw_certificate() const;

	/**
	 * \brief Must be called after having received certificate_verification_event
	 *
	 * Can be used to trust a certificate even if it is not trusted via the system trust store.
	 */
	void set_verification_result(bool trusted);

	std::string get_protocol() const;

	std::string get_key_exchange() const;
	std::string get_cipher() const;
	std::string get_mac() const;
	int get_algorithm_warnings() const;

	/// After a successful handshake, returns whether the session has been resumed.
	bool resumed_session() const;

	/// Returns a human-readable list of all TLS ciphers available with the passed priority string
	static std::string list_tls_ciphers(std::string const& priority);

	/** \brief Sets the file containing the certificate (and its chain) and the file with the corresponding private key.
	 *
	 * For servers a certificate is mandatory, it is presented to the client during the handshake.
	 *
	 * For clients it is the optional client certificate.
	 *
	 * If the pem flag is set, the input is assumed to be in PEM, otherwise DER.
	 */
	bool set_certificate_file(native_string const& keyfile, native_string const& certsfile, native_string const& password, bool pem = true);

	/** \brief Sets the certificate (and its chain) and the private key
	 *
	 * For servers it is mandatory and is the certificate the server presents to the client.
	 *
	 * For clients it is the optional client certificate.
	 *
	 * If the pem flag is set, the input is assumed to be in PEM, otherwise DER.
	 */
	bool set_certificate(std::string_view const& key, std::string_view const& certs, native_string const& password, bool pem = true);

	/** \brief Sets the certificate (and its chain) and the private key
	 *
	 * For servers it is mandatory and is the certificate the server presents to the client.
	 *
	 * For clients it is the optional client certificate.
	 *
	 * The key and the certs can be:
	 *   1. located on the filesystem, via a tls_filepath instance;
	 *   2. reacheble via a pkcs11 URL, via a tls_pkcs11url instance;
	 *   3. blobs of data in memory, via a tls_blob instance;
	 *
	 * The format parameter applies only to certs and key that are not referenced by a pkcs11 url. If set to pem or der,
	 * then the certs and key are all expected to be in PEM or DER format respectively, otherwise the format is automatically
	 * detected for the key and certs indepedently.
	 */
	bool set_key_and_certs(const_tls_param_ref key, const_tls_param_ref certs, native_string const &password, tls_data_format format = tls_data_format::autodetect);

	/// Returns the version of the loaded GnuTLS library, may be different than the version used at compile-time.
	static std::string get_gnutls_version();

	/// Type of certificate to create.
	enum class cert_type {
		any, /// Except ca. Includes, but is not limited to, client and server.
		client,
		server,
		ca,
		codesign
	};

	/** \brief Creates a new private key and a self-signed certificate.
	 *
	 * The distinguished name must be a RFC4514-compliant string.
	 *
	 * If the password is non-empty, the private key gets encrypted using it.
	 *
	 * The output pair is in PEM, first element is the key and the second the certificate.
	 */
	static std::pair<std::string, std::string> generate_selfsigned_certificate(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, cert_type type = cert_type::any, bool ecdsa = true, logger_interface &logger = get_null_logger());

	/** \brief Creates a new a self-signed certificate using the private key in the provided file.
	 *
	 * The key file can also be a blob of data or a pkcs11 URL.
	 *
	 * The distinguished name must be a RFC4514-compliant string.
	 *
	 * The provided password is used to decrypt the key or, if it's a pkcs11 URL, to access it.
	 *
	 * The output is in PEM.
	 *
	 * The format of the key is automatically detected.
	 */
	static std::string generate_selfsigned_certificate(const_tls_param_ref key, native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, cert_type type = cert_type::any, logger_interface &logger = get_null_logger());

	/// Creates CA certificate.
	static std::pair<std::string, std::string> generate_ca_certificate(native_string const& password, std::string const& distinguished_name, duration const& lifetime = {}, bool ecdsa = true, logger_interface &logger = get_null_logger());

	/// Creates a CSR
	static std::pair<std::string, std::string> generate_csr(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem = true, cert_type type = cert_type::any, bool ecdsa = true, logger_interface &logger = get_null_logger());

	/// Creates a CSR with the provided private key
	static std::string generate_csr(const_tls_param_ref key, native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem, tls_layer::cert_type type = cert_type::any, logger_interface &logger = get_null_logger());

	/**
	 * \brief Creates a certificate from a CSR.
	 *
	 * If DN and hostnames are not given, the DN/hostnames from the CSR are taken.
	 */
	static std::string generate_cert_from_csr(std::pair<std::string, std::string> const& issuer, native_string const& password, std::string const& csr, std::string const& distinguished_name = {}, std::vector<std::string> const& hostnames = {}, duration const& lifetime = {}, cert_type type = cert_type::any, logger_interface &logger = get_null_logger());

	/**
	 * \brief Add a PKCS#11 provider to the internal list of providers
	 *
	 * By invoking this function, the global PKCS#11 configuration is ignored for the lifetime of the application.
	 *
	 * Note: this function is not thread safe.
	 */
	static bool add_pkcs11_provider(native_string_view const &path, logger_interface &logger = get_null_logger());

	/** \brief Negotiate application protocol
	 *
	 * If the peer makes use of ALPN, the handshake fails if no matching protocol is found.
	 * If the peer does not use/support ALPN, the handshake continues and no protocol is negotiated.
	 *
	 * Needs to be called prior to handshaking.
	 *
	 * Which protocol is eventually chosen is always a server-side decsion.
	 * Iff running as server, server_priority controls the ALPN should be chosen
	 * based on the server's or the client's order in the list of ALPNs supported
	 * by both. server_priority is ignored if unning as client.
	 */
	bool set_alpn(std::string_view const& alpn);
	bool set_alpn(std::vector<std::string> const& alpns, bool server_priority = false);

	/** \brief Sets minimum allowed TLS version
	 */
	void set_min_tls_ver(tls_ver ver);

	/** \brief Sets maximum allowed TLS versions
	 *
	 * Don't set a max version in production, it is for testing things.
	 */
	void set_max_tls_ver(tls_ver ver);

	/// After a successful handshake, returns which protocol, if any, has been negotiated
	std::string get_alpn() const;

	/// If running as server, get the SNI sent by the client
	native_string get_hostname() const;

	bool is_server() const;

	/** \brief If running as server with TLS1.3, send out a new session ticket before the next data payload.
	 *
	 * Returns 0 on success, socket error otheerwise. Never returns EAGAIN.
	 *
	 * It's a NOOP if TLS version != 1.3
	 *
	 * Returns EINVAL if not server.
	 */
	int new_session_ticket();

	/** \brief Sets a callback to control whether unexpected eof is seen as error
	 *
	 * With TLS, an EOF on the socket prior to receiving a closure alert normally is an error.
	 * In many cases this is harmless though, e.g. if the connection is idle.
	 *
	 * If this callback is set, premature termination is no longer seen as error if the
	 * callback returns false.
	 *
	 * Callback must not call any tls_layer function.
	 *
	 * Only controls the layer's own logging. Functions such as read will still return
	 * ECONNABORTED.
	 */
	void set_unexpected_eof_cb(std::function<bool()> const& cb);
	void set_unexpected_eof_cb(std::function<bool()> && cb);

	virtual socket_state get_state() const override;

	virtual int connect(native_string const& host, unsigned int port, address_type family = address_type::unknown) override;

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	virtual int shutdown() override;

	virtual int shutdown_read() override;

	virtual void set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block = socket_event_flag{}) override;

	/// PKCS#11 support depends on how GnuTLS got configured.
	static bool supports_pkcs11();

private:
	virtual void FZ_PRIVATE_SYMBOL operator()(event_base const& ev) override;

	friend class tls_layer_impl;
	std::unique_ptr<tls_layer_impl> impl_;
};
}

#endif
