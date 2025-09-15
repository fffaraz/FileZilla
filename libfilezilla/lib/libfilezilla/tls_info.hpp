#ifndef LIBFILEZILLA_TLS_INFO_HEADER
#define LIBFILEZILLA_TLS_INFO_HEADER

/** \file
 * \brief Classes to query parameters of a TLS session, including the certificate chain
 */

#include "time.hpp"
#include "tls_params.hpp"

namespace fz {
class logger_interface;

/**
 * \brief Represents all relevant information of a X.509 certificate as used by TLS.
 */
class FZ_PUBLIC_SYMBOL x509_certificate final
{
public:
	/// A subject name, typically a DNS hostname
	class subject_name final
	{
	public:
		std::string name;
		bool is_dns{};
	};

	x509_certificate() = default;
	~x509_certificate() noexcept = default;
	x509_certificate(x509_certificate const&) = default;
	x509_certificate(x509_certificate&&) noexcept = default;
	x509_certificate& operator=(x509_certificate const&) = default;
	x509_certificate& operator=(x509_certificate&&) noexcept = default;

	x509_certificate(
		std::vector<uint8_t> const& rawData,
		fz::datetime const& activation_time, fz::datetime const& expiration_time,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<subject_name> const& alt_subject_names,
		bool const self_signed);

	x509_certificate(
		std::vector<uint8_t> && rawdata,
		fz::datetime const& activation_time, fz::datetime const& expiration_time,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<subject_name> && alt_subject_names,
		bool const self_Signed);


	/// The raw, DER-encoded X.509 certificate
	std::vector<uint8_t> get_raw_data() const { return raw_cert_; }

	fz::datetime const& get_activation_time() const { return activation_time_; }
	fz::datetime const& get_expiration_time() const { return expiration_time_; }

	std::string const& get_serial() const { return serial_; }

	/// The public key algorithm used by the certificate
	std::string const& get_pubkey_algorithm() const { return pkalgoname_; }

	/// The number of bits of the public key algorithm
	unsigned int get_pubkey_bits() const { return pkalgobits_; }

	/// The algorithm used for signing, typically the public key algorithm combined with a hash
	std::string const& get_signature_algorithm() const { return signalgoname_; }

	/// Gets fingerprint as hex-encoded sha256
	std::string const& get_fingerprint_sha256() const { return fingerprint_sha256_; }

	/// Gets fingerprint as hex-encoded sha1
	std::string const& get_fingerprint_sha1() const { return fingerprint_sha1_; }

	/** \brief Gets the subject of the certificate as RDN as described in RFC4514
	 *
	 * Never use the CN field to compare it against a hostname, that's what the SANs are for.
	 */
	std::string const& get_subject() const { return subject_; }

	/// Gets the issuer of the certificate as RDN as described in RFC4514
	std::string const& get_issuer() const { return issuer_; }

	/// Gets the alternative subject names (SANSs) of the certificated, usually hostnames
	std::vector<subject_name> const& get_alt_subject_names() const { return alt_subject_names_; }

	explicit operator bool() const { return !raw_cert_.empty(); }

	/// Indicates whether the certificate is self-signed
	bool self_signed() const { return self_signed_; }

private:
	fz::datetime activation_time_;
	fz::datetime expiration_time_;

	std::vector<uint8_t> raw_cert_;

	std::string serial_;
	std::string pkalgoname_;
	unsigned int pkalgobits_{};

	std::string signalgoname_;

	std::string fingerprint_sha256_;
	std::string fingerprint_sha1_;

	std::string issuer_;
	std::string subject_;

	std::vector<subject_name> alt_subject_names_;

	bool self_signed_{};
};

/**
 * \brief Gets the certificate information for the certificates in the file.
 *
 * If the sort flag is not set, certificates are returned in input order.
 * If the sort flag is set, a chain is built, with certificate i signed by i+1.
 * If building the chain fails, nothing is returned.
 */
std::vector<x509_certificate> FZ_PUBLIC_SYMBOL load_certificates_file(native_string const& certsfile, bool pem, bool sort, logger_interface * logger = nullptr);
std::vector<x509_certificate> FZ_PUBLIC_SYMBOL load_certificates(std::string_view const& certdata, bool pem, bool sort, logger_interface * logger = nullptr);
std::vector<x509_certificate> FZ_PUBLIC_SYMBOL load_certificates(const_tls_param_ref cert, tls_data_format format, bool sort, logger_interface * logger = nullptr);

/** \brief Checks that the key and certificates chain are valid and matching.
 *
 * If the password is non-empty, the private key is assumed to having been encrypted using it.
 *
 * If the pem flag is set, the input is assumed to be in PEM, otherwise DER.
 *
 * Returns an error string. If empty, then the check was successful.
 */
native_string FZ_PUBLIC_SYMBOL check_certificate_status(std::string_view const& key, std::string_view const& certs, native_string const& password, bool pem = true);

/** \brief Checks that the key and certificates chain contained in the files are valid and matching
 *
 * The key and the certs can be:
 *   1. located on the filesystem, via a tls_filepath instance;
 *   2. reacheble via a pkcs11 URL, via a tls_pkcs11url instance;
 *   3. blobs of data in memory, via a tls_blob instance;
 *
 * The format parameter applies only to certs and key that are not referenced by a pkcs11 url. If set to pem or der,
 * then the certs and key are all expected to be in PEM or DER format respectively, otherwise the format is automatically
 * detected for the key and certs indepedently.
 *
 * If the password is non-empty, the private key is assumed to having been encrypted using it;
 * If the key is referenced by a pkcs11 url, the password is used to gain access to it.
 *
 * Returns an error string. If empty, then the check was successful.
 */
native_string FZ_PUBLIC_SYMBOL check_key_and_certs_status(const_tls_param_ref key, const_tls_param_ref certs, native_string const& password, tls_data_format format = tls_data_format::autodetect);

/**
 * \brief Information about a TLS session
 *
 * Includes information about the used ciphers and details on the certificates
 * sent by the server.
 *
 * Includes flags whether the certificate chain is trusted by the system
 * trust store and whether the expected hostname matches.
 */
class FZ_PUBLIC_SYMBOL tls_session_info final
{
public:
	tls_session_info() = default;
	~tls_session_info() = default;
	tls_session_info(tls_session_info const&) = default;
	tls_session_info(tls_session_info&&) noexcept = default;
	tls_session_info& operator=(tls_session_info const&) = default;
	tls_session_info& operator=(tls_session_info&&) noexcept = default;

	tls_session_info(std::string const& host, unsigned int port,
		std::string const& protocol,
		std::string const& key_exchange,
		std::string const& session_cipher,
		std::string const& session_mac,
		int algorithm_warnings,
		std::vector<x509_certificate>&& peer_certificates,
		std::vector<x509_certificate>&& system_trust_chain,
		bool hostname_mismatch);

	/// The server's hostname used to connect
	std::string const& get_host() const { return host_; }

	/// The server's port
	unsigned int get_port() const { return port_; }

	/// The symmetric algorithm used to encrypt all exchanged application data
	std::string const& get_session_cipher() const { return session_cipher_; }

	/// The MAC used for integrity-protect and authenticate the exchanged application data
	std::string const& get_session_mac() const { return session_mac_; }

	/** \brief The server's certificate chain
	 *
	 * The chain is ordered from the server's own certificate at index 0 up to the self-signed
	 * root CA.
	 *
	 * Chain may be partial, ie. not ending at a self-signed cert.
	 *
	 * If system_trust() is set, this is the chain to the actual trust anchor which may differ from the
	 * chain sent by the server.
	 *
	 * If system_trust() is not set, it is chain as received from the server, after sorting.
	 */
	std::vector<fz::x509_certificate> const& get_certificates() const { return system_trust_chain_.empty() ? peer_certificates_ : system_trust_chain_; }

	/** \brief The certificate chain sent by the peer
	 *
	 * The chain is ordered from the server's own certificate at index 0 up to the self-signed
	 * root CA.
	 *
	 * Chain may be partial, ie. not ending at a self-signed cert.
	 *
	 * This is is chain as received from the server, after sorting. \sa get_certificates()
	 */
	std::vector<fz::x509_certificate> const& get_peer_certificates() const { return peer_certificates_; }

	/// TLS version
	std::string const& get_protocol() const { return protocol_; }

	/// Key exchange algorithm
	std::string const& get_key_exchange() const { return key_exchange_; }

	enum algorithm_warnings_t
	{
		tlsver = 1,
		cipher = 2,
		mac = 4,
		kex = 8
	};

	/// Warnings about old algorithms used, which are considered weak
	int get_algorithm_warnings() const { return algorithm_warnings_; }

	/// Returns true if the server certificate is to be trusted according to
	/// the operating system's trust store.
	bool system_trust() const { return !system_trust_chain_.empty(); }

	/// True if the hostname in the SANs does not match the requested hostname
	bool mismatched_hostname() const { return hostname_mismatch_; }

private:
	std::string host_;
	unsigned int port_{};

	std::string protocol_;
	std::string key_exchange_;
	std::string session_cipher_;
	std::string session_mac_;
	int algorithm_warnings_{};

	std::vector<x509_certificate> peer_certificates_;
	std::vector<x509_certificate> system_trust_chain_;

	bool hostname_mismatch_{};
};
}

#endif
