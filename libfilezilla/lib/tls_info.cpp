#include "libfilezilla/tls_info.hpp"
#include "tls_layer_impl.hpp"

namespace fz {
x509_certificate::x509_certificate(
		std::vector<uint8_t> const& rawData,
		datetime const& activation_time, datetime const& expiration_time,
		std::string const& serial,
		std::string const& pkalgoname, unsigned int bits,
		std::string const& signalgoname,
		std::string const& fingerprint_sha256,
		std::string const& fingerprint_sha1,
		std::string const& issuer,
		std::string const& subject,
		std::vector<subject_name> const& alt_subject_names,
		bool const self_signed)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(alt_subject_names)
	, self_signed_(self_signed)
{
}

x509_certificate::x509_certificate(
	std::vector<uint8_t> && rawData,
	datetime const& activation_time, datetime const& expiration_time,
	std::string const& serial,
	std::string const& pkalgoname, unsigned int bits,
	std::string const& signalgoname,
	std::string const& fingerprint_sha256,
	std::string const& fingerprint_sha1,
	std::string const& issuer,
	std::string const& subject,
	std::vector<subject_name> && alt_subject_names,
	bool const self_signed)
	: activation_time_(activation_time)
	, expiration_time_(expiration_time)
	, raw_cert_(rawData)
	, serial_(serial)
	, pkalgoname_(pkalgoname)
	, pkalgobits_(bits)
	, signalgoname_(signalgoname)
	, fingerprint_sha256_(fingerprint_sha256)
	, fingerprint_sha1_(fingerprint_sha1)
	, issuer_(issuer)
	, subject_(subject)
	, alt_subject_names_(alt_subject_names)
	, self_signed_(self_signed)
{
}

tls_session_info::tls_session_info(std::string const& host, unsigned int port,
		std::string const& protocol,
		std::string const& key_exchange,
		std::string const& session_cipher,
		std::string const& session_mac,
		int algorithm_warnings,
		std::vector<x509_certificate> && peer_certificates,
		std::vector<x509_certificate> && system_trust_chain,
		bool hostname_mismatch)
	: host_(host)
	, port_(port)
	, protocol_(protocol)
	, key_exchange_(key_exchange)
	, session_cipher_(session_cipher)
	, session_mac_(session_mac)
	, algorithm_warnings_(algorithm_warnings)
	, peer_certificates_(peer_certificates)
	, system_trust_chain_(system_trust_chain)
	, hostname_mismatch_(hostname_mismatch)
{
}

std::vector<x509_certificate> load_certificates(const_tls_param_ref certs, tls_data_format format, bool sort, logger_interface * logger)
{
	cert_list_holder h;
	if (tls_layer_impl::load_certificates(certs, format, h.certs, h.certs_size, sort, logger) != GNUTLS_E_SUCCESS) {
		return {};
	}

	std::vector<x509_certificate> certificates;
	certificates.reserve(h.certs_size);
	for (unsigned int i = 0; i < h.certs_size; ++i) {
		x509_certificate cert;
		if (tls_layer_impl::extract_cert(h.certs[i], cert, i + 1 == h.certs_size, logger)) {
			certificates.emplace_back(std::move(cert));
		}
		else {
			certificates.clear();
			break;
		}
	}

	return certificates;
}

std::vector<x509_certificate> load_certificates_file(native_string const& certsfile, bool pem, bool sort, logger_interface * logger)
{
	return load_certificates(tls_filepath(certsfile), pem ? tls_data_format::pem : tls_data_format::der, sort, logger);
}

std::vector<x509_certificate> load_certificates(std::string_view const& certdata, bool pem, bool sort, logger_interface * logger)
{
	return load_certificates(tls_blob(certdata), pem ? tls_data_format::pem : tls_data_format::der, sort, logger);
}

native_string check_key_and_certs_status(const_tls_param_ref key, const_tls_param_ref certs, native_string const& password, tls_data_format format)
{
	native_string ret;
	native_string_logger logger(ret, logmsg::error);

	{
		tls_layer_impl::cert_context ctx { logger, false, true };

		if (!ctx) {
			return ret;
		}

		if (!tls_layer_impl::set_key_and_certs(ctx, key, certs, password, format)) {
			return ret;
		}
	}

	auto x059 = load_certificates(certs, format, true, &logger);
	auto now = datetime::now();

	if (now < x059[0].get_activation_time()) {
		tls_layer_impl::log_gnutls_error(logger, GNUTLS_E_NOT_YET_ACTIVATED);
		return ret;
	}

	if (x059[0].get_expiration_time() < now) {
		tls_layer_impl::log_gnutls_error(logger, GNUTLS_E_EXPIRED);
		return ret;
	}

	return {};
}

native_string check_certificate_status(std::string_view const& key, std::string_view const& certs, native_string const& password, bool pem)
{
	return check_key_and_certs_status(tls_blob(key), tls_blob(certs), password, pem ? tls_data_format::pem : tls_data_format::der);
}

}
