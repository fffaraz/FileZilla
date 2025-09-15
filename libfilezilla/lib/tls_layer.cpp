#include "libfilezilla/tls_layer.hpp"
#include "tls_layer_impl.hpp"

namespace fz {

tls_layer::tls_layer(event_loop& event_loop, event_handler* evt_handler, socket_interface & next_layer, tls_system_trust_store* system_trust_store, logger_interface & logger)
	: event_handler(event_loop)
	, socket_layer(evt_handler, next_layer, false)
{
	impl_ = std::make_unique<tls_layer_impl>(*this, system_trust_store, logger);
	next_layer.set_event_handler(this);
}

tls_layer::~tls_layer()
{
	remove_handler();
}

bool tls_layer::client_handshake(std::vector<uint8_t> const& required_certificate, std::vector<uint8_t> const& session_to_resume, native_string const& session_hostname, tls_client_flags flags)
{
	return impl_->client_handshake(session_to_resume, session_hostname, required_certificate, nullptr, flags);
}

bool tls_layer::client_handshake(event_handler* const verification_handler, std::vector<uint8_t> const& session_to_resume, native_string const& session_hostname, tls_client_flags flags)
{
	return impl_->client_handshake(session_to_resume, session_hostname, std::vector<uint8_t>(), verification_handler, flags);
}

bool tls_layer::server_handshake(std::vector<uint8_t> const& session_to_resume, std::string_view const& preamble, tls_server_flags flags)
{
	return impl_->server_handshake(session_to_resume, preamble, flags);
}

int tls_layer::read(void *buffer, unsigned int size, int& error)
{
	return impl_->read(buffer, size, error);
}

int tls_layer::write(void const* buffer, unsigned int size, int& error)
{
	return impl_->write(buffer, size, error);
}

int tls_layer::shutdown()
{
	return impl_->shutdown();
}

void tls_layer::set_verification_result(bool trusted)
{
	return impl_->set_verification_result(trusted);
}

socket_state tls_layer::get_state() const
{
	return impl_->get_state();
}

std::string tls_layer::get_protocol() const
{
	return impl_->get_protocol();
}

std::string tls_layer::get_key_exchange() const
{
	return impl_->get_key_exchange();
}

std::string tls_layer::get_cipher() const
{
	return impl_->get_cipher();
}

std::string tls_layer::get_mac() const
{
	return impl_->get_mac();
}

int tls_layer::get_algorithm_warnings() const
{
	return impl_->get_algorithm_warnings();
}

bool tls_layer::resumed_session() const
{
	return impl_->resumed_session();
}

std::string tls_layer::list_tls_ciphers(std::string const& priority)
{
	return tls_layer_impl::list_tls_ciphers(priority);
}

bool tls_layer::set_certificate_file(native_string const& keyfile, native_string const& certsfile, native_string const& password, bool pem)
{
	return impl_->set_key_and_certs(tls_filepath(keyfile), tls_filepath(certsfile), password, pem ? tls_data_format::pem : tls_data_format::der);
}

bool tls_layer::set_certificate(std::string_view const& key, std::string_view const& certs, native_string const& password, bool pem)
{
	return impl_->set_key_and_certs(tls_blob(key), tls_blob(certs), password, pem ? tls_data_format::pem : tls_data_format::der);
}

bool tls_layer::set_key_and_certs(const_tls_param_ref key, const_tls_param_ref certs, native_string const& password, tls_data_format format)
{
	return impl_->set_key_and_certs(key, certs, password, format);
}

void tls_layer::operator()(event_base const& ev)
{
	return impl_->operator()(ev);
}

std::string tls_layer::get_gnutls_version()
{
	return tls_layer_impl::get_gnutls_version();
}

std::vector<uint8_t> tls_layer::get_session_parameters() const
{
	return impl_->get_session_parameters();
}

std::vector<uint8_t> tls_layer::get_raw_certificate() const
{
	return impl_->get_raw_certificate();
}

int tls_layer::connect(native_string const& host, unsigned int port, address_type family)
{
	return impl_->connect(host, port, family);
}

std::pair<std::string, std::string> tls_layer::generate_selfsigned_certificate(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, cert_type type, bool ecdsa, logger_interface &logger)
{
	return tls_layer_impl::generate_selfsigned_certificate(password, distinguished_name, hostnames, duration(), type, ecdsa, logger);
}

std::string tls_layer::generate_selfsigned_certificate(const_tls_param_ref key, native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, cert_type type, logger_interface &logger)
{
	return tls_layer_impl::generate_selfsigned_certificate(key, password, distinguished_name, hostnames, duration(), type, logger);
}

std::pair<std::string, std::string> tls_layer::generate_ca_certificate(native_string const& password, std::string const& distinguished_name, duration const& lifetime, bool ecdsa, logger_interface &logger)
{
	return tls_layer_impl::generate_selfsigned_certificate(password, distinguished_name, {}, lifetime, cert_type::ca, ecdsa, logger);
}

std::pair<std::string, std::string> tls_layer::generate_csr(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem, cert_type type, bool ecdsa, logger_interface &logger)
{
	return tls_layer_impl::generate_csr(password, distinguished_name, hostnames, csr_as_pem, type, ecdsa, logger);
}

std::string tls_layer::generate_csr(const_tls_param_ref key, native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem, tls_layer::cert_type type, logger_interface &logger)
{
	return tls_layer_impl::generate_csr(key, password, distinguished_name, hostnames, csr_as_pem, type, logger);
}

std::string tls_layer::generate_cert_from_csr(std::pair<std::string, std::string> const& issuer, native_string const& password, std::string const& csr, std::string const& distinguished_name, std::vector<std::string> const& hostnames, duration const& lifetime, cert_type type, logger_interface &logger)
{
	return tls_layer_impl::generate_cert_from_csr(issuer, password, csr, distinguished_name, hostnames, lifetime, type, logger);
}

bool tls_layer::add_pkcs11_provider(const native_string_view &path, logger_interface &logger)
{
	return tls_layer_impl::add_pkcs11_provider(path, logger);
}

int tls_layer::shutdown_read()
{
	return impl_->shutdown_read();
}

void tls_layer::set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block)
{
	return impl_->set_event_handler(pEvtHandler, retrigger_block);
}

bool tls_layer::set_alpn(std::string_view const& alpn)
{
	if (!impl_) {
		return false;
	}

	impl_->alpn_.clear();
	impl_->alpn_.emplace_back(alpn);
	impl_->alpn_server_priority_ = false;
	return true;
}

bool tls_layer::set_alpn(std::vector<std::string> const& alpn, bool server_priority)
{
	if (!impl_) {
		return false;
	}

	impl_->alpn_ = alpn;
	impl_->alpn_server_priority_ = server_priority;
	return true;
}

std::string tls_layer::get_alpn() const
{
	if (!impl_) {
		return {};
	}

	return impl_->get_alpn();
}

native_string tls_layer::get_hostname() const
{
	if (!impl_) {
		return {};
	}

	return impl_->get_hostname();
}

bool tls_layer::is_server() const
{
	return impl_ ? impl_->server_ : false;
}

void tls_layer::set_min_tls_ver(tls_ver ver)
{
	if (impl_) {
		impl_->set_min_tls_ver(ver);
	}
}

void tls_layer::set_max_tls_ver(tls_ver ver)
{
	if (impl_) {
		impl_->set_max_tls_ver(ver);
	}
}

int tls_layer::new_session_ticket()
{
	return impl_ ? impl_->new_session_ticket() : false;
}

void tls_layer::set_unexpected_eof_cb(std::function<bool()> const& cb)
{
	if (impl_) {
		std::function<bool()> f = cb;
		impl_->set_unexpected_eof_cb(std::move(f));
	}
}

void tls_layer::set_unexpected_eof_cb(std::function<bool()> && cb)
{
	if (impl_) {
		impl_->set_unexpected_eof_cb(std::move(cb));
	}
}

}
