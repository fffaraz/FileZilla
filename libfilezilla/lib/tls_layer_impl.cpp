#include "libfilezilla/tls_layer.hpp"
#include "tls_layer_impl.hpp"
#include "libfilezilla/tls_info.hpp"
#include "tls_system_trust_store_impl.hpp"

#include "libfilezilla/file.hpp"
#include "libfilezilla/iputils.hpp"
#include "libfilezilla/translate.hpp"
#include "libfilezilla/util.hpp"

#include <gnutls/x509.h>

#include <algorithm>
#include <set>

#include <string.h>

// In case GnuTLS has been compiled without PKCS#11 support
#if FZ_WINDOWS
#include "libfilezilla/glue/dll.hpp"

namespace fz {
dll& get_gnutls_dll() {
	static dll gnutls_dll = dll::from_address(gnutls_malloc);
	return gnutls_dll;
}

#define dynamic_gnutls_func(f) \
	reinterpret_cast<decltype(&f)>(get_gnutls_dll()[ #f ])
}

#else

#include <dlfcn.h>

#define dynamic_gnutls_func(f) \
	reinterpret_cast<decltype(&f)>(dlsym(RTLD_DEFAULT, #f))

#endif

using namespace std::literals;

#if DEBUG_SOCKETEVENTS
#include <assert.h>

namespace fz {
bool FZ_PRIVATE_SYMBOL has_pending_event(event_handler * handler, socket_event_source const* const source, socket_event_flag event);
}
#endif

namespace fz {

namespace {

#if FZ_USE_GNUTLS_SYSTEM_CIPHERS
char const ciphers[] = "@SYSTEM:-ARCFOUR-128:-3DES-CBC:-MD5:-SIGN-RSA-MD5:-VERS-SSL3.0";
#else
	char const ciphers[] = "SECURE256:+SECURE128:-ARCFOUR-128:-3DES-CBC:-MD5:+SIGN-ALL:-SIGN-RSA-MD5:+CTYPE-X509:-VERS-SSL3.0";
#endif

#define TLSDEBUG 0
#if TLSDEBUG
// This is quite ugly
logger_interface* pLogging;
extern "C" void log_func(int level, char const* msg)
{
	if (!msg || !pLogging) {
		return;
	}
	std::wstring s = to_wstring(msg);
	trim(s);
	pLogging->log(logmsg::debug_debug, L"tls: %d %s", level, s);
}
#endif

void remove_verification_events(event_handler* handler, tls_layer const* const source)
{
	if (!handler) {
		return;
	}

	auto event_filter = [&](event_base const& ev) -> bool {
		if (ev.derived_type() == certificate_verification_event::type()) {
			return std::get<0>(static_cast<certificate_verification_event const&>(ev).v_) == source;
		}
		return false;
	};

	handler->filter_events(event_filter);
}

extern "C" ssize_t c_push_function(gnutls_transport_ptr_t ptr, const void* data, size_t len)
{
	return ((tls_layer_impl*)ptr)->push_function(data, len);
}

extern "C" ssize_t c_pull_function(gnutls_transport_ptr_t ptr, void* data, size_t len)
{
	return ((tls_layer_impl*)ptr)->pull_function(data, len);
}
}

class tls_layerCallbacks
{
public:
	static int handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming)
	{
		if (!session) {
			return 0;
		}
		auto* tls = reinterpret_cast<tls_layer_impl*>(gnutls_session_get_ptr(session));
		if (!tls) {
			return 0;
		}

		char const* prefix;
		if (incoming) {
			if (post) {
				prefix = "Processed";
			}
			else {
				prefix = "Received";
			}
		}
		else {
			if (post) {
				prefix = "Sent";
			}
			else {
				prefix = "About to send";
			}
		}

		char const* name = gnutls_handshake_description_get_name(static_cast<gnutls_handshake_description_t>(htype));

		tls->logger_.log(logmsg::debug_debug, L"TLS handshakep: %s %s", prefix, name);

		return 0;
	}

	static int store_session(void* ptr, gnutls_datum_t const& key, gnutls_datum_t const& data)
	{
		auto* tls = reinterpret_cast<tls_layer_impl*>(ptr);
		if (!tls) {
			return 0;
		}
		if (!key.size || !data.size) {
			return 0;
		}
		tls->session_db_key_.resize(key.size);
		memcpy(tls->session_db_key_.data(), key.data, key.size);
		tls->session_db_data_.resize(data.size);
		memcpy(tls->session_db_data_.data(), data.data, data.size);

		return 0;
	}

	static gnutls_datum_t retrieve_session(void *ptr, gnutls_datum_t key)
	{
		auto* tls = reinterpret_cast<tls_layer_impl*>(ptr);
		if (!tls) {
			return {};
		}
		if (!key.size) {
			return {};
		}

		if (key.size == tls->session_db_key_.size() && !memcmp(tls->session_db_key_.data(), key.data, key.size)) {
			gnutls_datum_t d{};
			d.data = reinterpret_cast<unsigned char*>(gnutls_malloc(tls->session_db_data_.size()));
			if (d.data) {
				d.size = tls->session_db_data_.size();
				memcpy(d.data, tls->session_db_data_.data(), d.size);
			}
			return d;
		}

		return gnutls_datum_t{};
	}

	static void verify_output_cb(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crl_t crl, unsigned int verification_output)
	{
		if (verify_output_cb_) {
			verify_output_cb_(cert, issuer, crl, verification_output);
		}
	}
	static thread_local std::function<void(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crl_t crl, unsigned int verification_output)> verify_output_cb_;

	static int pin_callback(void *userdata, int attempt, const char *token_url, const char *token_label, unsigned int flags, char *pin, size_t pin_max)
	{
		tls_layer_impl::cert_context &c = *static_cast<tls_layer_impl::cert_context*>(userdata);

		if (!(flags & GNUTLS_PIN_USER)) {
			c.logger.log_u(logmsg::error, fztranslate("Wrong type of PIN requested. Flags: %d, Token: %s, URL: %s."), flags, token_label, token_url);
			return GNUTLS_E_PKCS11_PIN_ERROR;
		}

		if (flags & GNUTLS_PIN_WRONG) {
			c.logger.log_u(logmsg::debug_warning, fztranslate("The last tried PIN was wrong. Token: %s, URL: %s."), token_label, token_url);
			return GNUTLS_E_PKCS11_PIN_ERROR;
		}

		if (attempt == 0) {
			if (c.pin.size() + 1 > pin_max) {
				c.logger.log_u(logmsg::error, fztranslate("PIN length (%d) exceeds the maximum (%d). Token: %s, URL: %s"), c.pin.size(), pin_max, token_label, token_url);
				return GNUTLS_E_PKCS11_PIN_ERROR;
			}

			if (flags & GNUTLS_PIN_COUNT_LOW) {
				c.logger.log_u(logmsg::debug_warning, fztranslate("Only few PIN tries remaining before the token is locked. Token: %s, URL: %s."), token_label, token_url);
			}
			else if (flags & GNUTLS_PIN_FINAL_TRY) {
				c.logger.log_u(logmsg::debug_warning, fztranslate("This is the last PIN try remaining before the token is locked. Token: %s, URL: %s."), token_label, token_url);
			}
			else {
				c.logger.log_u(logmsg::debug_info, fztranslate("Attempting to use PIN. Token: %s, URL: %s."), token_label, token_url);
			}

			memcpy(pin, c.pin.c_str(), c.pin.size()+1);

			return 0;
		}

		c.logger.log_u(logmsg::error, fztranslate("Too many attempts (%d) while trying the PIN. Token: %s, URL: %s."), attempt+1, token_label, token_url);

		return GNUTLS_E_PKCS11_PIN_ERROR;
	}
};
thread_local std::function<void(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crl_t crl, unsigned int verification_output)> tls_layerCallbacks::verify_output_cb_;

std::string_view FZ_PRIVATE_SYMBOL to_view(gnutls_datum_t const& d)
{
	if (d.data && d.size) {
		return std::string_view(reinterpret_cast<char const*>(d.data), d.size);
	}
	return {};
}

namespace {
extern "C" int handshake_hook_func(gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming, gnutls_datum_t const*)
{
	return tls_layerCallbacks::handshake_hook_func(session, htype, post, incoming);
}

extern "C" int db_store_func(void *ptr, gnutls_datum_t key, gnutls_datum_t data)
{
	return tls_layerCallbacks::store_session(ptr, key, data);
}

extern "C" gnutls_datum_t db_retr_func(void *ptr, gnutls_datum_t key)
{
	return tls_layerCallbacks::retrieve_session(ptr, key);
}
extern "C" int c_verify_output_cb(gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crl_t crl, unsigned int verification_output)
{
	tls_layerCallbacks::verify_output_cb(cert, issuer, crl, verification_output);
	return 0;
}

std::string to_string(gnutls_datum_t const& d)
{
	if (d.data && d.size) {
		return std::string(d.data, d.data + d.size);
	}
	return {};
}

struct datum_holder final : gnutls_datum_t
{
	datum_holder() {
		data = nullptr;
		size = 0;
	}

	~datum_holder() {
		gnutls_free(data);
	}

	void clear()
	{
		gnutls_free(data);
		data = nullptr;
		size = 0;
	}

	datum_holder(datum_holder const&) = delete;
	datum_holder& operator=(datum_holder const&) = delete;

	std::string to_string() const {
		return data ? std::string(data, data + size) : std::string();
	}

	std::string_view to_string_view() const {
		return data ? std::string_view(reinterpret_cast<char *>(data), size) : std::string_view();
	}
};

void clone_cert(gnutls_x509_crt_t in, gnutls_x509_crt_t &out)
{
	gnutls_x509_crt_deinit(out);
	out = nullptr;

	if (in) {
		datum_holder der;
		if (gnutls_x509_crt_export2(in, GNUTLS_X509_FMT_DER, &der) == GNUTLS_E_SUCCESS) {
			gnutls_x509_crt_init(&out);
			if (gnutls_x509_crt_import(out, &der, GNUTLS_X509_FMT_DER) != GNUTLS_E_SUCCESS) {
				gnutls_x509_crt_deinit(out);
				out = nullptr;
			}
		}
	}
}
}

tls_layer_impl::tls_layer_impl(tls_layer& layer, tls_system_trust_store* systemTrustStore, logger_interface & logger)
	: tls_layer_(layer)
	, logger_(logger)
	, system_trust_store_(systemTrustStore)
{
}

tls_layer_impl::~tls_layer_impl()
{
	deinit();
}

bool tls_layer_impl::cert_context::init()
{
	if (!credentials) {
		int res = gnutls_certificate_allocate_credentials(&credentials);
		if (res < 0) {
			log_gnutls_error(res, L"gnutls_certificate_allocate_credentials"sv);
			return false;
		}
	}

	return true;
}

bool tls_layer_impl::init()
{
	// This function initializes GnuTLS
	if (!initialized_) {
		initialized_ = true;
		int res = gnutls_global_init();
		if (res) {
			log_error(res, L"gnutls_global_init"sv);
			deinit();
			return false;
		}

#if TLSDEBUG
		if (!pLogging) {
			pLogging = &logger_;
			gnutls_global_set_log_function(log_func);
			gnutls_global_set_log_level(99);
		}
#endif
	}

	if (!cert_context_.init()) {
		deinit();
		return false;
	}

	return true;
}

static std::string read_file(native_string const& path, bool cert, logger_interface * logger)
{
	file cf(path, file::reading, file::existing);
	if (!cf.opened()) {
		if (logger) {
			auto format = cert
				? fztranslate("Could not open certificate file.")
				: fztranslate("Could not open key file.");

			logger->log_raw(logmsg::error, format);
		}
		return {};
	}
	int64_t const cs = cf.size();
	if (cs < 0 || cs > 1024 * 1024) {
		if (logger) {
			auto format = cert
				? fztranslate("Certificate file too big.")
				: fztranslate("Key file too big.");

			logger->log_raw(logmsg::error, format);
		}
		return {};
	}
	std::string c;
	c.resize(cs);
	auto read = cf.read2(c.data(), static_cast<size_t>(cs));
	if (!read || read.value_ != static_cast<size_t>(cs)) {
		if (logger) {
			auto format = cert
				? fztranslate("Could not read certificate file.")
				: fztranslate("Could not key file.");

			logger->log_raw(logmsg::error, format);
		}
		return {};
	}
	return c;
}

static std::string read_certificates_file(native_string const& certsfile, logger_interface * logger)
{
	return read_file(certsfile, true, logger);
}

static std::string read_key_file(native_string const& keyfile, logger_interface * logger)
{
	return read_file(keyfile, false, logger);
}

static bool is_pem(std::string_view blob, tls_data_format format)
{
	if (format == tls_data_format::autodetect) {
		return is_pem(blob);
	}

	return format == tls_data_format::pem;
}

unique_gnutls_privkey tls_layer_impl::import_private_key(cert_context &ctx, const_tls_param_ref key, native_string const& password, tls_data_format format)
{
	unique_gnutls_privkey k;

	{
		gnutls_privkey_t priv;
		int res = gnutls_privkey_init(&priv);
		if (res < 0) {
			ctx.log_gnutls_error(res, L"gnutls_privkey_init"sv);
			return nullptr;
		}

		k.reset(priv);
	}


	if (auto url = key.pkcs11url()) {
		if (!*url) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Invalid pkcs11 URL in key"));
			return nullptr;
		}

		ctx.pin = to_utf8(password);
		gnutls_privkey_set_pin_function(k.get(), tls_layerCallbacks::pin_callback, &ctx);

		int res = gnutls_privkey_import_url(k.get(), url->value.c_str(), 0);
		if (res < 0) {
			ctx.log_gnutls_error(res, L"gnutls_privkey_import_url"sv);
			return nullptr;
		}

		return k;
	}

	auto import_raw = [&](unique_gnutls_privkey k, std::string_view blob) -> unique_gnutls_privkey {
		bool pem = is_pem(blob, format);

		gnutls_datum_t d;
		d.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(blob.data()));
		d.size = blob.size();

		int res = gnutls_privkey_import_x509_raw(k.get(), &d, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER,
												 to_utf8(password).c_str(), 0);

		if (res < 0) {
			ctx.log_gnutls_error(res, L"gnutls_privkey_import_x509_raw"sv);
			return nullptr;
		}

		return k;
	};

	if (auto keyfile = key.filepath()) {
		if (!*keyfile) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Invalid file path for key"));
			return nullptr;
		}

		auto blob = read_key_file(keyfile->value, &ctx.logger);
		if (blob.empty()) {
			return nullptr;
		}

		return import_raw(std::move(k), blob);
	}

	if (auto blob = key.blob()) {
		if (!*blob) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Invalid data blob for key"));
			return nullptr;
		}

		return import_raw(std::move(k), blob->value);
	}

	ctx.logger.log_raw(logmsg::error, fztranslate("Internal error: invalid key"));

	return nullptr;
}

std::vector<gnutls_pcert_st> tls_layer_impl::import_certs(cert_context &ctx, const_tls_param_ref certs, tls_data_format format)
{
	if (certs.pkcs11url()) {
		ctx.logger.log_raw(logmsg::error, fztranslate("PKCS11 URLs not supported yet for certificates"));
		return {};
	}

	auto import_raw = [&](std::string_view blob) -> std::vector<gnutls_pcert_st> {
		bool pem = is_pem(blob, format);

		gnutls_datum_t d;
		d.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(blob.data()));
		d.size = blob.size();

		unsigned int num_certs = 0;
		int res = gnutls_pcert_list_import_x509_raw(nullptr, &num_certs, &d, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
		if (res != GNUTLS_E_SHORT_MEMORY_BUFFER) {
			ctx.log_gnutls_error(res, L"gnutls_pcert_list_import_x509_raw count"sv);
			return {};
		}

		std::vector<gnutls_pcert_st> pcerts(num_certs);
		res = gnutls_pcert_list_import_x509_raw(pcerts.data(), &num_certs, &d, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED);
		if (res != 0) {
			ctx.log_gnutls_error(res, L"gnutls_pcert_list_import_x509_raw"sv);
			return {};
		}

		return pcerts;
	};

	if (auto certsfile = certs.filepath()) {
		if (!*certsfile) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Invalid file path for certificates"));
			return {};
		}

		auto blob = read_certificates_file(certsfile->value, &ctx.logger);
		if (blob.empty()) {
			return {};
		}

		return import_raw(blob);
	}

	if (auto blob = certs.blob()) {
		if (!*blob) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Invalid data blob for certificates"));
			return {};
		}

		return import_raw(blob->value);
	}

	ctx.logger.log_raw(logmsg::error, fztranslate("Internal error: invalid certs"));

	return {};
}

bool tls_layer_impl::set_key_and_certs(cert_context &ctx, const_tls_param_ref key, const_tls_param_ref certs, native_string const& password, tls_data_format format)
{
	if (!ctx.credentials) {
		return false;
	}

	auto cs = import_certs(ctx, certs, format);
	if (cs.empty()) {
		return false;
	}

	auto k = import_private_key(ctx, key, password, format);
	if (!k) {
		return false;
	}

	int res = gnutls_certificate_set_key(ctx.credentials, nullptr, 0, cs.data(), cs.size(), k.get());
	if (res < 0) {
		ctx.log_gnutls_error(res, L"gnutls_certificate_set_key"sv);

		for (auto &c: cs) {
			gnutls_pcert_deinit(&c);
		}

		return false;
	}

	k.release();

	return true;
}

bool tls_layer_impl::set_key_and_certs(const_tls_param_ref key, const_tls_param_ref certs, native_string const& password, tls_data_format format)
{
	if (init()) {
		if (!set_key_and_certs(cert_context_, key, certs, password, format)) {
			deinit();
			return false;
		}
	}

	return true;
}

bool tls_layer_impl::init_session(bool client, int extra_flags)
{
	if (!cert_context_.credentials) {
		deinit();
		return false;
	}

	int flags = client ? GNUTLS_CLIENT : GNUTLS_SERVER;
	flags |= extra_flags;
	int res = gnutls_init(&session_, flags);
	if (res) {
		log_error(res, L"gnutls_init"sv);
		deinit();
		return false;
	}

	if (!client && !(extra_flags & GNUTLS_NO_TICKETS)) {
		if (ticket_key_.empty()) {
			datum_holder h;
			res = gnutls_session_ticket_key_generate(&h);
			if (res) {
				log_error(res, L"gnutls_session_ticket_key_generate"sv);
				deinit();
				return false;
			}
			ticket_key_.assign(h.data, h.data + h.size);
		}

		gnutls_datum_t k;
		k.data = ticket_key_.data();
		k.size = ticket_key_.size();
		res = gnutls_session_ticket_enable_server(session_, &k);
		if (res) {
			log_error(res, L"gnutls_session_ticket_enable_server"sv);
			deinit();
			return false;
		}
	}

	// For use in callbacks
	gnutls_session_set_ptr(session_, this);
	gnutls_db_set_ptr(session_, this);

	// Even though the name gnutls_db_set_cache_expiration
	// implies expiration of some cache, it also governs
	// the actual session lifetime, independend whether the
	// session is cached or not.
	gnutls_db_set_cache_expiration(session_, 100000000);

	if (!client) {
		gnutls_db_set_ptr(session_, this);
		gnutls_db_set_store_function(session_, &db_store_func);
		gnutls_db_set_retrieve_function(session_, &db_retr_func);
	}

	std::string prio = ciphers;
	switch (min_tls_ver_) {
	case tls_ver::v1_3:
		prio += ":-VERS-TLS1.2";
		// Fallthrough
	case tls_ver::v1_2:
		prio += ":-VERS-TLS1.1";
		// Fallthrough
	case tls_ver::v1_1:
		prio += ":-VERS-TLS1.0";
		break;
	default:
		break;
	}

	if (max_tls_ver_) {
		switch (*max_tls_ver_) {
		case tls_ver::v1_0:
			prio += ":-VERS-TLS1.1";
			// Fallthrough
		case tls_ver::v1_1:
			prio += ":-VERS-TLS1.2";
			// Fallthrough
		case tls_ver::v1_2:
			prio += ":-VERS-TLS1.3";
			break;
		default:
			break;
		}
	}

	res = gnutls_priority_set_direct(session_, prio.c_str(), nullptr);
	if (res) {
		log_error(res, L"gnutls_priority_set_direct"sv);
		deinit();
		return false;
	}

	gnutls_dh_set_prime_bits(session_, 1024);

	gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE, cert_context_.credentials);

	// Setup transport functions
	gnutls_transport_set_push_function(session_, c_push_function);
	gnutls_transport_set_pull_function(session_, c_pull_function);
	gnutls_transport_set_ptr(session_, (gnutls_transport_ptr_t)this);

	if (!do_set_alpn()) {
		deinit();
		return false;
	}

	return true;
}

void tls_layer_impl::cert_context::deinit()
{
	if (credentials) {
		gnutls_certificate_free_credentials(credentials);
		credentials = nullptr;
	}
}

void tls_layer_impl::deinit()
{
	deinit_session();

	cert_context_.deinit();

	if (initialized_) {
		initialized_ = false;
		gnutls_global_deinit();
	}

	ticket_key_.clear();

	state_ = socket_state::failed;

#if TLSDEBUG
	if (pLogging == &logger_) {
		pLogging = nullptr;
	}
#endif

	remove_verification_events(verification_handler_, &tls_layer_);
	verification_handler_ = nullptr;
}


void tls_layer_impl::deinit_session()
{
	if (session_) {
		gnutls_deinit(session_);
		session_ = nullptr;
	}
}


void tls_layer_impl::log_gnutls_error(logger_interface &logger, int code, std::wstring_view const& function, logmsg::type logLevel)
{
	char const* error = gnutls_strerror(code);
	if (error) {
		if (function.empty()) {
			logger.log(logLevel, fztranslate("GnuTLS error %d: %s"), code, error);
		}
		else {
			logger.log(logLevel, fztranslate("GnuTLS error %d in %s: %s"), code, function, error);
		}
	}
	else {
		if (function.empty()) {
			logger.log(logLevel, fztranslate("GnuTLS error %d"), code);
		}
		else {
			logger.log(logLevel, fztranslate("GnuTLS error %d in %s"), code, function);
		}
	}
}

void tls_layer_impl::log_error(int code, std::wstring_view const& function, logmsg::type logLevel)
{
	if (logLevel < logmsg::debug_warning && state_ >= socket_state::shut_down && shutdown_silence_read_errors_) {
		logLevel = logmsg::debug_warning;
	}

	if (code == GNUTLS_E_WARNING_ALERT_RECEIVED || code == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		log_alert(logLevel);
	}
	else if (code == GNUTLS_E_PULL_ERROR) {
		if (function.empty()) {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not read from socket: %s", socket_error_description(socket_error_));
		}
		else {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not read from socket in %s: %s", function, socket_error_description(socket_error_));
		}
	}
	else if (code == GNUTLS_E_PUSH_ERROR) {
		if (function.empty()) {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not write to socket: %s", socket_error_description(socket_error_));
		}
		else {
			logger_.log(logmsg::debug_warning, L"GnuTLS could not write to socket in %s: %s", function, socket_error_description(socket_error_));
		}
	}
	else {
		log_gnutls_error(logger_, code, function, logLevel);
	}
}

void tls_layer_impl::log_alert(logmsg::type logLevel)
{
	gnutls_alert_description_t last_alert = gnutls_alert_get(session_);
	char const* alert = gnutls_alert_get_name(last_alert);
	if (alert) {
		logger_.log(logLevel,
					server_ ? fztranslate("Received TLS alert from the client: %s (%d)") : fztranslate("Received TLS alert from the server: %s (%d)"),
					alert, last_alert);
	}
	else {
		logger_.log(logLevel,
					server_ ? fztranslate("Received unknown TLS alert %d from the client") : fztranslate("Received unknown TLS alert %d from the server"),
					last_alert);
	}
}

ssize_t tls_layer_impl::push_function(void const* data, size_t len)
{
#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::push_function(%d)", len);
#endif
	if (!can_write_to_socket_) {
		gnutls_transport_set_errno(session_, EAGAIN);
		return -1;
	}

	int error;
	int written = tls_layer_.next_layer_.write(data, static_cast<unsigned int>(len), error);

	if (written < 0) {
		can_write_to_socket_ = false;
		if (error != EAGAIN) {
			socket_error_ = error;
		}
		gnutls_transport_set_errno(session_, error);
#if TLSDEBUG
		logger_.log(logmsg::debug_debug, L"  returning -1 due to %d", error);
#endif
		return -1;
	}

#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"  returning %d", written);
#endif

	return written;
}

ssize_t tls_layer_impl::pull_function(void* data, size_t len)
{
#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::pull_function(%d)",  (int)len);
#endif

	if (!can_read_from_socket_) {
		gnutls_transport_set_errno(session_, EAGAIN);
		return -1;
	}

	int error;
	int read = tls_layer_.next_layer_.read(data, static_cast<unsigned int>(len), error);
	if (read < 0) {
		if (error != EAGAIN) {
			socket_error_ = error;
		}
		else {
			can_read_from_socket_ = false;
		}
		gnutls_transport_set_errno(session_, error);
#if TLSDEBUG
		logger_.log(logmsg::debug_debug, L"  returning -1 due to %d", error);
#endif
		return -1;
	}

	if (!read) {
		socket_eof_ = true;
	}

#if TLSDEBUG
	logger_.log(logmsg::debug_debug, L"  returning %d", read);
#endif

	return read;
}

void tls_layer_impl::operator()(event_base const& ev)
{
	dispatch<socket_event, hostaddress_event>(ev, this
		, &tls_layer_impl::on_socket_event
		, &tls_layer_impl::forward_hostaddress_event);
}

void tls_layer_impl::forward_hostaddress_event(socket_event_source* source, std::string const& address)
{
	tls_layer_.forward_hostaddress_event(source, address);
}

void tls_layer_impl::on_socket_event(socket_event_source* s, socket_event_flag t, int error)
{
	if (!session_) {
		return;
	}

	if (t == socket_event_flag::connection_next) {
		tls_layer_.forward_socket_event(s, t, error);
		return;
	}

	if (error) {
		socket_error_ = error;
		deinit();
		tls_layer_.forward_socket_event(s, t, error);
		return;
	}

	switch (t)
	{
	case socket_event_flag::read:
		on_read();
		break;
	case socket_event_flag::write:
		on_send();
		break;
	case socket_event_flag::connection:
		if (hostname_.empty()) {
			set_hostname(tls_layer_.next_layer_.peer_host());
		}
		on_send();
		break;
	default:
		break;
	}
}

void tls_layer_impl::on_read()
{
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::on_read()");

#if DEBUG_SOCKETEVENTS
	assert(!can_read_from_socket_);
#endif
	can_read_from_socket_ = true;

	if (!session_) {
		return;
	}

	if (state_ == socket_state::connecting) {
		continue_handshake();
	}
	else if (state_ == socket_state::connected || state_ == socket_state::shutting_down || state_ == socket_state::shut_down) {
#if DEBUG_SOCKETEVENTS
		assert(!debug_can_read_);
		debug_can_read_ = true;
#endif
		if (tls_layer_.event_handler_) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, 0);
		}
	}
}

void tls_layer_impl::on_send()
{
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::on_send()");

	can_write_to_socket_ = true;

	if (!session_) {
		return;
	}

	if (state_ == socket_state::connecting) {
		continue_handshake();
	}
	else if (state_ == socket_state::shutting_down) {
		int res = continue_write();
		if (res) {
			return;
		}

		res = continue_shutdown();
		if (res != EAGAIN) {
			if (tls_layer_.event_handler_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::write, res);
			}
		}
	}
	else if (state_ == socket_state::connected) {
		continue_write();
	}
}

int tls_layer_impl::continue_write()
{
	while (!send_buffer_.empty()) {
		ssize_t res = GNUTLS_E_AGAIN;
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
			res = gnutls_record_send(session_, send_buffer_.get(), send_buffer_.size());
		}

		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			return EAGAIN;
		}

		if (res < 0) {
			failure(static_cast<int>(res), true);
			return ECONNABORTED;
		}

		if (static_cast<size_t>(res) > send_buffer_.size()) {
			logger_.log(logmsg::error, L"gnutls_record_send has processed more data than it has buffered");
			failure(0, true);
			return ECONNABORTED;
		}

		send_buffer_.consume(static_cast<size_t>(res));
	}

	if (send_new_ticket_) {
		int res = GNUTLS_E_AGAIN;
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
			res = gnutls_session_ticket_send(session_, 1, 0);
		}

		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			return EAGAIN;
		}

		if (res < 0) {
			failure(static_cast<int>(res), true);
			return ECONNABORTED;
		}

		send_new_ticket_ = false;
	}

	if (write_blocked_by_send_buffer_) {
		write_blocked_by_send_buffer_ = false;

		if (state_ == socket_state::connected) {
#if DEBUG_SOCKETEVENTS
			assert(!debug_can_write_);
			debug_can_write_ = true;
#endif
			if (tls_layer_.event_handler_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::write, 0);
			}
		}
	}

	return 0;
}

bool tls_layer_impl::resumed_session() const
{
	return gnutls_session_is_resumed(session_) != 0;
}

bool tls_layer_impl::client_handshake(std::vector<uint8_t> const& session_to_resume, native_string const& session_hostname, std::vector<uint8_t> const& required_certificate, event_handler *const verification_handler, tls_client_flags flags)
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::client_handshake()");

	if (state_ != socket_state::none) {
		logger_.log(logmsg::debug_warning, L"Called tls_layer_impl::client_handshake on a socket that isn't idle");
		return false;
	}

	server_ = false;

	int extra_flags{};
	if (flags & tls_client_flags::debug_no_tickets) {
		extra_flags |= GNUTLS_NO_TICKETS;
	}

	if (!init() || !init_session(true, extra_flags)) {
		return false;
	}

	state_ = socket_state::connecting;

	if (!required_certificate.empty()) {
		std::string_view v(reinterpret_cast<char const*>(required_certificate.data()), required_certificate.size());
		size_t i = v.find_first_not_of("-");
		size_t p = v.find("BEGIN ");
		if (i != std::string_view::npos && i >= 4 && i == p) {
			// It's PEM
			gnutls_datum_t in;
			in.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(required_certificate.data()));
			in.size = required_certificate.size();

			datum_holder der;
			gnutls_pem_base64_decode2(nullptr, &in, &der);

			required_certificate_.assign(der.data, der.data + der.size);
		}
		else {
			// Must be DER
			required_certificate_ = required_certificate;
		}
	}

	verification_handler_ = verification_handler;

	if (!session_to_resume.empty()) {
		int res = gnutls_session_set_data(session_, session_to_resume.data(), session_to_resume.size());
		if (res) {
			logger_.log(logmsg::debug_info, L"gnutls_session_set_data failed: %d. Going to reinitialize session.", res);
			deinit_session();
			if (!init_session(true, extra_flags)) {
				return false;
			}
		}
		else {
			logger_.log(logmsg::debug_info, L"Trying to resume existing TLS session.");
		}
	}

	if (logger_.should_log(logmsg::debug_debug)) {
		gnutls_handshake_set_hook_function(session_, GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_BOTH, &handshake_hook_func);
	}

	if (!session_hostname.empty()) {
		set_hostname(session_hostname);
	}
	else if (!hostname_.empty()) {
		set_hostname(hostname_);
	}

	if (tls_layer_.next_layer_.get_state() == socket_state::none || tls_layer_.next_layer_.get_state() == socket_state::connecting) {
		// Wait until the socket gets connected
		return true;
	}
	else if (tls_layer_.next_layer_.get_state() != socket_state::connected) {
		// We're too late
		return false;
	}

	if (hostname_.empty()) {
		set_hostname(tls_layer_.next_layer_.peer_host());
	}
	return continue_handshake() == EAGAIN;
}

namespace {
bool extract_with_size(uint8_t const* &p, uint8_t const* const end, std::vector<uint8_t>& target)
{
	size_t s;
	if (static_cast<size_t>(end - p) < sizeof(s)) {
		return false;
	}
	memcpy(&s, p, sizeof(s));
	p += sizeof(s);
	if (static_cast<size_t>(end - p) < s) {
		return false;
	}
	target.resize(s);
	if (s) {
		memcpy(target.data(), p, s);
		p += s;
	}
	return true;
}
}

bool tls_layer_impl::server_handshake(std::vector<uint8_t> const& session_to_resume, std::string_view const& preamble, tls_server_flags flags)
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::server_handshake()");

	if (state_ != socket_state::none) {
		logger_.log(logmsg::debug_warning, L"Called tls_layer_impl::server_handshake on a socket that isn't idle");
		return false;
	}

	server_ = true;

	if (!session_to_resume.empty()) {
		auto const* p = session_to_resume.data();
		auto const* const end = p + session_to_resume.size();
		if (!extract_with_size(p, end, ticket_key_)) {
			return false;
		}
		if (!extract_with_size(p, end, session_db_key_)) {
			return false;
		}
		if (!extract_with_size(p, end, session_db_data_)) {
			return false;
		}
	}

	int extra_flags{};
	if (flags & tls_server_flags::no_auto_ticket) {
		extra_flags |= GNUTLS_NO_AUTO_SEND_TICKET;
	}
	if (flags & tls_server_flags::debug_no_tickets) {
		extra_flags |= GNUTLS_NO_TICKETS;
		ticket_key_.clear();
	}
	if (!init() || !init_session(false, extra_flags)) {
		return false;
	}

	state_ = socket_state::connecting;

	if (logger_.should_log(logmsg::debug_debug)) {
		gnutls_handshake_set_hook_function(session_, GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_BOTH, &handshake_hook_func);
	}

	if (tls_layer_.next_layer_.get_state() == socket_state::none || tls_layer_.next_layer_.get_state() == socket_state::connecting) {
		// Wait until the socket gets connected
		return true;
	}
	else if (tls_layer_.next_layer_.get_state() != socket_state::connected) {
		// We're too late
		return false;
	}

	preamble_.append(preamble);

	return continue_handshake() == EAGAIN;
}

int tls_layer_impl::continue_handshake()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::continue_handshake()");
	if (!session_ || state_ != socket_state::connecting) {
		return ENOTCONN;
	}

	while (!preamble_.empty()) {
		if (!can_write_to_socket_) {
			return EAGAIN;
		}

		int error{};
		int written = tls_layer_.next_layer_.write(preamble_.get(), static_cast<int>(preamble_.size()), error);
		if (written < 0) {
			can_write_to_socket_ = false;
			if (error != EAGAIN) {
				socket_error_ = error;
				failure(0, true);
			}
			return error;
		}
		preamble_.consume(static_cast<size_t>(written));
	}

	int res = gnutls_handshake(session_);
	while (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) {
		if (!(gnutls_record_get_direction(session_) ? can_write_to_socket_ : can_read_from_socket_)) {
			break;
		}
		res = gnutls_handshake(session_);
	}
	if (!res) {
		logger_.log(logmsg::debug_info, L"TLS Handshake successful");
		handshake_successful_ = true;

		if (resumed_session()) {
			logger_.log(logmsg::debug_info, L"TLS Session resumed");
		}

		std::string const protocol = get_protocol();
		std::string const keyExchange = get_key_exchange();
		std::string const cipherName = get_cipher();
		std::string const macName = get_mac();

		logger_.log(logmsg::debug_info, L"Protocol: %s, Key exchange: %s, Cipher: %s, MAC: %s, ALPN: %s", protocol, keyExchange, cipherName, macName, get_alpn());

		if (!server_) {
			return verify_certificate();
		}
		else {
			state_ = socket_state::connected;

#if DEBUG_SOCKETEVENTS
			if (can_read_from_socket_) {
				assert(!debug_can_read_);
				debug_can_read_ = true;
			}
			assert(!debug_can_write_);
			debug_can_write_ = true;
#endif
			if (tls_layer_.event_handler_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::connection, 0);
				if (can_read_from_socket_) {
					tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, 0);
				}
			}
		}

		return 0;
	}
	else if (res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) {
		if (!socket_error_) {
			return EAGAIN;
		}

		// GnuTLS has a writev() emulation that ignores trailing errors if
		// at least some data got sent
		res = GNUTLS_E_PUSH_ERROR;
	}

	failure(res, true);

	return socket_error_ ? socket_error_ : ECONNABORTED;
}

int tls_layer_impl::read(void *buffer, unsigned int len, int& error)
{
	if (state_ == socket_state::connecting) {
		error = EAGAIN;
		return -1;
	}
	else if (state_ != socket_state::connected && state_ != socket_state::shutting_down && state_ != socket_state::shut_down) {
		error = ENOTCONN;
		return -1;
	}

#if DEBUG_SOCKETEVENTS
	assert(debug_can_read_);
	assert(!has_pending_event(tls_layer_.event_handler_, &tls_layer_, socket_event_flag::read));
#endif

	int res = do_call_gnutls_record_recv(buffer, len);
	if (res >= 0) {
		error = 0;
		return res;
	}
	else if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
#if DEBUG_SOCKETEVENTS
		debug_can_read_ = false;
#endif
		error = EAGAIN;
	}
	else {
		failure(res, false, L"gnutls_record_recv"sv);
		error = socket_error_ ? socket_error_ : ECONNABORTED;
	}

	return -1;
}

int tls_layer_impl::write(void const* buffer, unsigned int len, int& error)
{
	if (state_ == socket_state::connecting) {
		error = EAGAIN;
		return -1;
	}
	else if (state_ == socket_state::shutting_down || state_ == socket_state::shut_down) {
		error = ESHUTDOWN;
		return -1;
	}
	else if (state_ != socket_state::connected) {
		error = ENOTCONN;
		return -1;
	}

#if DEBUG_SOCKETEVENTS
	assert(debug_can_write_);
	assert(!has_pending_event(tls_layer_.event_handler_, &tls_layer_, socket_event_flag::write));
#endif

	if (!send_buffer_.empty() || send_new_ticket_) {
		write_blocked_by_send_buffer_ = true;
#if DEBUG_SOCKETEVENTS
		debug_can_write_ = false;
#endif
		error = EAGAIN;
		return -1;
	}

	ssize_t res = gnutls_record_send(session_, buffer, len);

	while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
		res = gnutls_record_send(session_, nullptr, 0);
	}

	if (res >= 0) {
		error = 0;
		return static_cast<int>(res);
	}

	if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
		if (!socket_error_) {
			// Unfortunately we can't return EAGAIN here as GnuTLS has already consumed some data.
			// With our semantics, EAGAIN means nothing has been handed off yet.
			// Thus remember up to gnutls_record_get_max_size bytes from the input.
			unsigned int max = static_cast<unsigned int>(gnutls_record_get_max_size(session_));
			if (len > max) {
				len = max;
			}
			send_buffer_.append(reinterpret_cast<unsigned char const*>(buffer), len);
			return static_cast<int>(len);
		}

		// GnuTLS has a writev() emulation that ignores trailing errors if
		// at least some data got sent
		res = GNUTLS_E_PUSH_ERROR;
	}

	failure(static_cast<int>(res), false, L"gnutls_record_send"sv);
	error = socket_error_ ? socket_error_ : ECONNABORTED;
	return -1;
}

void tls_layer_impl::failure(int code, bool send_close, std::wstring_view const& function)
{
	logger_.log(logmsg::debug_debug, L"tls_layer_impl::failure(%d)", code);
	if (code) {
		bool suppress{};
		auto level = logmsg::error;

		bool const premature_eof = socket_eof_ && (code == GNUTLS_E_UNEXPECTED_PACKET_LENGTH || code == GNUTLS_E_PREMATURE_TERMINATION);

		if (premature_eof) {
			suppress = state_ == socket_state::shut_down && shutdown_silence_read_errors_;
			if (!suppress && state_ == socket_state::connected && unexpected_eof_cb_) {
				suppress = !unexpected_eof_cb_();
			}
			if (suppress) {
				level = logmsg::debug_warning;
			}
		}
		log_error(code, function, level);
		if (!suppress && premature_eof) {
			logger_.log(logmsg::status, server_ ? fztranslate("Client did not properly shut down TLS connection") : fztranslate("Server did not properly shut down TLS connection"));
		}
	}

	auto const oldState = state_;

	deinit();

	if (send_close && tls_layer_.event_handler_) {
		int error = socket_error_;
		if (!error) {
			error = ECONNABORTED;
		}
		if (oldState == socket_state::connecting) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::connection, error);
		}
		else {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, error);
		}
	}
}

int tls_layer_impl::shutdown()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::shutdown()");

	if (state_ == socket_state::shut_down) {
		return 0;
	}
	else if (state_ == socket_state::shutting_down) {
		return EAGAIN;
	}
	else if (state_ != socket_state::connected) {
		return ENOTCONN;
	}

	state_ = socket_state::shutting_down;

	if (!send_buffer_.empty() || send_new_ticket_) {
		logger_.log(logmsg::debug_verbose, L"Postponing shutdown, send_buffer_ not empty");
		return EAGAIN;
	}

	return continue_shutdown();
}

int tls_layer_impl::continue_shutdown()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::continue_shutdown()");

	if (!sent_closure_alert_) {
		int res = gnutls_bye(session_, GNUTLS_SHUT_WR);
		while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
			res = gnutls_bye(session_, GNUTLS_SHUT_WR);
		}
		if (res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) {
			if (!socket_error_) {
				return EAGAIN;
			}

			// GnuTLS has a writev() emulation that ignores trailing errors if
			// at least some data got sent
			res = GNUTLS_E_PUSH_ERROR;
		}
		if (res) {
			failure(res, false, L"gnutls_bye"sv);
			return socket_error_ ? socket_error_ : ECONNABORTED;
		}
		sent_closure_alert_ = true;
	}

	int res = tls_layer_.next_layer_.shutdown();
	if (res == EAGAIN) {
		return EAGAIN;
	}

	if (!res) {
		state_ = socket_state::shut_down;
	}
	else {
		socket_error_ = res;
		failure(0, false);
	}
	return res;
}

void tls_layer_impl::set_verification_result(bool trusted)
{
	logger_.log(logmsg::debug_verbose, L"set_verification_result(%s)", trusted ? "true"sv : "false"sv);

	if (state_ != socket_state::connecting && !handshake_successful_) {
		logger_.log(logmsg::debug_warning, L"set_verification_result called at wrong time.");
		return;
	}

	remove_verification_events(verification_handler_, &tls_layer_);
	verification_handler_ = nullptr;

	if (trusted) {
		state_ = socket_state::connected;

#if DEBUG_SOCKETEVENTS
		if (can_read_from_socket_) {
			assert(!debug_can_read_);
			debug_can_read_ = true;
		}
		assert(!debug_can_write_);
		debug_can_write_ = true;
#endif
		if (tls_layer_.event_handler_) {
			tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::connection, 0);
			if (can_read_from_socket_) {
				tls_layer_.event_handler_->send_event<socket_event>(&tls_layer_, socket_event_flag::read, 0);
			}
		}

		return;
	}

	logger_.log(logmsg::error, fztranslate("Remote certificate not trusted."));
	failure(0, true);
}

static std::string bin2hex(unsigned char const* in, size_t size)
{
	std::string str;
	str.reserve(size * 3);
	for (size_t i = 0; i < size; ++i) {
		if (i) {
			str += ':';
		}
		str += int_to_hex_char<char>(in[i] >> 4);
		str += int_to_hex_char<char>(in[i] & 0xf);
	}

	return str;
}


bool tls_layer_impl::extract_cert(gnutls_x509_crt_t const& cert, x509_certificate& out, bool last, logger_interface * logger)
{
	datetime expiration_time(gnutls_x509_crt_get_expiration_time(cert), datetime::seconds);
	datetime activation_time(gnutls_x509_crt_get_activation_time(cert), datetime::seconds);

	if (!activation_time || !expiration_time || expiration_time < activation_time) {
		if (logger) {
			logger->log(logmsg::error, fztranslate("Could not extract validity period of certificate"));
		}
		return false;
	}

	// Get the serial number of the certificate
	unsigned char buffer[40];
	size_t size = sizeof(buffer);
	int res = gnutls_x509_crt_get_serial(cert, buffer, &size);
	if (res != 0) {
		size = 0;
	}

	auto serial = bin2hex(buffer, size);

	unsigned int pk_bits;
	int pkAlgo = gnutls_x509_crt_get_pk_algorithm(cert, &pk_bits);
	std::string pk_algo_name;
	if (pkAlgo >= 0) {
		char const* pAlgo = gnutls_pk_algorithm_get_name((gnutls_pk_algorithm_t)pkAlgo);
		if (pAlgo) {
			pk_algo_name = pAlgo;
		}
	}

	int signAlgo = gnutls_x509_crt_get_signature_algorithm(cert);
	std::string signAlgoName;
	if (signAlgo >= 0) {
		char const* pAlgo = gnutls_sign_algorithm_get_name((gnutls_sign_algorithm_t)signAlgo);
		if (pAlgo) {
			signAlgoName = pAlgo;
		}
	}

	std::string subject, issuer;

	datum_holder raw_subject;
	res = gnutls_x509_crt_get_dn3(cert, &raw_subject, 0);
	if (!res) {
		subject = raw_subject.to_string_view();
	}
	else {
		if (logger) {
			logger->log(logmsg::debug_warning, "gnutls_x509_crt_get_dn3 failed with %d", res);
		}
	}
	if (subject.empty()) {
		if (logger) {
			logger->log(logmsg::error, fztranslate("Could not get distinguished name of certificate subject, gnutls_x509_get_dn failed"));
		}
		return false;
	}

	std::vector<x509_certificate::subject_name> alt_subject_names = get_cert_subject_alt_names(cert);

	datum_holder raw_issuer;
	res = gnutls_x509_crt_get_issuer_dn3(cert, &raw_issuer, 0);
	if (!res) {
		issuer = raw_issuer.to_string_view();
	}
	else {
		if (logger) {
			logger->log(logmsg::debug_warning, "gnutls_x509_crt_get_issuer_dn3 failed with %d", res);
		}
	}
	if (issuer.empty() ) {
		if (logger) {
			logger->log(logmsg::error, fztranslate("Could not get distinguished name of certificate issuer, gnutls_x509_get_issuer_dn failed"));
		}
		return false;
	}

	std::string fingerprint_sha256;
	std::string fingerprint_sha1;

	unsigned char digest[100];
	size = sizeof(digest) - 1;
	if (!gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA256, digest, &size)) {
		digest[size] = 0;
		fingerprint_sha256 = bin2hex(digest, size);
	}
	size = sizeof(digest) - 1;
	if (!gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, digest, &size)) {
		digest[size] = 0;
		fingerprint_sha1 = bin2hex(digest, size);
	}

	datum_holder der;
	if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_DER, &der) != GNUTLS_E_SUCCESS || !der.data || !der.size) {
		if (logger) {
			logger->log(logmsg::error, L"gnutls_x509_crt_get_issuer_dn");
		}
		return false;
	}
	std::vector<uint8_t> data(der.data, der.data + der.size);

	out = x509_certificate(
		std::move(data),
		activation_time, expiration_time,
		serial,
		pk_algo_name, pk_bits,
		signAlgoName,
		fingerprint_sha256,
		fingerprint_sha1,
		issuer,
		subject,
		std::move(alt_subject_names),
		last ? gnutls_x509_crt_check_issuer(cert, cert) : false);

	return true;
}


std::vector<x509_certificate::subject_name> tls_layer_impl::get_cert_subject_alt_names(gnutls_x509_crt_t cert)
{
	std::vector<x509_certificate::subject_name> ret;

	char san[4096];
	for (unsigned int i = 0; i < 10000; ++i) { // I assume this is a sane limit
		size_t san_size = sizeof(san) - 1;
		int const type_or_error = gnutls_x509_crt_get_subject_alt_name(cert, i, san, &san_size, nullptr);
		if (type_or_error == GNUTLS_E_SHORT_MEMORY_BUFFER) {
			continue;
		}
		else if (type_or_error < 0) {
			break;
		}

		if (type_or_error == GNUTLS_SAN_DNSNAME || type_or_error == GNUTLS_SAN_RFC822NAME) {
			std::string dns = san;
			if (!dns.empty()) {
				ret.emplace_back(x509_certificate::subject_name{std::move(dns), type_or_error == GNUTLS_SAN_DNSNAME});
			}
		}
		else if (type_or_error == GNUTLS_SAN_IPADDRESS) {
			std::string ip = socket::address_to_string(san, static_cast<int>(san_size));
			if (!ip.empty()) {
				ret.emplace_back(x509_certificate::subject_name{std::move(ip), false});
			}
		}
	}
	return ret;
}

bool tls_layer_impl::certificate_is_blacklisted(cert_list_holder const& certs)
{
	for (size_t i = 0; i < certs.certs_size; ++i) {
		if (certificate_is_blacklisted(certs.certs[i])) {
			return true;
		}
	}
	return false;
}

bool tls_layer_impl::certificate_is_blacklisted(gnutls_x509_crt_t const& cert)
{
	static std::set<std::string, std::less<>> const bad_authority_key_ids = {
		std::string("\xF4\x94\xBF\xDE\x50\xB6\xDB\x6B\x24\x3D\x9E\xF7\xBE\x3A\xAE\x36\xD7\xFB\x0E\x05", 20) // Nation-wide MITM in Kazakhstan
	};

	char buf[256];
	unsigned int critical{};
	size_t size = sizeof(buf);
	int res = gnutls_x509_crt_get_authority_key_id(cert, buf, &size, &critical);
	if (!res) {
		auto it = bad_authority_key_ids.find(std::string_view(buf, size));
		if (it != bad_authority_key_ids.cend()) {
			return true;
		}
	}

	return false;
}

int tls_layer_impl::get_algorithm_warnings() const
{
	int algorithmWarnings{};

	switch (gnutls_protocol_get_version(session_))
	{
		case GNUTLS_SSL3:
		case GNUTLS_VERSION_UNKNOWN:
			algorithmWarnings |= tls_session_info::tlsver;
			break;
		default:
			break;
	}

	switch (gnutls_cipher_get(session_)) {
		case GNUTLS_CIPHER_UNKNOWN:
		case GNUTLS_CIPHER_NULL:
		case GNUTLS_CIPHER_ARCFOUR_128:
		case GNUTLS_CIPHER_3DES_CBC:
		case GNUTLS_CIPHER_ARCFOUR_40:
		case GNUTLS_CIPHER_RC2_40_CBC:
		case GNUTLS_CIPHER_DES_CBC:
			algorithmWarnings |= tls_session_info::cipher;
			break;
		default:
			break;
	}

	switch (gnutls_mac_get(session_)) {
		case GNUTLS_MAC_UNKNOWN:
		case GNUTLS_MAC_NULL:
		case GNUTLS_MAC_MD5:
		case GNUTLS_MAC_MD2:
		case GNUTLS_MAC_UMAC_96:
			algorithmWarnings |= tls_session_info::mac;
			break;
		default:
			break;
	}

	switch (gnutls_kx_get(session_)) {
		case GNUTLS_KX_UNKNOWN:
		case GNUTLS_KX_ANON_DH:
		case GNUTLS_KX_RSA_EXPORT:
		case GNUTLS_KX_ANON_ECDH:
			algorithmWarnings |= tls_session_info::kex;
			break;
		default:
			break;
	}

	return algorithmWarnings;
}

int tls_layer_impl::load_certificates(const_tls_param_ref in, tls_data_format format, gnutls_x509_crt_t *& certs, unsigned int & certs_size, bool & sort, logger_interface *logger)
{
	if (in.pkcs11url()) {
		if (logger) {
			logger->log_raw(logmsg::error, fztranslate("PKCS11 URLs not supported yet for certificates"));
		}

		return {};
	}

	if (auto certsfile = in.filepath()) {
		if (!certsfile) {
			if (logger) {
				logger->log_raw(logmsg::error, fztranslate("Invalid file path for certificates"));
			}

			return {};
		}

		auto blob = read_certificates_file(certsfile->value, logger);
		if (blob.empty()) {
			return {};
		}

		return load_certificates(blob, is_pem(blob, format), certs, certs_size, sort);
	}

	if (auto blob = in.blob()) {
		if (!blob) {
			if (logger) {
				logger->log_raw(logmsg::error, fztranslate("Invalid data blob for certificates"));
			}

			return {};
		}

		return load_certificates(blob->value, is_pem(blob->value, format), certs, certs_size, sort);
	}

	if (logger) {
		logger->log_raw(logmsg::error, fztranslate("Internal error: invalid certs"));
	}

	return {};
}

int tls_layer_impl::load_certificates(std::string_view const& in, bool pem, gnutls_x509_crt_t *& certs, unsigned int & certs_size, bool & sort)
{
	gnutls_datum_t dpem;
	dpem.data = reinterpret_cast<unsigned char*>(const_cast<char *>(in.data()));
	dpem.size = in.size();
	unsigned int flags{};
	if (sort) {
		flags |= GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED;
	}

	int res = gnutls_x509_crt_list_import2(&certs, &certs_size, &dpem, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, flags);
	if (res == GNUTLS_E_CERTIFICATE_LIST_UNSORTED) {
		sort = false;
		flags |= GNUTLS_X509_CRT_LIST_SORT;
		res = gnutls_x509_crt_list_import2(&certs, &certs_size, &dpem, pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, flags);
	}

	if (res != GNUTLS_E_SUCCESS) {
		certs = nullptr;
		certs_size = 0;
	}
	return res;
}

bool tls_layer_impl::get_sorted_peer_certificates(gnutls_x509_crt_t *& certs, unsigned int & certs_size)
{
	certs = nullptr;
	certs_size = 0;

	// First get unsorted list of peer certificates in DER
	unsigned int cert_list_size;
	const gnutls_datum_t* cert_list = gnutls_certificate_get_peers(session_, &cert_list_size);
	if (!cert_list || !cert_list_size) {
		logger_.log(logmsg::error, fztranslate("gnutls_certificate_get_peers returned no certificates"));
		return false;
	}

	// Convert them all to PEM
	// Avoid gnutls_pem_base64_encode2, excessive allocations.
	auto constexpr header = "-----BEGIN CERTIFICATE-----\r\n"sv;
	auto constexpr footer = "\r\n-----END CERTIFICATE-----\r\n"sv;

	size_t cap = cert_list_size * header.size() + footer.size();
	for (unsigned i = 0; i < cert_list_size; ++i) {
		cap += ((cert_list[i].size + 2) / 3) * 4;
	}

	std::string pem;
	pem.reserve(cap);

	for (unsigned i = 0; i < cert_list_size; ++i) {
		pem += header;
		base64_encode_append(pem, to_view(cert_list[i]), base64_type::standard, true);
		pem += footer;
	}

	// And now import the certificates
	bool sort = true;
	int res = load_certificates(pem, true, certs, certs_size, sort);
	if (res == GNUTLS_E_CERTIFICATE_LIST_UNSORTED) {
		logger_.log(logmsg::error, fztranslate("Could not sort peer certificates"));
	}
	else if (!sort) {
		logger_.log(logmsg::error, fztranslate("Server sent unsorted certificate chain in violation of the TLS specifications"));
	}

	return res == GNUTLS_E_SUCCESS;
}

void tls_layer_impl::log_verification_error(int status)
{
	gnutls_datum_t buffer{};
	gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &buffer, 0);
	if (buffer.data) {
		logger_.log(logmsg::debug_warning, L"Gnutls Verification status: %s", buffer.data);
		gnutls_free(buffer.data);
	}

	if (status & GNUTLS_CERT_REVOKED) {
		logger_.log(logmsg::error, fztranslate("Beware! Certificate has been revoked"));

		// The remaining errors are no longer of interest
		return;
	}
	if (status & GNUTLS_CERT_SIGNATURE_FAILURE) {
		logger_.log(logmsg::error, fztranslate("Certificate signature verification failed"));
		status &= ~GNUTLS_CERT_SIGNATURE_FAILURE;
	}
	if (status & GNUTLS_CERT_INSECURE_ALGORITHM) {
		logger_.log(logmsg::error, fztranslate("A certificate in the chain was signed using an insecure algorithm"));
		status &= ~GNUTLS_CERT_INSECURE_ALGORITHM;
	}
	if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
		logger_.log(logmsg::error, fztranslate("An issuer in the certificate chain is not a certificate authority"));
		status &= ~GNUTLS_CERT_SIGNER_NOT_CA;
	}
	if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
		logger_.log(logmsg::error, fztranslate("The server's hostname does not match the certificate's hostname"));
		status &= ~GNUTLS_CERT_UNEXPECTED_OWNER;
	}
	if (status & GNUTLS_CERT_MISSING_OCSP_STATUS) {
		logger_.log(logmsg::error, fztranslate("The certificate requires the server to include an OCSP status in its response, but the OCSP status is missing."));
		status &= ~GNUTLS_CERT_MISSING_OCSP_STATUS;
	}
	if (status) {
		if (status == GNUTLS_CERT_INVALID) {
			logger_.log(logmsg::error, fztranslate("Received certificate chain could not be verified."));
		}
		else {
			logger_.log(logmsg::error, fztranslate("Received certificate chain could not be verified. Verification status is %d."), status);
		}
	}
}

int tls_layer_impl::verify_certificate()
{
	logger_.log(logmsg::debug_verbose, L"tls_layer_impl::verify_certificate()");

	if (state_ != socket_state::connecting) {
		logger_.log(logmsg::debug_warning, L"verify_certificate called at wrong time");
		return ENOTCONN;
	}

	if (gnutls_certificate_type_get(session_) != GNUTLS_CRT_X509) {
		logger_.log(logmsg::error, fztranslate("Unsupported certificate type"));
		failure(0, true);
		return EOPNOTSUPP;
	}

	cert_list_holder certs;
	if (!get_sorted_peer_certificates(certs.certs, certs.certs_size)) {
		failure(0, true);
		return EINVAL;
	}

	if (certificate_is_blacklisted(certs)) {
		logger_.log(logmsg::error, fztranslate("Man-in-the-Middle attack detected, aborting connection."));
		failure(0, true);
		return EINVAL;
	}

	if (!required_certificate_.empty()) {
		datum_holder cert_der{};
		int res = gnutls_x509_crt_export2(certs.certs[0], GNUTLS_X509_FMT_DER, &cert_der);
		if (res != GNUTLS_E_SUCCESS) {
			failure(res, true, L"gnutls_x509_crt_export2"sv);
			return ECONNABORTED;
		}

		if (required_certificate_.size() != cert_der.size ||
			memcmp(required_certificate_.data(), cert_der.data, cert_der.size))
		{
			logger_.log(logmsg::error, fztranslate("Certificate of connection does not match expected certificate."));
			failure(0, true);
			return EINVAL;
		}

		set_verification_result(true);

		if (state_ != socket_state::connected && state_ != socket_state::shutting_down && state_ != socket_state::shut_down) {
			return ECONNABORTED;
		}
		return 0;
	}

	bool const uses_hostname = !hostname_.empty() && get_address_type(hostname_) == address_type::unknown;

	bool const can_use_trust_store = uses_hostname && system_trust_store_;
	bool systemTrust = false;
	bool hostnameMismatch = false;

	// Our trust-model is user-guided TOFU on the host's certificate.
	//
	// First we verify it against the system trust store.
	//
	// If that fails, we validate the certificate chain sent by the server
	// allowing three impairments:
	// - Hostname mismatch
	// - Out of validity
	// - Signer not found
	//
	// In any case, actual trust decision is done later by the user.

	std::vector<x509_certificate> system_trust_chain;

	// First, check system trust
	if (can_use_trust_store) {
		auto lease = system_trust_store_->impl_->lease();
		auto cred = std::get<0>(lease);
		if (cred) {
			bool trust_path_ok{true};
			std::vector<x509_certificate> trust_path;
			tls_layerCallbacks::verify_output_cb_ = [this, &trust_path_ok, &trust_path](gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crl_t crl, unsigned int verification_output) {
				if (!trust_path_ok) {
					return;
				}
				if (cert && !issuer && crl && !verification_output) {
					// Verified against a CRL that the cert isn't expired
					return;
				}
				if (verification_output != 0) {
					trust_path.clear();
					return;
				}
				if (!issuer || !cert) {
					trust_path_ok = false;
					return;
				}

				x509_certificate info;
				if (!extract_cert(issuer, info, true, &logger_)) {
					trust_path_ok = false;
					return;
				}
				if (trust_path.empty() || info.get_fingerprint_sha256() != trust_path.back().get_fingerprint_sha256()) {
					trust_path.emplace_back(std::move(info));
				}
			};

			gnutls_session_set_verify_output_function(session_, c_verify_output_cb);
			gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE, cred);
			unsigned int status = 0;
			int verifyResult = gnutls_certificate_verify_peers3(session_, to_utf8(hostname_).c_str(), &status);
			gnutls_credentials_set(session_, GNUTLS_CRD_CERTIFICATE, cert_context_.credentials);
			std::get<1>(lease).unlock();

			gnutls_session_set_verify_output_function(session_, nullptr);
			tls_layerCallbacks::verify_output_cb_ = nullptr;

			if (verifyResult < 0) {
				logger_.log(logmsg::debug_warning, L"gnutls_certificate_verify_peers2 returned %d with status %u", verifyResult, status);
				logger_.log(logmsg::error, fztranslate("Failed to verify peer certificate"));
				failure(0, true);
				return EINVAL;
			}

			if (!status) {
				if (!trust_path_ok || trust_path.empty()) {
					logger_.log(logmsg::error, fztranslate("Failed to extract certificate trust path"));
					failure(0, true);
					return EINVAL;
				}

				// Reverse chain so that it starts at server certificate and add the server cert
				system_trust_chain.reserve(trust_path.size() + 1);
				x509_certificate cert;
				if (!extract_cert(certs.certs[0], cert, false, &logger_)) {
					failure(0, true);
					return ECONNABORTED;
				}
				system_trust_chain.emplace_back(std::move(cert));
				for (auto it = trust_path.rbegin(); it != trust_path.rend(); ++it) {
					system_trust_chain.emplace_back(std::move(*it));
				}
				systemTrust = true;
			}
			logger_.log(logmsg::debug_verbose, L"System trust store decision: %s", systemTrust ? "true"sv : "false"sv);
		}
		else {
			std::get<1>(lease).unlock();
			logger_.log(logmsg::debug_warning, L"System trust store could not be loaded");
		}
	}

	if (!verification_handler_) {
		if (!systemTrust) {
			logger_.log(logmsg::error, fztranslate("Remote certificate not trusted."));
		}
		set_verification_result(systemTrust);
		return systemTrust ? 0 : ECONNABORTED;
	}
	else {
		if (!systemTrust) {
			// System trust store cannot verify this certificate. Allow three impairments:
			//
			// 1. For now, add the highest certificate from the chain to trust list. Otherwise
			// gnutls_certificate_verify_peers2 always stops with GNUTLS_CERT_SIGNER_NOT_FOUND
			// at the highest certificate in the chain.
			gnutls_x509_crt_t root{};
			clone_cert(certs.certs[certs.certs_size - 1], root);
			if (!root) {
				logger_.log(logmsg::error, fztranslate("Could not copy certificate"));
				failure(0, true);
				return ECONNABORTED;
			}

			gnutls_x509_trust_list_t tlist;
			gnutls_certificate_get_trust_list(cert_context_.credentials, &tlist);
			if (gnutls_x509_trust_list_add_cas(tlist, &root, 1, 0) != 1) {
				logger_.log(logmsg::error, fztranslate("Could not add certificate to temporary trust list"));
				failure(0, true);
				return ECONNABORTED;
			}

			// 2. Also disable time checks. We allow expired/not yet valid certificates, though only
			// after explicit user confirmation.
			gnutls_certificate_set_verify_flags(cert_context_.credentials, gnutls_certificate_get_verify_flags(cert_context_.credentials) | GNUTLS_VERIFY_DISABLE_TIME_CHECKS | GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS);

			unsigned int status = 0;
			int verifyResult = gnutls_certificate_verify_peers2(session_, &status);

			if (verifyResult < 0) {
				logger_.log(logmsg::debug_warning, L"gnutls_certificate_verify_peers2 returned %d with status %u", verifyResult, status);
				logger_.log(logmsg::error, fztranslate("Failed to verify peer certificate"));
				failure(0, true);
				return EINVAL;
			}

			if (status != 0) {
				log_verification_error(status);

				failure(0, true);
				return EINVAL;
			}

			// 3. Hostname mismatch
			if (uses_hostname) {
				if (!gnutls_x509_crt_check_hostname(certs.certs[0], to_utf8(hostname_).c_str())) {
					hostnameMismatch = true;
					logger_.log(logmsg::debug_warning, L"Hostname does not match certificate SANs");
				}
			}
		}

		std::vector<x509_certificate> certificates;
		certificates.reserve(certs.certs_size);
		for (unsigned int i = 0; i < certs.certs_size; ++i) {
			x509_certificate cert;
			if (extract_cert(certs.certs[i], cert, i + 1 == certs.certs_size, &logger_)) {
				certificates.emplace_back(std::move(cert));
			}
			else {
				failure(0, true);
				return ECONNABORTED;
			}
		}

		// Lengthen incomplete chains to the root using the trust store.
		if (!certificates.empty() && !certificates.back().self_signed() && system_trust_store_) {
			auto lease = system_trust_store_->impl_->lease();
			auto cred = std::get<0>(lease);
			if (cred) {
				gnutls_x509_crt_t cert = certs.certs[certs.certs_size - 1];
				while (!certificates.back().self_signed()) {
					gnutls_x509_crt_t issuer{};
					if (gnutls_certificate_get_issuer(cred, cert, &issuer, 0) || !issuer) {
						break;
					}

					// Why is this cert even in the trust store? Antivirus MITM?
					if (certificate_is_blacklisted(issuer)) {
						logger_.log(logmsg::error, fztranslate("Man-in-the-Middle attack detected, aborting connection."));
						failure(0, true);
						return EINVAL;
					}

					x509_certificate out;
					if (!extract_cert(issuer, out, true, &logger_)) {
						failure(0, true);
						return ECONNABORTED;
					}
					certificates.push_back(out);
					cert = issuer;
				}
			}
		}

		int const algorithmWarnings = get_algorithm_warnings();

		int error;
		auto port = tls_layer_.peer_port(error);
		if (port == -1) {
			socket_error_ = error;
			failure(0, true);
			return ECONNABORTED;
		}

		tls_session_info session_info(
			to_utf8(to_wstring(hostname_)),
			port,
			get_protocol(),
			get_key_exchange(),
			get_cipher(),
			get_mac(),
			algorithmWarnings,
			std::move(certificates),
			std::move(system_trust_chain),
			hostnameMismatch
		);

		logger_.log(logmsg::debug_verbose, L"Sending certificate_verification_event");
		verification_handler_->send_event<certificate_verification_event>(&tls_layer_, std::move(session_info));

		return EAGAIN;
	}
}

std::string tls_layer_impl::get_protocol() const
{
	std::string ret;

	char const* s = gnutls_protocol_get_name(gnutls_protocol_get_version(session_));
	if (s && *s) {
		ret = s;
	}

	if (ret.empty()) {
		ret = to_utf8(fztranslate("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::get_key_exchange() const
{
	std::string ret;

	char const* s{};
	gnutls_kx_algorithm_t alg = gnutls_kx_get(session_);
	bool const dh = (alg == GNUTLS_KX_DHE_RSA || alg == GNUTLS_KX_DHE_DSS);
	bool const ecdh = (alg == GNUTLS_KX_ECDHE_RSA || alg == GNUTLS_KX_ECDHE_ECDSA);
	if (dh || ecdh) {
		char const* const signature_name = gnutls_sign_get_name(static_cast<gnutls_sign_algorithm_t>(gnutls_sign_algorithm_get(session_)));
		ret = (ecdh ? "ECDHE" : "DHE");
		s = gnutls_group_get_name(gnutls_group_get(session_));
		if (s && *s) {
			ret += "-";
			ret += s;
		}
		if (signature_name && *signature_name) {
			ret += "-";
			ret += signature_name;
		}
	}
	else {
		s = gnutls_kx_get_name(alg);
		if (s && *s) {
			ret = s;
		}
	}


	if (ret.empty()) {
		ret = to_utf8(fztranslate("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::get_cipher() const
{
	std::string ret;

	char const* cipher = gnutls_cipher_get_name(gnutls_cipher_get(session_));
	if (cipher && *cipher) {
		ret = cipher;
	}

	if (ret.empty()) {
		ret = to_utf8(fztranslate("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::get_mac() const
{
	std::string ret;

	char const* mac = gnutls_mac_get_name(gnutls_mac_get(session_));
	if (mac && *mac) {
		ret = mac;
	}

	if (ret.empty()) {
		ret = to_utf8(fztranslate("unknown"));
	}

	return ret;
}

std::string tls_layer_impl::list_tls_ciphers(std::string const& priority)
{
	auto list = sprintf("Ciphers for %s:\n", priority.empty() ? ciphers : priority);

	gnutls_priority_t pcache;
	char const* err = nullptr;
	int ret = gnutls_priority_init(&pcache, priority.empty() ? ciphers : priority.c_str(), &err);
	if (ret < 0) {
		list += sprintf("gnutls_priority_init failed with code %d: %s", ret, err ? err : "Unknown error");
		return list;
	}
	else {
		for (unsigned int i = 0; ; ++i) {
			unsigned int idx;
			ret = gnutls_priority_get_cipher_suite_index(pcache, i, &idx);
			if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
				break;
			}
			if (ret == GNUTLS_E_UNKNOWN_CIPHER_SUITE) {
				continue;
			}

			gnutls_protocol_t version;
			unsigned char id[2];
			char const* name = gnutls_cipher_suite_info(idx, id, nullptr, nullptr, nullptr, &version);

			if (name != nullptr) {
				list += sprintf(
					"%-50s    0x%02x, 0x%02x    %s\n",
					name,
					(unsigned char)id[0],
					(unsigned char)id[1],
					gnutls_protocol_get_name(version));
			}
		}
	}

	return list;
}

int tls_layer_impl::do_call_gnutls_record_recv(void* data, size_t len)
{
	ssize_t res = gnutls_record_recv(session_, data, len);
	while ((res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) && can_read_from_socket_ && !gnutls_record_get_direction(session_)) {
		// Spurious EAGAIN. Can happen if GnuTLS gets a partial
		// record and the socket got closed.
		// The unexpected close is being ignored in this case, unless
		// gnutls_record_recv is being called again.
		// Manually call gnutls_record_recv as in case of eof on the socket,
		// we are not getting another receive event.
		logger_.log(logmsg::debug_verbose, L"gnutls_record_recv returned spurious EAGAIN");
		res = gnutls_record_recv(session_, data, len);
	}

	if ((res == GNUTLS_E_AGAIN || res == GNUTLS_E_INTERRUPTED) && socket_error_) {
		res = GNUTLS_E_PULL_ERROR;
	}

	return static_cast<int>(res);
}

std::string tls_layer_impl::get_gnutls_version()
{
	char const* v = gnutls_check_version(nullptr);
	if (!v || !*v) {
		return "unknown";
	}

	return v;
}

void tls_layer_impl::set_hostname(native_string const& host)
{
	hostname_ = host;
	if (session_ && !hostname_.empty() && get_address_type(hostname_) == address_type::unknown) {
		auto const utf8 = to_utf8(hostname_);
		if (!utf8.empty()) {
			int res = gnutls_server_name_set(session_, GNUTLS_NAME_DNS, utf8.c_str(), utf8.size());
			if (res) {
				log_error(res, L"gnutls_server_name_set"sv, logmsg::debug_warning);
			}
		}
	}
}

native_string tls_layer_impl::get_hostname() const
{
	if (!session_) {
		return {};
	}

	size_t len{};
	unsigned int type{};
	unsigned int i{};
	int ret;
	do {
		ret = gnutls_server_name_get(session_, nullptr, &len, &type, i++);
	}
	while (ret == GNUTLS_E_SHORT_MEMORY_BUFFER && type != GNUTLS_NAME_DNS);

	if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
		std::string name;
		name.resize(len - 1);
		ret = gnutls_server_name_get(session_, name.data(), &len, &type, --i);
		if (!ret) {
			return fz::to_native(name);
		}
	}

	return {};
}

int tls_layer_impl::connect(native_string const& host, unsigned int port, address_type family)
{
	if (hostname_.empty()) {
		set_hostname(host);
	}

	return tls_layer_.next_layer_.connect(host, port, family);
}

namespace {
void append_with_size(uint8_t * &p, std::vector<uint8_t> const& d)
{
	size_t s = d.size();
	memcpy(p, &s, sizeof(s));
	p += sizeof(s);
	if (s) {
		memcpy(p, d.data(), s);
		p += s;
	}
}
}

std::vector<uint8_t> tls_layer_impl::get_session_parameters() const
{
	std::vector<uint8_t> ret;

	if (!server_) {
		datum_holder d;
		int res = gnutls_session_get_data2(session_, &d);
		if (res) {
			logger_.log(logmsg::debug_warning, L"gnutls_session_get_data2 failed: %d", res);
		}
		else {
			ret.assign(d.data, d.data + d.size);
		}
	}
	else {
		ret.resize(sizeof(size_t) * 3 + ticket_key_.size() + session_db_key_.size() + session_db_data_.size());
		auto* p = ret.data();
		append_with_size(p, ticket_key_);
		append_with_size(p, session_db_key_);
		append_with_size(p, session_db_data_);
	}

	return ret;
}

std::vector<uint8_t> tls_layer_impl::get_raw_certificate() const
{
	std::vector<uint8_t> ret;

	// Implicitly trust certificate of primary socket
	unsigned int cert_list_size;
	gnutls_datum_t const* const cert_list = gnutls_certificate_get_peers(session_, &cert_list_size);
	if (cert_list && cert_list_size) {
		ret.assign(cert_list[0].data, cert_list[0].data + cert_list[0].size);
	}

	return ret;
}

namespace {
bool get_purposes(gnutls_x509_crt_t & crt, std::set<std::string> & purposes)
{
	for (unsigned int i = 0; ; ++i) {
		char buf[512];
		size_t s = 512;
		unsigned int critical{};
		int res = gnutls_x509_crt_get_key_purpose_oid(crt, i, &buf, &s, &critical);
		if (res) {
			return res == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		}
		if (!purposes.emplace(buf).second) {
			return false;
		}
	}

	return false;
}

bool get_purposes(gnutls_x509_crq_t & crq, std::set<std::string> & purposes)
{
	for (unsigned int i = 0; ; ++i) {
		char buf[512];
		size_t s = 512;
		unsigned int critical{};
		int res = gnutls_x509_crq_get_key_purpose_oid(crq, i, &buf, &s, &critical);
		if (res) {
			return res == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		}
		if (!purposes.emplace(buf).second) {
			return false;
		}
	}

	return false;
}

bool verify_purposes(std::set<std::string> & purposes, tls_layer::cert_type t)
{
	for (auto const& p : purposes) {
		if (p == GNUTLS_KP_TLS_WWW_CLIENT) {
			if (t != tls_layer::cert_type::any && t != tls_layer::cert_type::client) {
				return {};
			}
		}
		else if (p == GNUTLS_KP_TLS_WWW_SERVER) {
			if (t != tls_layer::cert_type::any && t != tls_layer::cert_type::server) {
				return {};
			}
		}
		else if (p == GNUTLS_KP_CODE_SIGNING) {
			if (t != tls_layer::cert_type::any && t != tls_layer::cert_type::codesign) {
				return {};
			}
		}
		else {
			return {};
		}
	}

	return true;
}

bool set_purposes_from_type(tls_layer_impl::cert_context &ctx, gnutls_x509_crt_t & crt, tls_layer::cert_type t)
{
	std::set<std::string> purposes;
	if (!get_purposes(crt, purposes)) {
		ctx.logger.log_raw(logmsg::error, fztranslate("Could not get certificate purposes."));
		return {};
	}
	if (!verify_purposes(purposes, t)) {
		ctx.logger.log_raw(logmsg::error, fztranslate("Certificate purposes do not match with its intended type."));
		return {};
	}
	char const* oid{};
	switch (t) {
	case tls_layer::cert_type::client:
		oid = GNUTLS_KP_TLS_WWW_CLIENT;
		break;
	case tls_layer::cert_type::server:
		oid = GNUTLS_KP_TLS_WWW_SERVER;
		break;
	case tls_layer::cert_type::codesign:
		oid = GNUTLS_KP_CODE_SIGNING;
		break;
	default:
		break;
	}
	if (oid) {
		if (purposes.find(oid) == purposes.end()) {
			int res = gnutls_x509_crt_set_key_purpose_oid(crt, oid, 1);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_key_purpose_oid");
				return {};
			}
		}
	}

	return true;
}

static bool set_cert_params(tls_layer_impl::cert_context &ctx, gnutls_x509_crt_t & crt, tls_layer::cert_type t, std::string const& distinguished_name, std::vector<std::string> const& hostnames, duration lifetime)
{
	int res = gnutls_x509_crt_set_serial(crt, random_bytes(20).data(), 20);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_serial");
		return {};
	}

	if (!distinguished_name.empty()) {
		char const* out{};
		int res = gnutls_x509_crt_set_dn(crt, distinguished_name.c_str(), &out);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_dn");
			return {};
		}
	}

	if (!hostnames.empty()) {
		for (size_t i = 0; i < hostnames.size(); ++i) {
			res = gnutls_x509_crt_set_subject_alt_name(crt, GNUTLS_SAN_DNSNAME, hostnames[i].c_str(), hostnames[i].size(), i ? GNUTLS_FSAN_APPEND : GNUTLS_FSAN_SET);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_subject_alt_name");
				return {};
			}
		}
	}

	auto const now = datetime::now();

	if (lifetime <= duration()) {
		lifetime = duration::from_days(366);
	}

	res = gnutls_x509_crt_set_activation_time(crt, (now - duration::from_minutes(5)).get_time_t());
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_activation_time");
		return {};
	}
	res = gnutls_x509_crt_set_expiration_time(crt, (now + lifetime).get_time_t());
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_expiration_time");
		return {};
	}

	int usage{};
	if (t == tls_layer::cert_type::ca) {
		usage = GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN;
	}
	else if (t == tls_layer::cert_type::codesign) {
		usage = GNUTLS_KEY_DIGITAL_SIGNATURE;
	}
	else {
		usage = GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT;
	}

	res = gnutls_x509_crt_set_key_usage(crt, usage);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_key_usage");
		return {};
	}


	res = gnutls_x509_crt_set_basic_constraints(crt, (t == tls_layer::cert_type::ca) ? 1 : 0, -1);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_basic_constraints");
		return {};
	}

	if (!set_purposes_from_type(ctx, crt, t)) {
		return {};
	}

	return true;
}
}

std::string tls_layer_impl::generate_selfsigned_certificate(cert_context &ctx, unique_gnutls_privkey priv, std::string const& distinguished_name, std::vector<std::string> const& hostnames, duration const& lifetime, tls_layer::cert_type type)
{
	gnutls_x509_crt_t crt;
	int res = gnutls_x509_crt_init(&crt);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_init");
		return {};
	}

	auto ret = [&]() -> std::string {
		res = gnutls_x509_crt_set_version(crt, 3);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_version");
			return {};
		}

		{
			gnutls_pubkey_t pub;
			res = gnutls_pubkey_init(&pub);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_pubkey_init");
			}
			else {
				unsigned int key_usage = (type == tls_layer::cert_type::ca) ? (GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN) : (GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT);

				res = gnutls_pubkey_import_privkey(pub, priv.get(), key_usage, 0);
				if (res) {
					ctx.log_gnutls_error(res, L"gnutls_pubkey_import_privkey");
				}
				else {
					res = gnutls_x509_crt_set_pubkey(crt, pub);
					if (res) {
						ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_pubkey");
					}
				}
				gnutls_pubkey_deinit(pub);
			}
		}

		if (res) {
			return {};
		}

		if (!set_cert_params(ctx, crt, type, distinguished_name, hostnames, lifetime)) {
			return {};
		}

		res = gnutls_x509_crt_privkey_sign(crt, crt, priv.get(), GNUTLS_DIG_SHA256, 0);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_privkey_sign");
			return {};
		}

		datum_holder ch;
		res = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &ch);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_export2");
			return {};
		}

		return ch.to_string();
	}();

	gnutls_x509_crt_deinit(crt);

	return ret;
}

static std::pair<unique_gnutls_privkey, std::string> generate_priv_key_for_cert(tls_layer_impl::cert_context &ctx, native_string const& password, tls_layer::cert_type type, bool ecdsa)
{
	gnutls_x509_privkey_t priv;
	int res = gnutls_x509_privkey_init(&priv);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_privkey_init");
		return {};
	}

	auto ret = [&]() -> std::pair<unique_gnutls_privkey, std::string> {

		auto fmt = ecdsa ? GNUTLS_PK_ECDSA : GNUTLS_PK_RSA;
		unsigned int bits = gnutls_sec_param_to_pk_bits(fmt, GNUTLS_SEC_PARAM_HIGH);
		if (fmt == GNUTLS_PK_RSA) {
			unsigned int const min_rsa_bits = type == tls_layer::cert_type::ca ? 4096 : 2048;
			if (bits < min_rsa_bits) {
				bits = min_rsa_bits;
			}
		}

		res = gnutls_x509_privkey_generate(priv, fmt, bits, 0);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_privkey_generate");
			return {};
		}

		datum_holder kh;

		if (password.empty()) {
			res = gnutls_x509_privkey_export2(priv, GNUTLS_X509_FMT_PEM, &kh);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_x509_privkey_export2");
				return {};
			}
		}
		else {
			res = gnutls_x509_privkey_export2_pkcs8(priv, GNUTLS_X509_FMT_PEM, to_utf8(password).c_str(), 0, &kh);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_x509_privkey_export2_pkcs8");
				return {};
			}
		}

		gnutls_privkey_t abstract_priv;
		res = gnutls_privkey_init(&abstract_priv);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_privkey_init");
			return {};
		}

		res = gnutls_privkey_import_x509(abstract_priv, priv, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_privkey_import_x509");
			gnutls_privkey_deinit(abstract_priv);
			return {};
		}

		priv = nullptr;

		return {unique_gnutls_privkey(abstract_priv), kh.to_string()};
	}();

	if (priv) {
		gnutls_x509_privkey_deinit(priv);
	}

	return ret;
}

std::pair<std::string, std::string> tls_layer_impl::generate_selfsigned_certificate(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, duration const& lifetime, tls_layer::cert_type type, bool ecdsa, logger_interface &logger)
{
	cert_context ctx(logger);

	auto [priv, key] = generate_priv_key_for_cert(ctx, password, type, ecdsa);
	if (!priv) {
		return {};
	}

	auto cert = generate_selfsigned_certificate(ctx, std::move(priv), distinguished_name, hostnames, lifetime, type);
	if (cert.empty()) {
		return {};
	}

	return {std::move(key), std::move(cert)};
}

std::string tls_layer_impl::generate_selfsigned_certificate(const_tls_param_ref key, native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, duration const& lifetime, tls_layer::cert_type type, logger_interface &logger)
{
	cert_context ctx(logger);

	auto priv = import_private_key(ctx, key, password, tls_data_format::autodetect);
	if (!priv) {
		return {};
	}

	auto cert = generate_selfsigned_certificate(ctx, std::move(priv), distinguished_name, hostnames, lifetime, type);
	if (cert.empty()) {
		return {};
	}

	return cert;
}

std::string tls_layer_impl::generate_cert_from_csr(std::pair<std::string, std::string> const& issuer, native_string const& password, std::string const& csr, std::string const& distinguished_name, std::vector<std::string> const& hostnames, duration const& lifetime, tls_layer::tls_layer::cert_type type, logger_interface &logger)
{
	cert_context ctx(logger);

	gnutls_x509_privkey_t priv;
	int res = gnutls_x509_privkey_init(&priv);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_privkey_init");
		return {};
	}
	gnutls_x509_crt_t icrt;
	res = gnutls_x509_crt_init(&icrt);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_init");
		gnutls_x509_privkey_deinit(priv);
		return {};
	}
	gnutls_x509_crq_t crq;
	res = gnutls_x509_crq_init(&crq);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crq_init");
		gnutls_x509_crt_deinit(icrt);
		gnutls_x509_privkey_deinit(priv);
		return {};
	}
	gnutls_x509_crt_t crt;
	res = gnutls_x509_crt_init(&crt);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crt_init");
		gnutls_x509_crq_deinit(crq);
		gnutls_x509_crt_deinit(icrt);
		gnutls_x509_privkey_deinit(priv);
		return {};
	}

	std::string cert = [&]() -> std::string {

		gnutls_datum_t kd;
		kd.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(issuer.first.data()));
		kd.size = issuer.first.size();
		res = gnutls_x509_privkey_import2(priv, &kd, GNUTLS_X509_FMT_PEM, to_utf8(password).c_str(), 0);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_privkey_import2");
			return {};
		}

		gnutls_datum_t icrtd;
		icrtd.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(issuer.second.data()));
		icrtd.size = issuer.second.size();
		res = gnutls_x509_crt_import(icrt, &icrtd, GNUTLS_X509_FMT_PEM);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_import");
			return {};
		}

		gnutls_datum_t csrd;
		csrd.data = const_cast<unsigned char*>(reinterpret_cast<unsigned char const*>(csr.data()));
		csrd.size = csr.size();
		res = gnutls_x509_crq_import(crq, &csrd, GNUTLS_X509_FMT_PEM);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_import");
			return {};
		}

		res = gnutls_x509_crq_verify(crq, 0);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_verify");
			return {};
		}

		// Verify key purpose oids
		std::set<std::string> purposes;
		if (!get_purposes(crq, purposes)) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Could not get certificate request purposes."));
			return {};
		}
		if (!verify_purposes(purposes, type)) {
			ctx.logger.log_raw(logmsg::error, fztranslate("Certificate request purposes do not match with its type."));
			return {};
		}

		// Verify key usage
		unsigned int usage{};
		unsigned int critical{};
		if ((res = gnutls_x509_crq_get_key_usage(crq, &usage, &critical)) && res != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_get_key_usage");
			return {};
		}

		if (type == tls_layer::cert_type::ca) {
			if (usage & ~(GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN)) {
				ctx.logger.log_raw(logmsg::error, fztranslate("Certificate request has wrong key usage types set."));
				return {};
			}
		}
		else {
			if (usage & ~(GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT)) {
				ctx.logger.log_raw(logmsg::error, fztranslate("Certificate request has wrong key usage types set."));
				return {};
			}
		}

		res = gnutls_x509_crt_set_version(crt, 3);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_version");
			return {};
		}

		res = gnutls_x509_crt_set_crq(crt, crq);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_crq");
			return {};
		}

		res = gnutls_x509_crt_set_crq_extensions(crt, crq);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_set_crq_extensions");
			return {};
		}

		if (!set_cert_params(ctx, crt, type, distinguished_name, hostnames, lifetime)) {
			return {};
		}

		res = gnutls_x509_crt_sign(crt, icrt, priv);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_sign");
			return {};
		}

		datum_holder ch;
		res = gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_PEM, &ch);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crt_export2");
			return {};
		}

		return ch.to_string();
	}();

	gnutls_x509_crt_deinit(crt);
	gnutls_x509_crq_deinit(crq);
	gnutls_x509_crt_deinit(icrt);
	gnutls_x509_privkey_deinit(priv);

	return cert;
}

std::string tls_layer_impl::generate_csr(cert_context &ctx, unique_gnutls_privkey priv, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem, tls_layer::cert_type type)
{
	gnutls_x509_crq_t crq;
	int res = gnutls_x509_crq_init(&crq);
	if (res) {
		ctx.log_gnutls_error(res, L"gnutls_x509_crq_init");
		return {};
	}

	auto ret = [&]() -> std::string {
		res = gnutls_x509_crq_set_version(crq, 3);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_version");
			return {};
		}

		unsigned int key_usage = (type == tls_layer::cert_type::ca) ? (GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN) : (GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT);

		{
			gnutls_pubkey_t pub;
			res = gnutls_pubkey_init(&pub);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_pubkey_init");
			}
			else {
				res = gnutls_pubkey_import_privkey(pub, priv.get(), key_usage, 0);
				if (res) {
					ctx.log_gnutls_error(res, L"gnutls_pubkey_import_privkey");
				}
				else {
					res = gnutls_x509_crq_set_pubkey(crq, pub);
					if (res) {
						ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_pubkey");
					}
				}
				gnutls_pubkey_deinit(pub);
			}
		}


		if (res) {
			return {};
		}

		char const* out{};
		res = gnutls_x509_crq_set_dn(crq, distinguished_name.c_str(), &out);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_dn");
			return {};
		}

		for (auto const& hostname : hostnames) {
			res = gnutls_x509_crq_set_subject_alt_name(crq, GNUTLS_SAN_DNSNAME, hostname.c_str(), hostname.size(), GNUTLS_FSAN_APPEND);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_subject_alt_name");
				return {};
			}
		}

		res = gnutls_x509_crq_set_key_usage(crq, key_usage);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_key_usage");
			return {};
		}

		if (type == tls_layer::cert_type::client || type == tls_layer::cert_type::server) {
			res = gnutls_x509_crq_set_key_purpose_oid(crq, (type == tls_layer::cert_type::server) ? GNUTLS_KP_TLS_WWW_SERVER : GNUTLS_KP_TLS_WWW_CLIENT, 1);
			if (res) {
				ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_key_purpose_oid");
				return {};
			}
		}

		res = gnutls_x509_crq_set_basic_constraints(crq, 0, -1);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_set_basic_constraints");
			return {};
		}

		res = gnutls_x509_crq_privkey_sign(crq, priv.get(), GNUTLS_DIG_SHA256, 0);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_privkey_sign");
			return {};
		}

		datum_holder ch;
		res = gnutls_x509_crq_export2(crq, csr_as_pem ? GNUTLS_X509_FMT_PEM : GNUTLS_X509_FMT_DER, &ch);
		if (res) {
			ctx.log_gnutls_error(res, L"gnutls_x509_crq_export2");
			return {};
		}

		return ch.to_string();
	}();

	gnutls_x509_crq_deinit(crq);

	return ret;
}

std::string tls_layer_impl::generate_csr(const_tls_param_ref key, native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem, tls_layer::cert_type type, logger_interface &logger)
{
	cert_context ctx(logger);

	auto priv = import_private_key(ctx, key, password, tls_data_format::autodetect);
	if (!priv) {
		return {};
	}

	return generate_csr(ctx, std::move(priv), distinguished_name, hostnames, csr_as_pem, type);
}

std::pair<std::string, std::string> tls_layer_impl::generate_csr(native_string const& password, std::string const& distinguished_name, std::vector<std::string> const& hostnames, bool csr_as_pem, tls_layer::cert_type type, bool ecdsa, logger_interface &logger)
{
	cert_context ctx(logger);

	auto [priv, key] = generate_priv_key_for_cert(ctx, password, type, ecdsa);
	if (!priv) {
		return {};
	}

	auto cert = generate_csr(ctx, std::move(priv), distinguished_name, hostnames, csr_as_pem, type);
	if (cert.empty()) {
		return {};
	}

	return {std::move(key), std::move(cert)};
}

bool tls_layer_impl::add_pkcs11_provider(const native_string_view &path, logger_interface &logger)
{
	static auto const pgnutls_pkcs11_init = dynamic_gnutls_func(gnutls_pkcs11_init);
	static auto const pgnutls_pkcs11_add_provider = dynamic_gnutls_func(gnutls_pkcs11_add_provider);

	if (!pgnutls_pkcs11_init || !pgnutls_pkcs11_add_provider) {
		logger.log(logmsg::error, fztranslate("GnuTLS has been compiled without PKCS#11 support"));
		return {};
	}

	int res = pgnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, nullptr);
	if (res) {
		log_gnutls_error(logger, res, L"gnutls_pkcs11_init");
		return {};
	}

	res = pgnutls_pkcs11_add_provider(to_string(path).c_str(), nullptr);
	if (res) {
		log_gnutls_error(logger, res, L"gnutls_pkcs11_add_provider");
		return {};
	}

	return true;
}

bool tls_layer::supports_pkcs11()
{
	static bool const supported = dynamic_gnutls_func(gnutls_pkcs11_init) != nullptr;
	return supported;
}

int tls_layer_impl::shutdown_read()
{
	if (!can_read_from_socket_) {
		return EAGAIN;
	}

	char c{};
	int error{};
	int res = tls_layer_.next_layer_.read(&c, 1, error);
	if (!res) {
		return tls_layer_.next_layer_.shutdown_read();
	}
	else if (res > 0) {
		// Have to fail the connection as we have now discarded data.
		return ECONNABORTED;
	}

	if (error == EAGAIN) {
		can_read_from_socket_ = false;
#if DEBUG_SOCKETEVENTS
		debug_can_read_ = false;
#endif
	}

	return error;
}

void tls_layer_impl::set_event_handler(event_handler* pEvtHandler, fz::socket_event_flag retrigger_block)
{
	write_blocked_by_send_buffer_ = false;

	fz::socket_event_flag const pending = change_socket_event_handler(tls_layer_.event_handler_, pEvtHandler, &tls_layer_, retrigger_block);
	tls_layer_.event_handler_ = pEvtHandler;

	if (pEvtHandler) {
		if (can_write_to_socket_ && (state_ == socket_state::connected || state_ == socket_state::shutting_down) && !(pending & (socket_event_flag::write | socket_event_flag::connection)) && !(retrigger_block & socket_event_flag::write)) {
			pEvtHandler->send_event<socket_event>(&tls_layer_, socket_event_flag::write, 0);
#if DEBUG_SOCKETEVENTS
			assert(debug_can_write_);
#endif
		}
		if (can_read_from_socket_ && (state_ == socket_state::connected || state_ == socket_state::shutting_down || state_ == socket_state::shut_down)) {
			if (!(pending & socket_event_flag::read) && !(retrigger_block & socket_event_flag::read)) {
				pEvtHandler->send_event<socket_event>(&tls_layer_, socket_event_flag::read, 0);
#if DEBUG_SOCKETEVENTS
				assert(debug_can_read_);
#endif
			}
		}
	}

}

bool tls_layer_impl::do_set_alpn()
{
	if (alpn_.empty()) {
		return true;
	}

	gnutls_datum_t * data = new gnutls_datum_t[alpn_.size()];
	for (size_t i = 0; i < alpn_.size(); ++i) {
		data[i].data = reinterpret_cast<unsigned char *>(const_cast<char*>(alpn_[i].c_str()));
		data[i].size = alpn_[i].size();
	}
	int flags = GNUTLS_ALPN_MANDATORY;
	if (alpn_server_priority_ && server_) {
		flags |= GNUTLS_ALPN_SERVER_PRECEDENCE;
	}
	int res = gnutls_alpn_set_protocols(session_, data, alpn_.size(), flags);
	delete [] data;

	if (res) {
		log_error(res, L"gnutls_alpn_set_protocols"sv);
	}
	return res == 0;
}

std::string tls_layer_impl::get_alpn() const
{
	if (session_) {
		gnutls_datum_t protocol;
		if (!gnutls_alpn_get_selected_protocol(session_, &protocol)) {
			return to_string(protocol);
		}
	}
	return {};
}

void tls_layer_impl::set_min_tls_ver(tls_ver ver)
{
	min_tls_ver_ = ver;
}

void tls_layer_impl::set_max_tls_ver(tls_ver ver)
{
	max_tls_ver_ = ver;
}

int tls_layer_impl::new_session_ticket()
{
	if (state_ == socket_state::shutting_down || state_ == socket_state::shut_down) {
		return ESHUTDOWN;
	}
	else if (state_ != socket_state::connected) {
		return ENOTCONN;
	}

	if (!server_) {
		return EINVAL;
	}

	if (gnutls_protocol_get_version(session_) != GNUTLS_TLS1_3) {
		return 0;
	}

#if DEBUG_SOCKETEVENTS
	assert(debug_can_write_);
	assert(!has_pending_event(tls_layer_.event_handler_, &tls_layer_, socket_event_flag::write));
#endif

	if (!send_buffer_.empty()|| send_new_ticket_) {
		send_new_ticket_ = true;
		return 0;
	}

	int res = GNUTLS_E_AGAIN;
	while ((res == GNUTLS_E_INTERRUPTED || res == GNUTLS_E_AGAIN) && can_write_to_socket_) {
		res = gnutls_session_ticket_send(session_, 1, 0);
	}

	if (res == GNUTLS_E_SUCCESS) {
		return 0;
	}
	else if (res == GNUTLS_E_AGAIN) {
		send_new_ticket_ = true;
		return 0;
	}

	failure(res, false, L"gnutls_session_ticket_send"sv);
	return socket_error_ ? socket_error_ : ECONNABORTED;
}

void tls_layer_impl::set_unexpected_eof_cb(std::function<bool()> && cb)
{
	unexpected_eof_cb_ = std::move(cb);
}

}
