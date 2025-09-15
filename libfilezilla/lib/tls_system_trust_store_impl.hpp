#ifndef LIBFILEZILLA_TLS_SYSTEM_TRUST_STORE_IMPL_HEADER
#define LIBFILEZILLA_TLS_SYSTEM_TRUST_STORE_IMPL_HEADER

#include "libfilezilla/tls_system_trust_store.hpp"

#if defined(_MSC_VER)
typedef std::make_signed_t<size_t> ssize_t;
#endif

#include <gnutls/gnutls.h>

#include "libfilezilla/thread_pool.hpp"

#include <tuple>

namespace fz {

class tls_system_trust_store_impl final
{
public:
	tls_system_trust_store_impl(thread_pool& pool);
	~tls_system_trust_store_impl();

	std::tuple<gnutls_certificate_credentials_t, scoped_lock> lease();

private:
	mutex mtx_{false};
	condition cond_;

	gnutls_certificate_credentials_t credentials_{};

	async_task task_;
};

}
#endif
