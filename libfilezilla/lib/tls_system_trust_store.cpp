#include "libfilezilla/tls_system_trust_store.hpp"
#include "tls_system_trust_store_impl.hpp"

namespace fz {

tls_system_trust_store_impl::tls_system_trust_store_impl(thread_pool& pool)
{
	task_ = pool.spawn([this]() {
		gnutls_certificate_credentials_t cred{};

		if (gnutls_certificate_allocate_credentials(&cred) >= 0) {
			if (gnutls_certificate_set_x509_system_trust(cred) < 0) {
				gnutls_certificate_free_credentials(cred);
				cred = nullptr;
			}
		}

		scoped_lock l(mtx_);
		credentials_ = cred;
		cond_.signal(l);
	});
}

tls_system_trust_store_impl::~tls_system_trust_store_impl()
{
	task_.join();

	if (credentials_) {
		gnutls_certificate_free_credentials(credentials_);
	}
}

std::tuple<gnutls_certificate_credentials_t, scoped_lock> tls_system_trust_store_impl::lease()
{
	scoped_lock l(mtx_);
	if (task_) {
		cond_.wait(l);
		task_.join();
	}

	return std::make_tuple(credentials_, std::move(l));
}


tls_system_trust_store::tls_system_trust_store(thread_pool& pool)
	: impl_(std::make_unique<tls_system_trust_store_impl>(pool))
{
}

tls_system_trust_store::~tls_system_trust_store()
{
}

}
