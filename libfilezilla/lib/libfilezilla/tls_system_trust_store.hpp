#ifndef LIBFILEZILLA_TLS_SYSTEM_TRUST_STORE_HEADER
#define LIBFILEZILLA_TLS_SYSTEM_TRUST_STORE_HEADER

/** \file
 * \brief System trust store for TLS certificates
 *
 * Declares the \ref fz::tls_system_trust_store class.
 */

#include "libfilezilla.hpp"

#include <memory>

namespace fz {
class thread_pool;
class tls_system_trust_store_impl;
class tls_layer_impl;

/**
 * \brief Opaque class to load the system trust store asynchronously
 *
 * Loading system trust store can take a significant amount of time
 * if there are large CRLs.
 *
 * Use it as shared resource that is loaded asynchronously.
 * This class is thread-safe and can be passed concurrently to
 * multiple instances of \ref fz::tls_layer.
 */
class FZ_PUBLIC_SYMBOL tls_system_trust_store final
{
public:
	tls_system_trust_store(thread_pool& pool);
	~tls_system_trust_store();

private:
	friend class tls_layer_impl;
	std::unique_ptr<tls_system_trust_store_impl> impl_;
};
}

#endif
