#ifndef LIBFILEZILLA_HOSTNAME_LOOKUP_HEADER
#define LIBFILEZILLA_HOSTNAME_LOOKUP_HEADER

/** \file
 * \brief Header for the \ref fz::hostname_lookup class
 */

#include "libfilezilla.hpp"
#include "iputils.hpp"
#include "event_handler.hpp"

namespace fz {
class FZ_PUBLIC_SYMBOL hostname_lookup
{
public:
	hostname_lookup(thread_pool& pool, event_handler& evt_handler);
	~hostname_lookup();

	hostname_lookup(hostname_lookup const&) = delete;
	hostname_lookup& operator=(hostname_lookup const&) = delete;

	/**
	 * \brief Looks up the passed host
	 *
	 * If family is unknown, looks up both IPv4 and IPv6 addresses, if the operating system
	 * is configured to resolve IPv6 addresses.
	 *
	 * If the function returns true, wait for the \ref hostname_lookup_event before you can call it again.
	 */
	bool lookup(native_string const& host, address_type family = address_type::unknown);

	void reset();

private:
	class impl;
	impl* impl_{};
};

/// \private
struct hostname_lookup_event_type {};

/// Results of hostname_lookup. On success, second argument is zero, otherwise an error code.
typedef simple_event<hostname_lookup_event_type, hostname_lookup*, int, std::vector<std::string>> hostname_lookup_event;
}

#endif
