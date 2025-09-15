#ifndef LIBFILEZILLA_IPUTILS_HEADER
#define LIBFILEZILLA_IPUTILS_HEADER

#include "libfilezilla.hpp"
#include <optional>

/** \file
 * \brief Various functions to deal with IP address strings
 */

namespace fz {

/** \brief Given a shortened IPv6 address, returns the full, unshortened address
 *
 * If passed address is encloded in square brackets, they are stripped.
 *
 * Returns an empty string if the passed string isn't a valid IPv6 address.
 */
std::string FZ_PUBLIC_SYMBOL get_ipv6_long_form(std::string_view const& short_address);
std::wstring FZ_PUBLIC_SYMBOL get_ipv6_long_form(std::wstring_view const& short_address);

/** \brief Tests whether the passed IP address is routable on the public Internet.
 *
 * Unroutable addresss are:
 * \li Invalid addresses
 * \li ::/128 (the unspecified address)
 * \li ::1/128 (localhost)
 * \li fe80::/10 (link-local)
 * \li fc00::/7 (unique local)
 * \li 127.0.0.0/8 (localhost)
 * \li 10.0.0.0/8 (private)
 * \li 172.16.0.0/12 (private)
 * \li 192.168.0.0/16 (private)
 * \li 169.254.0.0/16 (link-local)
 *
 * All other addresses are assumed routable.
 */
bool FZ_PUBLIC_SYMBOL is_routable_address(std::string_view const& address);
bool FZ_PUBLIC_SYMBOL is_routable_address(std::wstring_view const& address);

enum class address_type
{
	unknown,
	ipv4,
	ipv6,
	unix
};

/** \brief Gets the type of the passed IP address. */
address_type FZ_PUBLIC_SYMBOL get_address_type(std::string_view const& address);
address_type FZ_PUBLIC_SYMBOL get_address_type(std::wstring_view const& address);

struct FZ_PUBLIC_SYMBOL network_interface
{
	native_string name;
	std::string mac;
	std::vector<std::string> addresses;
};

std::optional<std::vector<network_interface>> FZ_PUBLIC_SYMBOL get_network_interfaces();
}

#endif
