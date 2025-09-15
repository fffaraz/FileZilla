#include "libfilezilla/iputils.hpp"
#include "libfilezilla/encode.hpp"

#if FZ_WINDOWS
#include "libfilezilla/socket.hpp"
#include "libfilezilla/glue/windows.hpp"
#include <winsock2.h>
#include <iphlpapi.h>
#include <memory>
#elif __linux__
#include "libfilezilla/socket.hpp"
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <map>
#endif

namespace fz {
template<typename String, typename Char = typename String::value_type, typename OutString = std::basic_string<Char>>
OutString do_get_ipv6_long_form(String const& short_address)
{
	size_t start = 0;
	size_t end = short_address.size();

	if (!short_address.empty() && short_address[0] == '[') {
		if (short_address.back() != ']') {
			return OutString();
		}
		++start;
		--end;
	}

	if ((end - start) < 2 || (end - start) > 39) {
		return OutString();
	}

	Char buf[39] = {
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0', ':',
		'0', '0', '0', '0'
	};

	size_t left_segments{};

	// Left half, before possible ::
	while (left_segments < 8 && start < end) {
		size_t pos = short_address.find(':', start);
		if (pos == String::npos) {
			pos = end;
		}
		if (pos == start) {
			if (!left_segments) {
				if (short_address[start + 1] != ':') {
					return OutString();
				}
				start = pos + 1;
			}
			else {
				start = pos;
			}
			break;
		}

		size_t group_length = pos - start;
		if (group_length > 4) {
			return OutString();
		}

		Char* out = buf + 5 * left_segments;
		out += 4 - group_length;
		for (size_t i = start; i < pos; ++i) {
			Char const& c = short_address[i];
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				*out++ = c;
			}
			else if (c >= 'A' && c <= 'F') {
				*out++ = c + ('a' - 'A');
			}
			else {
				// Invalid character
				return OutString();
			}
		}
		++left_segments;

		start = pos + 1;
	}

	size_t right_segments{};

	// Right half, after possible ::
	while (left_segments + right_segments < 8 && start < end) {
		--end;
		size_t pos = short_address.rfind(':', end); // Cannot be npos

		size_t const group_length = end - pos;
		if (!group_length) {
			if (left_segments || right_segments) {
				/// ::: or two ::
				return OutString();
			}
			break;
		}
		else if (group_length > 4) {
			return OutString();
		}

		Char* out = buf + 5 * (8 - right_segments) - 1;
		for (size_t i = end; i > pos; --i) {
			Char const& c = short_address[i];
			if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				*(--out) = c;
			}
			else if (c >= 'A' && c <= 'F') {
				*(--out) = c + ('a' - 'A');
			}
			else {
				// Invalid character
				return OutString();
			}
		}
		++right_segments;

		end = pos;
	}

	if (start < end) {
		// Too many segments
		return OutString();
	}

	return OutString(buf, 39);
}

std::string get_ipv6_long_form(std::string_view const& short_address)
{
	return do_get_ipv6_long_form(short_address);
}

std::wstring get_ipv6_long_form(std::wstring_view const& short_address)
{
	return do_get_ipv6_long_form(short_address);
}

template<typename String, typename Char = typename String::value_type>
bool do_is_routable_address(String const& address)
{
	auto const type = get_address_type(address);

	if (type == address_type::ipv6) {
		auto long_address = do_get_ipv6_long_form(address);
		if (long_address.size() != 39) {
			return false;
		}
		if (long_address[0] == '0') {
			// ::/128
			if (long_address == fzS(Char, "0000:0000:0000:0000:0000:0000:0000:0000")) {
				return false;
			}
			// ::1/128
			if (long_address == fzS(Char, "0000:0000:0000:0000:0000:0000:0000:0001")) {
				return false;
			}

			if (long_address.substr(0, 30) == fzS(Char, "0000:0000:0000:0000:0000:ffff:")) {
				char const dot = '.';
				// IPv4 mapped
				std::string ipv4 =
					toString<std::string>(hex_char_to_int(long_address[30]) * 16 + hex_char_to_int(long_address[31])) + dot +
					toString<std::string>(hex_char_to_int(long_address[32]) * 16 + hex_char_to_int(long_address[33])) + dot +
					toString<std::string>(hex_char_to_int(long_address[35]) * 16 + hex_char_to_int(long_address[36])) + dot +
					toString<std::string>(hex_char_to_int(long_address[37]) * 16 + hex_char_to_int(long_address[38]));

				return do_is_routable_address(ipv4);
			}

			return true;
		}
		if (long_address[0] == 'f') {
			if (long_address[1] == 'e') {
				// fe80::/10 (link local)
				int v = hex_char_to_int(long_address[2]);
				return (v & 0xc) != 0x8;
			}
			else if (long_address[1] == 'c' || long_address[1] == 'd') {
				// fc00::/7 (site local)
				return false;
			}
		}

		return true;
	}
	else if (type == address_type::ipv4) {
		if (address.size() < 7) {
			return false;
		}

		// Assumes address is already a valid IP address
		if (address.substr(0, 3) == fzS(Char, "127") ||
			address.substr(0, 3) == fzS(Char, "10.") ||
			address.substr(0, 7) == fzS(Char, "192.168") ||
			address.substr(0, 7) == fzS(Char, "169.254"))
		{
			return false;
		}

		if (address.substr(0, 3) == fzS(Char, "172")) {
			auto middle = address.substr(4);
			auto pos = middle.find('.');
			if (pos == String::npos || pos > 3) {
				return false;
			}

			auto segment = fz::to_integral<uint8_t>(middle.substr(0, pos)); // Cannot throw as we have verified it to be a valid IPv4
			if (segment >= 16 && segment <= 31) {
				return false;
			}
		}

		return true;
	}

	return false;
}

bool is_routable_address(std::string_view const& address)
{
	return do_is_routable_address(address);
}

bool is_routable_address(std::wstring_view const& address)
{
	return do_is_routable_address(address);
}

template<typename String>
address_type do_get_address_type(String const& address)
{
	if (!do_get_ipv6_long_form(address).empty()) {
		return address_type::ipv6;
	}

	int segment = 0;
	int dotcount = 0;

	for (size_t i = 0; i < address.size(); ++i) {
		auto const c = address[i];
		if (c == '.') {
			if (i + 1 < address.size() && address[i + 1] == '.') {
				// Disallow multiple dots in a row
				return address_type::unknown;
			}

			if (segment > 255) {
				return address_type::unknown;
			}
			if (!dotcount && !segment) {
				return address_type::unknown;
			}
			++dotcount;
			segment = 0;
		}
		else if (c < '0' || c > '9') {
			return address_type::unknown;
		}
		else {
			segment = segment * 10 + c - '0';
		}
	}
	if (dotcount != 3) {
		return address_type::unknown;
	}

	if (segment > 255) {
		return address_type::unknown;
	}

	return address_type::ipv4;
}

address_type get_address_type(std::string_view const& address)
{
	return do_get_address_type(address);
}

address_type get_address_type(std::wstring_view const& address)
{
	return do_get_address_type(address);
}


std::optional<std::vector<network_interface>> get_network_interfaces()
{
#if FZ_WINDOWS
	static winsock_initializer init;
	ULONG size = 16 * 1024;
	auto buf = std::make_unique<char[]>(16 * 1024);
	while (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get()), &size) != ERROR_SUCCESS) {
		DWORD err = GetLastError();
		if (err != ERROR_BUFFER_OVERFLOW) {
			return {};
		}
		buf = std::make_unique<char[]>(size);
	}

	std::vector<network_interface> out;
	for (auto cur = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get()); cur; cur = cur->Next) {
		std::wstring name = cur->FriendlyName;
		auto raw_mac = fz::hex_encode<std::string>(std::string_view{ reinterpret_cast<char const*>(cur->PhysicalAddress), cur->PhysicalAddressLength });
		std::string mac;
		for (size_t i = 0; i < raw_mac.size(); ++i) {
			if (i && !(i % 2)) {
				mac += ':';
			}
			mac += raw_mac[i];
		}

		std::vector<std::string> ips;
		for (auto addr = cur->FirstUnicastAddress; addr; addr = addr->Next) {
			if (!addr->Address.lpSockaddr) {
				continue;
			}
			if (addr->Address.lpSockaddr->sa_family != AF_INET && addr->Address.lpSockaddr->sa_family != AF_INET6) {
				continue;
			}
			if (!(addr->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE)) {
				continue;
			}
			ips.emplace_back(fz::socket_base::address_to_string(addr->Address.lpSockaddr, addr->Address.iSockaddrLength, false, true) + '/' + to_string(addr->OnLinkPrefixLength));
		}
		if (!ips.empty()) {
			out.emplace_back(network_interface{ std::move(name), std::move(mac), std::move(ips) });
		}
	}
	return out;

#elif __linux__
	int fd = ::socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd == -1) {
		return {};
	}

	std::map<int, std::pair<std::string, std::string>> interfaces;
	auto get_interfaces = [&]() -> bool {
		struct {
			nlmsghdr hdr{};
			ifinfomsg info{};
		} req{};
		req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
		req.hdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
		req.hdr.nlmsg_type = RTM_GETLINK;
		req.info.ifi_family = AF_UNSPEC;

		if (send(fd, &req, sizeof(req), MSG_NOSIGNAL) != sizeof(req)) {
			return false;
		}

		size_t constexpr bufsize = 32*1024;
		auto buf = std::make_unique<char[]>(bufsize);

		iovec iov{buf.get(), bufsize};
		msghdr msg{};
		sockaddr_nl sa{};
		msg.msg_name = &sa;
		msg.msg_namelen = sizeof(sa);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		while (true) {
			ssize_t r = recvmsg(fd, &msg, 0);

			for (nlmsghdr *hdr = reinterpret_cast<nlmsghdr*>(buf.get()); NLMSG_OK(hdr, r); hdr = NLMSG_NEXT(hdr, r)) {
				if (hdr->nlmsg_type == NLMSG_DONE) {
					return true;
				}
				if (hdr->nlmsg_type == NLMSG_ERROR) {
					return false;
				}

				if (hdr->nlmsg_type == RTM_NEWLINK) {
					ifinfomsg *info = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(hdr));

					int index = info->ifi_index;
					std::string name;
					std::string addr;

					rtattr* rta = IFLA_RTA(info);
					size_t rtalen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(ifinfomsg));
					while (RTA_OK(rta, rtalen)) {
						switch (rta->rta_type) {
							case IFLA_IFNAME:
								name = std::string_view(reinterpret_cast<char*>(RTA_DATA(rta)), RTA_PAYLOAD(rta));
								break;
							case IFLA_ADDRESS: {
								std::string_view v(reinterpret_cast<char*>(RTA_DATA(rta)), RTA_PAYLOAD(rta));
								auto raw = fz::hex_encode<std::string>(v);
								addr.clear();
								for (size_t i = 0; i < raw.size(); ++i) {
									if (i && !(i % 2)) {
										addr += ':';
									}
									addr += raw[i];
								}
								break;
							}
						}
						rta = RTA_NEXT(rta, rtalen);
					}
					if (rtalen) {
						return false;
					}
					if (name.empty()) {
						name = to_string(index);
					}
					interfaces[index] = std::make_pair(name, addr);
				}
			}
		}
		return true;
	};
	if (!get_interfaces()) {
		close(fd);
		return {};
	}


	std::vector<network_interface> out;
	auto get_addresses = [&]() -> bool {

		struct {
			nlmsghdr hdr{};
			ifaddrmsg info{};
		} req{};

		req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
		req.hdr.nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
		req.hdr.nlmsg_type = RTM_GETADDR;
		req.info.ifa_family = AF_UNSPEC;
		req.info.ifa_scope = RT_SCOPE_UNIVERSE;

		if (send(fd, &req, sizeof(req), MSG_NOSIGNAL) != sizeof(req)) {
			return false;
		}

		size_t constexpr bufsize = 32*1024;
		auto buf = std::make_unique<char[]>(bufsize);

		iovec iov{buf.get(), bufsize};
		msghdr msg{};
		sockaddr_nl sa{};
		msg.msg_name = &sa;
		msg.msg_namelen = sizeof(sa);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		while (true) {
			ssize_t r = recvmsg(fd, &msg, 0);
			if (r <= 0) {
				return false;
			}

			for (nlmsghdr *hdr = reinterpret_cast<nlmsghdr*>(buf.get()); NLMSG_OK(hdr, r); hdr = NLMSG_NEXT(hdr, r)) {
				if (hdr->nlmsg_type == NLMSG_DONE) {
					return true;
				}
				if (hdr->nlmsg_type == NLMSG_ERROR) {
					return false;
				}

				if (hdr->nlmsg_type == RTM_NEWADDR) {
					ifaddrmsg *ifa = reinterpret_cast<ifaddrmsg*>(NLMSG_DATA(hdr));

					uint32_t flags = ifa->ifa_flags;

					void* addr{};

					rtattr* rta = IFA_RTA(ifa);
					size_t rtalen = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(ifaddrmsg));
					while (RTA_OK(rta, rtalen)) {
						switch(rta->rta_type) {
							case IFA_ADDRESS:
								addr = RTA_DATA(rta);
								break;
							case IFA_FLAGS: {
								flags = *reinterpret_cast<uint32_t*>(RTA_DATA(rta));
								break;
							}
							default:
								break;
						}
						rta = RTA_NEXT(rta, rtalen);
					}
					if (rtalen) {
						return false;
					}

					if (flags & IFA_F_TEMPORARY) {
						continue;
					}
					if (!addr || (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)) {
						continue;
					}

					auto saddr = fz::socket_base::address_to_string(reinterpret_cast<char*>(addr), (ifa->ifa_family == AF_INET6) ? 16 : 4) + "/" + to_string(ifa->ifa_prefixlen);
					auto & iface = interfaces[ifa->ifa_index];
					if (iface.first.empty()) {
						iface.first = to_string(ifa->ifa_index);
					}

					auto it = std::find_if(out.begin(), out.end(), [&](auto const& ni) { return ni.name == iface.first; });
					if (it == out.cend()) {
						it = out.emplace(it);
						it->name = iface.first;
						it->mac = iface.second;
					}
					it->addresses.emplace_back(std::move(saddr));
				}
			}
		}
	};
	bool const success = get_addresses();
	close(fd);
	if (success) {
		return out;
	}
#endif

	return {};
}

}
