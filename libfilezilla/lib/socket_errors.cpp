#include "libfilezilla/libfilezilla.hpp"
#ifdef FZ_WINDOWS
  #include "libfilezilla/glue/windows.hpp"
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mstcpip.h>
#endif
#include "libfilezilla/format.hpp"
#include "libfilezilla/socket.hpp"
#include "libfilezilla/translate.hpp"
#ifndef FZ_WINDOWS
#include <netdb.h>
#endif

#include <unordered_map>

// Fixups needed on FreeBSD
#if !defined(EAI_ADDRFAMILY) && defined(EAI_FAMILY)
  #define EAI_ADDRFAMILY EAI_FAMILY
#endif

namespace fz {

namespace {
struct Error
{
	std::string name;
	std::string description;
};

std::unordered_map<int, Error> const& get_errors()
{
	static std::unordered_map<int, Error> const errors = [](){
		std::unordered_map<int, Error> ret;

		auto sorted_insert = [&ret](int code, std::string const& name, std::string const& description)
		{
			auto it = ret.find(code);
			if (it == ret.cend()) {
				ret[code] = {name, description};
			}
		};
		#define insert(c, desc) sorted_insert(c, #c, desc)

		insert(EACCES, fztranslate_mark("Permission denied"));
		insert(EADDRINUSE, fztranslate_mark("Local address in use"));
		insert(EAFNOSUPPORT, fztranslate_mark("The specified address family is not supported"));
		insert(EINPROGRESS, fztranslate_mark("Operation in progress"));
		insert(EINVAL, fztranslate_mark("Invalid argument passed"));
		insert(EMFILE, fztranslate_mark("Process file table overflow"));
		insert(ENFILE, fztranslate_mark("System limit of open files exceeded"));
		insert(ENOBUFS, fztranslate_mark("Out of memory"));
		insert(ENOMEM, fztranslate_mark("Out of memory"));
		insert(EPERM, fztranslate_mark("Permission denied"));
		insert(EPROTONOSUPPORT, fztranslate_mark("Protocol not supported"));
		insert(EAGAIN, fztranslate_mark("Resource temporarily unavailable"));
		insert(EALREADY, fztranslate_mark("Operation already in progress"));
		insert(EBADF, fztranslate_mark("Bad file descriptor"));
		insert(ECONNREFUSED, fztranslate_mark("Connection refused by server"));
		insert(EFAULT, fztranslate_mark("Socket address outside address space"));
		insert(EINTR, fztranslate_mark("Interrupted by signal"));
		insert(EISCONN, fztranslate_mark("Socket already connected"));
		insert(ENETUNREACH, fztranslate_mark("Network unreachable"));
		insert(ENOTSOCK, fztranslate_mark("File descriptor not a socket"));
		insert(ETIMEDOUT, fztranslate_mark("Connection attempt timed out"));
		insert(EHOSTUNREACH, fztranslate_mark("No route to host"));
		insert(ENOTCONN, fztranslate_mark("Socket not connected"));
		insert(ENETRESET, fztranslate_mark("Connection reset by network"));
		insert(EOPNOTSUPP, fztranslate_mark("Operation not supported"));
		insert(ESHUTDOWN, fztranslate_mark("Socket has been shut down"));
		insert(EMSGSIZE, fztranslate_mark("Message too large"));
		insert(ECONNABORTED, fztranslate_mark("Connection aborted"));
		insert(ECONNRESET, fztranslate_mark("Connection reset by peer"));
		insert(EPIPE, fztranslate_mark("Local endpoint has been closed"));
		insert(EHOSTDOWN, fztranslate_mark("Host is down"));

		// Getaddrinfo related
	#ifdef EAI_ADDRFAMILY
		insert(EAI_ADDRFAMILY, fztranslate_mark("Network host does not have any network addresses in the requested address family"));
	#endif
		insert(EAI_AGAIN, fztranslate_mark("Temporary failure in name resolution"));
		insert(EAI_BADFLAGS, fztranslate_mark("Invalid value for ai_flags"));
	#ifdef EAI_BADHINTS
		insert(EAI_BADHINTS, fztranslate_mark("Invalid value for hints"));
	#endif
		insert(EAI_FAIL, fztranslate_mark("Nonrecoverable failure in name resolution"));
		insert(EAI_FAMILY, fztranslate_mark("The ai_family member is not supported"));
		insert(EAI_MEMORY, fztranslate_mark("Memory allocation failure"));
	#ifdef EAI_NODATA
		insert(EAI_NODATA, fztranslate_mark("No address associated with nodename"));
	#endif
		insert(EAI_NONAME, fztranslate_mark("Neither nodename nor servname provided, or not known"));
	#ifdef EAI_OVERFLOW
		insert(EAI_OVERFLOW, fztranslate_mark("Argument buffer overflow"));
	#endif
	#ifdef EAI_PROTOCOL
		insert(EAI_PROTOCOL, fztranslate_mark("Resolved protocol is unknown"));
	#endif
		insert(EAI_SERVICE, fztranslate_mark("The servname parameter is not supported for ai_socktype"));
		insert(EAI_SOCKTYPE, fztranslate_mark("The ai_socktype member is not supported"));
	#ifdef EAI_SYSTEM
		insert(EAI_SYSTEM, fztranslate_mark("Other system error"));
	#endif
	#ifdef EAI_IDN_ENCODE
		insert(EAI_IDN_ENCODE, fztranslate_mark("Invalid characters in hostname"));
	#endif
	#ifdef EADDRNOTAVAIL
		insert(EADDRNOTAVAIL, fztranslate_mark("Cannot assign requested address"));
	#endif
		insert(ESOCKTNOSUPPORT, fztranslate_mark("Socket type not supported"));

	// Codes that have no POSIX equivalence
	#ifdef FZ_WINDOWS
		insert(WSANOTINITIALISED, fztranslate_mark("Not initialized, need to call WSAStartup"));
		insert(WSAENETDOWN, fztranslate_mark("System's network subsystem has failed"));
		insert(WSAEPROTOTYPE, fztranslate_mark("Protocol not supported on given socket type"));
		insert(WSAESOCKTNOSUPPORT, fztranslate_mark("Socket type not supported for address family"));
		insert(WSAEADDRNOTAVAIL, fztranslate_mark("Cannot assign requested address"));
		insert(ERROR_NETNAME_DELETED, fztranslate_mark("The specified network name is no longer available"));
	#endif

		return ret;
	}();

	return errors;
}
}

std::string socket_error_string(int error)
{
	auto const& errors = get_errors();
	auto const it = errors.find(error);
	if (it != errors.end()) {
		return it->second.name;
	}
	return to_string(error);
}

native_string socket_error_description(int error)
{
	auto const& errors = get_errors();
	auto const it = errors.find(error);
	if (it != errors.end()) {
		return to_native(to_native(std::string(it->second.name)) + fzT(" - ") + to_native(translate(it->second.description.c_str())));
	}

#if FZ_WINDOWS
	wchar_t* out{};
	if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<wchar_t*>(&out), 0, nullptr) != 0 && out && *out) {
		native_string ret = out;
		LocalFree(out);
		return ret;
	}
#endif

	return sprintf(fzT("%d"), error);
}

}
