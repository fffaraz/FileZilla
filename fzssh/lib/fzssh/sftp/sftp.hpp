#ifndef FZSSH_SFTP_HEADER
#define FZSSH_SFTP_HEADER

#include <string_view>
#include "../visibility.hpp"

#include <libfilezilla/time.hpp>

#include <optional>

namespace fz {

class logger_interface;

namespace ssh::sftp {

enum class status_code : uint32_t {
	SSH_FX_OK = 0,
	SSH_FX_EOF = 1,
	SSH_FX_NO_SUCH_FILE = 2,
	SSH_FX_PERMISSION_DENIED = 3,
	SSH_FX_FAILURE = 4,
	SSH_FX_BAD_MESSAGE = 5,
	SSH_FX_NO_CONNECTION = 6,
	SSH_FX_CONNECTION_LOST = 7,
	SSH_FX_OP_UNSUPPORTED = 8,

	MAX = SSH_FX_OP_UNSUPPORTED
};

std::string_view FZSSH_PUBLIC_SYMBOL to_string(status_code id);

enum class attribute_flags : uint32_t {
	SSH_FILEXFER_ATTR_SIZE = 0x1u,
	SSH_FILEXFER_ATTR_UIDGID = 0x2u,
	SSH_FILEXFER_ATTR_PERMISSIONS = 0x4u,
	SSH_FILEXFER_ATTR_ACMODTIME = 0x8u,
	SSH_FILEXFER_ATTR_EXTENDED = 0x80000000u
};

enum class file_flags : uint32_t {
	SSH_FXF_READ = 0x1u,
	SSH_FXF_WRITE = 0x2u,
	SSH_FXF_APPEND = 0x4u,
	SSH_FXF_CREAT = 0x8u,
	SSH_FXF_TRUNC = 0x10u,
	SSH_FXF_EXCL = 0x20u
};

struct FZSSH_PUBLIC_SYMBOL attributes
{
	std::optional<uint64_t> size_;

	std::optional<fz::datetime> accessed_;
	std::optional<fz::datetime> modified_;

	std::optional<uint32_t> perms_;

	std::optional<uint32_t> uid_;
	std::optional<uint32_t> gid_;

	bool is_directory() const;
	bool is_symlink() const;
};

inline bool operator&(file_flags lhs, file_flags rhs) {
	return (static_cast<std::underlying_type_t<file_flags>>(lhs) & static_cast<std::underlying_type_t<file_flags>>(rhs)) != 0;
}
inline file_flags operator|(file_flags lhs, file_flags rhs) {
	return static_cast<file_flags>(static_cast<std::underlying_type_t<file_flags>>(lhs) | static_cast<std::underlying_type_t<file_flags>>(rhs));
}
inline file_flags& operator|=(file_flags & lhs, file_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}

inline bool operator&(attribute_flags lhs, attribute_flags rhs) {
	return (static_cast<std::underlying_type_t<attribute_flags>>(lhs) & static_cast<std::underlying_type_t<attribute_flags>>(rhs)) != 0;
}
inline attribute_flags operator|(attribute_flags lhs, attribute_flags rhs) {
	return static_cast<attribute_flags>(static_cast<std::underlying_type_t<attribute_flags>>(lhs) | static_cast<std::underlying_type_t<attribute_flags>>(rhs));
}
inline attribute_flags& operator|=(attribute_flags & lhs, attribute_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}

enum class continuation {
	next,
	wait,
	wait_and_retry,
	error
};

}
}

#endif
