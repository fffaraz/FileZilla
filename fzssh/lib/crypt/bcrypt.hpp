#ifndef FZSSH_BCRYPT_HEADER
#define FZSSH_BCRYPT_HEADER

#include "visibility_crypt.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace fz::ssh {
std::string FZSSH_CRYPT_PUBLIC_SYMBOL openssh_bcrypt(std::string_view passphrase, std::string_view salt, uint32_t rounds, size_t bytes);
}

#endif
