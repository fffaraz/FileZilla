#ifndef FZSSH_CRYPT_MLKEM_HEADER
#define FZSSH_CRYPT_MLKEM_HEADER

#include <libfilezilla/buffer.hpp>

#include "visibility_crypt.hpp"

namespace fz::ssh {

void FZSSH_CRYPT_PUBLIC_SYMBOL mlkem_keygen(fz::buffer & pub, fz::buffer & priv);
fz::buffer FZSSH_CRYPT_PUBLIC_SYMBOL mlkem_encaps(fz::buffer & ciphertext, std::string_view const& pub);
fz::buffer FZSSH_CRYPT_PUBLIC_SYMBOL mlkem_decaps(fz::buffer & priv, std::string_view const& ciphertext);

}

#endif
