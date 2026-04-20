/*
 * 'bcrypt' password hash function, for PuTTY's import/export of
 * OpenSSH encrypted private key files.
 *
 * This is not really the same as the original bcrypt; OpenSSH has
 * modified it in various ways, and of course we have to do the same.
 *
 * License: See fz::ssh::openssh_bcrypt_license()
 */

#include "bcrypt.hpp"

#include "blowfish.h"

#include <libfilezilla/hash.hpp>
#include <libfilezilla/util.hpp>

#if FZ_WINDOWS
#include <libfilezilla/glue/windows.hpp>
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif
#include <stddef.h>
#include <string.h>

using namespace std::literals;

namespace fz::ssh {

static BlowfishContext *bcrypt_setup(const unsigned char *key, int keybytes,
                                     const unsigned char *salt, int saltbytes)
{
    int i;
    BlowfishContext *ctx;

    ctx = blowfish_make_context();
    blowfish_initkey(ctx);
    blowfish_expandkey(ctx, key, keybytes, salt, saltbytes);

    /* Original bcrypt replaces this fixed loop count with the
     * variable cost. OpenSSH instead iterates the whole thing more
     * than once if it wants extra rounds. */
    for (i = 0; i < 64; i++) {
        blowfish_expandkey(ctx, salt, saltbytes, NULL, 0);
        blowfish_expandkey(ctx, key, keybytes, NULL, 0);
    }

    return ctx;
}

static void bcrypt_hash(const unsigned char *key, int keybytes,
                        const unsigned char *salt, int saltbytes,
                        unsigned char output[32])
{
    BlowfishContext *ctx;
    int i;

    ctx = bcrypt_setup(key, keybytes, salt, saltbytes);
    /* This was quite a nice starting string until it ran into
     * little-endian Blowfish :-/ */
    memcpy(output, "cyxOmorhcitawolBhsiftawSanyDetim", 32);
    for (i = 0; i < 64; i++) {
        blowfish_lsb_encrypt_ecb(output, 32, ctx);
    }
    blowfish_free_context(ctx);
}

static void bcrypt_genblock(int counter,
                            const unsigned char hashed_passphrase[64],
                            const unsigned char *salt, int saltbytes,
                            unsigned char output[32])
{
    /* Hash the input salt with the counter value optionally suffixed
     * to get our real 32-byte salt */

	hash_accumulator hash(hash_algorithm::sha512);
	hash.update(salt, saltbytes);
	if (counter) {
		auto c = htonl(counter);
		hash.update(reinterpret_cast<uint8_t const*>(&c), 4);
	}
	auto digest = hash.digest();

	bcrypt_hash(hashed_passphrase, 64, digest.data(), 64, output);

	wipe(digest);
}

std::string openssh_bcrypt(std::string_view passphrase, std::string_view salt, uint32_t rounds, size_t bytes)
{
	std::string out;
	out.resize(bytes);

    unsigned char block[32], outblock[32];

	/* Hash the passphrase to get the bcrypt key material */
	auto hashed_passphrase = sha512(passphrase);

    /* We output key bytes in a scattered fashion to meld all output
     * key blocks into all parts of the output. To do this, we pick a
     * modulus, and we output the key bytes to indices of out[] in the
     * following order: first the indices that are multiples of the
     * modulus, then the ones congruent to 1 mod modulus, etc. Each of
     * those passes consumes exactly one block output from
     * bcrypt_genblock, so we must pick a modulus large enough that at
     * most 32 bytes are used in the pass. */
	size_t modulus = (out.size() + 31) / 32;

	for (size_t residue = 0; residue < modulus; residue++) {
        /* Our output block of data is the XOR of all blocks generated
         * by bcrypt in the following loop */
        memset(outblock, 0, sizeof(outblock));

		auto thissalt = reinterpret_cast<unsigned char const*>(salt.data());
		auto thissaltbytes = salt.size();
		for (size_t round = 0; round < rounds; round++) {
            bcrypt_genblock(round == 0 ? residue+1 : 0,
							hashed_passphrase.data(),
                            thissalt, thissaltbytes, block);
            /* Each subsequent bcrypt call reuses the previous one's
             * output as its salt */
            thissalt = block;
            thissaltbytes = 32;

			for (size_t i = 0; i < 32; ++i)
                outblock[i] ^= block[i];
        }

		for (size_t i = residue, j = 0; i < out.size(); i += modulus, j++)
            out[i] = outblock[j];
    }
	wipe(hashed_passphrase);

	return out;
}

}
