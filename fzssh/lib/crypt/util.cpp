#include "util.hpp"
#include <libfilezilla/util.hpp>
#include <libfilezilla/hash.hpp>
#include <libfilezilla/buffer.hpp>
#include <libfilezilla/nonowning_buffer.hpp>

#include <nettle/memops.h>
#include <nettle/sha3.h>

#include <string.h>

using namespace std::literals;

void buffer_sink_init(buffer_sink * s, unsigned char* p, size_t len)
{
	s->out = p;
	s->len = len;
}

ptrlen make_ptrlen(const void *ptr, size_t len)
{
	ptrlen pl;
	pl.ptr = ptr;
	pl.len = len;
	return pl;
}

void put_data(BinarySink * sink, void const* p, size_t len)
{
	if (sink->p) {
		sink->p->append(reinterpret_cast<unsigned char const*>(p), len);
		return;
	}
	if (sink->out && sink->len >= len) {
		memcpy(sink->out, p, len);
		sink->out += len;
		sink->len -= len;
	}
}

uint32_t GET_32BIT_LSB_FIRST(const void *vp)
{
	const uint8_t *p = (const uint8_t *)vp;
	return
		(((uint32_t)p[0]      ) | ((uint32_t)p[1] <<  8) |
		 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

void PUT_32BIT_LSB_FIRST(void *vp, uint32_t value)
{
	uint8_t *p = (uint8_t *)vp;
	p[0] = (uint8_t)(value);
	p[1] = (uint8_t)(value >> 8);
	p[2] = (uint8_t)(value >> 16);
	p[3] = (uint8_t)(value >> 24);
}

void smemclr(void* p, size_t n)
{
	fz::wipe(p, n);
}

bool smemeq(void const* p, void const *q, size_t n)
{
	return nettle_memeql_sec(p, q, n) != 0;
}

int ssh_sha3_256 = 256;
int ssh_sha3_512 = 512;
int ssh_shake256_32bytes = 256;

ssh_hash* ssh_hash_new(int* alg)
{
	fz::hash_accumulator* h;
	if (alg == &ssh_sha3_256) {
		h = new fz::hash_accumulator(fz::hash_algorithm::sha3_256);
	}
	else if (alg == &ssh_shake256_32bytes) {
		// It's the wrong one, but in this context all we care is the digest length being correct
		h = new fz::hash_accumulator(fz::hash_algorithm::sha3_256);
	}
	else {
		h = new fz::hash_accumulator(fz::hash_algorithm::sha3_512);
	}
	return h;
}

void put_datapl(ssh_hash* h, ptrlen pl)
{
	auto* acc = reinterpret_cast<fz::hash_accumulator*>(h);
	acc->update(reinterpret_cast<uint8_t const*>(pl.ptr), pl.len);
}

void put_data(ssh_hash* h, void const* p, size_t len)
{
	auto* acc = reinterpret_cast<fz::hash_accumulator*>(h);
	acc->update(reinterpret_cast<uint8_t const*>(p), len);
}

void put_byte(ssh_hash* h, uint8_t b)
{
	auto* acc = reinterpret_cast<fz::hash_accumulator*>(h);
	acc->update(b);
}


void ssh_hash_final(ssh_hash *h, void *p)
{
	auto* acc = reinterpret_cast<fz::hash_accumulator*>(h);
	acc->digest(reinterpret_cast<uint8_t*>(p), acc->digest_size());
	delete acc;
}

struct ShakeXOF
{
	union {
		sha3_128_ctx ctx128;
		sha3_256_ctx ctx256;
	} ctx_;

	size_t bits_;
};

ShakeXOF* shake128_xof_from_input(ptrlen seed)
{
	auto ctx = new ShakeXOF;
	ctx->bits_ = 128;
	sha3_128_init(&ctx->ctx_.ctx128);
	sha3_128_update(&ctx->ctx_.ctx128, seed.len, reinterpret_cast<uint8_t const*>(seed.ptr));
	return ctx;
}

ShakeXOF* shake256_xof_from_input(ptrlen seed)
{
	auto ctx = new ShakeXOF;
	ctx->bits_ = 256;
	sha3_256_init(&ctx->ctx_.ctx256);
	sha3_256_update(&ctx->ctx_.ctx256, seed.len, reinterpret_cast<uint8_t const*>(seed.ptr));
	return ctx;
}

void shake_xof_read(ShakeXOF* h, void* out, size_t len)
{
	if (h->bits_ == 128) {
		sha3_128_shake_output(&h->ctx_.ctx128, len, reinterpret_cast<uint8_t*>(out));
	}
	else {
		sha3_256_shake_output(&h->ctx_.ctx256, len, reinterpret_cast<uint8_t*>(out));
	}
}

void shake_xof_free(ShakeXOF *h)
{
	fz::wipe(h, sizeof(h));
	delete h;
}

void random_read(void* out, size_t len)
{
	fz::random_bytes(len, reinterpret_cast<uint8_t*>(out));
}

#include "visibility_crypt.hpp"

namespace fz::ssh {
std::string_view FZSSH_CRYPT_PUBLIC_SYMBOL putty_license()
{
	return
		"The implementations of openssh_bcrypt, Blowfish and ML-KEM in\n"
		"libfzssh-crypt are based on PuTTY. Below terms solely apply to these\n"
		"specific parts, but not to fzssh-crypt as a whole.\n\n"
		"PuTTY is copyright 1997-2026 Simon Tatham.\n"
		"\n"
		"Portions copyright Robert de Bath, Joris van Rantwijk, Delian\n"
		"Delchev, Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry,\n"
		"Justin Bradford, Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus\n"
		"Kuhn, Colin Watson, Christopher Staite, Lorenz Diener, Christian\n"
		"Brabandt, Jeff Smith, Pavel Kryukov, Maxim Kuznetsov, Svyatoslav\n"
		"Kuzmich, Nico Williams, Viktor Dukhovni, Josh Dersch, Lars Brinkhoff,\n"
		"and CORE SDI S.A.\n"
		"\n"
		"Permission is hereby granted, free of charge, to any person\n"
		"obtaining a copy of this software and associated documentation files\n"
		"(the \"Software\"), to deal in the Software without restriction,\n"
		"including without limitation the rights to use, copy, modify, merge,\n"
		"publish, distribute, sublicense, and/or sell copies of the Software,\n"
		"and to permit persons to whom the Software is furnished to do so,\n"
		"subject to the following conditions:\n"
		"\n"
		"The above copyright notice and this permission notice shall be\n"
		"included in all copies or substantial portions of the Software.\n"
		"\n"
		"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,\n"
		"EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF\n"
		"MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND\n"
		"NONINFRINGEMENT.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE\n"
		"FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF\n"
		"CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION\n"
		"WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n"sv;
}
}
