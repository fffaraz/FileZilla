#ifndef FZSSH_CRYPT_UTIL_HEADER
#define FZSSH_CRYPT_UTIL_HEADER

#include <string_view>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define snew(type) ((type *)malloc(sizeof(type)))
#define snewn(n, type) ((type *)malloc(n * sizeof(type)))
#define sfree free

uint32_t GET_32BIT_LSB_FIRST(const void *vp);
void PUT_32BIT_LSB_FIRST(void *vp, uint32_t value);

void smemclr(void* p, size_t n);
bool smemeq(void const* p, void const* q, size_t n);

namespace fz {
class buffer;
}
struct buffer_sink;
struct BinarySink
{
	fz::buffer* p{};
	unsigned char* out{};
	size_t len{};
};

#define BinarySink_UPCAST(s) s

void put_data(BinarySink* sink, void const* p, size_t len);

struct buffer_sink : BinarySink
{};

void buffer_sink_init(buffer_sink * s, unsigned char* p, size_t len);
/*
 * A small structure wrapping up a (pointer, length) pair so that it
 * can be conveniently passed to or from a function.
 */
typedef struct ptrlen{
	const void *ptr;
	size_t len;
} ptrlen;

ptrlen make_ptrlen(const void *ptr, size_t len);

extern int ssh_sha3_256;
extern int ssh_sha3_512;
extern int ssh_shake256_32bytes;

typedef void ssh_hash;
ssh_hash* ssh_hash_new(int* alg);
void put_datapl(ssh_hash* h, ptrlen pl);
void put_data(ssh_hash* h, void const* p, size_t len);
void put_byte(ssh_hash* h, uint8_t b);
void ssh_hash_final(ssh_hash* h, void* p);

void sha3_256(const void *in, size_t len, void* out);
void sha3_512(const void *in, size_t len, void* out);

typedef struct ShakeXOF ShakeXOF;
ShakeXOF* shake128_xof_from_input(ptrlen seed);
ShakeXOF* shake256_xof_from_input(ptrlen seed);
void shake_xof_read(ShakeXOF* h, void* out, size_t len);
void shake_xof_free(ShakeXOF* h);

void random_read(void* out, size_t len);

#endif
