#ifndef FZSSH_MPZ_HEADER
#define FZSSH_MPZ_HEADER

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/util.hpp>
#include <gmp.h>

namespace fz::ssh {

struct mpz final
{
	mpz()
	{
		mpz_init(v);
	}

	~mpz()
	{
		mpz_clear(v);
	}

	explicit mpz(unsigned long int n)
	{
		mpz_init(v);
		mpz_set_ui(v, n);
	}

	mpz(mpz const& p)
	{
		mpz_init(v);
		mpz_set(v, p.v);
	}

	mpz& operator=(mpz const& p)
	{
		if (this != &p) {
			mpz_set(v, p.v);
		}
		return *this;
	}

	operator mpz_t &() { return v; }
	operator mpz_t const&() const { return v; }

	mpz_t v;
};

void wipe(mpz & v);
using fz::wipe;

fz::buffer to_string(mpz_t const& n, size_t pad = 0);
void to_string_append(fz::buffer & buf, mpz_t const& n, size_t pad);

}

#endif

