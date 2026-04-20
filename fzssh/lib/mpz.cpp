#include "mpz.hpp"

#include <nettle/bignum.h>

namespace fz::ssh {

void wipe(mpz & v)
{
	auto c = mpz_size(v);
	if (c) {
		mpz_limbs_modify(v, c);
		fz::wipe(mpz_limbs_modify(v, c), c * sizeof(mp_limb_t));
	}
}

fz::buffer to_string(mpz_t const& n, size_t pad)
{
	fz::buffer ret;
	to_string_append(ret, n, pad);
	return ret;
}

void to_string_append(fz::buffer & buf, mpz_t const& n, size_t pad)
{
	size_t s = nettle_mpz_sizeinbase_256_u(n);
	if (s) {
		if (s < pad) {
			buf.append(pad - s, 0);
		}
		nettle_mpz_get_str_256(s, reinterpret_cast<unsigned char*>(buf.get(s)), n);
		buf.add(s);
	}
}

}
