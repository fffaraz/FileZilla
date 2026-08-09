#include "mpz.hpp"

#include "buffer_util.hpp"

#include <nettle/bignum.h>

namespace fz::ssh {

bool operator==(mpz const& l, mpz const& r)
{
	return mpz_cmp(l, r) == 0;
}

bool operator==(mpz const& l, unsigned long int r)
{
	return mpz_cmp_ui(l.v, r) == 0;
}

bool operator<=(mpz const& l, mpz const& r)
{
	return mpz_cmp(l, r) <= 0;
}

bool operator<(mpz const& l, mpz const& r)
{
	return mpz_cmp(l, r) < 0;
}

bool operator<=(mpz const& l, unsigned long int r)
{
	return mpz_cmp_ui(l.v, r) <= 0;
}

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

std::optional<mpz> extract_mpint(std::string_view & buf, bool allow_negative)
{
	auto blob = extract_string(buf, string_type::blob, true);
	if (!blob) {
		return {};
	}

	return mpint_from_blob(*blob, allow_negative);
}

std::optional<mpz> mpint_from_blob(std::string_view blob, bool allow_negative)
{
	mpz ret;
	if (!blob.empty()) {
		auto c = static_cast<uint8_t>(blob.front());
		if (c & 0x80u) {
			if (!allow_negative) {
				return {};
			}
			if (blob.size() >= 2 && c == 0xffu && static_cast<uint8_t>(blob[1]) & 0x80u) {
				// Unnecessary leading FF byte
				return {};
			}
			nettle_mpz_set_str_256_s(ret, blob.size(), reinterpret_cast<uint8_t const*>(blob.data()));
			return ret;
		}

		if (!c) {
			blob.remove_prefix(1);
			if (blob.empty() || !(static_cast<uint8_t>(blob.front()) & 0x80u)) {
				// Unecessary leading zero byte
				return {};
			}
		}
		nettle_mpz_set_str_256_u(ret, blob.size(), reinterpret_cast<uint8_t const*>(blob.data()));
	}

	return ret;
}

}
