#include "mpz.hpp"

#include "asn1.hpp"
#include "buffer_util.hpp"

#include <nettle/bignum.h>

#include <string.h>

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

void wipe(mpz_t & v)
{
	// It's a bit ugly to access the limbs directly
	// Should the GMP api change and no longer expose this, best we can do is mpz_size and mpz_limbs_modify
	auto const alloc = v[0]._mp_alloc;
	if (alloc > 0 && v[0]._mp_d) {
		fz::wipe(v[0]._mp_d, static_cast<size_t>(alloc) * sizeof(*v[0]._mp_d));
	}
	v[0]._mp_size = 0;
}

size_t to_string_size(mpz_t const& n, size_t pad)
{
	size_t s = nettle_mpz_sizeinbase_256_u(n);
	return std::max(s, pad);
}

fz::buffer to_string(mpz_t const& n, size_t pad)
{
	fz::buffer ret;
	to_string_append(ret, n, pad);
	return ret;
}

void to_string_append(fz::buffer & buf, mpz_t const& n, size_t pad)
{
	size_t s = to_string_size(n, 0);
	if (s < pad) {
		buf.append(pad - s, 0);
	}
	if (s) {
		nettle_mpz_get_str_256(s, reinterpret_cast<unsigned char*>(buf.get(s)), n);
		buf.add(s);
	}
}

bool to_string_append(uint8_t* out, size_t size, mpz_t const& n, size_t pad)
{
	size_t needed = to_string_size(n, 0);
	if (std::max(needed, pad) != size) {
		return false;
	}
	size_t offset{};
	if (needed < pad) {
		offset = pad - needed;
		memset(out, 0, offset);
	}
	if (needed) {
		nettle_mpz_get_str_256(needed, reinterpret_cast<unsigned char*>(out + offset), n);
	}
	return true;
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

namespace {
template<typename T>
void der_encode_impl(T& out, mpz_t const& v)
{
	auto const sign = mpz_sgn(v);
	auto const negative = sign < 0;

	size_t bytes = 1;
	if (sign) {
		bytes = (mpz_sizeinbase(v, 2) + 7) / 8;

		// Add a sign-extension byte if the selected width would encode
		// the value with the wrong DER INTEGER sign bit.
		bool const sign_bit = mpz_tstbit(v, bytes * 8 - 1) != 0;
		if (sign_bit != negative) {
			++bytes;
		}
	}

	out += static_cast<char>(ASN1Type::Integer);
	der_encode_length(out, bytes);

	auto const pos = out.size();
	out.resize(pos + bytes);

	for (size_t i = 0; i < bytes; ++i) {
		uint8_t b{};
		auto const base = (bytes - 1 - i) * 8;
		for (unsigned bit = 0; bit < 8; ++bit) {
			if (mpz_tstbit(v, base + bit)) {
				b |= static_cast<uint8_t>(1u << bit);
			}
		}
		out[pos + i] = static_cast<char>(b);
	}
}
}

void der_encode(std::string& out, mpz_t const& v)
{
	der_encode_impl(out, v);
}

void der_encode(secure_buffer& out, mpz_t const& v)
{
	der_encode_impl(out, v);
}
}
