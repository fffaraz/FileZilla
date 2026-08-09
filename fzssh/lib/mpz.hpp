#ifndef FZSSH_MPZ_HEADER
#define FZSSH_MPZ_HEADER

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/util.hpp>
#include <gmp.h>

#include <optional>
#include <string_view>

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

	mpz(mpz &&p) noexcept
	{
		mpz_init(v);
		mpz_swap(v, p.v);
	}

	mpz& operator=(mpz &&p) noexcept
	{
		mpz_swap(v, p.v);
		return *this;
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

bool operator==(mpz const& l, mpz const& r);
bool operator==(mpz const& l, unsigned long int r);
bool operator<(mpz const& l, mpz const& r);
bool operator<=(mpz const& l, unsigned long int r);
bool operator<=(mpz const& l, mpz const& r);
inline bool operator!=(mpz const& l, mpz const& r) { return !(l == r); }
inline bool operator>(mpz const& l, mpz const& r) { return r < l; }
inline bool operator>=(mpz const& l, mpz const& r) { return r <= l; }

void wipe(mpz & v);
using fz::wipe;

fz::buffer to_string(mpz_t const& n, size_t pad = 0);
void to_string_append(fz::buffer & buf, mpz_t const& n, size_t pad);

std::optional<mpz> extract_mpint(std::string_view & buf, bool allow_negative);
std::optional<mpz> mpint_from_blob(std::string_view buf, bool allow_negative);

}

#endif

