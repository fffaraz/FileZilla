#ifndef FZSSH_ECC_HEADER
#define FZSSH_ECC_HEADER

#include <libfilezilla/hash.hpp>

#include <nettle/ecc.h>

struct ecc_curve;

namespace fz::ssh {
enum class nistp_curve : unsigned {
	nistp256,
	nistp384,
	nistp521
};

hash_algorithm get_digest(nistp_curve c);
const struct ecc_curve * get_nettle_curve(nistp_curve c);
std::string_view key_name(nistp_curve c);
std::string_view curve_name(nistp_curve c);
size_t curve_bytes(nistp_curve c);
std::string_view curve_oid(nistp_curve c);

struct curve_point final
{
	curve_point() = delete;
	curve_point(curve_point const&) = delete;
	curve_point& operator=(curve_point const&) = delete;

	explicit curve_point(nistp_curve c);
	~curve_point();

	operator ecc_point *() { return &p; }
	operator ecc_point const*() const { return &p; }

	ecc_point p;
};

struct curve_scalar final
{
	curve_scalar() = delete;
	curve_scalar(curve_scalar const&) = delete;
	curve_scalar& operator=(curve_scalar const&) = delete;

	explicit curve_scalar(nistp_curve c);
	~curve_scalar();

	operator ecc_scalar *() { return &p; }
	operator ecc_scalar const*() const { return &p; }

	ecc_scalar p;
};

}

#endif
