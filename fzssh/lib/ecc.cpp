#include "ecc.hpp"
#include "mpz.hpp"

#include <nettle/ecc-curve.h>

using namespace std::literals;

namespace fz::ssh {

hash_algorithm get_digest(nistp_curve c)
{
	switch (c) {
	case nistp_curve::nistp256:
		return hash_algorithm::sha256;
	case nistp_curve::nistp384:
		return hash_algorithm::sha384;
	case nistp_curve::nistp521:
		return hash_algorithm::sha512;
	}
	return {};
}

const struct ecc_curve * get_nettle_curve(nistp_curve c) {
	switch (c) {
	case nistp_curve::nistp256:
		return nettle_get_secp_256r1();
	case nistp_curve::nistp384:
		return nettle_get_secp_384r1();
	case nistp_curve::nistp521:
		return nettle_get_secp_521r1();
	}

	return nullptr;
}

std::string_view key_name(nistp_curve c) {
	switch (c) {
	case nistp_curve::nistp256:
		return "ecdsa-sha2-nistp256"sv;
	case nistp_curve::nistp384:
		return "ecdsa-sha2-nistp384"sv;
	case nistp_curve::nistp521:
		return "ecdsa-sha2-nistp521"sv;
	}

	return {};
}

std::string_view curve_name(nistp_curve c) {
	switch (c) {
	case nistp_curve::nistp256:
		return "nistp256"sv;
	case nistp_curve::nistp384:
		return "nistp384"sv;
	case nistp_curve::nistp521:
		return "nistp521"sv;
	}

	return {};
}

size_t curve_bytes(nistp_curve c)
{
	switch (c) {
	case nistp_curve::nistp256:
		return 256 / 8;
	case nistp_curve::nistp384:
		return 384 / 8;
	case nistp_curve::nistp521:
		return (521 + 7) / 8;
	}

	return {};
}

std::string_view curve_oid(nistp_curve c) {
	switch (c) {
	case nistp_curve::nistp256:
		return "1.2.840.10045.3.1.7"sv;
	case nistp_curve::nistp384:
		return "1.3.132.0.34"sv;
	case nistp_curve::nistp521:
		return "1.3.132.0.35"sv;
	}

	return {};
}

curve_point::curve_point(nistp_curve c)
{
	nettle_ecc_point_init(&p, get_nettle_curve(c));
}

curve_point::~curve_point()
{
	nettle_ecc_point_clear(&p);
}

curve_scalar::curve_scalar(nistp_curve c)
{
	nettle_ecc_scalar_init(&p, get_nettle_curve(c));
}

curve_scalar::~curve_scalar()
{
	nettle_ecc_scalar_set(&p, mpz(1));
	nettle_ecc_scalar_clear(&p);
}

}
