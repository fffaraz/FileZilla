#ifndef LIBFILEZILLA_JWS_HEADER
#define LIBFILEZILLA_JWS_HEADER

/** \file
 * \brief Functions to create JSON Web Keys (JWK) and JSON Web Signatures (JWS)
 */

#include "json.hpp"

namespace fz {
class logger_interface;

/// Algorithm of JWKs
enum class jwk_type {
	/// EC key type with P-256 as algorithm.
	ecdsa,

	/// RSA key
	rsa
};

/** \brief Creates a JWK pair
 *
 * Returns both the private key and the public key as JSON structurs.
 */
std::pair<json, json> FZ_PUBLIC_SYMBOL create_jwk(jwk_type t = jwk_type::ecdsa);

std::pair<json, json> FZ_PUBLIC_SYMBOL jwk_from_x509_privkey(std::string_view const& data, bool pem = true, logger_interface * logger = nullptr);

/** \brief Create a JWS, with optional protected data
 *
 * Only supports RSA keys, and EC keys using P-256. Signature algorithm is
 * RS256 or ES256 respectively.
 *
 * Returns the signature in the flattened JSON JWS representation.
 *
 * Any values passed through an object in the extra_protected are included in the JWS protected headers.
 *
 * Does not use the JWS Unprotected Header.
 */
json FZ_PUBLIC_SYMBOL jws_sign_flattened(json const& priv, json const& payload, json const& extra_protected = {});

std::string FZ_PUBLIC_SYMBOL create_jwt(json const& priv, json const& payload, json extra_protected = {});
}

#endif
