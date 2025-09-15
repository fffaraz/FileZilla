#ifndef LIBFILEZILLA_SIGNATURE_HEADER
#define LIBFILEZILLA_SIGNATURE_HEADER

/** \file
 * \brief Signature scheme using Ed25519
 *
 * See RFC 8032 for the X22519 specs.
 */

#include "libfilezilla.hpp"

#include <vector>
#include <string>

namespace fz {

/** \brief Represents a public key to verify messages signed using Ed25519.
 *
 * \sa private_signing_key
 */
class FZ_PUBLIC_SYMBOL public_verification_key
{
public:
	enum {
		key_size = 32
	};

	explicit operator bool() const {
		return key_.size() == key_size;
	}

	bool operator==(public_verification_key const& rhs) const {
		return key_ == rhs.key_;
	}

	bool operator!=(public_verification_key const& rhs) const {
		return !(*this == rhs);
	}

	bool operator<(public_verification_key const& rhs) const {
		return key_ < rhs.key_;
	}

	std::string to_base64() const;
	static public_verification_key from_base64(std::string_view const& base64);

	std::vector<uint8_t> key_;
};

/** \brief Represents a private key to sign message with using Ed25519.
 *
 * \sa public_verification_key
 */
class FZ_PUBLIC_SYMBOL private_signing_key
{
public:
	enum {
		key_size = 32
	};

	/// Generates a random private key
	static private_signing_key generate();

	explicit operator bool() const {
		return key_.size() == key_size;
	}

	/// Gets the public key corresponding to the private key
	public_verification_key pubkey() const;

	std::vector<uint8_t> const& data() const {
		return key_;
	}

	std::string to_base64() const; // Keep secret!
	static private_signing_key from_base64(std::string_view const& base64);

private:
	std::vector<uint8_t> key_;
};

enum {
	signature_size = 64
};

/// Returns the message with the signature appended, created using the passed private key
std::vector<uint8_t> FZ_PUBLIC_SYMBOL sign(std::vector<uint8_t> const& message, private_signing_key const& priv, bool include_message = true);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL sign(std::string_view const& message, private_signing_key const& priv, bool include_message = true);
std::vector<uint8_t> FZ_PUBLIC_SYMBOL sign(uint8_t const* message, size_t const size, private_signing_key const& priv, bool include_message = true);

/// Verify a message with attached signature. Returns true iff it has been signed by the private key corresponding to the passed public key
bool FZ_PUBLIC_SYMBOL verify(std::vector<uint8_t> const& message, public_verification_key const& pub);
bool FZ_PUBLIC_SYMBOL verify(std::string_view const& message, public_verification_key const& pub);
bool FZ_PUBLIC_SYMBOL verify(uint8_t const* message, size_t const size, public_verification_key const& pub);

/// Verify a message with detached signature. Returns true iff it has been signed by the private key corresponding to the passed public key
bool FZ_PUBLIC_SYMBOL verify(std::vector<uint8_t> const& message, std::vector<uint8_t> const& signature, public_verification_key const& pub);
bool FZ_PUBLIC_SYMBOL verify(std::string_view const& message, std::string_view const& signature, public_verification_key const& pub);
bool FZ_PUBLIC_SYMBOL verify(uint8_t const* message, size_t const message_size, uint8_t const* signature, size_t const sig_size, public_verification_key const& pub);

}

#endif
