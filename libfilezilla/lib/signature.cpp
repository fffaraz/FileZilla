#include "libfilezilla/signature.hpp"

#include "libfilezilla/encode.hpp"
#include "libfilezilla/util.hpp"

#include <nettle/eddsa.h>

namespace fz {

std::string public_verification_key::to_base64() const
{
	auto raw = std::string(key_.cbegin(), key_.cend());
	return fz::base64_encode(raw);
}

public_verification_key public_verification_key::from_base64(std::string_view const& base64)
{
	public_verification_key ret;

	auto raw = fz::base64_decode(base64);
	if (raw.size() == key_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + key_size);
	}

	return ret;
}

private_signing_key private_signing_key::generate()
{
	private_signing_key ret;

	ret.key_ = fz::random_bytes(key_size);
	return ret;
}

std::string private_signing_key::to_base64() const
{
	auto raw = std::string(key_.cbegin(), key_.cend());
	return fz::base64_encode(raw);
}

private_signing_key private_signing_key::from_base64(std::string_view const& base64)
{
	private_signing_key ret;

	auto raw = fz::base64_decode(base64);
	if (raw.size() == key_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + key_size);
	}

	return ret;
}

public_verification_key private_signing_key::pubkey() const
{
	public_verification_key ret;

	if (*this) {
		ret.key_.resize(public_verification_key::key_size);
		nettle_ed25519_sha512_public_key(ret.key_.data(), key_.data());
	}

	return ret;
}


std::vector<uint8_t> sign(uint8_t const* message, size_t const size, private_signing_key const& priv, bool include_message)
{
	std::vector<uint8_t> ret;

	auto const pub = priv.pubkey();
	if (priv && pub && size) {
		size_t retsize = signature_size;
		size_t offset{};
		if (include_message) {
			offset = size;
			retsize += size;
			ret.reserve(retsize);
			ret.assign(message, message + size);
		}
		ret.resize(retsize);

		nettle_ed25519_sha512_sign(pub.key_.data(), priv.data().data(), size, message, ret.data() + offset);
	}

	return ret;
}

std::vector<uint8_t> sign(std::vector<uint8_t> const& message, private_signing_key const& priv, bool include_message)
{
	return sign(message.data(), message.size(), priv, include_message);
}

std::vector<uint8_t> sign(std::string_view const& message, private_signing_key const& priv, bool include_message)
{
	return sign(reinterpret_cast<uint8_t const*>(message.data()), message.size(), priv, include_message);
}



bool verify(uint8_t const* message, size_t const message_size, uint8_t const* signature, size_t const sig_size, public_verification_key const& pub)
{
	if (!message || !signature || sig_size != signature_size) {
		return false;
	}
	return nettle_ed25519_sha512_verify(pub.key_.data(), message_size, message, signature) == 1;
}

bool verify(std::vector<uint8_t> const& message, std::vector<uint8_t> const& signature, public_verification_key const& pub)
{
	return verify(message.data(), message.size(), signature.data(), signature.size(), pub);
}

bool verify(std::string_view const& message, std::string_view const& signature, public_verification_key const& pub)
{
	return verify(reinterpret_cast<uint8_t const*>(message.data()), message.size(), reinterpret_cast<uint8_t const*>(signature.data()), signature.size(), pub);
}

bool verify(uint8_t const* message, size_t const size, public_verification_key const& pub)
{
	if (!message || size < signature_size) {
		return false;
	}
	return verify(message, size - signature_size, message + (size - signature_size), signature_size, pub);
}

bool verify(std::vector<uint8_t> const& message, public_verification_key const& pub)
{
	return verify(message.data(), message.size(), pub);
}

bool verify(std::string_view const& message, public_verification_key const& pub)
{
	return verify(reinterpret_cast<uint8_t const*>(message.data()), message.size(), pub);
}

}
