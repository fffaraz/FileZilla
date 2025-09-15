#include "libfilezilla/encryption.hpp"

#include "libfilezilla/encode.hpp"
#include "libfilezilla/hash.hpp"
#include "libfilezilla/util.hpp"

#include <cstring>

#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <nettle/curve25519.h>
#include <nettle/gcm.h>
#include <nettle/memops.h>
#include <nettle/sha2.h>
#include <nettle/version.h>

namespace fz {

std::string public_key::to_base64(bool pad) const
{
	auto raw = std::string(key_.cbegin(), key_.cend());
	raw += std::string(salt_.cbegin(), salt_.cend());
	return base64_encode(raw, base64_type::standard, pad);
}

namespace {
template<typename T>
public_key from_base64_impl(T const& base64)
{
	public_key ret;

	auto raw = base64_decode(base64);
	if (raw.size() == public_key::key_size + public_key::salt_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + public_key::key_size);
		ret.salt_.assign(p + public_key::key_size, p + public_key::key_size + public_key::salt_size);
	}

	return ret;
}
}

public_key public_key::from_base64(std::string_view const& base64)
{
	return from_base64_impl(base64);
}

public_key public_key::from_base64(std::wstring_view const& base64)
{
	return from_base64_impl(base64);
}

private_key private_key::generate()
{
	private_key ret;

	ret.key_ = random_bytes(key_size);
	ret.key_[0] &= 248;
	ret.key_[31] &= 127;
	ret.key_[31] |= 64;

	ret.salt_ = random_bytes(salt_size);

	return ret;
}

public_key private_key::pubkey() const
{
	public_key ret;

	if (*this) {
		static const uint8_t nine[32]{
			9, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0 };

		ret.key_.resize(32);
		nettle_curve25519_mul(ret.key_.data(), key_.data(), nine);

		ret.salt_ = salt_;
	}

	return ret;
}

private_key private_key::from_password(std::vector<uint8_t> const& password, std::vector<uint8_t> const& salt, unsigned int iterations)
{
	private_key ret;

	if (!password.empty() && salt.size() == salt_size && iterations >= min_iterations) {

		std::vector<uint8_t> key = pbkdf2_hmac_sha256(password, salt, 32, iterations);
		key[0] &= 248;
		key[31] &= 127;
		key[31] |= 64;

		ret.key_ = std::move(key);
		ret.salt_ = salt;
	}

	return ret;
}

std::string private_key::to_base64(bool pad) const
{
	auto raw = std::string(key_.cbegin(), key_.cend());
	raw += std::string(salt_.cbegin(), salt_.cend());
	return base64_encode(raw, base64_type::standard, pad);
}

private_key private_key::from_base64(std::string_view const& base64)
{
	private_key ret;

	auto raw = base64_decode(base64);
	if (raw.size() == key_size + salt_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + key_size);
		ret.key_[0] &= 248;
		ret.key_[31] &= 127;
		ret.key_[31] |= 64;
		ret.salt_.assign(p + key_size, p + key_size + salt_size);
	}

	return ret;
}


std::vector<uint8_t> private_key::shared_secret(public_key const& pub) const
{
	std::vector<uint8_t> ret;

	if (*this && pub) {
		ret.resize(32);

		nettle_curve25519_mul(ret.data(), key_.data(), pub.key_.data());
	}

	return ret;
}

namespace {
std::vector<uint8_t> encrypt(uint8_t const* plain, size_t size, public_key const& pub, uint8_t const* authenticated_data, size_t authenticated_data_size, bool authenticated)
{
	std::vector<uint8_t> ret;

	private_key ephemeral = private_key::generate();
	public_key ephemeral_pub = ephemeral.pubkey();

	if (pub && ephemeral && ephemeral_pub) {
		// Generate shared secret from pub and ephemeral
		std::vector<uint8_t> secret = ephemeral.shared_secret(pub);

		// Derive AES2556 key and CTR nonce from shared secret
		std::vector<uint8_t> const aes_key = hash_accumulator(hash_algorithm::sha256) << ephemeral_pub.salt_ << 0 << secret << ephemeral_pub.key_ << pub.key_ << pub.salt_;

		if (authenticated) {
			std::vector<uint8_t> iv = hash_accumulator(hash_algorithm::sha256) << ephemeral_pub.salt_ << 2 << secret << ephemeral_pub.key_ << pub.key_ << pub.salt_;
			static_assert(SHA256_DIGEST_SIZE >= GCM_IV_SIZE, "iv too small");
			iv.resize(GCM_IV_SIZE);

			gcm_aes256_ctx ctx;
			nettle_gcm_aes256_set_key(&ctx, aes_key.data());
			nettle_gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, iv.data());

			if (authenticated_data_size) {
				nettle_gcm_aes256_update(&ctx, authenticated_data_size, authenticated_data);
			}

			// Encrypt plaintext with AES256-GCM
			ret.resize(public_key::key_size + public_key::salt_size + size + GCM_DIGEST_SIZE);
			if (size) {
				nettle_gcm_aes256_encrypt(&ctx, size, ret.data() + public_key::key_size + public_key::salt_size, plain);
			}

			// Return ephemeral_pub.key_||ephemeral_pub.salt_||ciphertext||tag
			memcpy(ret.data(), ephemeral_pub.key_.data(), public_key::key_size);
			memcpy(ret.data() + public_key::key_size, ephemeral_pub.salt_.data(), public_key::salt_size);
			nettle_gcm_aes256_digest(&ctx, GCM_DIGEST_SIZE, ret.data() + public_key::key_size + public_key::salt_size + size);
		}
		else {
			std::vector<uint8_t> ctr = hash_accumulator(hash_algorithm::sha256) << ephemeral_pub.salt_ << 1 << secret << ephemeral_pub.key_ << pub.key_ << pub.salt_;

			aes256_ctx ctx;
			nettle_aes256_set_encrypt_key(&ctx, aes_key.data());

			// Encrypt plaintext with AES256-CTR
			ret.resize(public_key::key_size + public_key::salt_size + size);
			if (size) {
				nettle_ctr_crypt(&ctx, reinterpret_cast<nettle_cipher_func*>(nettle_aes256_encrypt), 16, ctr.data(), size, ret.data() + public_key::key_size + public_key::salt_size, plain);
			}

			// Return ephemeral_pub.key_||ephemeral_pub.salt_||ciphertext
			memcpy(ret.data(), ephemeral_pub.key_.data(), public_key::key_size);
			memcpy(ret.data() + public_key::key_size, ephemeral_pub.salt_.data(), public_key::salt_size);
		}
	}

	return ret;
}
}

std::vector<uint8_t> encrypt(uint8_t const* plain, size_t size, public_key const& pub, bool authenticated)
{
	return encrypt(plain, size, pub, nullptr, 0, authenticated);
}

std::vector<uint8_t> encrypt(std::vector<uint8_t> const& plain, public_key const& pub, bool authenticated)
{
	return encrypt(plain.data(), plain.size(), pub, nullptr, 0, authenticated);
}

std::vector<uint8_t> encrypt(std::string_view const& plain, public_key const& pub, bool authenticated)
{
	return encrypt(reinterpret_cast<uint8_t const*>(plain.data()), plain.size(), pub, nullptr, 0, authenticated);
}

std::vector<uint8_t> encrypt(uint8_t const* plain, size_t size, public_key const& pub, uint8_t const* authenticated_data, size_t authenticated_data_size)
{
	return encrypt(plain, size, pub, authenticated_data, authenticated_data_size, true);
}

std::vector<uint8_t> encrypt(std::vector<uint8_t> const& plain, public_key const& pub, std::vector<uint8_t> const& authenticated_data)
{
	return encrypt(plain.data(), plain.size(), pub, authenticated_data.data(), authenticated_data.size(), true);
}

std::vector<uint8_t> encrypt(std::string_view const& plain, public_key const& pub, std::string_view const& authenticated_data)
{
	return encrypt(reinterpret_cast<uint8_t const*>(plain.data()), plain.size(), pub, reinterpret_cast<uint8_t const*>(authenticated_data.data()), authenticated_data.size(), true);
}

namespace {
std::vector<uint8_t> decrypt(uint8_t const* cipher, size_t size, private_key const& priv, uint8_t const* authenticated_data, size_t authenticated_data_size, bool authenticated)
{
	size_t const overhead = public_key::key_size + public_key::salt_size + (authenticated ? GCM_DIGEST_SIZE : 0);

	std::vector<uint8_t> ret;

	if (priv && size >= overhead && cipher) {
		size_t const message_size = size - overhead;

		// Extract ephemeral_pub from cipher
		public_key ephemeral_pub;
		ephemeral_pub.key_.resize(public_key::key_size);
		ephemeral_pub.salt_.resize(public_key::salt_size);
		memcpy(ephemeral_pub.key_.data(), cipher, public_key::key_size);
		memcpy(ephemeral_pub.salt_.data(), cipher + public_key::key_size, public_key::salt_size);

		// Generate shared secret from ephemeral_pub and priv
		std::vector<uint8_t> const secret = priv.shared_secret(ephemeral_pub);

		public_key const pub = priv.pubkey();
		std::vector<uint8_t> const aes_key = hash_accumulator(hash_algorithm::sha256) << ephemeral_pub.salt_ << 0 << secret << ephemeral_pub.key_ << pub.key_ << pub.salt_;

		if (authenticated) {
			// Derive AES2556 key and GCM IV from shared secret
			std::vector<uint8_t> iv = hash_accumulator(hash_algorithm::sha256) << ephemeral_pub.salt_ << 2 << secret << ephemeral_pub.key_ << pub.key_ << pub.salt_;
			static_assert(SHA256_DIGEST_SIZE >= GCM_IV_SIZE, "iv too small");
			iv.resize(GCM_IV_SIZE);

			gcm_aes256_ctx ctx;
			nettle_gcm_aes256_set_key(&ctx, aes_key.data());
			nettle_gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, iv.data());

			if (authenticated_data_size) {
				nettle_gcm_aes256_update(&ctx, authenticated_data_size, authenticated_data);
			}

			// Decrypt ciphertext with AES256-GCM
			ret.resize(message_size);
			if (message_size) {
				nettle_gcm_aes256_decrypt(&ctx, message_size, ret.data(), cipher + public_key::key_size + public_key::salt_size);
			}

			// Last but not least, verify the tag
			uint8_t tag[GCM_DIGEST_SIZE];
			nettle_gcm_aes256_digest(&ctx, GCM_DIGEST_SIZE, tag);
			if (!nettle_memeql_sec(tag, cipher + size - GCM_DIGEST_SIZE, GCM_DIGEST_SIZE)) {
				ret.clear();
			}
		}
		else {
			// Derive AES2556 key and CTR nonce from shared secret
			std::vector<uint8_t> ctr = hash_accumulator(hash_algorithm::sha256) << ephemeral_pub.salt_ << 1 << secret << ephemeral_pub.key_ << pub.key_ << pub.salt_;

			aes256_ctx ctx;
			nettle_aes256_set_encrypt_key(&ctx, aes_key.data());

			// Decrypt ciphertext with AES256-CTR
			ret.resize(message_size);
			if (message_size) {
				nettle_ctr_crypt(&ctx, reinterpret_cast<nettle_cipher_func*>(nettle_aes256_encrypt), 16, ctr.data(), ret.size(), ret.data(), cipher + public_key::key_size + public_key::salt_size);
			}
		}
	}

	// Return the plaintext
	return ret;
}
}

std::vector<uint8_t> decrypt(uint8_t const* cipher, size_t size, private_key const& priv, bool authenticated)
{
	return decrypt(cipher, size, priv, nullptr, 0, authenticated);
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> const& cipher, private_key const& priv, bool authenticated)
{
	return decrypt(cipher.data(), cipher.size(), priv, nullptr, 0, authenticated);
}

std::vector<uint8_t> decrypt(std::string_view const& cipher, private_key const& priv, bool authenticated)
{
	return decrypt(reinterpret_cast<uint8_t const*>(cipher.data()), cipher.size(), priv, nullptr, 0, authenticated);
}

std::vector<uint8_t> decrypt(uint8_t const* cipher, size_t size, private_key const& priv, uint8_t const* authenticated_data, size_t authenticated_data_size)
{
	return decrypt(cipher, size, priv, authenticated_data, authenticated_data_size, true);
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> const& cipher, private_key const& priv, std::vector<uint8_t> const& authenticated_data)
{
	return decrypt(cipher.data(), cipher.size(), priv, authenticated_data.data(), authenticated_data.size(), true);
}

std::vector<uint8_t> decrypt(std::string_view const& cipher, private_key const& priv, std::string_view const& authenticated_data)
{
	return decrypt(reinterpret_cast<uint8_t const*>(cipher.data()), cipher.size(), priv, reinterpret_cast<uint8_t const*>(authenticated_data.data()), authenticated_data.size(), true);
}


symmetric_key symmetric_key::generate()
{
	symmetric_key ret;

	ret.key_ = random_bytes(key_size);
	ret.salt_ = random_bytes(salt_size);

	return ret;
}

symmetric_key symmetric_key::from_password(std::vector<uint8_t> const& password, std::vector<uint8_t> const& salt, unsigned int iterations)
{
	symmetric_key ret;

	if (!password.empty() && salt.size() == salt_size && iterations >= min_iterations) {
		std::vector<uint8_t> key = pbkdf2_hmac_sha256(password, salt, 32, iterations);
		ret.key_ = std::move(key);
		ret.salt_ = salt;
	}

	return ret;
}

std::string symmetric_key::to_base64(bool pad) const
{
	auto raw = std::string(key_.cbegin(), key_.cend());
	raw += std::string(salt_.cbegin(), salt_.cend());
	return base64_encode(raw, base64_type::standard, pad);
}

symmetric_key symmetric_key::from_base64(std::string_view const& base64)
{
	symmetric_key ret;

	auto raw = base64_decode(base64);
	if (raw.size() == key_size + salt_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + key_size);
		ret.salt_.assign(p + key_size, p + key_size + salt_size);
	}

	return ret;
}

symmetric_key symmetric_key::from_base64(std::wstring_view const& base64)
{
	symmetric_key ret;

	auto raw = base64_decode(base64);
	if (raw.size() == key_size + salt_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + key_size);
		ret.salt_.assign(p + key_size, p + key_size + salt_size);
	}

	return ret;
}

std::vector<uint8_t> const& symmetric_key::key() const
{
	return key_;
}

std::vector<uint8_t> symmetric_key::encrypt_key(fz::public_key const& kek)
{
	if (key_.empty() || salt_.empty() || !kek) {
		return std::vector<uint8_t>();
	}

	std::vector<uint8_t> tmp;
	tmp.resize(key_.size() + salt_.size());
	memcpy(tmp.data(), key_.data(), key_.size());
	memcpy(tmp.data() + key_.size(), salt_.data(), salt_.size());
	return fz::encrypt(tmp, kek);
}

symmetric_key symmetric_key::decrypt_key(std::vector<uint8_t> const& encrypted, fz::private_key const& kek)
{
	symmetric_key ret;

	auto raw = fz::decrypt(encrypted, kek);
	if (raw.size() == key_size + salt_size) {
		auto p = reinterpret_cast<uint8_t const*>(raw.data());
		ret.key_.assign(p, p + key_size);
		ret.salt_.assign(p + key_size, p + key_size + salt_size);
	}

	return ret;
}

bool operator==(symmetric_key const& lhs, symmetric_key const& rhs)
{
	if (!lhs) {
		return !rhs;
	}
	else if (!rhs) {
		return false;
	}

	// By definition both key and salt are non-empty and have the same size in each.
	return nettle_memeql_sec(lhs.salt().data(), rhs.salt().data(), lhs.salt().size()) && nettle_memeql_sec(lhs.key().data(), rhs.key().data(), lhs.key().size());
}

size_t symmetric_key::encryption_overhead()
{
	return symmetric_key::salt_size + GCM_DIGEST_SIZE;
}

std::vector<uint8_t> encrypt(uint8_t const* plain, size_t size, symmetric_key const& key, uint8_t const* authenticated_data, size_t authenticated_data_size)
{
	std::vector<uint8_t> ret;

	if (key) {
		// Generate per-message nonce
		auto nonce = random_bytes(symmetric_key::salt_size);

		// Derive AES2556 key and IV from symmetric key and nonce
		std::vector<uint8_t> const aes_key = hash_accumulator(hash_algorithm::sha256) << key.salt() << 3 << key.key() << nonce;
		std::vector<uint8_t> iv = hash_accumulator(hash_algorithm::sha256) << key.salt() << 4 << key.key() << nonce;
		static_assert(SHA256_DIGEST_SIZE >= GCM_IV_SIZE, "iv too small");
		iv.resize(GCM_IV_SIZE);

		gcm_aes256_ctx ctx;
		nettle_gcm_aes256_set_key(&ctx, aes_key.data());
		nettle_gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, iv.data());

		if (authenticated_data_size) {
			nettle_gcm_aes256_update(&ctx, authenticated_data_size, authenticated_data);
		}

		// Encrypt plaintext with AES256-GCM
		ret.resize(symmetric_key::salt_size + size + GCM_DIGEST_SIZE);
		if (size) {
			nettle_gcm_aes256_encrypt(&ctx, size, ret.data() + symmetric_key::salt_size, plain);
		}

		// Return nonce||ciphertext||tag
		memcpy(ret.data(), nonce.data(), symmetric_key::salt_size);
		nettle_gcm_aes256_digest(&ctx, GCM_DIGEST_SIZE, ret.data() + symmetric_key::salt_size + size);
	}

	return ret;
}

std::vector<uint8_t> encrypt(uint8_t const* plain, size_t size, symmetric_key const& key)
{
	return encrypt(plain, size, key, nullptr, 0);
}

std::vector<uint8_t> encrypt(std::vector<uint8_t> const& plain, symmetric_key const& key)
{
	return encrypt(plain.data(), plain.size(), key, nullptr, 0);
}

std::vector<uint8_t> encrypt(std::string_view const& plain, symmetric_key const& key)
{
	return encrypt(reinterpret_cast<uint8_t const*>(plain.data()), plain.size(), key, nullptr, 0);
}

std::vector<uint8_t> encrypt(std::vector<uint8_t> const& plain, symmetric_key const& key, std::vector<uint8_t> const& authenticated_data)
{
	return encrypt(plain.data(), plain.size(), key, authenticated_data.data(), authenticated_data.size());
}

std::vector<uint8_t> encrypt(std::string_view const& plain, symmetric_key const& key, std::string_view const& authenticated_data)
{
	return encrypt(reinterpret_cast<uint8_t const*>(plain.data()), plain.size(), key, reinterpret_cast<uint8_t const*>(authenticated_data.data()), authenticated_data.size());
}


std::vector<uint8_t> decrypt(uint8_t const* cipher, size_t size, symmetric_key const& key, uint8_t const* authenticated_data, size_t authenticated_data_size)
{
	std::vector<uint8_t> ret;

	size_t const overhead = symmetric_key::encryption_overhead();
	if (key && size >= overhead && cipher) {
		size_t const message_size = size - overhead;

		// Extract per-message nonce from cipher
		std::basic_string_view<uint8_t> const nonce(cipher, symmetric_key::salt_size);

		// Derive AES2556 key and IV from symmetric key and nonce
		std::vector<uint8_t> const aes_key = hash_accumulator(hash_algorithm::sha256) << key.salt() << 3 << key.key() << nonce;
		std::vector<uint8_t> iv = hash_accumulator(hash_algorithm::sha256) << key.salt() << 4 << key.key() << nonce;
		static_assert(SHA256_DIGEST_SIZE >= GCM_IV_SIZE, "iv too small");
		iv.resize(GCM_IV_SIZE);

		gcm_aes256_ctx ctx;
		nettle_gcm_aes256_set_key(&ctx, aes_key.data());
		nettle_gcm_aes256_set_iv(&ctx, GCM_IV_SIZE, iv.data());

		if (authenticated_data_size) {
			nettle_gcm_aes256_update(&ctx, authenticated_data_size, authenticated_data);
		}

		// Decrypt ciphertext with AES256-GCM
		ret.resize(message_size);
		if (message_size) {
			nettle_gcm_aes256_decrypt(&ctx, message_size, ret.data(), cipher + symmetric_key::salt_size);
		}

		// Last but not least, verify the tag
		uint8_t tag[GCM_DIGEST_SIZE];
		nettle_gcm_aes256_digest(&ctx, GCM_DIGEST_SIZE, tag);
		if (!nettle_memeql_sec(tag, cipher + size - GCM_DIGEST_SIZE, GCM_DIGEST_SIZE)) {
			ret.clear();
		}
	}

	// Return the plaintext
	return ret;
}

std::vector<uint8_t> decrypt(uint8_t const* cipher, size_t size, symmetric_key const& key)
{
	return decrypt(cipher, size, key, nullptr, 0);
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> const& cipher, symmetric_key const& key)
{
	return decrypt(cipher.data(), cipher.size(), key, nullptr, 0);
}

std::vector<uint8_t> decrypt(std::string_view const& cipher, symmetric_key const& key)
{
	return decrypt(reinterpret_cast<uint8_t const*>(cipher.data()), cipher.size(), key, nullptr, 0);
}

std::vector<uint8_t> decrypt(std::vector<uint8_t> const& cipher, symmetric_key const& key, std::vector<uint8_t> const& authenticated_data)
{
	return decrypt(cipher.data(), cipher.size(), key, authenticated_data.data(), authenticated_data.size());
}

std::vector<uint8_t> decrypt(std::string_view const& cipher, symmetric_key const& key, std::string_view const& authenticated_data)
{
	return decrypt(reinterpret_cast<uint8_t const*>(cipher.data()), cipher.size(), key, reinterpret_cast<uint8_t const*>(authenticated_data.data()), authenticated_data.size());
}

}
