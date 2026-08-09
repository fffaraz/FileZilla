#include "cipher.hpp"

#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/gcm.h>
#include <nettle/memops.h>
#include <nettle/version.h>

#include <libfilezilla/util.hpp>

using namespace std::literals;
namespace {
template<typename Char>
void write_uint32(Char * data, uint32_t v)
{
	data[3] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[2] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[1] = static_cast<Char>(v & 0xffu);
	v >>= 8;
	data[0] = static_cast<Char>(v);
}
}
namespace fz::ssh {

class cipher_none final : public cipher_base
{
public:
	cipher_none() noexcept
		: cipher_base(8, 0, 0, false, false)
	{}

	std::string_view name() const override { return "none"sv; }

	virtual bool encrypt(uint8_t*, size_t) override { return true; }
	virtual bool decrypt_length(uint8_t*, size_t) override { return true; }
	virtual bool decrypt(uint8_t*, size_t) override { return true; }
	virtual bool set_key(uint8_t const*, size_t) override { return true; }
	virtual bool set_iv(std::vector<uint8_t> &&) override { return true; }
};

class cipher_aes256_gcm final : public cipher_base
{
public:
	cipher_aes256_gcm();
	~cipher_aes256_gcm();

	std::string_view name() const override { return "aes256-gcm@openssh.com"sv; }

	virtual bool decrypt_length(uint8_t*, size_t) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;

	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

	virtual void add_authenticated_data(uint8_t const* data, size_t size) override;
private:
	std::vector<uint8_t> iv_;
	gcm_aes256_ctx ctx_;
};

cipher_aes256_gcm::cipher_aes256_gcm()
    : cipher_base(16, 32, 12, true, false, GCM_DIGEST_SIZE)
{
}

cipher_aes256_gcm::~cipher_aes256_gcm()
{
	fz::wipe(iv_);
}

bool cipher_aes256_gcm::decrypt_length(uint8_t*, size_t)
{
	return true;
}

void cipher_aes256_gcm::add_authenticated_data(uint8_t const* data, size_t size)
{
	gcm_aes256_update(&ctx_, size, reinterpret_cast<unsigned char const*>(data));
}

bool cipher_aes256_gcm::encrypt(uint8_t* plain, size_t size)
{
	if (size < GCM_DIGEST_SIZE) {
		return false;
	}

	gcm_aes256_encrypt(&ctx_, size - GCM_DIGEST_SIZE, plain, plain);

#if NETTLE_VERSION_MAJOR >= 4
	gcm_aes256_digest(&ctx_, plain + size - GCM_DIGEST_SIZE);
#else
	gcm_aes256_digest(&ctx_, GCM_DIGEST_SIZE, plain + size - GCM_DIGEST_SIZE);
#endif

	// Update IV
	for (size_t i = 11; i > 3; --i) {
		if (++iv_[i]) {
			break;
		}
	}
	gcm_aes256_set_iv(&ctx_, iv_.size(), iv_.data());

	return true;
}

bool cipher_aes256_gcm::decrypt(uint8_t* cipher, size_t size)
{
	if (size < GCM_DIGEST_SIZE) {
		return false;
	}

	gcm_aes256_decrypt(&ctx_, size - GCM_BLOCK_SIZE, cipher, cipher);

	uint8_t digest[GCM_DIGEST_SIZE];
#if NETTLE_VERSION_MAJOR >= 4
	gcm_aes256_digest(&ctx_, digest);
#else
	gcm_aes256_digest(&ctx_, GCM_DIGEST_SIZE, digest);
#endif
	if (!memeql_sec(digest, cipher + size - GCM_DIGEST_SIZE, GCM_DIGEST_SIZE)) {
		return false;
	}

	// Update IV
	for (size_t i = 11; i > 3; --i) {
		if (++iv_[i]) {
			break;
		}
	}
	gcm_aes256_set_iv(&ctx_, iv_.size(), iv_.data());
	return true;
}

bool cipher_aes256_gcm::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	gcm_aes256_set_key(&ctx_, key);
	return true;
}

bool cipher_aes256_gcm::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	gcm_aes256_set_iv(&ctx_, iv_.size(), iv_.data());
	return true;
}

class cipher_aes256_cbc final : public cipher_base
{
public:
	cipher_aes256_cbc();
	~cipher_aes256_cbc();

	std::string_view name() const override { return "aes256-cbc"sv; }

	virtual bool decrypt_length(uint8_t*, size_t) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;

	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

private:
	std::vector<uint8_t> iv_;
	aes256_ctx ctx_;
	aes256_ctx dec_ctx_;
};

cipher_aes256_cbc::cipher_aes256_cbc()
    : cipher_base(16, 32, 16, false, true)
{
}

cipher_aes256_cbc::~cipher_aes256_cbc()
{
	wipe(&ctx_, sizeof(aes256_ctx));
	wipe(&dec_ctx_, sizeof(aes256_ctx));
	wipe(iv_);
}

bool cipher_aes256_cbc::decrypt_length(uint8_t* cipher, size_t s)
{
	if (s != block_size_) {
		return false;
	}
	cbc_decrypt(&dec_ctx_, reinterpret_cast<nettle_cipher_func*>(&aes256_decrypt), block_size_, iv_.data(), s, cipher, cipher);
	return true;
}

bool cipher_aes256_cbc::encrypt(uint8_t* plain, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	cbc_encrypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes256_encrypt), block_size_, iv_.data(), size, plain, plain);
	return true;
}

bool cipher_aes256_cbc::decrypt(uint8_t* cipher, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	cbc_decrypt(&dec_ctx_, reinterpret_cast<nettle_cipher_func*>(&aes256_decrypt), block_size_, iv_.data(), size, cipher, cipher);
	return true;
}

bool cipher_aes256_cbc::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	aes256_set_encrypt_key(&ctx_, key);
	aes256_set_decrypt_key(&dec_ctx_, key);
	return true;
}

bool cipher_aes256_cbc::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	return true;
}

class cipher_aes192_cbc final : public cipher_base
{
public:
	cipher_aes192_cbc();
	~cipher_aes192_cbc();

	std::string_view name() const override { return "aes192-cbc"sv; }

	virtual bool decrypt_length(uint8_t*, size_t) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;

	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

private:
	std::vector<uint8_t> iv_;
	aes192_ctx ctx_;
	aes192_ctx dec_ctx_;
};

cipher_aes192_cbc::cipher_aes192_cbc()
	: cipher_base(16, 24, 16, false, true)
{
}

cipher_aes192_cbc::~cipher_aes192_cbc()
{
	wipe(&ctx_, sizeof(aes192_ctx));
	wipe(&ctx_, sizeof(aes192_ctx));
	wipe(iv_);
}

bool cipher_aes192_cbc::decrypt_length(uint8_t* cipher, size_t s)
{
	if (s != block_size_) {
		return false;
	}
	cbc_decrypt(&dec_ctx_, reinterpret_cast<nettle_cipher_func*>(&aes192_decrypt), block_size_, iv_.data(), s, cipher, cipher);
	return true;
}

bool cipher_aes192_cbc::encrypt(uint8_t* plain, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	cbc_encrypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes192_encrypt), block_size_, iv_.data(), size, plain, plain);
	return true;
}

bool cipher_aes192_cbc::decrypt(uint8_t* cipher, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	cbc_decrypt(&dec_ctx_, reinterpret_cast<nettle_cipher_func*>(&aes192_decrypt), block_size_, iv_.data(), size, cipher, cipher);
	return true;
}

bool cipher_aes192_cbc::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	aes192_set_encrypt_key(&ctx_, key);
	aes192_set_decrypt_key(&dec_ctx_, key);
	return true;
}

bool cipher_aes192_cbc::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	return true;
}

class cipher_aes128_cbc final : public cipher_base
{
public:
	cipher_aes128_cbc();
	~cipher_aes128_cbc();

	std::string_view name() const override { return "aes128-cbc"sv; }

	virtual bool decrypt_length(uint8_t*, size_t) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;

	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

private:
	std::vector<uint8_t> iv_;
	aes128_ctx ctx_;
	aes128_ctx dec_ctx_;
};

cipher_aes128_cbc::cipher_aes128_cbc()
	: cipher_base(16, 16, 16, false, true)
{
}

cipher_aes128_cbc::~cipher_aes128_cbc()
{
	wipe(&ctx_, sizeof(aes128_ctx));
	wipe(&ctx_, sizeof(aes128_ctx));
	wipe(iv_);
}

bool cipher_aes128_cbc::decrypt_length(uint8_t* cipher, size_t s)
{
	if (s != block_size_) {
		return false;
	}
	cbc_decrypt(&dec_ctx_, reinterpret_cast<nettle_cipher_func*>(&aes128_decrypt), block_size_, iv_.data(), s, cipher, cipher);
	return true;
}

bool cipher_aes128_cbc::encrypt(uint8_t* plain, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	cbc_encrypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes128_encrypt), block_size_, iv_.data(), size, plain, plain);
	return true;
}

bool cipher_aes128_cbc::decrypt(uint8_t* cipher, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	cbc_decrypt(&dec_ctx_, reinterpret_cast<nettle_cipher_func*>(&aes128_decrypt), block_size_, iv_.data(), size, cipher, cipher);
	return true;
}

bool cipher_aes128_cbc::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	aes128_set_encrypt_key(&ctx_, key);
	aes128_set_decrypt_key(&dec_ctx_, key);
	return true;
}

bool cipher_aes128_cbc::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	return true;
}


class cipher_aes256_ctr final : public cipher_base
{
public:
	cipher_aes256_ctr();
	~cipher_aes256_ctr();

	std::string_view name() const override { return "aes256-ctr"sv; }

	virtual bool decrypt_length(uint8_t* cipher, size_t s) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;
	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

private:
	std::vector<uint8_t> iv_;
	aes256_ctx ctx_;
};

cipher_aes256_ctr::cipher_aes256_ctr()
	: cipher_base(16, 32, 16, false, false)
{}

cipher_aes256_ctr::~cipher_aes256_ctr()
{
	fz::wipe(iv_);
}

bool cipher_aes256_ctr::decrypt_length(uint8_t* cipher, size_t s)
{
	if (s != block_size_) {
		return false;
	}
	ctr_crypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes256_encrypt), block_size_, iv_.data(), s, cipher, cipher);
	return true;
}

bool cipher_aes256_ctr::encrypt(uint8_t* plain, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	ctr_crypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes256_encrypt), block_size_, iv_.data(), size, plain, plain);
	return true;
}

bool cipher_aes256_ctr::decrypt(uint8_t* cipher, size_t size)
{
	return encrypt(cipher, size);
}

bool cipher_aes256_ctr::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	aes256_set_encrypt_key(&ctx_, key);
	return true;
}

bool cipher_aes256_ctr::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	return true;
}



class cipher_aes192_ctr final : public cipher_base
{
public:
	cipher_aes192_ctr();
	~cipher_aes192_ctr();

	std::string_view name() const override { return "aes192-ctr"sv; }

	virtual bool decrypt_length(uint8_t* cipher, size_t s) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;
	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

private:
	std::vector<uint8_t> iv_;
	aes192_ctx ctx_;
};

cipher_aes192_ctr::cipher_aes192_ctr()
    : cipher_base(16, 24, 16, false, false)
{}

cipher_aes192_ctr::~cipher_aes192_ctr()
{
}

bool cipher_aes192_ctr::decrypt_length(uint8_t* cipher, size_t s)
{
	if (s != block_size_) {
		return false;
	}
	ctr_crypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes192_encrypt), block_size_, iv_.data(), s, cipher, cipher);
	return true;
}

bool cipher_aes192_ctr::encrypt(uint8_t* plain, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	ctr_crypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes192_encrypt), block_size_, iv_.data(), size, plain, plain);
	return true;
}

bool cipher_aes192_ctr::decrypt(uint8_t* cipher, size_t size)
{
	return encrypt(cipher, size);
}

bool cipher_aes192_ctr::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	aes192_set_encrypt_key(&ctx_, key);
	return true;
}

bool cipher_aes192_ctr::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	return true;
}


class cipher_aes128_ctr final : public cipher_base
{
public:
	cipher_aes128_ctr();
	~cipher_aes128_ctr();

	std::string_view name() const override { return "aes128-ctr"sv; }

	virtual bool decrypt_length(uint8_t* cipher, size_t s) override;
	virtual bool encrypt(uint8_t* plain, size_t size) override;
	virtual bool decrypt(uint8_t* cipher, size_t size) override;
	virtual bool set_key(uint8_t const* key, size_t len) override;
	virtual bool set_iv(std::vector<uint8_t> && iv) override;

private:
	std::vector<uint8_t> iv_;
	aes128_ctx ctx_;
};

cipher_aes128_ctr::cipher_aes128_ctr()
    : cipher_base(16, 16, 16, false, false)
{}

cipher_aes128_ctr::~cipher_aes128_ctr()
{
}

bool cipher_aes128_ctr::decrypt_length(uint8_t* cipher, size_t s)
{
	if (s != block_size_) {
		return false;
	}
	ctr_crypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes128_encrypt), block_size_, iv_.data(), s, cipher, cipher);
	return true;
}

bool cipher_aes128_ctr::encrypt(uint8_t* plain, size_t size)
{
	if (size % block_size_) {
		return false;
	}
	ctr_crypt(&ctx_, reinterpret_cast<nettle_cipher_func*>(&aes128_encrypt), block_size_, iv_.data(), size, plain, plain);
	return true;
}

bool cipher_aes128_ctr::decrypt(uint8_t* cipher, size_t size)
{
	return encrypt(cipher, size);
}

bool cipher_aes128_ctr::set_key(uint8_t const* key, size_t len)
{
	if (len != key_size_) {
		return false;
	}
	aes128_set_encrypt_key(&ctx_, key);
	return true;
}

bool cipher_aes128_ctr::set_iv(std::vector<uint8_t> && iv)
{
	if (iv.size() != iv_size_) {
		return false;
	}
	iv_ = std::move(iv);
	return true;
}


std::unique_ptr<cipher_base> create_cipher(std::string_view const& alg)
{
	if (alg == "aes256-gcm@openssh.com"sv) {
		return std::make_unique<cipher_aes256_gcm>();
	}
	else if (alg == "aes256-cbc"sv) {
		return std::make_unique<cipher_aes256_cbc>();
	}
	else if (alg == "aes192-cbc"sv) {
		return std::make_unique<cipher_aes192_cbc>();
	}
	else if (alg == "aes128-cbc"sv) {
		return std::make_unique<cipher_aes128_cbc>();
	}
	else if (alg == "aes256-ctr"sv) {
		return std::make_unique<cipher_aes256_ctr>();
	}
	else if (alg == "aes192-ctr"sv) {
		return std::make_unique<cipher_aes192_ctr>();
	}
	else if (alg == "aes128-ctr"sv) {
		return std::make_unique<cipher_aes128_ctr>();
	}
	else if (alg == "none"sv) {
		return std::make_unique<cipher_none>();
	}
	return {};
}

size_t get_cipher_bits(std::string_view const& alg)
{
	if (alg == "aes256-gcm@openssh.com"sv) {
		return 256;
	}
	else if (alg == "aes256-cbc"sv) {
		return 256;
	}
	else if (alg == "aes192-cbc"sv) {
		return 192;
	}
	else if (alg == "aes128-cbc"sv) {
		return 128;
	}
	else if (alg == "aes256-ctr"sv) {
		return 256;
	}
	else if (alg == "aes192-ctr"sv) {
		return 192;
	}
	else if (alg == "aes128-ctr"sv) {
		return 128;
	}
	return {};
}

}
