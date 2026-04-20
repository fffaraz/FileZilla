#include "buffer_util.hpp"
#include "mac.hpp"

#include <string.h>

#include <libfilezilla/hash.hpp>

#include <nettle/memops.h>

using namespace std::literals;

namespace fz::ssh {

class mac_none final : public mac_base
{
public:
	mac_none(size_t mac_size = 0, bool etm = false) noexcept
		: mac_base(mac_size, etm)
	{}

	virtual bool generate(uint32_t, uint8_t const*, size_t, uint8_t*) override { return true; }
	virtual bool verify(uint32_t, uint8_t const*, size_t, uint8_t const*) override { return true; };
};

class mac_hmac final : public mac_base
{
public:
	mac_hmac(size_t mac_size, hmac_algorithm alg, std::vector<uint8_t> const& key, bool etm = false) noexcept
		: mac_base(mac_size, etm)
		, h_(alg, key)
	{}

	virtual bool generate(uint32_t seq, uint8_t const* data, size_t size, uint8_t* mac) override;
	virtual bool verify(uint32_t seq, uint8_t const* data, size_t size, uint8_t const* mac) override;

private:
	void calc(int32_t seq, uint8_t const* data, size_t size);
	hash_accumulator h_;
};

void mac_hmac::calc(int32_t seq, uint8_t const* data, size_t size)
{
	h_.update_uint32_be(seq);;
	h_.update(data, size);
}

bool mac_hmac::generate(uint32_t seq, uint8_t const* data, size_t size, uint8_t* mac)
{
	calc(seq, data, size);
	h_.digest(mac, h_.digest_size());
	return true;
}

bool mac_hmac::verify(uint32_t seq, uint8_t const* data, size_t size, uint8_t const* mac)
{
	calc(seq, data, size);
	return h_.is_digest(mac, h_.digest_size());
}

class mac_hmac_sha1_96 final : public mac_base
{
public:
	mac_hmac_sha1_96(std::vector<uint8_t> const& key) noexcept
		: mac_base(12)
		, h_(hmac_algorithm::sha1, key)
	{}

	virtual bool generate(uint32_t seq, uint8_t const* data, size_t size, uint8_t* mac) override
	{
		calc(seq, data, size);
		auto d = h_.digest();
		memcpy(mac, d.data(), 12);
		return true;
	}
	virtual bool verify(uint32_t seq, uint8_t const* data, size_t size, uint8_t const* mac) override
	{
		calc(seq, data, size);
		auto d = h_.digest();
		return memeql_sec(mac, d.data(), 12) != 0;
	}

private:
	void calc(int32_t seq, uint8_t const* data, size_t size)
	{
		h_.update_uint32_be(seq);
		h_.update(data, size);
	}

	hash_accumulator h_;
};

std::unique_ptr<mac_base> create_mac(std::string_view const& alg, std::vector<uint8_t> const& key)
{
	if (alg == "aes256-gcm@openssh.com"sv) {
		return std::make_unique<mac_none>(16, true);
	}
	else if (alg == "hmac-sha2-256"sv) {
		if (key.size() != 32) {
			return {};
		}
		return std::make_unique<mac_hmac>(32, hmac_algorithm::sha256, key);
	}
	else if (alg == "hmac-sha2-512"sv) {
		if (key.size() != 64) {
			return {};
		}
		return std::make_unique<mac_hmac>(64, hmac_algorithm::sha512, key);
	}
	else if (alg == "hmac-sha1"sv) {
		if (key.size() != 20) {
			return {};
		}
		return std::make_unique<mac_hmac>(20, hmac_algorithm::sha1, key);
	}
	else if (alg == "hmac-sha1-96"sv) {
		if (key.size() != 20) {
			return {};
		}
		return std::make_unique<mac_hmac_sha1_96>(key);
	}
	else if (alg == "hmac-sha2-256-etm@openssh.com"sv) {
		if (key.size() != 32) {
			return {};
		}
		return std::make_unique<mac_hmac>(32, hmac_algorithm::sha256, key, true);
	}
	else if (alg == "none"sv) {
		return std::make_unique<mac_none>();
	}
	return {};
}

size_t mac_key_size(std::string_view const& alg)
{
	if (alg == "aes256-gcm@openssh.com"sv) {
		return 16;
	}
	else if (alg == "hmac-sha1"sv) {
		return 20;
	}
	else if (alg == "hmac-sha1-96"sv) {
		return 20;
	}
	else if (alg == "hmac-sha2-256"sv) {
		return 32;
	}
	else if (alg == "hmac-sha2-512"sv) {
		return 64;
	}
	else if (alg == "hmac-sha2-256-etm@openssh.com"sv) {
		return 32;
	}
	return {};
}

}
