#ifndef FZSSH_CIPHER_HEADER
#define FZSSH_CIPHER_HEADER

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

using namespace std::literals;

namespace fz::ssh {

class cipher_base
{
public:
	cipher_base(size_t block_size, size_t key_size, size_t iv_size, bool plain_packet_length = false, bool requires_random_padding = true)
	    : block_size_(block_size)
	    , key_size_(key_size)
	    , iv_size_(iv_size)
	    , plain_packet_length_(plain_packet_length)
	    , requires_random_padding_(requires_random_padding)
	{}

	virtual ~cipher_base() noexcept = default;

	virtual std::string_view name() const = 0;

	virtual bool encrypt(uint8_t* plain, size_t size, uint8_t* mac, size_t mac_size) = 0;
	virtual bool decrypt_length(uint8_t* cipher, size_t size) = 0;
	virtual bool decrypt(uint8_t* cipher, size_t size, uint8_t* mac, size_t mac_size) = 0;
	virtual bool set_key(uint8_t const* key, size_t len) = 0;
	virtual bool set_iv(std::vector<uint8_t> && iv) = 0;

	template <typename Data,
		std::enable_if_t<sizeof(typename Data::value_type) == sizeof(uint8_t)>* = nullptr>
	bool set_key(Data const& d) {
		return set_key(reinterpret_cast<uint8_t const*>(d.data()), d.size());
	}

	size_t block_size() const { return block_size_; }
	size_t key_size() const { return key_size_; }
	size_t iv_size() const { return iv_size_; }
	bool plain_packet_length() const { return plain_packet_length_; }
	bool must_check_mac_before_length() const { return must_check_mac_before_length_; }

	bool requires_random_padding() const { return requires_random_padding_; }

protected:
	size_t const block_size_;
	size_t const key_size_;
	size_t const iv_size_;
	bool const plain_packet_length_{};
	bool const requires_random_padding_{true};
	bool const must_check_mac_before_length_{};
};

std::unique_ptr<cipher_base> create_cipher(std::string_view const& alg);
size_t get_cipher_bits(std::string_view const& alg);
}

#endif
