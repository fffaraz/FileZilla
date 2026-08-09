#ifndef FZSSH_DH_HEADER
#define FZSSH_DH_HEADER

#include "fzssh/visibility.hpp"

#include <libfilezilla/buffer.hpp>
#include <libfilezilla/hash.hpp>

#include <memory>
#include <string>
#include <vector>

namespace fz {
class logger_interface;
namespace ssh {

enum class kex_type
{
	dh,
	dhge,
	ecdh,
	pqth
};

kex_type get_kex_type(std::string_view v);

class dh_pubkey_base
{
public:
	virtual ~dh_pubkey_base() = default;

	virtual bool parse(std::string_view key) = 0;
	buffer const& key() const { return key_; }

	virtual size_t octet_size() const = 0;

protected:
	buffer key_;
};

class dh_privkey_base
{
public:
	virtual ~dh_privkey_base() noexcept = default;

	virtual bool generate(size_t bits_hint) = 0;

	buffer const& pubkey() const { return pub_; }

	virtual buffer shared_secret(std::unique_ptr<dh_pubkey_base> const& pub) = 0;

protected:
	buffer pub_;
};

hash_algorithm get_exchange_hash(std::string_view const& alg);
std::unique_ptr<dh_pubkey_base> create_dh_pubkey(std::string_view const& alg);
std::unique_ptr<dh_privkey_base> create_dh_privkey(std::string_view const& alg, bool is_server);

std::tuple<buffer, std::unique_ptr<dh_pubkey_base>, std::unique_ptr<dh_privkey_base>> FZSSH_PUBLIC_SYMBOL get_dh_group(uint32_t min, uint32_t bits, uint32_t max);
std::tuple<std::unique_ptr<dh_pubkey_base>, std::unique_ptr<dh_privkey_base>> FZSSH_PUBLIC_SYMBOL get_dh_group(std::string_view group_blob, uint32_t min_bits, uint32_t max_bits, logger_interface & log);
}
}

#endif
