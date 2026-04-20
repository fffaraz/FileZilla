#ifndef FZSSH_MAC_HEADER
#define FZSSH_MAC_HEADER

#include <memory>

namespace fz::ssh {

class mac_base
{
public:
	mac_base(size_t mac_size, bool etm = false)
	    : mac_size_(mac_size)
	    , etm_(etm)
	{}

	virtual ~mac_base() noexcept = default;

	virtual bool generate(uint32_t seq, uint8_t const* data, size_t size, uint8_t* mac) = 0;
	virtual bool verify(uint32_t seq, uint8_t const* data, size_t size, uint8_t const* mac) = 0;

	size_t size() const { return mac_size_; }
	bool etm() const { return etm_; }

protected:
	size_t const mac_size_;
	bool const etm_;
};

std::unique_ptr<mac_base> create_mac(std::string_view const& alg, std::vector<uint8_t> const& key);
size_t mac_key_size(std::string_view const& alg);

}

#endif
