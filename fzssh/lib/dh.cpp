#include "dh.hpp"
#include "ecc.hpp"

#include <libfilezilla/util.hpp>

#include <nettle/curve25519.h>
#include <nettle/ecc.h>
#include <nettle/ecdsa.h>

#include "crypt/mlkem.hpp"

#include "buffer_util.hpp"
#include "mpz.hpp"

#include <string.h>

#include <array>

using namespace std::literals;

namespace fz::ssh {

kex_type get_kex_type(std::string_view v)
{
	if (fz::starts_with(v, "diffie-hellman-group-exchange")) {
		return kex_type::dhge;
	}
	else if (fz::starts_with(v, "curve-22519-"sv) || fz::starts_with(v, "ecdh-"sv)) {
		return kex_type::ecdh;
	}
	else if (fz::starts_with(v, "mlkem"sv)) {
		return kex_type::pqth;
	}

	return kex_type::dh;
}

class dh_pubkey_curve25519 final : public dh_pubkey_base
{
public:
	virtual bool parse(std::string_view key) override
	{
		if (key.size() != octet_size()) {
			return false;
		}
		key_.append(key);

		return true;
	}

	virtual size_t octet_size() const override { return 32; }
};

class dh_privkey_curve25519 final : public dh_privkey_base
{
public:
	virtual bool generate(size_t /*bits_hint*/) override
	{
		priv_ = random_bytes(pub_octet_size());
		priv_[0] &= 248;
		priv_[31] &= 127;
		priv_[31] |= 64;

		static const uint8_t nine[32]{
			9, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0 };

		pub_.resize(pub_octet_size());
		nettle_curve25519_mul(pub_.data(), priv_.data(), nine);

		return true;
	}
	virtual buffer shared_secret(std::unique_ptr<dh_pubkey_base> const& pub) override;
	size_t pub_octet_size() const { return 32; }

	std::vector<uint8_t> priv_;
};

buffer dh_privkey_curve25519::shared_secret(std::unique_ptr<dh_pubkey_base> const& pub)
{
	auto pub2 = dynamic_cast<dh_pubkey_curve25519 const*>(pub.get());
	if (!pub2 || pub2->key().size() != pub_octet_size()) {
		return {};
	}

	buffer ret;
	ret.resize(pub_octet_size());
	nettle_curve25519_mul(ret.data(), priv_.data(), reinterpret_cast<uint8_t const*>(pub2->key().data()));
	return ret;
}

class dh_pubkey_sha2_nistp final : public dh_pubkey_base
{
public:
	dh_pubkey_sha2_nistp(nistp_curve curve)
		: curve_(curve)
	{
	}

	virtual bool parse(std::string_view key) override
	{
		if (key.size() != octet_size()) {
			return false;
		}
		key_.append(key);

		return true;
	}

	virtual size_t octet_size() const override { return curve_bytes(curve_) * 2 + 1; }

private:
	nistp_curve const curve_;
};

extern "C" void rnd(void *, size_t length, uint8_t *dst);

class dh_privkey_sha2_nistp final : public dh_privkey_base
{
public:
	dh_privkey_sha2_nistp(nistp_curve curve)
		: curve_(curve)
		, priv_(curve_)
	{
	}

	~dh_privkey_sha2_nistp()
	{
	}

	virtual bool generate(size_t /*bits_hint*/) override
	{
		pub_.clear();

		curve_point pub(curve_);

		ecdsa_generate_keypair(pub, priv_, nullptr, &rnd);

		pub_.append('\x04');

		mpz x, y;
		ecc_point_get(pub, x, y);

		to_string_append(pub_, x, curve_bytes(curve_));
		to_string_append(pub_, y, curve_bytes(curve_));

		return true;
	}

	virtual buffer shared_secret(std::unique_ptr<dh_pubkey_base> const& pub) override;
	size_t pub_octet_size() const { return curve_bytes(curve_) * 2 + 1; }

private:
	nistp_curve const curve_;
	curve_scalar priv_;
};

buffer dh_privkey_sha2_nistp::shared_secret(std::unique_ptr<dh_pubkey_base> const& pub)
{
	auto pub2 = dynamic_cast<dh_pubkey_sha2_nistp const*>(pub.get());
	if (!pub2 || pub2->key().size() != pub_octet_size()) {
		return {};
	}

	std::string_view raw = pub2->key().to_view();
	if (raw[0] != '\x04') {
		return {};
	}

	std::string_view x = raw.substr(1, curve_bytes(curve_));
	std::string_view y = raw.substr(1 + curve_bytes(curve_), curve_bytes(curve_));

	mpz xz;
	mpz yz;

	nettle_mpz_set_str_256_u(xz, x.size(), reinterpret_cast<uint8_t const*>(x.data()));
	nettle_mpz_set_str_256_u(yz, y.size(), reinterpret_cast<uint8_t const*>(y.data()));

	curve_point pubpoint(curve_);
	if (!nettle_ecc_point_set(pubpoint, xz, yz)) {
		return {};
	}

	curve_point shared(curve_);
	nettle_ecc_point_mul(shared, priv_, pubpoint);

	nettle_ecc_point_get(shared, xz, yz);

	return to_string(xz, curve_bytes(curve_));
}

namespace {
struct group
{
	group(char const* prime, char const* generator)
	{
		mpz_set_str(p, prime, 16);
		mpz_sub_ui(p_sub1, p, 1);
		mpz_set_str(g, generator, 16);
		mpz_tdiv_q_ui(q, p, 2);
		bits = mpz_sizeinbase(p, 2);
	}

	group(std::string_view const& prime, std::string_view const& generator)
	{
		mpz_import(p, prime.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(prime.data()));
		mpz_sub_ui(p_sub1, p, 1);
		mpz_import(g, generator.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(generator.data()));
		mpz_tdiv_q_ui(q, p, 2);
		bits = mpz_sizeinbase(p, 2);
	}
	size_t bits{};
	mpz p;
	mpz p_sub1;
	mpz q;
	mpz g;
};

enum class dh_group : size_t {
	group1, // Note: SSH group1 actually uses the second Oakly group
	group14,
	group15,
	group16,
	group17,
	group18,
};

std::array<group, 6> const& get_groups()
{
	// See RFC 2409, 3526

	static std::array<group, 6> groups({
		group{
			// group1 Note: _Second_ Oakley group
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
			"FFFFFFFFFFFFFFFF",
			"2"
		},
		{
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF",
			"2"
		},
		{
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
			"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
		   "2"
		},
		{
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
			"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
			"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
			"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
			"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
			"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
			"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
			"FFFFFFFFFFFFFFFF",
			"2"
		},
		{
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
			"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
			"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
			"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
			"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
			"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
			"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
			"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
			"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
			"B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
			"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
			"E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
			"99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
			"04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
			"233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
			"D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
			"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
			"AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
			"DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
			"2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
			"F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
			"BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
			"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
			"B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
			"387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
			"6DCC4024FFFFFFFFFFFFFFFF",
			"2"
		},
		{
			"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
			"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
			"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
			"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
			"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
			"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
			"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
			"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
			"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
			"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
			"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
			"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
			"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
			"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
			"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
			"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
			"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
			"12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
			"38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
			"741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
			"3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
			"22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
			"4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
			"062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
			"4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
			"B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
			"4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
			"9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
			"60C980DD 98EDD3DFFFFFFFFFFFFFFFFF",
			"2"
		}
	});

	return groups;
}

group const& get_group(dh_group g) {
	return get_groups()[static_cast<size_t>(g)];
}

dh_group get_group(size_t bits)
{
	auto const& groups = get_groups();
	for (size_t i = 0; i < groups.size(); ++i) {
		if (groups[i].bits >= bits) {
			return static_cast<dh_group>(i);
		}
	}
	return static_cast<dh_group>(groups.size() - 1);
}

}

class dh_pubkey_group final : public dh_pubkey_base
{
public:
	dh_pubkey_group(dh_group g);
	dh_pubkey_group(group const& g);

	virtual bool parse(std::string_view key) override;
	virtual size_t octet_size() const override;

	group g_;
	mpz f_;
};


class dh_privkey_group final : public dh_privkey_base
{
public:
	dh_privkey_group(dh_group g);
	dh_privkey_group(group const& g);
	virtual ~dh_privkey_group();

	virtual bool generate(size_t bits_hint) override;
	virtual buffer shared_secret(std::unique_ptr<dh_pubkey_base> const& pub) override;

	group g_;
	mpz x_;
};

dh_pubkey_group::dh_pubkey_group(dh_group g)
	: g_(get_group(g))
{
}

dh_pubkey_group::dh_pubkey_group(group const& g)
	: g_(g)
{
}

bool dh_pubkey_group::parse(std::string_view key)
{
	if (!g_.bits) {
		return false;
	}

	mpz_import(f_, key.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(key.data()));
	if (mpz_cmp_si(f_.operator mpz_t&(), 1) <= 0 || mpz_cmp(f_, g_.p_sub1) >= 0) {
		return false;
	}

	// Check for abnormal keys. The probability of this happening at random is infitesimal
	auto const b = mpz_popcount(f_);
	if (b < 8 || b > g_.bits - 8) {
		return false;
	}

	key_.append(key);

	return true;
}

size_t dh_pubkey_group::octet_size() const
{
	return g_.bits;
}

dh_privkey_group::dh_privkey_group(dh_group g)
	: g_(get_group(g))
{
}

dh_privkey_group::dh_privkey_group(group const& g)
	: g_(g)
{
}

dh_privkey_group::~dh_privkey_group()
{
	wipe(x_);
}

bool dh_privkey_group::generate(size_t bits_hint)
{
	if (!g_.bits) {
		return false;
	}

	// Short exponent optimization
	size_t bits = mpz_sizeinbase(g_.q, 2);
	bits_hint *= 2;
	if (bits_hint < bits) {
		bits = std::max(bits_hint, size_t(256));
	}

	mpz e;
	do {
		do {
			auto raw = fz::random_bytes((bits+7)/8);
			if (bits % 8) {
				uint8_t remainder_mask = ~((2u << (bits % 8 - 1)) - 1);
				raw[0] &= remainder_mask;
			}
			mpz_import(x_, raw.size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(raw.data()));
			wipe(raw);
		}
		while (mpz_cmp_ui(x_.operator mpz_t&(), 1) <= 0 || mpz_cmp(x_, g_.q) >= 0);

		mpz_powm_sec(e, g_.g, x_, g_.p);
	}
	while (mpz_cmp_si(e.operator mpz_t&(), 1) <= 0 || mpz_cmp(e, g_.p_sub1) >= 0);

	pub_.append(0);
	auto bytes = (mpz_sizeinbase(e, 2) + 7) / 8;
	mpz_export(pub_.get(bytes), nullptr, 1, 1, 0, 0, e);
	pub_.add(bytes);
	if (!(pub_[1] & 0x80)) {
		pub_.consume(1);
	}

	return true;
}

buffer dh_privkey_group::shared_secret(std::unique_ptr<dh_pubkey_base> const& pub)
{
	auto pub2 = dynamic_cast<dh_pubkey_group const*>(pub.get());
	if (!pub2) {
		return {};
	}

	mpz f;
	mpz_import(f, pub2->key().size(), 1, 1, 0, 0, reinterpret_cast<uint8_t const*>(pub2->key().data()));

	mpz k;
	scoped_wiper w(k);
	mpz_powm_sec(k, f, x_, g_.p);

	if (mpz_cmp_ui(k.operator mpz_t&(), 1) <= 0 || mpz_cmp(k, g_.p_sub1) >= 0) {
		return {};
	}

	buffer ret;
	auto bytes = (mpz_sizeinbase(k, 2) + 7) / 8;
	mpz_export(ret.get(bytes), nullptr, 1, 1, 0, 0, k);
	ret.add(bytes);
	return ret;
}

class dh_pubkey_mlkem final : public dh_pubkey_base
{
public:
	virtual bool parse(std::string_view key) override
	{
		// Length verification happens in dh_privkey_mlkem::shared_secret
		key_.append(key);
		return true;
	}

	virtual size_t octet_size() const override { return 64; }
};

class dh_privkey_mlkem final : public dh_privkey_base
{
public:
	dh_privkey_mlkem(bool server)
		: server_(server)
	{}

	virtual bool generate(size_t bits_hint) override
	{
		if (!traditional_.generate(bits_hint)) {
			return false;
		}

		if (!server_) {
			mlkem_keygen(pub_, priv_);
			pub_.append(traditional_.pubkey());
		}

		return true;
	}

	virtual buffer shared_secret(std::unique_ptr<dh_pubkey_base> const& pub) override;

private:
	size_t pub_octet_size() const { return 1184 + traditional_.pub_octet_size(); }

	fz::buffer priv_;
	dh_privkey_curve25519 traditional_;

	bool server_{};
};

buffer dh_privkey_mlkem::shared_secret(std::unique_ptr<dh_pubkey_base> const& pub3)
{
	auto pub2 = dynamic_cast<dh_pubkey_mlkem const*>(pub3.get());
	if (!pub2) {
		return {};
	}

	if (pub2->key().size() != (server_ ? 1184 : 1088) + traditional_.pub_octet_size()) {
		return {};
	}
	auto pq_part = pub2->key().to_view().substr(0, pub2->key().size() - traditional_.pub_octet_size());

	auto curve = create_dh_pubkey("curve25519-sha256"sv);
	if (!curve || !curve->parse(pub2->key().to_view().substr(pub2->key().size() - traditional_.pub_octet_size()))) {
		return {};
	}

	fz::buffer secret1;
	if (server_) {
		secret1 = mlkem_encaps(pub_, pq_part);
		pub_.append(traditional_.pubkey());
	}
	else {
		secret1 = mlkem_decaps(priv_, pq_part);
	}

	auto secret2 = traditional_.shared_secret(curve);

	fz::buffer ret;
	if (!secret1.empty() && !secret2.empty()) {
		fz::hash_accumulator acc(fz::hash_algorithm::sha256);
		acc << secret1;
		acc << secret2;
		acc.digest(ret.get(acc.digest_size()), acc.digest_size());
		ret.add(acc.digest_size());
	}

	fz::wipe(secret1);
	fz::wipe(secret2);

	return ret;
}

hash_algorithm get_exchange_hash(std::string_view const& alg)
{
	if (alg == "curve25519-sha256"sv || alg == "curve25519-sha256@libssh.org"sv) {
		return hash_algorithm::sha256;
	}
	else if (alg == "diffie-hellman-group14-sha1"sv || alg == "diffie-hellman-group1-sha1"sv || alg == "diffie-hellman-group-exchange-sha1"sv) {
		return hash_algorithm::sha1;
	}
	else if (alg == "diffie-hellman-group14-sha256"sv || alg == "diffie-hellman-group-exchange-sha256"sv) {
		return hash_algorithm::sha256;
	}
	else if (alg == "diffie-hellman-group15-sha512"sv || alg == "diffie-hellman-group16-sha512"sv || alg == "diffie-hellman-group17-sha512"sv || alg == "diffie-hellman-group18-sha512"sv) {
		return hash_algorithm::sha512;
	}
	else if (alg == "ecdh-sha2-nistp256"sv) {
		return hash_algorithm::sha256;
	}
	else if (alg == "ecdh-sha2-nistp384"sv) {
		return hash_algorithm::sha384;
	}
	else if (alg == "ecdh-sha2-nistp521"sv) {
		return hash_algorithm::sha512;
	}
	else if (alg == "mlkem768x25519-sha256"sv) {
		return hash_algorithm::sha256;
	}
	return {};
}

std::unique_ptr<dh_pubkey_base> create_dh_pubkey(std::string_view const& alg)
{
	if (alg == "curve25519-sha256"sv || alg == "curve25519-sha256@libssh.org"sv) {
		return std::make_unique<dh_pubkey_curve25519>();
	}
	else if (alg == "diffie-hellman-group14-sha1"sv || alg == "diffie-hellman-group14-sha256"sv) {
		return std::make_unique<dh_pubkey_group>(dh_group::group14);
	}
	else if (alg == "diffie-hellman-group1-sha1"sv) {
		return std::make_unique<dh_pubkey_group>(dh_group::group1);
	}
	else if (alg == "diffie-hellman-group15-sha512"sv) {
		return std::make_unique<dh_pubkey_group>(dh_group::group15);
	}
	else if (alg == "diffie-hellman-group16-sha512"sv) {
		return std::make_unique<dh_pubkey_group>(dh_group::group16);
	}
	else if (alg == "diffie-hellman-group17-sha512"sv) {
		return std::make_unique<dh_pubkey_group>(dh_group::group17);
	}
	else if (alg == "diffie-hellman-group18-sha512"sv) {
		return std::make_unique<dh_pubkey_group>(dh_group::group18);
	}
	else if (alg == "ecdh-sha2-nistp256"sv) {
		return std::make_unique<dh_pubkey_sha2_nistp>(nistp_curve::nistp256);
	}
	else if (alg == "ecdh-sha2-nistp384"sv) {
		return std::make_unique<dh_pubkey_sha2_nistp>(nistp_curve::nistp384);
	}
	else if (alg == "ecdh-sha2-nistp521"sv) {
		return std::make_unique<dh_pubkey_sha2_nistp>(nistp_curve::nistp521);
	}
	else if (alg == "mlkem768x25519-sha256"sv) {
		return std::make_unique<dh_pubkey_mlkem>();
	}

	return {};
}

std::unique_ptr<dh_privkey_base> create_dh_privkey(std::string_view const& alg, bool is_server)
{
	if (alg == "curve25519-sha256"sv || alg == "curve25519-sha256@libssh.org"sv) {
		return std::make_unique<dh_privkey_curve25519>();
	}
	else if (alg == "diffie-hellman-group14-sha1"sv || alg == "diffie-hellman-group14-sha256"sv) {
		return std::make_unique<dh_privkey_group>(dh_group::group14);
	}
	else if (alg == "diffie-hellman-group1-sha1"sv) {
		return std::make_unique<dh_privkey_group>(dh_group::group1);
	}
	else if (alg == "diffie-hellman-group15-sha512"sv) {
		return std::make_unique<dh_privkey_group>(dh_group::group15);
	}
	else if (alg == "diffie-hellman-group16-sha512"sv) {
		return std::make_unique<dh_privkey_group>(dh_group::group16);
	}
	else if (alg == "diffie-hellman-group17-sha512"sv) {
		return std::make_unique<dh_privkey_group>(dh_group::group17);
	}
	else if (alg == "diffie-hellman-group18-sha512"sv) {
		return std::make_unique<dh_privkey_group>(dh_group::group18);
	}
	else if (alg == "ecdh-sha2-nistp256"sv) {
		return std::make_unique<dh_privkey_sha2_nistp>(nistp_curve::nistp256);
	}
	else if (alg == "ecdh-sha2-nistp384"sv) {
		return std::make_unique<dh_privkey_sha2_nistp>(nistp_curve::nistp384);
	}
	else if (alg == "ecdh-sha2-nistp521"sv) {
		return std::make_unique<dh_privkey_sha2_nistp>(nistp_curve::nistp521);
	}
	else if (alg == "mlkem768x25519-sha256"sv) {
		return std::make_unique<dh_privkey_mlkem>(is_server);
	}

	return {};
}

std::tuple<buffer, std::unique_ptr<dh_pubkey_base>, std::unique_ptr<dh_privkey_base>> get_dh_group(uint32_t min, uint32_t bits, uint32_t max)
{
	dh_group g = get_group(bits);
	auto group = get_group(g);
	if (min && (group.bits < min || group.bits > max)) {
		return {};
	}

	fz::buffer param;
	write_mpint(param, to_string(group.p));
	write_mpint(param, to_string(group.g));

	return {param, std::make_unique<dh_pubkey_group>(g), std::make_unique<dh_privkey_group>(g)};
}

std::tuple<std::unique_ptr<dh_pubkey_base>, std::unique_ptr<dh_privkey_base>> FZSSH_PUBLIC_SYMBOL get_dh_group(std::string_view group_blob)
{
	auto prime = extract_blob(group_blob);
	auto gen = extract_blob(group_blob);
	if (!prime || !gen || !group_blob.empty()) {
		return {};
	}

	// Should we validate the parameters?

	auto g = group(*prime, *gen);
	return {std::make_unique<dh_pubkey_group>(g), std::make_unique<dh_privkey_group>(g)};
}
}
