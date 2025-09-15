#include "../lib/libfilezilla/encryption.hpp"
#include "../lib/libfilezilla/jws.hpp"
#include "../lib/libfilezilla/signature.hpp"
#include "../lib/libfilezilla/util.hpp"

#include "test_utils.hpp"

#include <string.h>

using namespace std::literals;

class crypto_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(crypto_test);
	CPPUNIT_TEST(test_encryption);
	CPPUNIT_TEST(test_encryption_with_password);
	CPPUNIT_TEST(test_signature);
	CPPUNIT_TEST(test_jwk);
	CPPUNIT_TEST(test_jws);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_encryption();
	void test_encryption_with_password();
	void test_signature();
	void test_jwk();
	void test_jws();
};

CPPUNIT_TEST_SUITE_REGISTRATION(crypto_test);

void crypto_test::test_encryption()
{
	auto priv = fz::private_key::generate();
	priv.generate();

	auto const pub = priv.pubkey();

	std::string const plain = "Hello world";

	auto cipher = fz::encrypt(plain, pub);
	CPPUNIT_ASSERT(fz::decrypt(cipher, priv) == std::vector<uint8_t>(plain.cbegin(), plain.cend()));
}


void crypto_test::test_encryption_with_password()
{
	auto const salt = fz::random_bytes(fz::private_key::salt_size);

	std::string const plain = "Hello world";
	std::vector<uint8_t> cipher;

	{
		auto priv = fz::private_key::from_password("super secret", salt);
		CPPUNIT_ASSERT(priv);

		auto const pub = priv.pubkey();

		cipher = fz::encrypt(plain, pub);
	}


	{
		auto priv = fz::private_key::from_password("super secret", salt);
		CPPUNIT_ASSERT(priv);

		CPPUNIT_ASSERT(fz::decrypt(cipher, priv) == std::vector<uint8_t>(plain.cbegin(), plain.cend()));
	}

}

void crypto_test::test_signature()
{
	// Test privkey generation
	auto const priv = fz::private_signing_key::generate();
	CPPUNIT_ASSERT(priv);
	CPPUNIT_ASSERT(!priv.to_base64().empty());
	CPPUNIT_ASSERT(fz::private_signing_key::from_base64(priv.to_base64()));

	// Test pubkey generation
	auto const pub = priv.pubkey();
	CPPUNIT_ASSERT(pub);
	CPPUNIT_ASSERT(!pub.to_base64().empty());
	CPPUNIT_ASSERT(fz::public_verification_key::from_base64(pub.to_base64()));

	// Test signing attached
	auto sig = fz::sign("Hello", priv);
	std::string_view sigv(reinterpret_cast<char const*>(sig.data()), sig.size());
	CPPUNIT_ASSERT(!sig.empty());

	// Test signing detached
	auto sig2 = fz::sign("Hello", priv, false);
	std::string_view sig2v(reinterpret_cast<char const*>(sig2.data()), sig2.size());
	CPPUNIT_ASSERT(!sig2.empty());

	// Test sig verification
	CPPUNIT_ASSERT(fz::verify(sig, pub));
	CPPUNIT_ASSERT(fz::verify("Hello", sig2v, pub));
	CPPUNIT_ASSERT(!fz::verify(sig2, pub));
	CPPUNIT_ASSERT(!fz::verify("Hello", sigv, pub));

	// Test verification with wrong key fails
	auto const pub2 = fz::private_signing_key::generate().pubkey();
	CPPUNIT_ASSERT(pub2);
	CPPUNIT_ASSERT(!fz::verify(sig, pub2));
	CPPUNIT_ASSERT(!fz::verify("Hello", sig2v, pub2));

	// Test verification of modified data fails
	sig[5] ^= 0x2c;
	sig2[5] ^= 0x2c;
	CPPUNIT_ASSERT(!fz::verify(sig, pub));
	CPPUNIT_ASSERT(!fz::verify("Hello", sig2v, pub));
}

void crypto_test::test_jwk()
{
	auto rsa =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		"MIIEpQIBAAKCAQEA6GY2rl8W+UZZj68WowmdzA1Hnpn05v88TiCsMP2iiQeCaDgk\n"
		"t4a4WV+b06f06KwXz/pAxjiY5UZ4qZtOHTnFbY4tqfuiI0V4gZQGa82GcSa/jm9o\n"
		"7sb13CBxk9xcdShRYt/8P4vLJf6diZVJ5edQsWHaf49bYBxSHc5qFeinuA+Xp2GV\n"
		"MGzUwjtqzY3K0uV9kPiR5RwO4xcWj+JWNpfsPRD4vvQwNZ9y0Zx4Wd1M4s41N7wd\n"
		"kRKeRESCRGT7atd7xSDCJPLsmTIg/O+bKUYY2t6EYqqoEgRjKrnG/p/em37sALb7\n"
		"todqBkbRc17X9M6uFxIa/6GH2VtVF1r00KICHQIDAQABAoIBAFpGqmMeCRyYGV5Z\n"
		"U1/N8oA7gGC5yYqaB2EKDBmTzTmRszSs6oZoTOBa5XtYuShRAYcG3XaisbIOp/yq\n"
		"mbN8p5ahLlfjqd4ttFwRllT2J4140dyQpqBqpUL3T2dyqG/SU5snCyPcN/Pwbl3t\n"
		"oiEutAfTzT7T/1jcZ4Gwl0EfeVdj6YZy/+q5yPCR+6R0fectXf7ctXYGmfgC+KeN\n"
		"jgh1lL2HM+nVBRJ5tIPy6kNz3fjW/4WQZ1kb4ocZtjLxMstWsFac7Xc9i8rinNLb\n"
		"poqsWsOaym9GPcPW5fMWnmeQCHjyjP6DrF9tLgHwdhWGhA/7MEoyUda8cRGbb7MS\n"
		"Gu7rsoECgYEA/ppTw+DqVgLY4WYajsfv6VWqFD6Iz7TjeoiUX79/5KRgIwZdrtt4\n"
		"Hwp0zjtW5k4tRuWZ3NMgLcHKA8PG6T/CJdRO6hXAF/iEQgLB4qW+SQFI9gdLUbkd\n"
		"Qo7NyjQZg7dXm2bvGmMq7uu8TIwR2lIX7F7dgmL/w2+MTtJipFWW220CgYEA6ayx\n"
		"uR6AOdJcZove7aa7CuhcBcxsrEJnfZgvo4FBC5FAA775WDBanzMjvZqIE2RfCrZz\n"
		"dEXO7RdC6bDAH1snuI3/t7fiVXAV6TgoW2TfGgq4oVdxoNwanXY0+jcK2YDz/aE8\n"
		"RuXmB40xPmR9OPCIdQpVvVhUinOJoGERWmzwY3ECgYEA3aHGbWtrUrhjx8K0N7rA\n"
		"k+Roi/rr6bPTmiUu1DLFyGl27sZp4v9WD99wUt7BBPbk3ySbzelTx8E8dA6HJyDD\n"
		"h17L22ZXtAY4S6ZO1Vfmz3J46wLqhBea6weZCP5Vf52oe7UdS2EsTJOVdSUxnVV9\n"
		"Udw7A3feoWiHQU5PZDLFgfkCgYEAgcZcKZBL7FDs6jKyC1A2vrcPLFU84Wo7qZ/U\n"
		"jTzij/cKE0qDlju8iH/RUKK7AfITapKrih6e7kOl8L0t5fwtEi0ioLiqJYMLWCvN\n"
		"FfzufrsHkOtMeubijSKyB2h8SRF58BkUrddOKlF60MjkVrQXRNEJjw+4W/AQthZS\n"
		"meK4mrECgYEAi9CNeH02kN2k35upy4sNt7SsDhkCzA2jGvL35R8VQiHEm0Kc8nXs\n"
		"4hBaGYsTQXRXzONQVPtyBWBnTmaJrjmaPmHm0Y0gGuZ4i5tKLs5VDx+ixDppv1T/\n"
		"/a8DTWAA13vaDCGKqkMwNmUO/LvvG9zkeCbpWfrhCCaxUrDcsxSP7A0=\n"
		"-----END RSA PRIVATE KEY-----\n"sv;

	auto rsapkcs8 =
		"-----BEGIN PRIVATE KEY-----\n"
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3GQer9rGaFfht\n"
		"4pr3rH+5zbu6PEpo3xLW6ofcGPLu+42p4T2U2ycih7rwhmvLNJqM1/dkfrm2uEPU\n"
		"LlduLStEHFTmh/GhQm/6eDWvva2USXBFry2z+ajX9XOmrH1Lucexz67xN1hZzSPr\n"
		"KA6eGa19qiFNkQZaeWP+mXCXtya4y95Xrle5BzJJTKcFKqJEXRc0SGPMGElGfa28\n"
		"7FyI4XYRp2Uhm/+1N7A3cLtlncaYKYZS9Pn7G9ZePHmnBQrW90PE0T/CWlhDQiHr\n"
		"OMX1pLCdPEmRF/lU4tSHU3HcGXU6NhlL2gJslmpdczWGpC/v5ZDbZZoVdF4zAFMa\n"
		"6VEHyly7AgMBAAECggEADyR2yfYBAilG/m97OXh+p7MoD2LlFH8+Y5/J1J4LmVAc\n"
		"iywhl6n4NpbbEwFK8OdM0NEbmKgSW9YpZebfPDFoHp3pN5eOmDOSZziB2CLrtBPO\n"
		"wTSXpwbCu/mEswgY5KZcqYvvf+t/1w1sJwqNCu48tuPXFT8lM15OssOl2CZBgY7W\n"
		"5izsR57u4GXrakADT5COIla2N3xygW7+SiU2jMgON1biJOUjnklGMSNF3PtAcnET\n"
		"/dEyAx0KJB3p5n6ct/TJGsJJTa6hrtkRo5zJO2LLmzOH7cnlJ16mhXL5f4K6dtf8\n"
		"N4c6/Vn5owjTsUEwO2UvRqeD3ngnmgC4nfp9/byUYQKBgQDTIQ6KHW2F8EnTXpXK\n"
		"ifQU25Jm5LYuLQmL5F10K5EKsXbKQrsYbyQjK5ufKbWLBJJMp+D3qZR4cFXWAEoO\n"
		"WvMYPEGtuTR6YoZCpUL8Clr+UAmZrxnyG5CIm+s04AurIH9Gcvke3QnkL0H8NBJD\n"
		"AwFcWvFm4RVXZLB+4xMMZnDIzQKBgQDeAt2n/C4+O7B2T7NgJ86Svb+Y2yp3ZbXk\n"
		"lDBo7npowmGoGy5XJboqHzkZ9HBiOiekRuOmrEKJhHm4ag9JQfGa1axI693qFqNJ\n"
		"zCy6OtN5Vt/JtC9jjQbS/+4M4Qa0rVd1WZDaRpOP9QTisb/D5mahJOFIRV+vOr4K\n"
		"UEBCWjDbpwKBgDF8YQ0MYrxvGs65L8DeXuB4qrMFTpI6Ki+o4iK1h3SLLf2wcGwE\n"
		"uOKpePtwakXgV24yNy+1hsBIDEZxoOoGdU4r6XUPoPZCm5eJZs7umm9bUTS9bwZp\n"
		"YZIzgYjOLs34evyHPE74njXmwb+ccN9WF/6OrmBfx4HJbvj+vls8s5jNAoGAdHmO\n"
		"bsZoQHAyWS/hTM41m1j/fyNkuTVcY2q3pyWOhQ2ODJMOEdySOe0dmRdcKryV9aLX\n"
		"ZqczVVByR6UlFesJ5ZC6jZtpVpm/20TKJn4cWqmQSRNGVXU0olhxPMKGMR5MJx3x\n"
		"WAL1Ae6rPH/CuvVS3LIrmy4CUD2CXIjT3bvRrDsCgYEAjzc7hQI87DmxwjxU+9Fx\n"
		"QsWG7gmWZG2F7ui4M4oGu19InfaDgmtxoaCnX3w+bHwbG+/3QuQq7o/uUMffBvjq\n"
		"M3JSV7NS4te4274D0V69wdY7P6SuHRd9YRXXLBM6w4TnzIm2mlz2ICE3gS9gn9ro\n"
		"sNbEeLVufEKtE85WXYPFNv0=\n"
		"-----END PRIVATE KEY-----\n"sv;

	auto ecdsa =
		"-----BEGIN EC PRIVATE KEY-----\n"
		"MHcCAQEEIEuvqM7sH3tb7tIK2Ijtpnx9YhSfm0I6R4JVUtuPzLDHoAoGCCqGSM49\n"
		"AwEHoUQDQgAEWOqhCFvRwIKCEisKU6/aIMr+ZhWlxbKOlSOaDGpLJm0W8IUlPp9E\n"
		"5fZ2JuXYFbwEe/yr4sqfC9AAp9H0xWL/uw==\n"
		"-----END EC PRIVATE KEY-----\n"sv;

	auto ecdsapkcs8 =
		"-----BEGIN PRIVATE KEY-----\n"
		"MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgK0ECI3ipQLXTiEwH\n"
		"MdduOg56abQ1f+f36Rr0Qq9bAFqgCgYIKoZIzj0DAQehRANCAATu8oqd+Q8MkxZ4\n"
		"JpfdD/4zaLdRdUCS/hfiJantyNdBC8HuAXp6u6RORYYNgCHz5bF4m6naM7rNw+dt\n"
		"wNkkayEF\n"
		"-----END PRIVATE KEY-----\n"sv;

	{
		auto jwk = fz::jwk_from_x509_privkey(rsa);
		CPPUNIT_ASSERT(jwk.first);
		CPPUNIT_ASSERT(jwk.second);
	}
	{
		auto jwk = fz::jwk_from_x509_privkey(rsapkcs8);
		CPPUNIT_ASSERT(jwk.first);
		CPPUNIT_ASSERT(jwk.second);
	}
	{
		auto jwk = fz::jwk_from_x509_privkey(ecdsa);
		CPPUNIT_ASSERT(jwk.first);
		CPPUNIT_ASSERT(jwk.second);
	}
	{
		auto jwk = fz::jwk_from_x509_privkey(ecdsapkcs8);
		CPPUNIT_ASSERT(jwk.first);
		CPPUNIT_ASSERT(jwk.second);
	}

}

void crypto_test::test_jws()
{
	fz::jwk_type types[] = {fz::jwk_type::ecdsa, fz::jwk_type::rsa};
	for (size_t i = 0; i < sizeof(types) / sizeof(fz::jwk_type); ++i) {
		auto t = types[i];
		auto jwk = fz::create_jwk(t);
		CPPUNIT_ASSERT(jwk.first);
		CPPUNIT_ASSERT(jwk.second);

		fz::json data;
		data["hello"] = "world";
		auto sig = fz::jws_sign_flattened(jwk.first, data);
		CPPUNIT_ASSERT(sig);

		auto sig2 = fz::create_jwt(jwk.first, data);
		CPPUNIT_ASSERT(!sig2.empty());
	}
}
