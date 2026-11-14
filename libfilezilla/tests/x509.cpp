#include "../lib/libfilezilla/tls_info.hpp"

#include "test_utils.hpp"

#include <string.h>

using namespace std::literals;

class x509_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(x509_test);
	CPPUNIT_TEST(test_dn);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_dn();
};

CPPUNIT_TEST_SUITE_REGISTRATION(x509_test);

void x509_test::test_dn()
{
	CPPUNIT_ASSERT(fz::is_valid_x509_distinguished_name("CN=Something"s));

	CPPUNIT_ASSERT(!fz::is_valid_x509_distinguished_name("C=DE,CN="s));
}

