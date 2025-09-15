#include "../lib/libfilezilla/encode.hpp"
#include "../lib/libfilezilla/util.hpp"

#include "test_utils.hpp"

#include <string.h>

class util_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(util_test);
	CPPUNIT_TEST(test_random);
	CPPUNIT_TEST(test_bitscan);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_random();
	void test_bitscan();
};

CPPUNIT_TEST_SUITE_REGISTRATION(util_test);

void util_test::test_random()
{
	auto const first = fz::hex_encode<std::string>(fz::random_bytes(64));
	auto const second = fz::hex_encode<std::string>(fz::random_bytes(64));

	CPPUNIT_ASSERT(!first.empty());
	CPPUNIT_ASSERT(first != second);
}

void util_test::test_bitscan()
{
	CPPUNIT_ASSERT(fz::bitscan(12) == 2);
	CPPUNIT_ASSERT(fz::bitscan_reverse(12) == 3);

	CPPUNIT_ASSERT(fz::bitscan(0x3000000000000000ull) == 60);
	CPPUNIT_ASSERT(fz::bitscan_reverse(0x3000000000000000ull) == 61);
}
