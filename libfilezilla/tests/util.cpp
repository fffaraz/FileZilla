#include "../lib/libfilezilla/encode.hpp"
#include "../lib/libfilezilla/mutex.hpp"
#include "../lib/libfilezilla/thread_pool.hpp"
#include "../lib/libfilezilla/util.hpp"

#include "test_utils.hpp"

#include <string.h>

class util_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(util_test);
	CPPUNIT_TEST(test_random);
	CPPUNIT_TEST(test_bitscan);
#ifdef LFZ_DEBUG_MUTEXES
	CPPUNIT_TEST(test_mutexdebug);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_random();
	void test_bitscan();
#ifdef LFZ_DEBUG_MUTEXES
	void test_mutexdebug();
#endif
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

#ifdef LFZ_DEBUG_MUTEXES
void util_test::test_mutexdebug()
{
	fz::mutex a, b, c;
	fz::thread_pool p;

	auto f = [&]{
		for (size_t i = 0; i < 50; ++i) {
			fz::scoped_lock la(a);
			fz::sleep(fz::duration::from_milliseconds(fz::random_number(0, 20)));
			fz::scoped_lock lb(b);
			fz::sleep(fz::duration::from_milliseconds(fz::random_number(0, 20)));
			fz::scoped_lock lc(c);
			fz::sleep(fz::duration::from_milliseconds(fz::random_number(0, 20)));
		}
	};

	auto g = [&]{
		for (size_t i = 0; i < 50; ++i) {
			fz::scoped_lock la(a);
			fz::sleep(fz::duration::from_milliseconds(fz::random_number(0, 20)));
			fz::scoped_lock lc(c);
			fz::sleep(fz::duration::from_milliseconds(fz::random_number(0, 20)));
			fz::scoped_lock lb(b);
			fz::sleep(fz::duration::from_milliseconds(fz::random_number(0, 20)));
		}
	};

	auto tf1 = p.spawn(f);
	auto tf2 = p.spawn(f);

	auto tg1 = p.spawn(g);
	auto tg2 = p.spawn(g);
}
#endif
