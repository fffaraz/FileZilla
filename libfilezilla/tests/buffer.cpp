#include "../lib/libfilezilla/buffer.hpp"

#include "test_utils.hpp"

#include <string.h>

class buffer_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(buffer_test);
	CPPUNIT_TEST(test_simple);
	CPPUNIT_TEST(test_append);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_simple();
	void test_append();
};

CPPUNIT_TEST_SUITE_REGISTRATION(buffer_test);

void buffer_test::test_simple()
{
	fz::buffer buf;
	buf.append("foo");
	buf.append("bar");

	ASSERT_EQUAL(size_t(6), buf.size());

	buf.consume(3);
	buf.append("baz");

	ASSERT_EQUAL(size_t(6), buf.size());

	fz::buffer buf2;
	memcpy(buf2.get(42), "barbaz", 6);
	buf2.add(6);

	CPPUNIT_ASSERT(buf == buf2);
}

void buffer_test::test_append()
{
	fz::buffer buf;
	buf.reserve(10);
	size_t const cap = buf.capacity();
	buf.add(cap);
	for (size_t i = 0; i < cap; ++i) {
		buf[i] = static_cast<unsigned char>(i);
	}
	buf.consume(5);
	buf.append(buf.get(), 5);
	CPPUNIT_ASSERT(buf.size() == buf.capacity());

	for (size_t i = 0; i < cap - 5; ++i) {
		CPPUNIT_ASSERT(buf[i] == static_cast<unsigned char>(i + 5));
	}

	for (size_t i = 0; i < 5; ++i) {
		CPPUNIT_ASSERT(buf[cap - 5 + i] == static_cast<unsigned char>(i + 5));
	}
}
