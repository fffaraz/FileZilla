#include "../lib/libfilezilla/buffer.hpp"

#include "test_utils.hpp"

#include <string.h>

class buffer_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(buffer_test);
	CPPUNIT_TEST(test_simple);
	CPPUNIT_TEST(test_append);
	CPPUNIT_TEST(test_get);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_simple();
	void test_append();
	void test_get();
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
	// This unit test specifically tests the memmove case with self-append in buffer::append
	fz::buffer buf;
	buf.reserve(100);
	size_t const cap = buf.capacity();
	buf.add(cap);
	auto const* old = buf.get();
	for (size_t i = 0; i < cap; ++i) {
		buf[i] = static_cast<unsigned char>(i);
	}
	size_t consumed = cap / 3 + 1;
	buf.consume(consumed);
	buf.append(buf.get(), 20);

	CPPUNIT_ASSERT(buf.capacity() == cap);
	CPPUNIT_ASSERT(old == buf.get());

	for (size_t i = 0; i < buf.size() - 20; ++i) {
		CPPUNIT_ASSERT(buf[i] == static_cast<unsigned char>(i + consumed));
	}

	for (size_t i = 0; i < 20; ++i) {
		CPPUNIT_ASSERT(buf[buf.size() - 20 + i] == static_cast<unsigned char>(i + consumed));
	}
}

void buffer_test::test_get()
{
	// This unit test specifically tests the memmove case in buffer::get
	fz::buffer buf;
	buf.reserve(100);
	size_t const cap = buf.capacity();
	buf.add(cap);
	auto const* old = buf.get();
	for (size_t i = 0; i < cap; ++i) {
		buf[i] = static_cast<unsigned char>(i);
	}
	size_t consumed = cap / 3 + 1;
	buf.consume(consumed);
	auto p = buf.get(20);
	memcpy(p, buf.get(), 20);
	buf.add(20);

	CPPUNIT_ASSERT(buf.capacity() == cap);
	CPPUNIT_ASSERT(old == buf.get());

	for (size_t i = 0; i < buf.size() - 20; ++i) {
		CPPUNIT_ASSERT(buf[i] == static_cast<unsigned char>(i + consumed));
	}

	for (size_t i = 0; i < 20; ++i) {
		CPPUNIT_ASSERT(buf[buf.size() - 20 + i] == static_cast<unsigned char>(i + consumed));
	}
}
