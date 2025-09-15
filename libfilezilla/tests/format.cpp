#include "../lib/libfilezilla/format.hpp"

#include "test_utils.hpp"
/*
 * This testsuite asserts the correctness of the
 * string formatting functions
 */

class format_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(format_test);
	CPPUNIT_TEST(test_sprintf);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_sprintf();
};

CPPUNIT_TEST_SUITE_REGISTRATION(format_test);

void format_test::test_sprintf()
{
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::sprintf("foo"));
	CPPUNIT_ASSERT_EQUAL(std::string("foo % bar"), fz::sprintf("foo %% bar"));

	CPPUNIT_ASSERT_EQUAL(std::string("foo bar"), fz::sprintf("foo %s", "bar"));
	CPPUNIT_ASSERT_EQUAL(std::string("foo bar"), fz::sprintf("foo %s", L"bar"));
	CPPUNIT_ASSERT_EQUAL(std::string("foo bar"), fz::sprintf("foo %s", std::string("bar")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo bar"), fz::sprintf("foo %s", std::wstring(L"bar")));

	CPPUNIT_ASSERT_EQUAL(std::string("    "), fz::sprintf("%4s", " "));

	CPPUNIT_ASSERT_EQUAL(std::string("0"), fz::sprintf("%d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string("   0"), fz::sprintf("%4d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string("0000"), fz::sprintf("%04d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string("   0"), fz::sprintf("% 4d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string(" 000"), fz::sprintf("% 04d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string(" 000"), fz::sprintf("%0 4d", 0));

	CPPUNIT_ASSERT_EQUAL(std::string("0"), fz::sprintf("%0d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string(" 0"), fz::sprintf("% 0d", 0));
	CPPUNIT_ASSERT_EQUAL(std::string(" 0"), fz::sprintf("% d", 0));

	CPPUNIT_ASSERT_EQUAL(std::string("1"), fz::sprintf("%d", 1));
	CPPUNIT_ASSERT_EQUAL(std::string("   1"), fz::sprintf("%4d", 1));
	CPPUNIT_ASSERT_EQUAL(std::string("0001"), fz::sprintf("%04d", 1));
	CPPUNIT_ASSERT_EQUAL(std::string("   1"), fz::sprintf("% 4d", 1));
	CPPUNIT_ASSERT_EQUAL(std::string(" 001"), fz::sprintf("% 04d", 1));
	CPPUNIT_ASSERT_EQUAL(std::string(" 001"), fz::sprintf("%0 4d", 1));

	CPPUNIT_ASSERT_EQUAL(std::string("123"), fz::sprintf("%d", 123));
	CPPUNIT_ASSERT_EQUAL(std::string(" 123"), fz::sprintf("%4d", 123));
	CPPUNIT_ASSERT_EQUAL(std::string("0123"), fz::sprintf("%04d", 123));
	CPPUNIT_ASSERT_EQUAL(std::string(" 123"), fz::sprintf("% 4d", 123));
	CPPUNIT_ASSERT_EQUAL(std::string(" 123"), fz::sprintf("% 04d", 123));
	CPPUNIT_ASSERT_EQUAL(std::string(" 123"), fz::sprintf("%0 4d", 123));

	CPPUNIT_ASSERT_EQUAL(std::string("1234"), fz::sprintf("%d", 1234));
	CPPUNIT_ASSERT_EQUAL(std::string("1234"), fz::sprintf("%4d", 1234));
	CPPUNIT_ASSERT_EQUAL(std::string("1234"), fz::sprintf("%04d", 1234));
	CPPUNIT_ASSERT_EQUAL(std::string(" 1234"), fz::sprintf("% 4d", 1234));
	CPPUNIT_ASSERT_EQUAL(std::string(" 1234"), fz::sprintf("% 04d", 1234));
	CPPUNIT_ASSERT_EQUAL(std::string(" 1234"), fz::sprintf("%0 4d", 1234));

	CPPUNIT_ASSERT_EQUAL(std::string("12345"), fz::sprintf("%d", 12345));
	CPPUNIT_ASSERT_EQUAL(std::string("12345"), fz::sprintf("%4d", 12345));
	CPPUNIT_ASSERT_EQUAL(std::string("12345"), fz::sprintf("%04d", 12345));
	CPPUNIT_ASSERT_EQUAL(std::string(" 12345"), fz::sprintf("% 4d", 12345));
	CPPUNIT_ASSERT_EQUAL(std::string(" 12345"), fz::sprintf("% 04d", 12345));
	CPPUNIT_ASSERT_EQUAL(std::string(" 12345"), fz::sprintf("%0 4d", 12345));

	CPPUNIT_ASSERT_EQUAL(std::string("-42"), fz::sprintf("%d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string("-42"), fz::sprintf("%d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string("-42"), fz::sprintf("%0d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string("-42"), fz::sprintf("% d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string("-42"), fz::sprintf("% 0d", -42));

	CPPUNIT_ASSERT_EQUAL(std::string(" -42"), fz::sprintf("%4d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string(" -42"), fz::sprintf("%4d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string("-042"), fz::sprintf("%04d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string(" -42"), fz::sprintf("% 4d", -42));
	CPPUNIT_ASSERT_EQUAL(std::string("-042"), fz::sprintf("% 04d", -42));

	CPPUNIT_ASSERT_EQUAL(std::string("foo 7 foo"), fz::sprintf("%2$s %1$d %2$s", 7, "foo"));

	CPPUNIT_ASSERT_EQUAL(std::string("0"), fz::sprintf("%x", 0));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("%x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23BF0A"), fz::sprintf("%X", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("%0x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("% x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("% 0x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("0a"), fz::sprintf("%02x", 10));

	CPPUNIT_ASSERT_EQUAL(std::string("   0"), fz::sprintf("%4x", 0));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("%4x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23BF0A"), fz::sprintf("%4X", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("%04x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("% 4x", 2342666));
	CPPUNIT_ASSERT_EQUAL(std::string("23bf0a"), fz::sprintf("% 04x", 2342666));

	CPPUNIT_ASSERT_EQUAL(std::string("77     "), fz::sprintf("%-7d", 77));
	CPPUNIT_ASSERT_EQUAL(std::string("-77    "), fz::sprintf("%-7d", -77));
	CPPUNIT_ASSERT_EQUAL(std::string(" 77    "), fz::sprintf("% -7d", 77));
	CPPUNIT_ASSERT_EQUAL(std::string("-77    "), fz::sprintf("% -7d", -77));
	CPPUNIT_ASSERT_EQUAL(std::string(" 77    "), fz::sprintf("%- 7d", 77));
	CPPUNIT_ASSERT_EQUAL(std::string("-77    "), fz::sprintf("%- 7d", -77));
	CPPUNIT_ASSERT_EQUAL(std::string("ok     "), fz::sprintf("%- 7s", "ok"));
	CPPUNIT_ASSERT_EQUAL(std::string("hello"), fz::sprintf("%-3s", "hello"));

	CPPUNIT_ASSERT_EQUAL(std::string("    +77"), fz::sprintf("%+7d", 77));
	CPPUNIT_ASSERT_EQUAL(std::string("    -77"), fz::sprintf("%+7d", -77));
	CPPUNIT_ASSERT_EQUAL(std::string("+77    "), fz::sprintf("%+-7d", 77));
	CPPUNIT_ASSERT_EQUAL(std::string("-77    "), fz::sprintf("%+-7d", -77));

	CPPUNIT_ASSERT_EQUAL(std::string("x"), fz::sprintf("%c", char('x')));
	CPPUNIT_ASSERT_EQUAL(std::string("x"), fz::sprintf("%c", int('x')));

	CPPUNIT_ASSERT_EQUAL(std::string("x"), fz::sprintf("%s", std::string_view("x", 1)));
	CPPUNIT_ASSERT_EQUAL(std::string("x"), fz::sprintf("%s", std::wstring_view(L"x", 1)));
	//CPPUNIT_ASSERT_EQUAL(std::wstring(L"x"), fz::sprintf(L"%s", std::string_view("x", 1)));
	//CPPUNIT_ASSERT_EQUAL(std::wstring(L"x"), fz::sprintf(L"%s", std::wstring_view(L"x", 1)));

	CPPUNIT_ASSERT_EQUAL(std::string("1"), fz::sprintf("%d", true));
	CPPUNIT_ASSERT_EQUAL(std::string("0"), fz::sprintf("%d", false));

	int16_t const neg16 = -42;
	CPPUNIT_ASSERT_EQUAL(std::string("ffd6"), fz::sprintf("%x", neg16));
	int32_t const neg32 = -42;
	CPPUNIT_ASSERT_EQUAL(std::string("ffffffd6"), fz::sprintf("%x", neg32));
	int64_t const neg64 = -42;
	CPPUNIT_ASSERT_EQUAL(std::string("ffffffffffffffd6"), fz::sprintf("%x", neg64));
}
