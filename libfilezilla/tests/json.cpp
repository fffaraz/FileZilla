#include "../lib/libfilezilla/json.hpp"

#include "test_utils.hpp"

class json_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(json_test);
	CPPUNIT_TEST(test_surrogate_pair);
	CPPUNIT_TEST(test_subscript);
	CPPUNIT_TEST(test_number);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_surrogate_pair();
	void test_subscript();
	void test_number();
};

CPPUNIT_TEST_SUITE_REGISTRATION(json_test);

void json_test::test_surrogate_pair()
{
	auto j = fz::json::parse("\"\\ud83d\\ude01\"");
	CPPUNIT_ASSERT(j);
	auto const& v = j.string_value();
	CPPUNIT_ASSERT(v.size() == 4);
	auto u = reinterpret_cast<unsigned char const*>(v.c_str()); // as char may be signed
	CPPUNIT_ASSERT(u[0] == 0xf0);
	CPPUNIT_ASSERT(u[1] == 0x9f);
	CPPUNIT_ASSERT(u[2] == 0x98);
	CPPUNIT_ASSERT(u[3] == 0x81);
}

void json_test::test_subscript()
{
	fz::json jo;
	jo["foo"] = "bar";
	CPPUNIT_ASSERT(jo.type() == fz::json_type::object);

	fz::json ja;
	ja[0] = "bar";
	CPPUNIT_ASSERT(ja.type() == fz::json_type::array);
}

void json_test::test_number()
{
	{
		auto j = fz::json::parse("[ -128, -129, 127, 128 ]");
		CPPUNIT_ASSERT(j);
		CPPUNIT_ASSERT_EQUAL(int8_t(-128), j[0].number_value<int8_t>());
		CPPUNIT_ASSERT(!j[1].number_value_o<int8_t>());
		CPPUNIT_ASSERT_EQUAL(int16_t(-129), j[1].number_value<int16_t>());
		CPPUNIT_ASSERT_EQUAL(int8_t(127),  j[2].number_value<int8_t>());
		CPPUNIT_ASSERT(!j[3].number_value_o<int8_t>());
		CPPUNIT_ASSERT_EQUAL(int16_t(128), j[3].number_value<int16_t>());
	}

	{
		auto j = fz::json::parse("[ 255, 256 ]");
		CPPUNIT_ASSERT_EQUAL(uint8_t(255), j[0].number_value<uint8_t>());
		CPPUNIT_ASSERT(!j[1].number_value_o<uint8_t>());
	}

	{
		// Just simple stuff. Note that rounding errors are possible even if the notation would allow for an exact int, as internally double is used.
		auto j = fz::json::parse("[ 2E3, 2.2E3, 250E-1, 1E19, 1E20 ]");
		CPPUNIT_ASSERT_EQUAL(2000, j[0].number_value<int>());
		CPPUNIT_ASSERT_EQUAL(2200, j[1].number_value<int>());
		CPPUNIT_ASSERT_EQUAL(25, j[2].number_value<int>());
		CPPUNIT_ASSERT_EQUAL(uint64_t(10000000000000000000ull), j[3].number_value<uint64_t>());
		CPPUNIT_ASSERT(!j[4].number_value_o<uint64_t>());
	}
}
