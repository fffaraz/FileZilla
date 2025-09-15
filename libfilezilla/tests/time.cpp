#include "../lib/libfilezilla/time.hpp"
#include "../lib/libfilezilla/util.hpp"

#include <cppunit/extensions/HelperMacros.h>

#ifndef _MSC_VER
#include <unistd.h>
#endif

class TimeTest final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(TimeTest);
	CPPUNIT_TEST(testNow);
	CPPUNIT_TEST(testPreEpoch);
	CPPUNIT_TEST(testAlternateMidnight);
	CPPUNIT_TEST(testRFC822);
	CPPUNIT_TEST(testRFC3339);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void testNow();
	void testPreEpoch();

	void testAlternateMidnight();

	void testRFC822();
	void testRFC3339();
};

CPPUNIT_TEST_SUITE_REGISTRATION(TimeTest);

void TimeTest::testNow()
{
	fz::datetime const t1 = fz::datetime::now();

	fz::sleep(fz::duration::from_seconds(2));

	fz::datetime const t2 = fz::datetime::now();

	CPPUNIT_ASSERT(!t1.empty());
	CPPUNIT_ASSERT(!t2.empty());
	CPPUNIT_ASSERT(t2 > t1);

	auto const diff = t2 - t1;

	CPPUNIT_ASSERT(diff.get_seconds() >= 2);
	CPPUNIT_ASSERT(diff.get_seconds() < 4); // May fail if running on a computer for ants

	CPPUNIT_ASSERT(t1.get_time_t() > 1431333788); // The time this test was written
}

void TimeTest::testPreEpoch()
{
	fz::datetime const now = fz::datetime::now();

	fz::datetime const t1(fz::datetime::utc, 1957, 10, 4, 19, 28, 34);

	CPPUNIT_ASSERT(!t1.empty());
	CPPUNIT_ASSERT(t1 < now);

	CPPUNIT_ASSERT(t1.get_time_t() < -1);

	auto const tm1 = t1.get_tm(fz::datetime::utc);
	CPPUNIT_ASSERT_EQUAL(57, tm1.tm_year);
	CPPUNIT_ASSERT_EQUAL(9,  tm1.tm_mon);
	CPPUNIT_ASSERT_EQUAL(4,  tm1.tm_mday);
	CPPUNIT_ASSERT_EQUAL(19, tm1.tm_hour);
	CPPUNIT_ASSERT_EQUAL(28, tm1.tm_min);
	CPPUNIT_ASSERT_EQUAL(34, tm1.tm_sec);


	fz::datetime const t2(fz::datetime::utc, 1969, 12, 31, 23, 59, 59);

	CPPUNIT_ASSERT(!t2.empty());
	CPPUNIT_ASSERT(t2 > t1);
	CPPUNIT_ASSERT(t2 < now);

	auto const tm2 = t2.get_tm(fz::datetime::utc);
	CPPUNIT_ASSERT_EQUAL(69, tm2.tm_year);
	CPPUNIT_ASSERT_EQUAL(11, tm2.tm_mon);
	CPPUNIT_ASSERT_EQUAL(31, tm2.tm_mday);
	CPPUNIT_ASSERT_EQUAL(23, tm2.tm_hour);
	CPPUNIT_ASSERT_EQUAL(59, tm2.tm_min);
	CPPUNIT_ASSERT_EQUAL(59, tm2.tm_sec);
}

void TimeTest::testAlternateMidnight()
{
	fz::datetime const t1(fz::datetime::utc, 2016, 4, 13, 0, 0, 0);
	fz::datetime const t2(fz::datetime::utc, 2016, 4, 12, 24, 0, 0);
	fz::datetime const t3("2016-04-13 00:00:00", fz::datetime::utc);
	fz::datetime const t4("2016-04-12 24:00:00", fz::datetime::utc);

	CPPUNIT_ASSERT(!t1.empty());
	CPPUNIT_ASSERT(!t2.empty());
	CPPUNIT_ASSERT(!t3.empty());
	CPPUNIT_ASSERT(!t4.empty());

	CPPUNIT_ASSERT(t1 == t2);
	CPPUNIT_ASSERT(t1 == t3);
	CPPUNIT_ASSERT(t1 == t4);

	fz::datetime imbue("2016-04-12", fz::datetime::utc);
	CPPUNIT_ASSERT(imbue.imbue_time(24, 0, 0));
	CPPUNIT_ASSERT(t1 == imbue);

}

void TimeTest::testRFC822()
{
	fz::datetime const t1(fz::datetime::utc, 2020, 3, 2, 12, 35, 0);

	std::string s = t1.get_rfc822();
	CPPUNIT_ASSERT(!s.empty());

	fz::datetime t;
	CPPUNIT_ASSERT(t.set_rfc822(s));
	CPPUNIT_ASSERT(t == t1);

	std::string const offset1 = "Mon, 02 Mar 2020 13:35:00 +0100";
	std::string const offset2 = "Mon, 02 Mar 2020 07:35:00 -0500";

	CPPUNIT_ASSERT(t.set_rfc822(offset1));
	CPPUNIT_ASSERT(t == t1);
	CPPUNIT_ASSERT(t.set_rfc822(offset2));
	CPPUNIT_ASSERT(t == t1);
}

void TimeTest::testRFC3339()
{
	fz::datetime const t1(fz::datetime::utc, 1985, 4, 12, 23, 20, 50, 520);
	fz::datetime const t2(fz::datetime::utc, 1996, 12, 20, 0, 39, 57);

	std::string const s1 = "1985-04-12T23:20:50.52Z";
	std::string const s2 = "1996-12-19T16:39:57-08:00";

	fz::datetime t;
	CPPUNIT_ASSERT(t.set_rfc3339(s1));
	CPPUNIT_ASSERT(t == t1);
	CPPUNIT_ASSERT(t.set_rfc3339(s2));
	CPPUNIT_ASSERT(t == t2);
}
