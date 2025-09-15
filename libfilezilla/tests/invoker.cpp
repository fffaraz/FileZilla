#include "../lib/libfilezilla/event_handler.hpp"
#include "../lib/libfilezilla/event_loop.hpp"
#include "../lib/libfilezilla/invoker.hpp"
#include "../lib/libfilezilla/time.hpp"

#include "test_utils.hpp"

#include <cppunit/extensions/HelperMacros.h>

class InvokerTest final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(InvokerTest);
	CPPUNIT_TEST(testInvoker);
	CPPUNIT_TEST(testInvokerFactory);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void testInvoker();
	void testInvokerFactory();
};

CPPUNIT_TEST_SUITE_REGISTRATION(InvokerTest);

void InvokerTest::testInvoker()
{
	fz::event_loop loop;
	fz::mutex mtx{false};
	fz::condition cond;

	int c{};
	auto f = [&]() {
		fz::scoped_lock l(mtx);
		++c;
		cond.signal(l);
	};

	std::function<void()> func = f;

	auto inv = fz::make_invoker(loop, std::move(func));

	{
		inv();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}

	{
		c = 0;
		inv();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}

	auto inv2 = fz::make_invoker(loop, std::move(f));

	{
		c = 0;
		inv2();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}

	{
		c = 0;
		inv2();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}
}

void InvokerTest::testInvokerFactory()
{

	fz::event_loop loop;
	fz::mutex mtx{false};
	fz::condition cond;

	fz::invoker_factory factory = get_invoker_factory(loop);

	int c{};
	auto f = [&]() {
		fz::scoped_lock l(mtx);
		++c;
		cond.signal(l);
	};

	std::function<void()> func = f;

	auto inv = fz::make_invoker(factory, std::move(func));

	{
		inv();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}

	{
		c = 0;
		inv();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}

	auto inv2 = fz::make_invoker(factory, std::move(f));

	{
		c = 0;
		inv2();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}

	{
		c = 0;
		inv2();
		fz::scoped_lock l(mtx);
		CPPUNIT_ASSERT(cond.wait(l, fz::duration::from_seconds(1)));
		ASSERT_EQUAL(1, c);
	}
}
