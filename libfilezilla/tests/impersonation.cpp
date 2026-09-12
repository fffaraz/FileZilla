#include "../lib/libfilezilla/impersonation.hpp"

#include <cppunit/extensions/HelperMacros.h>

class impersonation_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(impersonation_test);
	CPPUNIT_TEST(test_capabilities);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_capabilities();
};

CPPUNIT_TEST_SUITE_REGISTRATION(impersonation_test);

void impersonation_test::test_capabilities()
{
	using capability = fz::impersonation_capability;
	using capability_state = fz::impersonation_capability_state;

	auto const all = fz::impersonation_token::get_capabilities({
		capability::password,
		capability::passwordless,
		capability::user_profile
	});
	for (auto capability : {capability::password, capability::passwordless, capability::user_profile}) {
		CPPUNIT_ASSERT_MESSAGE("A requested capability must be evaluated", all[capability] != capability_state::not_requested);
	}

	auto const filtered = fz::impersonation_token::get_capabilities({capability::user_profile});
	CPPUNIT_ASSERT_MESSAGE("An unrequested capability must not be evaluated", filtered[capability::password] == capability_state::not_requested);
	CPPUNIT_ASSERT_MESSAGE("An unrequested capability must not be evaluated", filtered[capability::passwordless] == capability_state::not_requested);
	CPPUNIT_ASSERT_MESSAGE("A requested capability must be evaluated", filtered[capability::user_profile] != capability_state::not_requested);
}
