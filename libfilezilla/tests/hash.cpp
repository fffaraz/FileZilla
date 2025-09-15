#include "../lib/libfilezilla/encode.hpp"
#include "../lib/libfilezilla/hash.hpp"
#include "../lib/libfilezilla/string.hpp"

#include "test_utils.hpp"

using namespace std::literals;

/*
 * This testsuite asserts the correctness of the
 * hash functions
 */

class hash_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(hash_test);
	CPPUNIT_TEST(test_simple);
	CPPUNIT_TEST(test_accumulator);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_simple();
	void test_accumulator();
};

CPPUNIT_TEST_SUITE_REGISTRATION(hash_test);

void hash_test::test_simple()
{
	CPPUNIT_ASSERT_EQUAL("9e107d9d372bb6826bd81d3542a419d6"s, fz::hex_encode<std::string>(fz::md5("The quick brown fox jumps over the lazy dog")));
}

void hash_test::test_accumulator()
{
	struct data {
		fz::hash_algorithm alg_;
		std::string_view hash_;
	};
	data d[] = {
	    {fz::hash_algorithm::md5, "3b1cb913b15718423b799c58955689eb"sv },
	    {fz::hash_algorithm::sha1, "e8a3d113c78ed954efacdf24084669f52a185f4c"sv },
	    {fz::hash_algorithm::sha256, "713b68b7a7b1d5dcd60102ae684f8497a236e819deef92ecfeef1d1289d1f29a"sv },
	    {fz::hash_algorithm::sha512, "8fbd195116d42999689ee6706e2f3dfa79de91064e8b4c7ccbf01432954272cd32fe1068911a7cf168378e9009f1fff64270f8c68966d8a6043e6ff55cfd9fd3"sv },
	};

	// Chosen to be of prime length
	auto input = "And I would hash 500 strings and I would hash 500 more just to be the man who hashes a 1000 strings. "sv;

	for (size_t i = 0; i < sizeof(d) / sizeof(data); ++i) {
		{
			fz::hash_accumulator acc(d[i].alg_);
			for (size_t j = 0; j < 1000; ++j) {
				acc.update(input);
			}
			auto const digest = fz::hex_encode<std::string>(acc.digest());
			CPPUNIT_ASSERT(digest == d[i].hash_);
		}

	}

	// Test state export/import
	{
		size_t i = 1;
		std::vector<uint8_t> state;
		for (size_t j = 0; j < 1000; ++j) {
			fz::hash_accumulator acc(d[i].alg_);
			if (!state.empty()) {
				CPPUNIT_ASSERT(acc.import_state(state));
			}
			acc.update(input);
			state = acc.export_state();
			CPPUNIT_ASSERT(!state.empty());
		}

		fz::hash_accumulator acc(d[i].alg_);
		CPPUNIT_ASSERT(acc.import_state(state));
		auto const digest = fz::hex_encode<std::string>(acc.digest());
		CPPUNIT_ASSERT(digest == d[i].hash_);
	}
}
