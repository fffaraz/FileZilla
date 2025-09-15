#include "../lib/libfilezilla/encode.hpp"
#include "../lib/libfilezilla/string.hpp"

#include "test_utils.hpp"

using namespace std::literals;

/*
 * This testsuite asserts the correctness of the
 * string functions
 */

class string_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(string_test);
	CPPUNIT_TEST(test_conversion);
	CPPUNIT_TEST(test_conversion2);
	CPPUNIT_TEST(test_conversion_utf8);
	CPPUNIT_TEST(test_conversion_null);
	CPPUNIT_TEST(test_base64);
	CPPUNIT_TEST(test_trim);
	CPPUNIT_TEST(test_strtok);
	CPPUNIT_TEST(test_startsendswith);
	CPPUNIT_TEST(test_normalize_hyphens);
	CPPUNIT_TEST(test_is_valid_utf8);
	CPPUNIT_TEST(test_utf16_to_utf8_append);
	CPPUNIT_TEST(test_to_integral);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_conversion();
	void test_conversion2();
	void test_conversion_utf8();
	void test_conversion_null();
	void test_base64();
	void test_trim();
	void test_strtok();
	void test_startsendswith();
	void test_normalize_hyphens();
	void test_is_valid_utf8();
	void test_utf16_to_utf8_append();
	void test_to_integral();
};

CPPUNIT_TEST_SUITE_REGISTRATION(string_test);

void string_test::test_conversion()
{
	std::string const s("hello world!");

	std::wstring const w = fz::to_wstring(s);

	CPPUNIT_ASSERT_EQUAL(s.size(), w.size());

	for (size_t i = 0; i < s.size(); ++i) {
		CPPUNIT_ASSERT_EQUAL(static_cast<wchar_t>(s[i]), w[i]);
	}


	std::string const s2 = fz::to_string(s);

	CPPUNIT_ASSERT_EQUAL(s, s2);
}

void string_test::test_conversion2()
{
	wchar_t const p[] = { 'M', 'o', 't', 0xf6, 'r', 'h', 'e', 'a', 'd', 0 };
	std::wstring const w(p);

	std::string const s = fz::to_string(w);

	CPPUNIT_ASSERT(s.size() >= w.size());

	std::wstring const w2 = fz::to_wstring(s);

	ASSERT_EQUAL(w, w2);
}

void string_test::test_conversion_utf8()
{
	wchar_t const p[] = { 'M', 'o', 't', 0xf6, 'r', 'h', 'e', 'a', 'd', 0 };
	unsigned char const p_utf8[] = { 'M', 'o', 't', 0xc3, 0xb6, 'r', 'h', 'e', 'a', 'd', 0 };

	std::wstring const w(p);
	std::string const u(reinterpret_cast<char const*>(p_utf8));

	std::string const s = fz::to_utf8(w);

	CPPUNIT_ASSERT(s.size() >= w.size());

	ASSERT_EQUAL(s, u);

	std::wstring const w2 = fz::to_wstring_from_utf8(s);

	ASSERT_EQUAL(w, w2);
}

void string_test::test_conversion_null()
{
	wchar_t const w[7] = {'A', 0, 'B', 0, 0, 'C', 0};
	unsigned char const n[7] = {'A', 0, 'B', 0, 0, 'C', 0};
	{
		std::wstring const in(w, w + 7);

		std::string const ref(n, n + 7);
		std::string const out = fz::to_string(in);
		CPPUNIT_ASSERT(out.size() >= in.size());
		ASSERT_EQUAL(ref, out);

		std::wstring const out2 = fz::to_wstring(out);
		CPPUNIT_ASSERT(out2.size() <= out.size());
		ASSERT_EQUAL(in, out2);
	}
	{
		std::wstring const in(w, w + 7);

		std::string const ref(n, n + 7);
		std::string const out = fz::to_utf8(in);
		CPPUNIT_ASSERT(out.size() >= in.size());
		ASSERT_EQUAL(ref, out);

		std::wstring const out2 = fz::to_wstring_from_utf8(out);
		CPPUNIT_ASSERT(out2.size() <= out.size());
		ASSERT_EQUAL(in, out2);
	}
}

void string_test::test_base64()
{
	CPPUNIT_ASSERT_EQUAL(std::string(""),         fz::base64_encode(""));
	CPPUNIT_ASSERT_EQUAL(std::string("Zg=="),     fz::base64_encode("f"));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm8="),     fz::base64_encode("fo"));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm9v"),     fz::base64_encode("foo"));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm9vbA=="), fz::base64_encode("fool"));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm9vbHM="), fz::base64_encode("fools"));

	CPPUNIT_ASSERT_EQUAL(std::string("Zg"),     fz::base64_encode("f", fz::base64_type::standard, false));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm8"),     fz::base64_encode("fo", fz::base64_type::standard, false));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm9vbA"), fz::base64_encode("fool", fz::base64_type::standard, false));
	CPPUNIT_ASSERT_EQUAL(std::string("Zm9vbHM"), fz::base64_encode("fools", fz::base64_type::standard, false));

	CPPUNIT_ASSERT_EQUAL(std::string("AAECA/3+/w=="), fz::base64_encode(std::string({0, 1, 2, 3, '\xfd', '\xfe', '\xff'})));

	CPPUNIT_ASSERT_EQUAL(std::string("AAECA_3-_w=="), fz::base64_encode(std::string({0, 1, 2, 3, '\xfd', '\xfe', '\xff'}), fz::base64_type::url));

	// decode
	CPPUNIT_ASSERT_EQUAL(std::string(""),      fz::base64_decode_s(""));
	CPPUNIT_ASSERT_EQUAL(std::string("f"),     fz::base64_decode_s("Zg=="));
	CPPUNIT_ASSERT_EQUAL(std::string("fo"),    fz::base64_decode_s("Zm8="));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"),   fz::base64_decode_s("Zm9v"));
	CPPUNIT_ASSERT_EQUAL(std::string("fool"),  fz::base64_decode_s("Zm9vbA=="));
	CPPUNIT_ASSERT_EQUAL(std::string("fools"), fz::base64_decode_s("Zm9vbHM="));

	CPPUNIT_ASSERT_EQUAL(std::string("f"),     fz::base64_decode_s("Zg"));
	CPPUNIT_ASSERT_EQUAL(std::string("fo"),    fz::base64_decode_s("Zm8"));
	CPPUNIT_ASSERT_EQUAL(std::string("fool"),  fz::base64_decode_s("Zm9vbA"));
	CPPUNIT_ASSERT_EQUAL(std::string("fools"), fz::base64_decode_s("Zm9vbHM"));

	CPPUNIT_ASSERT_EQUAL(std::string({0, 1, 2, 3, '\xfd', '\xfe', '\xff'}), fz::base64_decode_s("AAECA/3+/w=="));
	CPPUNIT_ASSERT_EQUAL(std::string({0, 1, 2, 3, '\xfd', '\xfe', '\xff'}), fz::base64_decode_s("AAECA_3-_w"));

	// with whitespace
	CPPUNIT_ASSERT_EQUAL(std::string("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."),
						 fz::base64_decode_s(" TG9yZW0gaXBzdW0gZG9sb3Igc2l0I\nGFtZXQsIGNvbnNlY3Rld\rHVyIGFkaXBpc2NpbmcgZWxpd \tCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEu "));

	// invalid
	CPPUNIT_ASSERT_EQUAL(std::string(""), fz::base64_decode_s("Zm9vbHM=="));
	CPPUNIT_ASSERT_EQUAL(std::string(""), fz::base64_decode_s("Zm9vb==="));
	CPPUNIT_ASSERT_EQUAL(std::string(""), fz::base64_decode_s("Zm9vbHM=Zg=="));
}

void string_test::test_trim()
{
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string("foo")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string(" foo")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string("\t foo")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string("foo ")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string("foo \n")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string(" foo\n")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string("\t foo\r")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string(" foo  ")));
	CPPUNIT_ASSERT_EQUAL(std::string("foo"), fz::trimmed(std::string("\t foo  ")));
	CPPUNIT_ASSERT_EQUAL(std::string(""), fz::trimmed(std::string(" \t\r \n \t")));
}

void string_test::test_strtok()
{
	auto tokens = fz::strtok("hello world", ' ');
	CPPUNIT_ASSERT_EQUAL(size_t(2), tokens.size());
	CPPUNIT_ASSERT_EQUAL(std::string("hello"), tokens[0]);
	CPPUNIT_ASSERT_EQUAL(std::string("world"), tokens[1]);

	tokens = fz::strtok(" hello   world  ", " eo");
	CPPUNIT_ASSERT_EQUAL(size_t(4), tokens.size());
	CPPUNIT_ASSERT_EQUAL(std::string("h"), tokens[0]);
	CPPUNIT_ASSERT_EQUAL(std::string("ll"), tokens[1]);
	CPPUNIT_ASSERT_EQUAL(std::string("w"), tokens[2]);
	CPPUNIT_ASSERT_EQUAL(std::string("rld"), tokens[3]);

	tokens = fz::strtok("a b c", ' ');
	CPPUNIT_ASSERT_EQUAL(size_t(3), tokens.size());
	CPPUNIT_ASSERT_EQUAL(std::string("a"), tokens[0]);
	CPPUNIT_ASSERT_EQUAL(std::string("b"), tokens[1]);
	CPPUNIT_ASSERT_EQUAL(std::string("c"), tokens[2]);

	tokens = fz::strtok("a b  c  d   ", ' ', false);
	CPPUNIT_ASSERT_EQUAL(size_t(8), tokens.size());
	CPPUNIT_ASSERT_EQUAL(std::string("a"), tokens[0]);
	CPPUNIT_ASSERT_EQUAL(std::string("b"), tokens[1]);
	CPPUNIT_ASSERT_EQUAL(std::string(""), tokens[2]);
	CPPUNIT_ASSERT_EQUAL(std::string("c"), tokens[3]);
	CPPUNIT_ASSERT_EQUAL(std::string(""), tokens[4]);
	CPPUNIT_ASSERT_EQUAL(std::string("d"), tokens[5]);
	CPPUNIT_ASSERT_EQUAL(std::string(""), tokens[6]);
	CPPUNIT_ASSERT_EQUAL(std::string(""), tokens[7]);
}

void string_test::test_startsendswith()
{
	CPPUNIT_ASSERT_EQUAL(false, fz::starts_with(std::string("hello"), std::string("world")));
	CPPUNIT_ASSERT_EQUAL(true, fz::starts_with(std::string("hello"), std::string("hell")));
	CPPUNIT_ASSERT_EQUAL(false, fz::starts_with(std::string("hell"), std::string("hello")));
	CPPUNIT_ASSERT_EQUAL(false, fz::starts_with(std::string("hello"), std::string("HELL")));

	CPPUNIT_ASSERT_EQUAL(false, fz::starts_with<true>(std::string("hello"), std::string("world")));
	CPPUNIT_ASSERT_EQUAL(true, fz::starts_with<true>(std::string("hello"), std::string("hell")));
	CPPUNIT_ASSERT_EQUAL(false, fz::starts_with<true>(std::string("hell"), std::string("hello")));
	CPPUNIT_ASSERT_EQUAL(true, fz::starts_with<true>(std::string("hello"), std::string("HELL")));

	CPPUNIT_ASSERT_EQUAL(false, fz::ends_with(std::string("hello"), std::string("world")));
	CPPUNIT_ASSERT_EQUAL(true, fz::ends_with(std::string("hello"), std::string("ello")));
	CPPUNIT_ASSERT_EQUAL(false, fz::ends_with(std::string("ello"), std::string("HELLO")));
	CPPUNIT_ASSERT_EQUAL(false, fz::ends_with(std::string("hello"), std::string("ELLO")));

	CPPUNIT_ASSERT_EQUAL(false, fz::ends_with<true>(std::string("hello"), std::string("world")));
	CPPUNIT_ASSERT_EQUAL(true, fz::ends_with<true>(std::string("hello"), std::string("ello")));
	CPPUNIT_ASSERT_EQUAL(false, fz::ends_with<true>(std::string("ello"), std::string("HELLO")));
	CPPUNIT_ASSERT_EQUAL(true, fz::ends_with<true>(std::string("hello"), std::string("ELLO")));
}

void string_test::test_normalize_hyphens()
{
	CPPUNIT_ASSERT_EQUAL(std::string("--------"), fz::normalize_hyphens(fz::percent_decode_s("-" "%e2%80%90" "%e2%80%91" "%e2%80%92" "%e2%80%93" "%e2%80%94" "%e2%80%95" "%e2%88%92")));
	ASSERT_EQUAL(std::wstring(L"--------"), fz::normalize_hyphens(fz::to_wstring_from_utf8(fz::percent_decode_s("-" "%e2%80%90" "%e2%80%91" "%e2%80%92" "%e2%80%93" "%e2%80%94" "%e2%80%95" "%e2%88%92"))));
}

void string_test::test_is_valid_utf8()
{
	auto const utf8 = "Das bl\xc3\xb6" "de SCHEI\xe1\xba\x9e" "EMOJI \xf0\x9f\x92\xa9, ein Haufen Mist."sv;
	size_t state{};
	CPPUNIT_ASSERT(fz::is_valid_utf8(utf8, state));
	CPPUNIT_ASSERT_EQUAL(size_t(0), state);

	for (size_t i = 0; i < utf8.size(); ++i) {
		CPPUNIT_ASSERT(fz::is_valid_utf8(utf8.substr(i, 1), state));
	}
	CPPUNIT_ASSERT_EQUAL(size_t(0), state);

	auto const valid1 = "\xed\x9f\xbf"sv; // Technically undefined, but valid. Just before surrogates
	auto const valid2 = "\xee\x80\x80"sv; // Private use area. Just after surrogates
	CPPUNIT_ASSERT(fz::is_valid_utf8(valid1));
	CPPUNIT_ASSERT(fz::is_valid_utf8(valid2));

	auto const invalid1 = "\xc3\xc3"sv; // Two starting bytes
	auto const invalid2 = "\xed\xa0\x80"sv; // Surrogate
	auto const invalid3 = "\xed\xbf\xbf"sv; // Surrogate
	CPPUNIT_ASSERT(!fz::is_valid_utf8(invalid1));
	CPPUNIT_ASSERT(!fz::is_valid_utf8(invalid2));
	CPPUNIT_ASSERT(!fz::is_valid_utf8(invalid3));
}

namespace {
void do_test_utf16_to_utf8_append(std::string_view be, std::string_view expected)
{
	CPPUNIT_ASSERT(!(be.size() % 2));
	std::string le;
	le.resize(be.size());
	for (size_t i = 0; i < be.size(); i += 2) {
		le[i] = be[i+1];
		le[i+1] = be[i];
	}

	std::string out;
	uint32_t state{};
	CPPUNIT_ASSERT(fz::utf16be_to_utf8_append(out, be, state));
	CPPUNIT_ASSERT_EQUAL(uint32_t(0), state);
	CPPUNIT_ASSERT(expected == out);
	out.clear();
	CPPUNIT_ASSERT(fz::utf16le_to_utf8_append(out, le, state));
	CPPUNIT_ASSERT_EQUAL(uint32_t(0), state);
	CPPUNIT_ASSERT(expected == out);
	out.clear();

	for (size_t i = 0; i < be.size(); ++i) {
		CPPUNIT_ASSERT(fz::utf16be_to_utf8_append(out, be.substr(i, 1), state));
	}
	CPPUNIT_ASSERT_EQUAL(uint32_t(0), state);
	CPPUNIT_ASSERT(expected == out);
	out.clear();
	for (size_t i = 0; i < le.size(); ++i) {
		CPPUNIT_ASSERT(fz::utf16le_to_utf8_append(out, le.substr(i, 1), state));
	}
	CPPUNIT_ASSERT_EQUAL(uint32_t(0), state);
	CPPUNIT_ASSERT(expected == out);
	out.clear();
}
}

void string_test::test_utf16_to_utf8_append()
{
	// Big-endian
	auto const poop = "\xd8\x3d\xdc\xa9"sv;
	auto const cheese = "\0K\0\xe4\0s\0e"sv;

	auto const poop_utf8 = "\xf0\x9f\x92\xa9"sv;
	auto const cheese_utf8 = "K\xc3\xa4se"sv;
	do_test_utf16_to_utf8_append(poop, poop_utf8);
	do_test_utf16_to_utf8_append(cheese, cheese_utf8);

	{
		std::string out;
		uint32_t state{};
		CPPUNIT_ASSERT(fz::utf16be_to_utf8_append(out, poop.substr(0, 2), state));
		CPPUNIT_ASSERT(state != 0);
		CPPUNIT_ASSERT(!fz::utf16be_to_utf8_append(out, cheese.substr(0, 2), state));
		state = 0;
		CPPUNIT_ASSERT(!fz::utf16be_to_utf8_append(out, poop.substr(2), state));
	}
}

void string_test::test_to_integral()
{
	short v = std::numeric_limits<short>::min();
	for (size_t i = 0; i < 65536; ++i, ++v) {
		// signed
		auto s = fz::to_string(v);
		auto v2 = fz::to_integral_o<short>(s);
		CPPUNIT_ASSERT(v2);
		CPPUNIT_ASSERT(v == v2);

		// unsigned
		s = fz::to_string(i);
		auto v3 = fz::to_integral_o<unsigned short>(s);
		CPPUNIT_ASSERT(v3);
		CPPUNIT_ASSERT(i == v3);
	}
	CPPUNIT_ASSERT(!fz::to_integral_o<short>("32768"sv));
	CPPUNIT_ASSERT(!fz::to_integral_o<short>("-32769"sv));
	CPPUNIT_ASSERT(!fz::to_integral_o<unsigned short>("-1"sv));
	CPPUNIT_ASSERT(!fz::to_integral_o<unsigned short>("65536"sv));
}

