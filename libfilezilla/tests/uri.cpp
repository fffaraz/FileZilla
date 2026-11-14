#include "../lib/libfilezilla/uri.hpp"

#include "test_utils.hpp"

class uri_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(uri_test);
	CPPUNIT_TEST(test_ipv6_authority);
	CPPUNIT_TEST(test_host_escaping);
	CPPUNIT_TEST_SUITE_END();

public:
	void test_ipv6_authority();
	void test_host_escaping();
};

CPPUNIT_TEST_SUITE_REGISTRATION(uri_test);

void uri_test::test_ipv6_authority()
{
	// Valid URI IPv6 hosts include brackets. Preserve these literals, including
	// their colons, when serializing the authority and the complete URI.
	for (auto const* host : {"[::1]", "[::]", "[2001:db8::1]", "[2001:0DB8:0000:0000:0000:0000:0000:0001]"}) {
		for (auto const* scheme : {"https:", ""}) {
			for (auto const* userinfo : {"", "user%40name:p%3Ass@"}) {
				auto const authority = std::string(host) + ":8443";
				auto const input = std::string(scheme) + "//" + userinfo + authority + "/path%20with%20spaces?x=a%2Fb#section";
				fz::uri uri;
				CPPUNIT_ASSERT_MESSAGE("Valid IPv6 URI must parse", uri.parse(input));
				ASSERT_EQUAL_DATA(std::string(host), uri.host_, input);
				ASSERT_EQUAL_DATA(authority, uri.get_authority(false), input);
				ASSERT_EQUAL_DATA(std::string(userinfo) + authority, uri.get_authority(true), input);
				ASSERT_EQUAL_DATA(input, uri.to_string(), input);
				ASSERT_EQUAL_DATA(input.substr(0, input.find('?')), uri.to_string(false), input);

				fz::uri reparsed;
				CPPUNIT_ASSERT_MESSAGE("Serialized IPv6 URI must parse", reparsed.parse(uri.to_string()));
				CPPUNIT_ASSERT_MESSAGE("Serialization must preserve URI components", reparsed == uri);
			}
		}
	}
}

void uri_test::test_host_escaping()
{
	// Assign host_ directly to bypass parser validation. Only valid bracketed
	// IPv6 literals bypass escaping; delimiters in other host values remain data.
	for (auto const& value : std::initializer_list<std::pair<std::string, std::string>>{
		{"", ""},
		{"example.test", "example.test"},
		{"127.0.0.1", "127.0.0.1"},
		{"example name", "example%20name"},
		{"example:name", "example%3Aname"},
		// Valid bracketed IPv6 stays literal, unlike the malformed values below.
		{"[::1]", "[::1]"},
		// Bare IPv6 text lacks URI brackets; the other two values are not IP literals.
		{"::1", "%3A%3A1"},
		{"[not an IP]", "%5Bnot%20an%20IP%5D"},
		{"[::1]/path", "%5B%3A%3A1%5D%2Fpath"}
	}) {
		fz::uri uri;
		uri.host_ = value.first;
		ASSERT_EQUAL_DATA(value.second, uri.get_authority(false), value.first);
	}
}
