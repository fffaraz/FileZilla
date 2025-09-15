#include "../lib/libfilezilla/xml.hpp"

#include "test_utils.hpp"

using namespace std::literals;

class xml_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(xml_test);
	CPPUNIT_TEST(test_simple);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_simple();
};

CPPUNIT_TEST_SUITE_REGISTRATION(xml_test);

namespace {
void do_test(std::string_view in)
{
	fz::xml::parser parser;
	fz::xml::namespace_parser ns_parser;
	CPPUNIT_ASSERT(parser.parse(in));
	CPPUNIT_ASSERT(ns_parser.parse(in));
	CPPUNIT_ASSERT(parser.finalize());
	CPPUNIT_ASSERT(ns_parser.finalize());

	fz::xml::parser parser2;
	fz::xml::namespace_parser ns_parser2;
	for (size_t i = 0; i < in.size(); ++i) {
		CPPUNIT_ASSERT(parser2.parse(in.substr(i, 1)));
		CPPUNIT_ASSERT(ns_parser2.parse(in.substr(i, 1)));
	}
	CPPUNIT_ASSERT(parser2.finalize());
	CPPUNIT_ASSERT(ns_parser2.finalize());
}
}
void xml_test::test_simple()
{
	// Test this simple XML in all supported encodings, with and without BOM
	auto utf8 = "<?xml version=\"1.0\" ?><!DOCTYPE nonsense PUBLIC \"makes\" 'nosense'><?PI blabla test?><foo attr = \"baz&lt;\"><![CDATA[]]><!--foo--><empty  foo   = 'bar\"'/><otherempty /><?INNERPI?>bar &#xe4; foo<foo ></foo></foo > <?PI2?>"sv;

	std::string utf16be, utf16le;
	for (auto const& c : utf8) {
		utf16be.append(1, 0);
		utf16be.append(1, c);

		utf16le.append(1, c);
		utf16le.append(1, 0);
	}

	std::string utf8bom = "\xef" "\xbb" "\xbf";
	utf8bom += utf8;

	std::string utf16bebom = "\xfe" "\xff";
	utf16bebom += utf16be;

	std::string utf16lebom = "\xff" "\xfe";
	utf16lebom += utf16le;

	do_test(utf8);
	do_test(utf16be);
	do_test(utf16le);
	do_test(utf8bom);
	do_test(utf16bebom);
	do_test(utf16lebom);
}
