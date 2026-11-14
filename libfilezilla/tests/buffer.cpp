#include "../lib/libfilezilla/buffer.hpp"
#include "../lib/libfilezilla/nonowning_buffer.hpp"

#include "test_utils.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <type_traits>
#include <string.h>

static_assert(std::is_convertible_v<fz::buffer&, fz::buffer_access_interface&>);
static_assert(std::is_convertible_v<fz::secure_buffer&, fz::buffer_access_interface&>);
static_assert(std::is_convertible_v<fz::nonowning_buffer&, fz::buffer_access_interface&>);
static_assert(std::is_convertible_v<fz::buffer&, fz::buffer_interface&>);
static_assert(std::is_convertible_v<fz::secure_buffer&, fz::buffer_interface&>);
static_assert(!std::is_convertible_v<fz::nonowning_buffer&, fz::buffer_interface&>);
static_assert(!std::is_convertible_v<fz::buffer_access_interface&, fz::buffer&>);
static_assert(!std::is_convertible_v<fz::buffer_access_interface&, fz::secure_buffer&>);
static_assert(!std::is_constructible_v<fz::buffer, fz::secure_buffer const&>);
static_assert(!std::is_constructible_v<fz::secure_buffer, fz::buffer const&>);
static_assert(!std::is_assignable_v<fz::buffer&, fz::secure_buffer const&>);
static_assert(!std::is_assignable_v<fz::secure_buffer&, fz::buffer const&>);
static_assert(!std::is_constructible_v<fz::buffer, fz::nonowning_buffer const&>);
static_assert(!std::is_constructible_v<fz::secure_buffer, fz::nonowning_buffer const&>);
static_assert(!std::is_assignable_v<fz::buffer_access_interface&, fz::buffer_access_interface const&>);
static_assert(std::is_final_v<fz::buffer> && std::is_final_v<fz::secure_buffer>);
static_assert(std::has_virtual_destructor_v<fz::buffer_access_interface>);
// Internal buffer operations must not regain virtual dispatch through inheritance.
static_assert(!std::is_polymorphic_v<fz::basic_buffer<fz::buffer_wipe_policy::normal>>);
static_assert(!std::is_polymorphic_v<fz::basic_buffer<fz::buffer_wipe_policy::wipe_on_release>>);
static_assert(!std::is_base_of_v<fz::basic_buffer<fz::buffer_wipe_policy::normal>, fz::buffer>);
static_assert(!std::is_base_of_v<fz::basic_buffer<fz::buffer_wipe_policy::wipe_on_release>, fz::secure_buffer>);

class buffer_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(buffer_test);
	CPPUNIT_TEST(test_simple);
	CPPUNIT_TEST(test_append);
	CPPUNIT_TEST(test_get);
	CPPUNIT_TEST(test_interface);
	CPPUNIT_TEST(test_interface_wiping);
	CPPUNIT_TEST(test_nonowning_interface);
	CPPUNIT_TEST(test_forwarding_api);
	CPPUNIT_TEST(test_forwarding_member_pointers);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_simple();
	void test_append();
	void test_get();
	void test_interface();
	void test_interface_wiping();
	void test_nonowning_interface();
	void test_forwarding_api();
	void test_forwarding_member_pointers();
};

CPPUNIT_TEST_SUITE_REGISTRATION(buffer_test);

void buffer_test::test_forwarding_member_pointers()
{
	auto exercise = [](auto& buffer) {
		using buffer_type = std::decay_t<decltype(buffer)>;

		// Volatile member pointers keep optimization from hiding missing DLL symbols.
		void (buffer_type::*volatile append)(unsigned char) = &buffer_type::append;
		size_t (buffer_type::*volatile size)() const = &buffer_type::size;

		(buffer.*append)(static_cast<unsigned char>('a'));

		CPPUNIT_ASSERT_EQUAL_MESSAGE("Forwarders must remain callable through member pointers", size_t(1), (buffer.*size)());
		CPPUNIT_ASSERT_EQUAL_MESSAGE("The forwarded append must preserve its byte", static_cast<unsigned char>('a'), buffer[0]);
	};

	fz::buffer buffer;
	exercise(buffer);

	fz::secure_buffer secure;
	exercise(secure);
}

void buffer_test::test_forwarding_api()
{
	auto exercise = [](auto& buffer) {
		using buffer_type = std::decay_t<decltype(buffer)>;
		buffer = std::string_view("a");
		buffer.append(static_cast<unsigned char>('b'));
		buffer.push_back('c');
		buffer.append(2, 'd');
		buffer += static_cast<unsigned char>('e');
		buffer += std::string_view("f");
		std::vector<uint8_t> bytes{'g', 'h'};
		buffer.append(bytes);
		buffer += bytes;
		buffer.append(std::basic_string_view<uint8_t>(bytes.data(), bytes.size()));
		buffer_type suffix(std::string_view("i"));
		buffer.append(suffix);
		buffer += suffix;

		CPPUNIT_ASSERT_MESSAGE("Forwarded append overloads and operators must preserve data", buffer == "abcddefghghghii");
		CPPUNIT_ASSERT_MESSAGE("Forwarded comparison must preserve equality semantics", buffer == buffer && !(buffer != buffer) && buffer != "different");
		CPPUNIT_ASSERT_MESSAGE("Forwarded views must expose the active bytes", buffer.to_view() == std::string_view("abcddefghghghii") && bool(buffer));
		auto const& read_only = buffer;
		CPPUNIT_ASSERT_MESSAGE("Forwarded pointer access must refer to the same storage", buffer.data() == buffer.get() && read_only.data() == read_only.get());
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Const indexed access must read the first byte", static_cast<unsigned char>('a'), read_only[0]);

		buffer_type copy;
		copy = buffer;
		copy[0] = 'z';
		CPPUNIT_ASSERT_MESSAGE("Copy assignment must own independent storage", buffer[0] == 'a' && copy[0] == 'z');
		buffer_type moved;
		moved = std::move(copy);
		CPPUNIT_ASSERT_MESSAGE("Move assignment must transfer ownership", copy.empty() && !bool(copy) && moved[0] == 'z');

		buffer.clear();
		memcpy(buffer.get(3), "end", 3);
		buffer.add(-1);
		CPPUNIT_ASSERT_MESSAGE("The signed add overload must ignore negative amounts", buffer.empty());
		buffer.add(3);
		CPPUNIT_ASSERT_MESSAGE("The signed add overload must commit positive amounts", buffer == "end");
	};

	fz::buffer ordinary;
	fz::secure_buffer secure;
	exercise(ordinary);
	exercise(secure);
}

void buffer_test::test_interface()
{
	fz::buffer ordinary;
	fz::secure_buffer secure;
	fz::buffer_interface* buffers[] = {&ordinary, &secure};
	for (auto buffer : buffers) {
		buffer->reserve(32);
		std::string expected(buffer->capacity(), 'x');
		memcpy(buffer->get(expected.size()), expected.data(), expected.size());
		buffer->add(expected.size());

		buffer->consume(3);
		expected.erase(0, 3);
		buffer->append(buffer->get(), buffer->size());
		expected += expected;
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Interface access must preserve appended contents", expected,
			std::string(reinterpret_cast<char const*>(buffer->get()), buffer->size()));

		buffer->reserve(buffer->capacity() + 1);
		buffer->resize(expected.size() + 3);
		expected.append(3, '\0');
		fz::buffer_access_interface const& read_only = *buffer;
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Reserve and resize must preserve contents and zero new bytes", expected,
			std::string(reinterpret_cast<char const*>(read_only.get()), read_only.size()));

		buffer->clear_and_free();
		CPPUNIT_ASSERT_MESSAGE("Clearing through the interface must release storage", !buffer->size() && !buffer->capacity());
		buffer->append(reinterpret_cast<unsigned char const*>("again"), 5);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("A released buffer must remain reusable", size_t(5), buffer->size());
	}

	fz::buffer ordinary_copy(ordinary);
	fz::buffer ordinary_moved(std::move(ordinary_copy));
	fz::secure_buffer secure_copy(secure);
	fz::secure_buffer secure_moved(std::move(secure_copy));
	CPPUNIT_ASSERT_MESSAGE("Copying and moving ordinary buffers must still work", ordinary_moved == "again" && ordinary_copy.empty());
	CPPUNIT_ASSERT_MESSAGE("Copying and moving secure buffers must still work", secure_moved == "again" && secure_copy.empty());

	std::unique_ptr<fz::buffer_access_interface> owned = std::make_unique<fz::secure_buffer>("secret");
	owned.reset();
}

void buffer_test::test_interface_wiping()
{
	fz::secure_buffer secure;
	fz::buffer_access_interface& buffer = secure;
	secure.reserve(32);
	auto capacity = buffer.capacity();
	auto storage = buffer.get(capacity);
	std::fill_n(storage, capacity, 's');
	buffer.add(capacity);
	buffer.consume(3);
	buffer.resize(5);

	secure.wipe_unused();
	CPPUNIT_ASSERT_MESSAGE("Wiping unused storage must erase consumed bytes", std::all_of(storage, storage + 3, [](auto byte) { return byte == 0; }));
	CPPUNIT_ASSERT_MESSAGE("Wiping unused storage must preserve active bytes", secure == "sssss");
	CPPUNIT_ASSERT_MESSAGE("Wiping unused storage must erase the unused tail", std::all_of(storage + 8, storage + capacity, [](auto byte) { return byte == 0; }));

	// The allocation remains owned after clear, so checking its bytes is valid.
	buffer.clear();
	CPPUNIT_ASSERT_MESSAGE("Clearing a secure buffer through the interface must wipe its allocation", std::all_of(storage, storage + capacity, [](auto byte) { return byte == 0; }));
	CPPUNIT_ASSERT_MESSAGE("Clearing must retain reusable capacity", !buffer.size() && buffer.capacity() == capacity);

	buffer.append(reinterpret_cast<unsigned char const*>("secret"), 6);
	secure.wipe();
	CPPUNIT_ASSERT_MESSAGE("Explicit wiping must preserve size while zeroing data", buffer.size() == 6 && std::all_of(storage, storage + capacity, [](auto byte) { return byte == 0; }));
}

void buffer_test::test_nonowning_interface()
{
	std::array<uint8_t, 16> storage{};
	fz::nonowning_buffer fixed(storage.data(), storage.size());
	fz::buffer_access_interface& buffer = fixed;
	buffer.append(reinterpret_cast<unsigned char const*>("abcdef"), 6);
	buffer.consume(4);

	std::string const suffix(12, 'x');
	memcpy(buffer.get(suffix.size()), suffix.data(), suffix.size());
	buffer.add(suffix.size());
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Fixed storage must compact without changing its capacity", storage.size(), buffer.capacity());
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Compaction must preserve unconsumed data", std::string("ef") + suffix, std::string(fixed.to_view()));

	auto copy = fixed;
	fz::nonowning_buffer assigned;
	assigned = fixed;
	auto moved = std::move(copy);
	assigned = std::move(moved);
	assigned.get()[0] = 'z';
	CPPUNIT_ASSERT_MESSAGE("Copies and moves of nonowning buffers must remain shallow", fixed[0] == 'z');
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Shallow copies must keep their own position", fixed.size(), assigned.size());

	buffer.clear();
	storage.fill(0x5a);
	buffer.resize(8);
	CPPUNIT_ASSERT_MESSAGE("Growing a nonowning buffer must not initialize caller-owned bytes", std::all_of(storage.begin(), storage.end(), [](auto byte) { return byte == 0x5a; }));
	buffer.clear();
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Clearing fixed storage must retain its capacity", storage.size(), buffer.capacity());

	fixed.reset();
	CPPUNIT_ASSERT_MESSAGE("Reset must detach rather than release caller-owned storage", !buffer.size() && !buffer.capacity());
	CPPUNIT_ASSERT_MESSAGE("Detached buffers must expose no writable storage", buffer.get() == nullptr && buffer.get(0) == nullptr);
}

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
