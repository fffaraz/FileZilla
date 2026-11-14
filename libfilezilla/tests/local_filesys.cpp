#include "../lib/libfilezilla/buffer.hpp"
#include "../lib/libfilezilla/encode.hpp"
#include "../lib/libfilezilla/local_filesys.hpp"
#include "../lib/libfilezilla/recursive_remove.hpp"
#include "../lib/libfilezilla/util.hpp"

#ifdef HAVE_CONFIG_H
#include "config.hpp"
#endif

#include <cppunit/extensions/HelperMacros.h>

#include <algorithm>
#include <cstdlib>
#include <string_view>
#include <thread>

#ifdef FZ_WINDOWS
#include "../lib/libfilezilla/glue/dll.hpp"
#else
#include <errno.h>
#endif

#ifdef __linux__
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
// Writes at the current position. Failure can leave partially written data.
static fz::rwresult write_file(fz::file & f, std::string_view data)
{
	size_t const size = data.size();
	while (!data.empty()) {
		auto const written = f.write2(data.data(), std::min(data.size(), size_t(1024 * 128)));
		if (!written) {
			return written;
		}

		if (!written.value_) {
			return fz::rwresult{fz::rwresult::other, 0};
		}

		data.remove_prefix(written.value_);
	}

	return fz::rwresult{size};
}

static fz::result write_file(fz::native_string const& name, std::string_view data,
	fz::file::creation_flags flags)
{
	fz::file f;
	auto const res = f.open(name, fz::file::writing, flags);
	if (!res) {
		return res;
	}

	auto const written = write_file(f, data);
	if (written) {
		return {fz::result::ok};
	}

	switch (written.error_) {
	case fz::rwresult::invalid:
		return {fz::result::invalid, written.raw_};
	case fz::rwresult::nospace:
		return {fz::result::nospace, written.raw_};
	default:
		return {fz::result::other, written.raw_};
	}
}
}

class local_filesys_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(local_filesys_test);
	CPPUNIT_TEST(test_rename_wrapper);
	CPPUNIT_TEST(test_rename_no_replace);
#if defined(FZ_WINDOWS) || defined(HAVE_RENAMEAT2_NOREPLACE) || defined(FZ_MAC)
	CPPUNIT_TEST(test_competing_renames);
#endif
	CPPUNIT_TEST(test_write_file);
	CPPUNIT_TEST(test_invalid_file_io);
	CPPUNIT_TEST(test_modification_time);
	CPPUNIT_TEST(test_directory_modification_time);
#ifdef FZ_WINDOWS
	CPPUNIT_TEST(test_renamed_handle_modification_time);
#endif
#ifdef __linux__
	CPPUNIT_TEST(test_rename_symlink);
	CPPUNIT_TEST(test_rename_cross_filesystem);
#endif
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() override;
	void tearDown() override;

	void test_rename_wrapper();
	void test_rename_no_replace();
#if defined(FZ_WINDOWS) || defined(HAVE_RENAMEAT2_NOREPLACE) || defined(FZ_MAC)
	void test_competing_renames();
#endif
	void test_write_file();
	void test_invalid_file_io();
	void test_modification_time();
	void test_directory_modification_time();
#ifdef FZ_WINDOWS
	void test_renamed_handle_modification_time();
#endif
#ifdef __linux__
	void test_rename_symlink();
	void test_rename_cross_filesystem();
#endif

private:
	fz::native_string make_directory(fz::native_string const& parent);
	void write(fz::native_string const& path, char const* value);
	std::string read(fz::native_string const& path);

	fz::native_string root_;
	fz::native_string other_root_;
};

CPPUNIT_TEST_SUITE_REGISTRATION(local_filesys_test);

void local_filesys_test::setUp()
{
#ifdef FZ_WINDOWS
	wchar_t path[MAX_PATH + 1];
	auto const len = GetTempPathW(MAX_PATH + 1, path);
	CPPUNIT_ASSERT_MESSAGE("Temporary directory must be available", len > 0 && len <= MAX_PATH);
	root_ = make_directory(fz::native_string(path, len));
#else
	auto const* path = std::getenv("TMPDIR");
	root_ = make_directory(path && *path ? path : "/tmp");
#endif
}

void local_filesys_test::tearDown()
{
	fz::recursive_remove remover;
	if (!root_.empty()) {
		remover.remove(root_);
		root_.clear();
	}

	if (!other_root_.empty()) {
		remover.remove(other_root_);
		other_root_.clear();
	}
}


fz::native_string local_filesys_test::make_directory(fz::native_string const& parent)
{
	auto path = parent;
	if (path.empty() || !fz::local_filesys::is_separator(path.back())) {
		path += static_cast<fz::native_string::value_type>(fz::local_filesys::path_separator);
	}

	path += fzT("libfilezilla-rename-") + fz::to_native(fz::base32_encode(fz::random_bytes(16), fz::base32_type::locale_safe));
	fz::native_string created;
	auto const res = fz::mkdir(path, false, fz::mkdir_permissions::cur_user, &created);
	CPPUNIT_ASSERT_MESSAGE("Test directory creation must succeed", res);
	if (!created.empty()) {
		return path + static_cast<fz::native_string::value_type>(fz::local_filesys::path_separator);
	}

	CPPUNIT_FAIL("Could not create a private test directory");
	return {};
}

void local_filesys_test::write(fz::native_string const& path, char const* value)
{
	CPPUNIT_ASSERT_MESSAGE("Test file contents must be written", write_file(path, value, fz::file::empty));
}

std::string local_filesys_test::read(fz::native_string const& path)
{
	fz::buffer contents;
	CPPUNIT_ASSERT_MESSAGE("Test file contents must be readable", fz::read_file(path, contents, 256));
	return std::string(contents.to_view());
}

void local_filesys_test::test_modification_time()
{
	auto const path = root_ + fzT("timestamp");
	fz::file file;
	CPPUNIT_ASSERT_MESSAGE("Test file must open", file.open(path, fz::file::writing));

	auto const time = fz::datetime(fz::datetime::utc, 2025, 1, 2, 3, 4, 5);
	CPPUNIT_ASSERT_MESSAGE("Borrowed handle must support timestamp updates", fz::local_filesys::set_modification_time(file.fd(), time));
	// Filesystems may report a different accuracy; compare at the shared precision.
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp must match", 0, file.get_modification_time().compare(time));

	fz::datetime retrieved;
	CPPUNIT_ASSERT_MESSAGE("Borrowed handle must support timestamp retrieval", fz::local_filesys::get_modification_time(file.fd(), retrieved));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Retrieved timestamp must match", 0, retrieved.compare(time));

	// A write proves neither helper closed the handle, but also changes its mtime.
	CPPUNIT_ASSERT_MESSAGE("Timestamp update must not close the handle", write_file(file, "x"));
	CPPUNIT_ASSERT_MESSAGE("Legacy member must delegate successfully", file.set_modification_time(time));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Legacy member must update the timestamp", 0, file.get_modification_time().compare(time));

	auto const invalid_time = fz::local_filesys::set_modification_time(file.fd(), {});
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Empty timestamp must be invalid", fz::result::invalid, invalid_time.error_);
	CPPUNIT_ASSERT_MESSAGE("Legacy member must reject empty timestamps", !file.set_modification_time({}));

	file.close();
	CPPUNIT_ASSERT_MESSAGE("Path setter must remain usable", fz::local_filesys::set_modification_time(path, time));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Path setter must update the timestamp", 0, fz::local_filesys::get_modification_time(path).compare(time));
	CPPUNIT_ASSERT_MESSAGE("Test file must reopen for reading", file.open(path, fz::file::reading));
	auto const read_time = time + fz::duration::from_seconds(60);
	CPPUNIT_ASSERT_MESSAGE("Read handle must support timestamp updates when authorized", file.set_modification_time(read_time));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Read handle timestamp must match", 0, file.get_modification_time().compare(read_time));
	char contents{};
	auto const read = file.read2(&contents, 1);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp update must preserve readable contents", fz::rwresult::none, read.error_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp update must preserve readable contents", size_t(1), read.value_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp update must not change contents", 'x', contents);
	file.close();

	auto const invalid_handle = fz::local_filesys::set_modification_time(file.fd(), time);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Invalid handle must fail", fz::result::other, invalid_handle.error_);
#ifdef FZ_WINDOWS
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Invalid handle must retain the native error", fz::result::raw_t(ERROR_INVALID_HANDLE), invalid_handle.raw_);
#else
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Invalid descriptor must retain the native error", EBADF, invalid_handle.raw_);
#endif
	CPPUNIT_ASSERT_MESSAGE("Legacy member must reject closed handles", !file.set_modification_time(time));

	// Start with a nonempty value so a failure that clears the output is detected.
	auto const previous = retrieved;
	auto const invalid_get = fz::local_filesys::get_modification_time(file.fd(), retrieved);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp retrieval on an invalid handle must fail", fz::result::other, invalid_get.error_);
#ifdef FZ_WINDOWS
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp retrieval must retain the native error", fz::result::raw_t(ERROR_INVALID_HANDLE), invalid_get.raw_);
#else
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Timestamp retrieval must retain the native error", EBADF, invalid_get.raw_);
#endif

	CPPUNIT_ASSERT_MESSAGE("Failed retrieval must leave the output unchanged", retrieved == previous);
	CPPUNIT_ASSERT_MESSAGE("Legacy getter must return an empty timestamp on failure", file.get_modification_time().empty());
}

void local_filesys_test::test_directory_modification_time()
{
	fz::local_filesys directory;
#ifdef FZ_WINDOWS
	// Listing must not require permission to change timestamps.
	auto const handle = CreateFileW(root_.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	CPPUNIT_ASSERT_MESSAGE("Directory handle must open", handle != INVALID_HANDLE_VALUE);
	CPPUNIT_ASSERT_MESSAGE("Directory must take ownership of the handle", directory.begin_find_files(handle));
#else
	CPPUNIT_ASSERT_MESSAGE("Directory must open", directory.begin_find_files(root_));
#endif

	auto const time = fz::datetime(fz::datetime::utc, 2025, 1, 2, 3, 4, 5);
	auto const updated = fz::local_filesys::set_modification_time(directory.fd(), time);
	CPPUNIT_ASSERT_MESSAGE("Directory handle must support timestamp updates (category " +
		std::to_string(updated.error_) + ", native error " + std::to_string(updated.raw_) + ")", updated);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Directory timestamp must match", 0, fz::local_filesys::get_modification_time(root_).compare(time));

	fz::datetime retrieved;
	CPPUNIT_ASSERT_MESSAGE("Borrowed directory handle must support timestamp retrieval", fz::local_filesys::get_modification_time(directory.fd(), retrieved));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Retrieved directory timestamp must match", 0, retrieved.compare(time));

	CPPUNIT_ASSERT_MESSAGE("Borrowed directory handle must remain usable", fz::local_filesys::set_modification_time(directory.fd(), time));
	auto const path_time = time + fz::duration::from_seconds(60);
	CPPUNIT_ASSERT_MESSAGE("Path setter must support directories", fz::local_filesys::set_modification_time(root_, path_time));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Path setter must update the directory timestamp", 0, fz::local_filesys::get_modification_time(root_).compare(path_time));
}

#ifdef FZ_WINDOWS
void local_filesys_test::test_renamed_handle_modification_time()
{
	static fz::dll ntdll(L"ntdll.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	bool const under_wine = ntdll["wine_get_version"] != nullptr;

	for (bool directory : {false, true}) {
		if (under_wine && !directory) {
			// There is a bug in wine, it reopen's the file using a stored old path, not via
			// its handle. As this test cannot succeed, skip it.
			continue;
		}

		auto const path = root_ + (directory ? fzT("timestamp-directory") : fzT("timestamp-file"));
		auto const moved = path + fzT("-moved");

		if (directory) {
			CPPUNIT_ASSERT_MESSAGE("Original directory must be created", fz::mkdir(path, false));
		}
		else {
			write(path, "original");
		}

		// fz::file::open does not offer FILE_SHARE_DELETE, which lets the entry move while open.
		fz::file original(CreateFileW(path.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
		CPPUNIT_ASSERT_MESSAGE("Original read/listing handle must open", original.opened());

		CPPUNIT_ASSERT_MESSAGE("Original entry must move while its handle stays open", fz::rename_file(path, moved, false));

		if (directory) {
			CPPUNIT_ASSERT_MESSAGE("Replacement directory must be created", fz::mkdir(path, false));
		}
		else {
			write(path, "replacement");
		}

		auto const before = fz::local_filesys::get_modification_time(path);
		CPPUNIT_ASSERT_MESSAGE("Replacement timestamp must be readable", !before.empty());

		auto const time = fz::datetime(fz::datetime::utc, 2025, 1, 2, 3, 4, 5);
		CPPUNIT_ASSERT_MESSAGE("Test timestamp must differ from the replacement timestamp", before != time);

		auto const updated = fz::local_filesys::set_modification_time(original.fd(), time);
		CPPUNIT_ASSERT_MESSAGE("Renamed handle must support timestamp updates (native error " +
			std::to_string(updated.raw_) + ")", updated);

		CPPUNIT_ASSERT_EQUAL_MESSAGE("Update must reach the moved original", 0, fz::local_filesys::get_modification_time(moved).compare(time));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Replacement timestamp must remain unchanged", 0, fz::local_filesys::get_modification_time(path).compare(before));
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Original handle must remain usable", 0, original.get_modification_time().compare(time));
	}
}
#endif

void local_filesys_test::test_write_file()
{
	auto const path = root_ + fzT("contents");
	std::string const data("a\0b", 3);
	CPPUNIT_ASSERT_MESSAGE("Binary data must be written", write_file(path, data, fz::file::empty));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Writing preserves embedded NULs", data, read(path));

	auto res = write_file(path, "replacement", fz::file::fresh);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Exclusive creation must preserve existing files",
		fz::result::preexisting, res.error_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Failed open preserves existing contents", data, read(path));

	CPPUNIT_ASSERT_MESSAGE("Writing empty data truncates an existing file", write_file(path, {}, fz::file::empty));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Truncated file must be empty", std::string(), read(path));

	{
		fz::file f(path, fz::file::writing);
		CPPUNIT_ASSERT_MESSAGE("Test file must open", f.opened());

		auto const first = write_file(f, "a");
		CPPUNIT_ASSERT_MESSAGE("Open-file writing must succeed", first);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Open-file writing reports its byte count", size_t(1), first.value_);

		CPPUNIT_ASSERT_MESSAGE("A second write uses the current position", write_file(f, "b"));
	}

	CPPUNIT_ASSERT_EQUAL_MESSAGE("Open-file writes advance the position", std::string("ab"), read(path));

	fz::file closed;
	auto const written = write_file(closed, "data");
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Writing a closed file reports invalid", fz::rwresult::invalid, written.error_);

	res = write_file({}, "data", fz::file::empty);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Path overload preserves open errors", fz::result::invalid, res.error_);
}

void local_filesys_test::test_invalid_file_io()
{
	fz::file closed;
	char buffer{};
	auto const read = closed.read2(&buffer, 1);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Reading a closed file reports invalid", fz::rwresult::invalid, read.error_);

	auto const written = closed.write2(&buffer, 1);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Writing a closed file reports invalid", fz::rwresult::invalid, written.error_);

#ifdef FZ_WINDOWS
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Closed-file read retains the native error", fz::rwresult::raw_t(ERROR_INVALID_HANDLE), read.raw_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Closed-file write retains the native error", fz::rwresult::raw_t(ERROR_INVALID_HANDLE), written.raw_);
#else
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Closed-file read retains the native error", EBADF, read.raw_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Closed-file write retains the native error", EBADF, written.raw_);
#endif
}

void local_filesys_test::test_rename_wrapper()
{
	for (bool allow_copy : {false, true}) {
		write(root_ + fzT("source"), "source");
		write(root_ + fzT("dest"), "dest");

		CPPUNIT_ASSERT_MESSAGE("The bool overload must still replace existing files",
			fz::rename_file(root_ + fzT("source"), root_ + fzT("dest"), allow_copy));
		CPPUNIT_ASSERT_MESSAGE("Successful rename removes the source",
			fz::local_filesys::get_file_type(root_ + fzT("source")) == fz::local_filesys::unknown);
		CPPUNIT_ASSERT_EQUAL_MESSAGE("Replacement retains source contents",
			std::string("source"), read(root_ + fzT("dest")));
	}
}

void local_filesys_test::test_rename_no_replace()
{
	using flags = fz::rename_flags;

	write(root_ + fzT("source"), "source");
	write(root_ + fzT("dest"), "dest");

	auto res = fz::rename_file(root_ + fzT("source"), root_ + fzT("dest"), flags::no_replace);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Existing destination reports a conflict", fz::result::preexisting, res.error_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Conflict preserves the source",
		std::string("source"), read(root_ + fzT("source")));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Conflict preserves the destination",
		std::string("dest"), read(root_ + fzT("dest")));

	fz::remove_file(root_ + fzT("dest"), false);
	CPPUNIT_ASSERT_MESSAGE("No-replace rename succeeds for an absent destination",
		fz::rename_file(root_ + fzT("source"), root_ + fzT("dest"), flags::no_replace));
	CPPUNIT_ASSERT_MESSAGE("Successful rename removes the source",
		fz::local_filesys::get_file_type(root_ + fzT("source")) == fz::local_filesys::unknown);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Successful rename retains contents",
		std::string("source"), read(root_ + fzT("dest")));

	CPPUNIT_ASSERT_MESSAGE("Test directory must be created", fz::mkdir(root_ + fzT("dir-source"), false));
	CPPUNIT_ASSERT_MESSAGE("Test directory must be created", fz::mkdir(root_ + fzT("dir-dest"), false));

	res = fz::rename_file(root_ + fzT("dir-source"), root_ + fzT("dir-dest"), flags::no_replace);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Existing directory is also a conflict", fz::result::preexisting, res.error_);
	CPPUNIT_ASSERT_MESSAGE("Directory conflict preserves both entries",
		fz::local_filesys::get_file_type(root_ + fzT("dir-source")) == fz::local_filesys::dir &&
		fz::local_filesys::get_file_type(root_ + fzT("dir-dest")) == fz::local_filesys::dir);

	fz::remove_dir(root_ + fzT("dir-dest"), true);
	CPPUNIT_ASSERT_MESSAGE("No-replace directory rename succeeds for an absent destination",
		fz::rename_file(root_ + fzT("dir-source"), root_ + fzT("dir-dest"), flags::no_replace));
}

#if defined(FZ_WINDOWS) || defined(HAVE_RENAMEAT2_NOREPLACE) || defined(FZ_MAC)
// Only native no-replace APIs guarantee a single winner under concurrent renames.
void local_filesys_test::test_competing_renames()
{
	// Only run this test if a rename succeeds, the filesystem may not support it.
	auto const probe = root_ + fzT("check_noreplace_support");
	write(probe, "");
	if (fz::rename_file(probe, root_ + fzT("rename_noreplace_supported"), fz::rename_flags::no_replace)) {
		for (unsigned i = 0; i < 32; ++i) {
			write(root_ + fzT("a"), "a");
			write(root_ + fzT("b"), "b");

			fz::result a, b;
			std::thread first([&] {
				a = fz::rename_file(root_ + fzT("a"), root_ + fzT("dest"), fz::rename_flags::no_replace);
			});

			std::thread second([&] {
				b = fz::rename_file(root_ + fzT("b"), root_ + fzT("dest"), fz::rename_flags::no_replace);
			});

			first.join();
			second.join();

			CPPUNIT_ASSERT_MESSAGE("Only one competing no-replace rename can succeed", bool(a) != bool(b));
			CPPUNIT_ASSERT_EQUAL_MESSAGE("The losing rename reports a conflict",
				fz::result::preexisting, (a ? b : a).error_);
			CPPUNIT_ASSERT_EQUAL_MESSAGE("Destination contains the winning source",
				std::string(a ? "a" : "b"), read(root_ + fzT("dest")));
			CPPUNIT_ASSERT_EQUAL_MESSAGE("The losing source remains intact",
				std::string(a ? "b" : "a"), read(root_ + (a ? fzT("b") : fzT("a"))));

			fz::remove_file(root_ + fzT("a"), false);
			fz::remove_file(root_ + fzT("b"), false);
			fz::remove_file(root_ + fzT("dest"), false);
		}
	}
}

#endif

#ifdef __linux__
void local_filesys_test::test_rename_symlink()
{
	write(root_ + fzT("source"), "source");
	CPPUNIT_ASSERT_MESSAGE("Test symlink must be created",
		symlink((root_ + fzT("absent")).c_str(), (root_ + fzT("dest")).c_str()) == 0);

	auto const res = fz::rename_file(root_ + fzT("source"), root_ + fzT("dest"), fz::rename_flags::no_replace);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("A dangling destination symlink is a conflict",
		fz::result::preexisting, res.error_);
	CPPUNIT_ASSERT_MESSAGE("Conflict preserves the symlink",
		fz::local_filesys::get_file_type(root_ + fzT("dest")) == fz::local_filesys::link);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Conflict preserves the source",
		std::string("source"), read(root_ + fzT("source")));
}

void local_filesys_test::test_rename_cross_filesystem()
{
	// Prefer the user's runtime directory when it is on a separate filesystem.
	// Linux normally mounts tmpfs at /dev/shm for POSIX shared memory:
	// https://man7.org/linux/man-pages/man7/shm_overview.7.html
	// tmpfs permits file creation subject to permissions and resource limits:
	// https://docs.kernel.org/filesystems/tmpfs.html
	// Here it supplies a separate filesystem, not shared-memory IPC. Use it only
	// when writable, inside a private test directory removed by tearDown().
	struct stat local{};
	if (stat(root_.c_str(), &local)) {
		return;
	}

	char const* const candidates[] = {std::getenv("XDG_RUNTIME_DIR"), "/dev/shm"};
	for (auto const* path : candidates) {
		struct stat other{};
		if (!path || path[0] != '/' || stat(path, &other) || !S_ISDIR(other.st_mode) ||
			local.st_dev == other.st_dev || access(path, W_OK | X_OK)) {
			continue;
		}

		other_root_ = make_directory(path);
		break;
	}

	if (other_root_.empty()) {
		return;
	}

	using flags = fz::rename_flags;

	write(root_ + fzT("source"), "source");
	write(other_root_ + fzT("dest"), "dest");

	auto res = fz::rename_file(root_ + fzT("source"), other_root_ + fzT("dest"),
		flags::allow_copy | flags::no_replace);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Copy fallback rejects an existing destination",
		fz::result::preexisting, res.error_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Copy conflict preserves source contents",
		std::string("source"), read(root_ + fzT("source")));
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Copy conflict preserves destination contents",
		std::string("dest"), read(other_root_ + fzT("dest")));

	fz::remove_file(other_root_ + fzT("dest"), false);
	res = fz::rename_file(root_ + fzT("source"), other_root_ + fzT("dest"), flags::no_replace);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Cross-filesystem rename without allow_copy reports cross_device",
		fz::result::cross_device, res.error_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Cross-filesystem rename preserves the native error", EXDEV, res.raw_);
	CPPUNIT_ASSERT_MESSAGE("Rejected copy preserves the source and absent destination",
		fz::local_filesys::get_file_type(root_ + fzT("source")) == fz::local_filesys::file &&
		fz::local_filesys::get_file_type(other_root_ + fzT("dest")) == fz::local_filesys::unknown);

	CPPUNIT_ASSERT_MESSAGE("allow_copy enables an exclusive cross-filesystem move",
		fz::rename_file(root_ + fzT("source"), other_root_ + fzT("dest"), flags::allow_copy | flags::no_replace));
	CPPUNIT_ASSERT_MESSAGE("Successful copy move removes the source",
		fz::local_filesys::get_file_type(root_ + fzT("source")) == fz::local_filesys::unknown);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Successful copy retains contents",
		std::string("source"), read(other_root_ + fzT("dest")));

	CPPUNIT_ASSERT_MESSAGE("Test directory must be created", fz::mkdir(root_ + fzT("dir-source"), false));
	res = fz::rename_file(root_ + fzT("dir-source"), other_root_ + fzT("dir-dest"), flags::no_replace);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Cross-filesystem directory rename reports cross_device",
		fz::result::cross_device, res.error_);
	CPPUNIT_ASSERT_EQUAL_MESSAGE("Directory rename preserves the native error", EXDEV, res.raw_);
	CPPUNIT_ASSERT_MESSAGE("Rejected directory move preserves the source and absent destination",
		fz::local_filesys::get_file_type(root_ + fzT("dir-source")) == fz::local_filesys::dir &&
		fz::local_filesys::get_file_type(other_root_ + fzT("dir-dest")) == fz::local_filesys::unknown);
}
#endif
