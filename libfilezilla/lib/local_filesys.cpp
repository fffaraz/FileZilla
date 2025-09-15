#include "libfilezilla/local_filesys.hpp"

#include "libfilezilla/buffer.hpp"
#include "libfilezilla/file.hpp"

#ifdef FZ_WINDOWS
#include "libfilezilla/glue/dll.hpp"
#include "windows/security_descriptor_builder.hpp"
#include <winioctl.h>
#include <winternl.h>
#else
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <utime.h>
#endif

namespace fz {

namespace {
template<typename T>
int64_t make_int64fzT(T hi, T lo)
{
	return (static_cast<int64_t>(hi) << 32) + static_cast<int64_t>(lo);
}
}

#ifdef FZ_WINDOWS
char const local_filesys::path_separator = '\\';
#else
char const local_filesys::path_separator = '/';
#endif


local_filesys::~local_filesys()
{
	end_find_files();
}

namespace {
#ifdef FZ_WINDOWS
bool IsNameSurrogateReparsePoint(std::wstring const& file)
{
	WIN32_FIND_DATA data;
	HANDLE hFind = FindFirstFile(file.c_str(), &data);
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
		return IsReparseTagNameSurrogate(data.dwReserved0);
	}
	return false;
}

bool is_drive_letter(wchar_t c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
#endif

local_filesys::type do_get_file_type(native_string const& path, bool follow_links)
{

#ifdef FZ_WINDOWS
	DWORD attributes = GetFileAttributes(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES) {
		return local_filesys::unknown;
	}

	bool is_dir = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

	if (attributes & FILE_ATTRIBUTE_REPARSE_POINT && IsNameSurrogateReparsePoint(path)) {
		if (!follow_links) {
			return local_filesys::link;
		}

		// Follow the reparse point
		HANDLE hFile = CreateFile(path.c_str(), FILE_READ_ATTRIBUTES | FILE_READ_EA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
		if (hFile == INVALID_HANDLE_VALUE) {
			return local_filesys::unknown;
		}

		BY_HANDLE_FILE_INFORMATION info{};
		int ret = GetFileInformationByHandle(hFile, &info);
		CloseHandle(hFile);
		if (!ret) {
			return local_filesys::unknown;
		}

		is_dir = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
	}

	return is_dir ? local_filesys::dir : local_filesys::file;
#else
	struct stat buf;
	int result = lstat(path.c_str(), &buf);
	if (result) {
		return local_filesys::unknown;
	}

#ifdef S_ISLNK
	if (S_ISLNK(buf.st_mode)) {
		if (!follow_links) {
			return local_filesys::link;
		}

		result = stat(path.c_str(), &buf);
		if (result) {
			return local_filesys::unknown;
		}
	}
#endif

	if (S_ISDIR(buf.st_mode)) {
		return local_filesys::dir;
	}

	return local_filesys::file;
#endif
}
}

local_filesys::type local_filesys::get_file_type(native_string const& path, bool follow_links)
{
#ifdef FZ_WINDOWS
	if (path.size() == 6 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\' && is_drive_letter(path[4]) && path[5] == ':') {
		return do_get_file_type(path + L"\\", follow_links);
	}
	if (path.size() == 7 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\' && is_drive_letter(path[4]) && path[5] == ':' && is_separator(path[6])) {
		return do_get_file_type(path, follow_links);
	}
#endif
	if (path.size() > 1 && is_separator(path.back())) {
		return do_get_file_type(path.substr(0, path.size() - 1), follow_links);
	}

	return do_get_file_type(path, follow_links);
}

namespace {
#ifndef FZ_WINDOWS
result get_file_info_impl(result(*do_stat)(struct stat & buf, char const* path, DIR* dir, bool follow), char const* path, DIR* dir, bool &is_link, local_filesys::type& type, int64_t* size, datetime* modification_time, int *mode, bool follow_links)
{
	struct stat buf{};
	static_assert(sizeof(buf.st_size) >= 8, "The st_size member of struct stat must be 8 bytes or larger.");

	auto result = do_stat(buf, path, dir, false);
	if (!result) {
		is_link = false;
		if (size) {
			*size = -1;
		}
		if (mode) {
			*mode = -1;
		}
		if (modification_time) {
			*modification_time = datetime();
		}
		type = local_filesys::unknown;
		return result;
	}

#ifdef S_ISLNK
	if (S_ISLNK(buf.st_mode)) {
		is_link = true;

		if (follow_links) {
			result = do_stat(buf, path, dir, true);
			if (!result) {
				if (size) {
					*size = -1;
				}
				if (mode) {
					*mode = -1;
				}
				if (modification_time) {
					*modification_time = datetime();
				}
				type = local_filesys::unknown;
				return result;
			}
		}
		else {
			if (modification_time) {
#if HAVE_STRUCT_STAT_ST_MTIM
				*modification_time = datetime(buf.st_mtim.tv_sec, datetime::milliseconds) + fz::duration::from_milliseconds(buf.st_mtim.tv_nsec/1000000);
#else
				*modification_time = datetime(buf.st_mtime, datetime::seconds);
#endif
			}

			if (mode) {
				*mode = buf.st_mode & 0777;
			}
			if (size) {
				*size = -1;
			}
			type = local_filesys::link;
			return { result::ok, 0 };
		}
	}
	else
#endif
		is_link = false;

	if (modification_time) {
#if HAVE_STRUCT_STAT_ST_MTIM
		*modification_time = datetime(buf.st_mtim.tv_sec, datetime::milliseconds) + fz::duration::from_milliseconds(buf.st_mtim.tv_nsec/1000000);
#else
		*modification_time = datetime(buf.st_mtime, datetime::seconds);
#endif
	}

	if (mode) {
		*mode = buf.st_mode & 0777;
	}

	if (S_ISDIR(buf.st_mode)) {
		if (size) {
			*size = -1;
		}
		type = local_filesys::dir;
		return { result::ok, 0 };
	}

	if (size) {
		*size = buf.st_size;
	}

	type = local_filesys::file;
	return { result::ok, 0 };
}

static result stat2result(int res)
{
	if (res) {
		int err = errno;

		switch (err) {
		case 0:
			break;
		case EACCES:
		case EPERM:
			return {result::noperm, err};
		default:
			return {result::other, err};
		}
	}

	return {result::ok, 0};
}

result get_file_info_at(char const* path, DIR* dir, bool &is_link, local_filesys::type& type, int64_t* size, datetime* modification_time, int *mode, bool follow)
{
	auto do_stat = [](struct stat & buf, char const* path, DIR * dir, bool follow) -> result
	{
		return stat2result(fstatat(dirfd(dir), path, &buf, follow ? 0 : AT_SYMLINK_NOFOLLOW));
	};
	return get_file_info_impl(do_stat, path, dir, is_link, type, size, modification_time, mode, follow);
}
#endif

result do_get_file_info(native_string const& path, bool& is_link, local_filesys::type& type, int64_t* size, datetime* modification_time, int* mode, bool follow_links)
{
#ifdef FZ_WINDOWS
	static auto last_result = []() -> result {
		DWORD const err = GetLastError();
		switch (err) {
		case ERROR_ACCESS_DENIED:
		case ERROR_LOGON_FAILURE:
			return {result::noperm, err};
		default:
			return {result::other, err};
		}
	};

	is_link = false;

	WIN32_FILE_ATTRIBUTE_DATA data;
	if (!GetFileAttributesEx(path.c_str(), GetFileExInfoStandard, &data)) {
		auto result = last_result();

		if (size) {
			*size = -1;
		}
		if (mode) {
			*mode = 0;
		}
		if (modification_time) {
			*modification_time = datetime();
		}
		type = local_filesys::unknown;
		return result;
	}

	bool is_dir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

	if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT && IsNameSurrogateReparsePoint(path)) {
		is_link = true;

		if (!follow_links) {
			if (modification_time) {
				*modification_time = datetime(data.ftLastWriteTime, datetime::milliseconds);
				if (modification_time->empty()) {
					*modification_time = datetime(data.ftCreationTime, datetime::milliseconds);
				}
			}

			if (mode) {
				*mode = (int)data.dwFileAttributes;
			}

			if (size) {
				*size = -1;
			}
			type = local_filesys::link;
			return {result::ok, 0};
		}

		HANDLE hFile = is_dir ? INVALID_HANDLE_VALUE : CreateFile(path.c_str(), FILE_READ_ATTRIBUTES | FILE_READ_EA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile != INVALID_HANDLE_VALUE) {
			BY_HANDLE_FILE_INFORMATION info{};
			int ret = GetFileInformationByHandle(hFile, &info);
			CloseHandle(hFile);
			if (ret != 0) {
				if (modification_time) {
					if (!modification_time->set(info.ftLastWriteTime, datetime::milliseconds)) {
						modification_time->set(info.ftCreationTime, datetime::milliseconds);
					}
				}

				if (mode) {
					*mode = (int)info.dwFileAttributes;
				}

				if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					if (size) {
						*size = -1;
					}
					type = local_filesys::dir;
					return {result::ok, 0};
				}

				if (size) {
					*size = make_int64fzT(info.nFileSizeHigh, info.nFileSizeLow);
				}

				type = local_filesys::file;
				return {result::ok, 0};
			}
		}

		if (size) {
			*size = -1;
		}
		if (mode) {
			*mode = 0;
		}
		if (modification_time) {
			*modification_time = datetime();
		}
		type = is_dir ? local_filesys::dir : local_filesys::unknown;
		return {result::ok, 0};
	}

	if (modification_time) {
		*modification_time = datetime(data.ftLastWriteTime, datetime::milliseconds);
		if (modification_time->empty()) {
			*modification_time = datetime(data.ftCreationTime, datetime::milliseconds);
		}
	}

	if (mode) {
		*mode = (int)data.dwFileAttributes;
	}

	if (is_dir) {
		if (size) {
			*size = -1;
		}
		type = local_filesys::dir;
		return {result::ok, 0};
	}
	else {
		if (size) {
			*size = make_int64fzT(data.nFileSizeHigh, data.nFileSizeLow);
		}
		type = local_filesys::file;
		return {result::ok, 0};
	}
#else
	auto do_stat = [](struct stat& buf, char const* path, DIR*, bool follow)
	{
		if (follow) {
			stat2result(stat(path, &buf));
		}

		return stat2result(lstat(path, &buf));
	};
	return get_file_info_impl(do_stat, path.c_str(), nullptr, is_link, type, size, modification_time, mode, follow_links);
#endif
}
}

local_filesys::type local_filesys::get_file_info(native_string const& path, bool& is_link, int64_t* size, datetime* modification_time, int *mode, bool follow_links)
{
	local_filesys::type type;

	if (!get_file_info(path, is_link, type, size, modification_time, mode, follow_links)) {
		type = local_filesys::unknown;
	}

	return type;
}

fz::result local_filesys::get_file_info(native_string const& path, bool& is_link, type& type, int64_t* size, datetime* modification_time, int *mode, bool follow_links)
{
#ifdef FZ_WINDOWS
	if (path.size() == 6 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\' && is_drive_letter(path[4]) && path[5] == ':') {
		return do_get_file_info(path + L"\\", is_link, type, size, modification_time, mode, follow_links);
	}
	if (path.size() == 7 && path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\' && is_drive_letter(path[4]) && path[5] == ':' && is_separator(path[6])) {
		return do_get_file_info(path, is_link, type, size, modification_time, mode, follow_links);
	}
#endif
	if (path.size() > 1 && is_separator(path.back())) {
		return do_get_file_info(path.substr(0, path.size() - 1), is_link, type, size, modification_time, mode, follow_links);
	}

	return do_get_file_info(path, is_link, type, size, modification_time, mode, follow_links);
}

result local_filesys::begin_find_files(native_string path, bool dirs_only, bool query_symlink_targets)
{
	end_find_files();

	if (path.empty()) {
		return {result::invalid};
	}

	dirs_only_ = dirs_only;
	query_symlink_targets_ = query_symlink_targets;

#ifdef FZ_WINDOWS
	if (!is_separator(path.back())) {
		path += '\\';
	}

	dir_ = CreateFile(path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if (dir_ == INVALID_HANDLE_VALUE) {
		auto const err = GetLastError();
		switch (err) {
		case ERROR_ACCESS_DENIED:
		case ERROR_LOGON_FAILURE:
			return result{result::noperm, err};
		case ERROR_TOO_MANY_OPEN_FILES:
			return {result::resource_limit, err};
		default:
			return result{result::other, err};
		}
	}

	buffer_.resize(64 * 1024);
	return result{result::ok};
#else
	if (path.size() > 1 && path.back() == '/') {
		path.pop_back();
	}

	dir_ = opendir(path.c_str());
	if (!dir_) {
		int const err = errno;
		switch (err) {
			case EACCES:
			case EPERM:
				return {result::noperm, err};
			case ENOTDIR:
			case ENOENT:
				return {result::nodir, err};
			case EMFILE:
			case ENFILE:
				return {result::resource_limit, err};
			default:
				return {result::other, err};
		}
	}

	return {result::ok};
#endif
}

#if FZ_WINDOWS
result local_filesys::begin_find_files(HANDLE dir, bool dirs_only, bool query_symlink_targets)
{
	end_find_files();

	if (dir == INVALID_HANDLE_VALUE) {
		return {result::nodir};
	}

	dirs_only_ = dirs_only;
	query_symlink_targets_ = query_symlink_targets;

	dir_ = dir;
	buffer_.resize(64 * 1024);
	return {result::ok};
}
#else
result local_filesys::begin_find_files(int fd, bool dirs_only, bool query_symlink_targets)
{
	end_find_files();

	if (fd == -1) {
		return {result::nodir};
	}

	dirs_only_ = dirs_only;
	query_symlink_targets_ = query_symlink_targets;

	dir_ = fdopendir(fd);
	if (!dir_) {
		close(fd);
		int const err = errno;
		switch (err) {
			case EACCES:
			case EPERM:
				return {result::noperm, err};
			case ENOTDIR:
			case ENOENT:
				return {result::nodir, err};
			case EMFILE:
			case ENFILE:
				return {result::resource_limit, err};
			default:
				return {result::other, err};
		}
	}

	return result{result::ok};
}
#endif

void local_filesys::end_find_files()
{
#ifdef FZ_WINDOWS
	if (dir_ != INVALID_HANDLE_VALUE) {
		CloseHandle(dir_);
		dir_ = INVALID_HANDLE_VALUE;
	}
	buffer_.clear();
	cur_ = nullptr;
#else
	if (dir_) {
		closedir(dir_);
		dir_ = nullptr;
	}
#endif
}

#ifdef FZ_WINDOWS
namespace {
extern "C" {
// Sadly ddk/ntifs.h is unusuable. Manually declare the needed things.
typedef enum
{
	lfzFileDirectoryInformation = 1
} lfzFILE_INFORMATION_CLASS;

typedef struct {
	ULONG NextEntryOffset;
	ULONG unused1;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER unused2;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
} lfzFILE_DIRECTORY_INFORMATION;

typedef NTSTATUS(NTAPI* lfzNtQueryDirectoryFile)(HANDLE dir, HANDLE ev, void*, void*, IO_STATUS_BLOCK* status, void* buffer, ULONG size, lfzFILE_INFORMATION_CLASS c, BOOL single, void*, BOOL restart);
typedef NTSTATUS(NTAPI* lfzNtOpenFile)(HANDLE* file, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* attributes, IO_STATUS_BLOCK* status, ULONG ShareAccess, ULONG OpenOptions);
}

bool read_dir_buffer(HANDLE dir, void* buf, ULONG size, lfzFILE_INFORMATION_CLASS c)
{
	static dll ntdll(L"ntdll.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	static auto f = reinterpret_cast<lfzNtQueryDirectoryFile>(ntdll["NtQueryDirectoryFile"]);
	if (!f) {
		return false;
	}
	IO_STATUS_BLOCK s{};
	NTSTATUS res = f(dir, nullptr, nullptr, nullptr, &s, buf, size, c, FALSE, nullptr, FALSE);
	if (res != 0 || !s.Information) {
		return false;
	}
	return true;
}

HANDLE OpenAt(HANDLE dir, std::wstring const& name, ACCESS_MASK DesiredAccess, ULONG ShareAccess, ULONG OpenOptions)
{
	static dll ntdll(L"ntdll.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
	static auto const func = reinterpret_cast<lfzNtOpenFile>(ntdll["NtOpenFile"]);
	if (!func) {
		return INVALID_HANDLE_VALUE;
	}

	if ((name.size() * 2 + 2) > std::numeric_limits<decltype(UNICODE_STRING::Length)>::max()) {
		return INVALID_HANDLE_VALUE;
	}

	UNICODE_STRING uname;
	uname.Length = static_cast<decltype(UNICODE_STRING::Length)>(name.size() * 2);
	uname.MaximumLength = static_cast<decltype(UNICODE_STRING::Length)>(name.size() * 2 + 2);
	uname.Buffer = const_cast<wchar_t*>(name.c_str());

	OBJECT_ATTRIBUTES attrs{};
	attrs.Length = sizeof(OBJECT_ATTRIBUTES);
	attrs.RootDirectory = dir;
	attrs.ObjectName = &uname;

	HANDLE file;
	IO_STATUS_BLOCK s{};
	NTSTATUS res = func(&file, DesiredAccess | SYNCHRONIZE, &attrs, &s, ShareAccess, OpenOptions | FILE_SYNCHRONOUS_IO_NONALERT);
	if (res) {
		return INVALID_HANDLE_VALUE;
	}
	return file;
}

bool IsNameSurrogateReparsePoint(HANDLE dir, std::wstring const& name)
{
	HANDLE file = OpenAt(dir, name, FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT);
	if (file != INVALID_HANDLE_VALUE) {
		FILE_ATTRIBUTE_TAG_INFO buf{};

		bool ret{};
		if (GetFileInformationByHandleEx(file, FileAttributeTagInfo, &buf, sizeof(FILE_ATTRIBUTE_TAG_INFO)) != 0) {
			ret = IsReparseTagNameSurrogate(buf.ReparseTag);
		}
		CloseHandle(file);

		return ret;
	}

	return false;
}
}

bool local_filesys::check_buffer()
{
	if (!cur_) {
		cur_ = buffer_.data();
		if (!read_dir_buffer(dir_, cur_, static_cast<ULONG>(buffer_.size()), lfzFileDirectoryInformation)) {
			return false;
		}
	}
	return true;
}
#endif

bool local_filesys::get_next_file(native_string& name)
{
#ifdef FZ_WINDOWS
	while (dir_ != INVALID_HANDLE_VALUE) {
		if (!check_buffer()) {
			name.clear();
			end_find_files();
			return false;
		}

		auto & data = *reinterpret_cast<lfzFILE_DIRECTORY_INFORMATION*>(cur_);
		cur_ = data.NextEntryOffset ? (cur_ + data.NextEntryOffset) : nullptr;

		if (!data.FileNameLength || (data.FileNameLength % sizeof(wchar_t))) {
			continue;
		}
		if (dirs_only_ && !(data.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			continue;
		}

		// Array may be larger than neceessary, look for terminating null
		std::wstring_view v(static_cast<wchar_t const*>(data.FileName), data.FileNameLength / sizeof(wchar_t));
		size_t pos = v.find(wchar_t(0));
		name.assign(v.substr(0, pos));
		if (name.empty() || name == fzT(".") || name == fzT("..")) {
			continue;
		}

		return true;
	}

	name.clear();
	return false;
#else
	if (!dir_) {
		return false;
	}

	struct dirent* entry;
	while ((entry = readdir(dir_))) {
		if (!entry->d_name[0] ||
			!strcmp(entry->d_name, ".") ||
			!strcmp(entry->d_name, ".."))
			continue;

		if (dirs_only_) {
#if HAVE_STRUCT_DIRENT_D_TYPE
			if (entry->d_type == DT_LNK) {
				bool wasLink{};
				local_filesys::type type;

				if (!get_file_info_at(entry->d_name, dir_, wasLink, type, nullptr, nullptr, nullptr, query_symlink_targets_) || type != dir) {
					continue;
				}
			}
			else if (entry->d_type != DT_DIR) {
				continue;
			}
#else
			// Solaris doesn't have d_type
			bool wasLink{};
			local_filesys::type type;
			if (!get_file_info_at(entry->d_name, dir_, wasLink, type, nullptr, nullptr, nullptr, query_symlink_targets_) || type != dir) {
				continue;
			}
#endif
		}

		name = entry->d_name;

		return true;
	}

	return false;
#endif
}

bool local_filesys::get_next_file(native_string& name, bool &is_link, local_filesys::type & t, int64_t* size, datetime* modification_time, int* mode)
{
#ifdef FZ_WINDOWS
	while (dir_ != INVALID_HANDLE_VALUE) {
		if (!check_buffer()) {
			name.clear();
			end_find_files();
			return false;
		}

		auto& data = *reinterpret_cast<lfzFILE_DIRECTORY_INFORMATION*>(cur_);
		cur_ = data.NextEntryOffset ? (cur_ + data.NextEntryOffset) : nullptr;

		if (!data.FileNameLength || (data.FileNameLength % sizeof(wchar_t))) {
			continue;
		}
		if (dirs_only_ && !(data.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			continue;
		}

		// Array may be larger than neceessary, look for terminating null
		std::wstring_view v(static_cast<wchar_t const*>(data.FileName), data.FileNameLength / sizeof(wchar_t));
		size_t pos = v.find(wchar_t(0));
		name.assign(v.substr(0, pos));
		if (name.empty() || name == fzT(".") || name == fzT("..")) {
			continue;
		}

		t = (data.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? dir : file;

		is_link = (data.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 && IsNameSurrogateReparsePoint(dir_, name);
		if (is_link && query_symlink_targets_) {
			// Follow the reparse point
			HANDLE hFile = OpenAt(dir_, name, FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_FOR_BACKUP_INTENT);
			if (hFile != INVALID_HANDLE_VALUE) {
				BY_HANDLE_FILE_INFORMATION info{};
				int ret = GetFileInformationByHandle(hFile, &info);
				CloseHandle(hFile);
				if (ret != 0) {
					if (modification_time) {
						*modification_time = datetime(info.ftLastWriteTime, datetime::milliseconds);
						if (modification_time->empty()) {
							*modification_time = datetime(info.ftCreationTime, datetime::milliseconds);
						}
					}

					if (mode) {
						*mode = (int)info.dwFileAttributes;
					}

					t = (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? dir : file;
					if (size) {
						if (t == dir) {
							*size = -1;
						}
						else {
							*size = make_int64fzT(info.nFileSizeHigh, info.nFileSizeLow);
						}
					}

					return true;
				}
			}

			if (dirs_only_ && t != dir) {
				continue;
			}

			if (size) {
				*size = -1;
			}
			if (mode) {
				*mode = 0;
			}
			if (modification_time) {
				*modification_time = datetime();
			}
		}
		else {
			if (modification_time) {
				FILETIME ft;
				ft.dwLowDateTime = data.LastWriteTime.LowPart;
				ft.dwHighDateTime = data.LastWriteTime.HighPart;
				*modification_time = datetime(ft, datetime::milliseconds);
				if (modification_time->empty()) {
					ft.dwLowDateTime = data.CreationTime.LowPart;
					ft.dwHighDateTime = data.CreationTime.HighPart;
					*modification_time = datetime(ft, datetime::milliseconds);
				}
			}

			if (mode) {
				*mode = (int)data.FileAttributes;
			}

			if (size) {
				if (t == dir) {
					*size = -1;
				}
				else {
					*size = data.EndOfFile.QuadPart;
				}
			}
		}
		return true;
	}

	return false;
#else
	if (!dir_) {
		return false;
	}

	struct dirent* entry;
	while ((entry = readdir(dir_))) {
		if (!entry->d_name[0] ||
			!strcmp(entry->d_name, ".") ||
			!strcmp(entry->d_name, ".."))
			continue;

#if HAVE_STRUCT_DIRENT_D_TYPE
		if (dirs_only_) {
			if (entry->d_type == DT_LNK) {
				if (!get_file_info_at(entry->d_name, dir_, is_link, t, size, modification_time, mode, query_symlink_targets_) || t != dir) {
					continue;
				}

				name = entry->d_name;
				t = dir;
				return true;
			}
			else if (entry->d_type != DT_DIR) {
				continue;
			}
		}
#endif

		if (!get_file_info_at(entry->d_name, dir_, is_link, t, size, modification_time, mode, query_symlink_targets_)) {
			t = unknown;
		}

		if (t == unknown) { // Happens for example in case of permission denied
#if HAVE_STRUCT_DIRENT_D_TYPE
			t = (entry->d_type == DT_DIR) ? dir : file;
#endif
			is_link = false;
			if (size) {
				*size = -1;
			}
			if (modification_time) {
				*modification_time = datetime();
			}
			if (mode) {
				*mode = 0;
			}
		}
		if (dirs_only_ && t != dir) {
			continue;
		}

		name = entry->d_name;

		return true;
	}

	return false;
#endif
}

datetime local_filesys::get_modification_time(native_string const& path)
{
	datetime mtime;

	bool tmp;
	if (get_file_info(path, tmp, nullptr, &mtime, nullptr) == unknown) {
		mtime = datetime();
	}

	return mtime;
}

result local_filesys::set_modification_time(native_string const& path, datetime const& t)
{
	if (t.empty()) {
		return {result::invalid, 0};
	}

#ifdef FZ_WINDOWS
	FILETIME ft = t.get_filetime();
	if (!ft.dwHighDateTime) {
		return {result::invalid, 0};
	}

	HANDLE h = CreateFile(path.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD const err = GetLastError();
		switch (err) {
			case ERROR_FILE_NOT_FOUND:
			case ERROR_PATH_NOT_FOUND:
				return {result::nofile, err};
			case ERROR_ACCESS_DENIED:
			case ERROR_LOGON_FAILURE:
				return {result::noperm, err};
			default:
				return {result::other, err};
		}
	}

	bool ret = SetFileTime(h, nullptr, &ft, &ft) == TRUE;
	DWORD err = GetLastError();
	CloseHandle(h);
	if (!ret) {
		// Dunnno how SetFileTime could have failed on a handle opened for writing
		return {result::other, err};
	}
	return {};
#else
	struct timespec times[2]{};
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = t.get_time_t();
	times[1].tv_nsec = t.get_milliseconds() * 1000000;
	int res = utimensat(AT_FDCWD, path.c_str(), times, 0);
	if (!res) {
		return {};
	}
	int err = errno;
	switch (err) {
	case EINVAL:
	case ENAMETOOLONG:
		return {result::invalid, err};
	case EPERM:
	case EACCES:
	case EROFS:
	case ESRCH:
		return {result::noperm, err};
	case ENOENT:
		return {result::nofile, err};
	default:
		return {result::other, err};
	}
#endif
}

int64_t local_filesys::get_size(native_string const& path, bool* is_link)
{
	int64_t ret = -1;
	bool tmp{};
	type t = get_file_info(path, is_link ? *is_link : tmp, &ret, nullptr, nullptr);
	if (t != file) {
		ret = -1;
	}

	return ret;
}

#if FZ_WINDOWS
namespace {
bool drive_letter(wchar_t c) {
	if (c >= 'a' && c <= 'z') {
		return true;
	}
	if (c >= 'A' && c <= 'Z') {
		return true;
	}
	return false;
}

// Get rid of those pesky \\?\ paths
void sanitize_path(native_string& path)
{
	for (auto& c : path) {
		if (c == '/') {
			c = '\\';
		}
	}
	while (starts_with(path, L"\\\\?")) {
		if (starts_with(path, L"\\\\?\\UNC\\")) {
			path = L"\\\\" + path.substr(8);
		}
		else if (starts_with(path, L"\\\\?\\")) {
			if (path.size() < 6 || !drive_letter(path[4]) || path[5] != ':') {
				path.clear();
			}
			else {
				path = path.substr(4);
			}
		}
		else {
			path.clear();
		}
	}
}
}
#endif

native_string local_filesys::get_final_link_target(native_string const& path)
{
	native_string target;

#ifdef FZ_WINDOWS
	HANDLE hFile = CreateFile(path.c_str(), FILE_READ_ATTRIBUTES | FILE_READ_EA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD const size = 1024;
		native_string::value_type out[size];
		DWORD ret = GetFinalPathNameByHandle(hFile, out, size, 0);
		if (ret > 0 && ret < size) {
			target = out;
			sanitize_path(target);
		}
		CloseHandle(hFile);
	}
#else
	if (path.size() > 1 && path.back() == '/') {
		return get_final_link_target(path.substr(0, path.size() - 1));
	}
	target.resize(PATH_MAX);
	auto res = realpath(path.c_str(), target.data());
	if (!res || *res != '/') {
		return {};
	}
	target.resize(strlen(target.data()));

#endif
	return target;
}

native_string local_filesys::get_link_target(native_string const& path)
{
	native_string target;

#ifdef FZ_WINDOWS
	HANDLE hFile = CreateFile(path.c_str(), FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (hFile != INVALID_HANDLE_VALUE) {

		// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913
		struct reparse_buffer {
			ULONG tag;
			USHORT len;
			USHORT reserved;
			union {
				struct {
					USHORT substitute_name_offset;
					USHORT substitute_name_length;
					USHORT print_name_offset;
					USHORT print_name_length;
					ULONG flags;
					WCHAR data[1];
				} symlink;
				struct {
					USHORT substitute_name_offset;
					USHORT substitute_name_length;
					USHORT print_name_offset;
					USHORT print_name_length;
					WCHAR data[1];
				} mountpoint;
				unsigned char dummy[2048];
			};
		};

		reparse_buffer buf;
		DWORD outlen{};
		if (DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, nullptr, 0, &buf, sizeof(buf), &outlen, nullptr) != 0) {
			if (buf.tag == IO_REPARSE_TAG_SYMLINK) {
				target.assign(buf.symlink.data + buf.symlink.print_name_offset / 2, buf.symlink.print_name_length / 2);
			}
			else if (buf.tag == IO_REPARSE_TAG_MOUNT_POINT) {
				target.assign(buf.mountpoint.data + buf.mountpoint.print_name_offset / 2, buf.mountpoint.print_name_length / 2);
			}
			sanitize_path(target);
		}

		CloseHandle(hFile);
	}
#else
	if (path.size() > 1 && path.back() == '/') {
		return get_link_target(path.substr(0, path.size() - 1));
	}

	target.resize(1024);
	while (true) {
		ssize_t res = readlink(path.c_str(), target.data(), target.size());
		if (res < 0) {
			return {};
		}
		if (static_cast<size_t>(res) < target.size()) {
			target.resize(res);
			break;
		}
		target.resize(target.size() * 2);
	}
#endif
	return target;
}

namespace {
result do_mkdir(native_string const& path, mkdir_permissions permissions)
{
#ifdef FZ_WINDOWS

	SECURITY_ATTRIBUTES attr{};
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);

	security_descriptor_builder sdb;
	if (permissions != mkdir_permissions::normal) {
		sdb.add(security_descriptor_builder::self);
		if (permissions == mkdir_permissions::cur_user_and_admins) {
			sdb.add(security_descriptor_builder::administrators);
		}
		auto sd = sdb.get_sd(sdb_flags::inheritable);
		if (!sd) {
			return {result::other};
		}
		attr.lpSecurityDescriptor = sd;
	}

	if (CreateDirectory(path.c_str(), &attr)) {
		return {result::ok};
	}

	auto const err = GetLastError();
	switch (err) {
	case ERROR_ACCESS_DENIED:
	case ERROR_LOGON_FAILURE:
		return {result::noperm, err};
	case ERROR_DISK_FULL:
	case ERROR_DISK_QUOTA_EXCEEDED:
		return {result::nospace, err};
	default:
		return {result::other, err};
	}
#else
	int res = ::mkdir(path.c_str(), (permissions == mkdir_permissions::normal) ? 0777 : 0700);
	if (!res) {
		return {result::ok};
	}

	int const err = errno;
	switch (err) {
	case EACCES:
	case EPERM:
	case EROFS:
		return {result::noperm, err};
	case EDQUOT:
	case ENOSPC:
		return {result::nospace, err};
	default:
		return {result::other, err};
	}
#endif
}
}

result mkdir(native_string const& absolute_path, bool recurse, mkdir_permissions permissions, native_string* last_created)
{
	// Step 0: Require an absolute path
#ifdef FZ_WINDOWS
	bool unc{};
	size_t offset{};
	size_t min_len{};
	if (starts_with(absolute_path, std::wstring(L"\\\\?\\"))) {
		offset = 4;
	}
	else if (starts_with(absolute_path, std::wstring(L"\\\\"))) {
		unc = true;
		size_t pos = absolute_path.find_first_of(L"\\/", 2);
		if (pos == std::wstring::npos || pos == 2) {
			return {result::invalid};
		}
		size_t pos2 = absolute_path.find_first_of(L"\\/", pos + 1);
		if (pos2 == pos + 1) {
			return {result::invalid};
		}
		min_len = (pos2 == std::wstring::npos) ? absolute_path.size() : (pos2 - 1);
	}

	if (!unc) {
		auto c = absolute_path[offset];
		if (absolute_path.size() < offset + 2 || absolute_path[offset + 1] != ':' || !is_drive_letter(c)) {
			return {result::invalid};
		}
		size_t pos = absolute_path.find_first_of(L"\\/", offset + 2);
		if (pos != std::wstring::npos && pos != offset + 2) {
			return result{result::invalid};
		}
		min_len = offset + 2;
	}
#else
	if (absolute_path.empty() || absolute_path[0] != '/') {
		return {result::invalid};
	}
	size_t const min_len = 1;
#endif

	// Step 1: Check if directory already exists
	auto t = fz::local_filesys::get_file_type(absolute_path, true);
	if (t == fz::local_filesys::dir) {
		return result{result::ok};
	}
	else if (t != fz::local_filesys::unknown) {
		return result{result::nodir};
	}

	if (recurse) {
		// Step 2: Find a parent that exist
		native_string work = absolute_path;
		while (!work.empty() && local_filesys::is_separator(work.back())) {
			work.pop_back();
		}

		bool found{};
		std::vector<native_string> segments;
		while (work.size() > min_len && !found) {
	#ifdef FZ_WINDOWS
			size_t pos = work.find_last_of(L"\\/");
	#else
			size_t pos = work.rfind('/');
	#endif
			if (pos == native_string::npos) {
				work.clear();
			}

			if (pos + 1 < work.size()) {
				segments.push_back(work.substr(pos + 1));
				work = work.substr(0, pos);
				auto t = fz::local_filesys::get_file_type(work.empty() ? fzT("/") : work, true);

				if (t == fz::local_filesys::dir) {
					found = true;
					break;
				}
				else if (t != fz::local_filesys::unknown) {
					return {result::nodir};
				}
			}
			else {
				work = work.substr(0, pos);
			}
		}
		if (!found) {
			return {result::nodir};
		}

		// Step 3: Create the segments
		for (size_t i = 0; i < segments.size(); ++i) {
			work += local_filesys::path_separator;
			work += segments[segments.size() - i - 1];
			result r = do_mkdir(work, ((i + 1) == segments.size()) ? permissions : mkdir_permissions::normal);
			if (!r) {
				return r;
			}
			if (last_created) {
				*last_created = work;
			}
		}
	}
	else {
		result r = do_mkdir(absolute_path, permissions);
		if (!r) {
			return r;
		}
		if (last_created) {
			*last_created = absolute_path;
		}
	}

	return {result::ok};
}

result remove_dir(native_string const& absolute_path, bool missing_dir_is_error)
{
	if (absolute_path.empty()) {
		return {result::invalid};
	}
#if FZ_WINDOWS
	if (!RemoveDirectoryW(absolute_path.c_str())) {
		DWORD const err = GetLastError();
		switch (err) {
			case ERROR_FILE_NOT_FOUND:
			case ERROR_PATH_NOT_FOUND:
				if (missing_dir_is_error) {
					return {result::nodir, err};
				}
				else {
					return {result::ok};
				}
			case ERROR_ACCESS_DENIED:
			case ERROR_LOGON_FAILURE:
				return {result::noperm, err};
			default:
				return {result::other, err};
		}
	}
#else
	if (rmdir(absolute_path.c_str()) != 0) {
		int const err = errno;
		switch (err) {
			case EACCES:
			case EPERM:
			case EROFS:
				return {result::noperm, err};
			case ENOTDIR:
				return {result::nodir, err};
			case ENOENT:
				if (missing_dir_is_error) {
					return {result::nodir, err};
				}
				else {
					return {result::ok};
				}
			default:
				return {result::other, err};
		}
	}
#endif
	return {result::ok};
}

#ifndef FZ_WINDOWS
namespace {
static result do_copy(native_string const& source, native_string const& dest, bool & dest_opened)
{
	fz::file in(source, fz::file::reading, fz::file::existing);

	if (!in.opened()) {
		// TODO error codes
		return {result::other};
	}

	fz::file out(dest, fz::file::writing, fz::file::empty);
	if (!out.opened()) {
		// TODO error codes
		return {result::other};
	}

	dest_opened = true;

	fz::buffer buffer;
	while (true) {
		if (buffer.empty()) {
			auto read = in.read2(buffer.get(64 * 1024), 64 * 1024);
			if (!read) {
				return {result::other};
			}
			else if (read.value_) {
				buffer.add(read.value_);
			}
			else {
				if (buffer.empty()) {
					return {result::ok};
				}
			}
		}
		auto written = out.write2(buffer.get(), buffer.size());
		if (!written) {
			return {result::other};
		}

		buffer.consume(written.value_);
	}
	if (!out.fsync()) {
		return {result::other};
	}

	return {result::ok};
}
}
#endif

result rename_file(native_string const& source, native_string const& dest, bool allow_copy)
{
#ifdef FZ_WINDOWS
	DWORD flags = MOVEFILE_REPLACE_EXISTING;
	if (allow_copy) {
		flags |= MOVEFILE_COPY_ALLOWED;
	}
	DWORD res = MoveFileExW(source.c_str(), dest.c_str(), flags);
	if (res) {
		return {result::ok};
	}

	DWORD const err = GetLastError();
	switch (err) {
		case ERROR_FILE_NOT_FOUND:
			return {result::nofile, err};
		case ERROR_PATH_NOT_FOUND:
		return {result::nodir, err};
		case ERROR_ACCESS_DENIED:
		case ERROR_LOGON_FAILURE:
			return {result::noperm, err};
		case ERROR_DISK_FULL:
		case ERROR_DISK_QUOTA_EXCEEDED:
			return {result::nospace, err};
		default:
			return {result::other, err};
	}
#else
	int res = rename(source.c_str(), dest.c_str());
	if (!res) {
		return {result::ok};
	}

	int const err = errno;
	switch (err) {
	case EPERM:
	case EACCES:
	case EROFS:
		return {result::noperm, err};
	case ENOSPC:
	case EDQUOT:
		return {result::nospace, err};
	case ENOTDIR:
		return {result::nodir, err};
	case ENOENT:
	case EISDIR:
		return {result::nofile, err};
	case EXDEV:
		if (!allow_copy) {
			return {result::other, err};
		}
		break;
	default:
		return {result::other, err};
	}

	bool dest_opened{};
	auto ret = do_copy(source, dest, dest_opened);
	if (!ret) {
		if (dest_opened) {
			unlink(dest.c_str());
		}
		return ret;
	}

	res = unlink(source.c_str());
	if (res != 0) {
		int const err = errno;
		switch (err) {
		case EPERM:
		case EACCES:
		case EROFS:
			return {result::noperm, err};
		case ENOTDIR:
			return {result::nodir, err};
		case ENOENT:
		case EISDIR:
			return {result::nofile, err};
		default:
			return {result::other, err};
		}
	}

	return result{result::ok};
#endif
}

local_filesys::local_filesys(local_filesys && op) noexcept
{
#if FZ_WINDOWS
	uintptr_t offset{};
	if (op.cur_) {
		offset = op.cur_ - op.buffer_.data();
	}

	buffer_ = std::move(op.buffer_);
	if (op.cur_) {
		cur_ = buffer_.data() + offset;
	}
	dir_ = op.dir_;

	op.buffer_.clear();
	op.cur_ = nullptr;
	op.dir_ = INVALID_HANDLE_VALUE;
#else
	dir_ = op.dir_;
	op.dir_ = nullptr;
#endif
	dirs_only_ = op.dirs_only_;
	query_symlink_targets_ = op.query_symlink_targets_;
}

local_filesys& local_filesys::operator=(local_filesys && op) noexcept
{
	if (&op != this) {
		end_find_files();

#if FZ_WINDOWS
		uintptr_t offset{};
		if (op.cur_) {
			offset = op.cur_ - op.buffer_.data();
		}

		buffer_ = std::move(op.buffer_);
		if (op.cur_) {
			cur_ = buffer_.data() + offset;
		}
		dir_ = op.dir_;

		op.buffer_.clear();
		op.cur_ = nullptr;
		op.dir_ = INVALID_HANDLE_VALUE;
#else
		dir_ = op.dir_;
		op.dir_ = nullptr;
#endif
		dirs_only_ = op.dirs_only_;
		query_symlink_targets_ = op.query_symlink_targets_;
	}
	return *this;
}

}
