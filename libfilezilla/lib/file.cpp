#include "libfilezilla/libfilezilla.hpp"
#include "libfilezilla/buffer.hpp"
#include "libfilezilla/file.hpp"
#include "libfilezilla/time.hpp"
#include "libfilezilla/util.hpp"

#ifdef FZ_WINDOWS
#include "windows/security_descriptor_builder.hpp"
#include "libfilezilla/util.hpp"
#else
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace fz {

file::file(native_string const& f, mode m, creation_flags d)
{
	open(f, m, d);
}

file::file(file::file_t fd)
	: fd_(fd)
{
}

file::~file()
{
	close();
}

#ifdef FZ_WINDOWS
file::file(file && op) noexcept
	: fd_{op.fd_}
{
	op.fd_ = INVALID_HANDLE_VALUE;
}

file& file::operator=(file && op) noexcept
{
	if (this != &op) {
		close();
		fd_ = op.fd_;
		op.fd_ = INVALID_HANDLE_VALUE;
	}
	return *this;
}

namespace {
DWORD to_access_mode(file::mode m)
{
	switch (m) {
		case file::reading:
			return GENERIC_READ;
		case file::writing:
			return GENERIC_WRITE;
		case file::readwrite:
			return GENERIC_READ|GENERIC_WRITE;
		case file::appending:
			return FILE_APPEND_DATA;
	}
	return 0;
}
}

result file::open(native_string const& f, mode m, creation_flags d)
{
	close();

	if (f.empty()) {
		return {result::invalid};
	}

	DWORD dispositionFlags;
	if (m == writing || m == readwrite || m == appending) {
		if (d & empty) {
			dispositionFlags = (d & nocreate) ? TRUNCATE_EXISTING : CREATE_ALWAYS;
		}
		else if (d & fresh) {
			dispositionFlags = CREATE_NEW;
		}
		else if (d & nocreate) {
			dispositionFlags = OPEN_EXISTING;
		}
		else {
			dispositionFlags = OPEN_ALWAYS;
		}
	}
	else {
		dispositionFlags = OPEN_EXISTING;
	}

	DWORD shareMode = FILE_SHARE_READ;
	if (m == reading) {
		shareMode |= FILE_SHARE_WRITE;
	}

	SECURITY_ATTRIBUTES attr{};
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);

	security_descriptor_builder sdb;
	if (d & (current_user_only | current_user_and_admins_only)) {
		sdb.add(security_descriptor_builder::self);
		if ((d & current_user_and_admins_only) == current_user_and_admins_only) {
			sdb.add(security_descriptor_builder::administrators);
		}

		auto sd = sdb.get_sd(sdb_flags::none);
		if (!sd) {
			return {result::other};
		}
		attr.lpSecurityDescriptor = sd;
	}
	fd_ = CreateFileW(f.c_str(), to_access_mode(m), shareMode, &attr, dispositionFlags, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

	if (fd_ == INVALID_HANDLE_VALUE) {
		auto const err = GetLastError();
		switch (err) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			return {result::nofile, err};
		case ERROR_ACCESS_DENIED:
			return {result::noperm, err};
		case ERROR_DISK_FULL:
		case ERROR_DISK_QUOTA_EXCEEDED:
			return {result::nospace, err};
		case ERROR_TOO_MANY_OPEN_FILES:
			return {result::resource_limit, err};
		case ERROR_FILE_EXISTS:
			return {result::preexisting, err};
		default:
			return {result::other, err};
		}
	}

	return {result::ok};
}

void file::close()
{
	if (fd_ != INVALID_HANDLE_VALUE) {
		CloseHandle(fd_);
		fd_ = INVALID_HANDLE_VALUE;
	}
}

file::file_t file::detach()
{
	file_t fd = fd_;
	fd_ = INVALID_HANDLE_VALUE;
	return fd;
}

int64_t file::size() const
{
	int64_t ret = -1;

	LARGE_INTEGER size{};
	if (GetFileSizeEx(fd_, &size)) {
		ret = static_cast<int64_t>(size.QuadPart);
	}
	return ret;
}

int64_t file::seek(int64_t offset, seek_mode m)
{
	int64_t ret = -1;

	LARGE_INTEGER dist{};
	dist.QuadPart = offset;

	DWORD method = FILE_BEGIN;
	if (m == current) {
		method = FILE_CURRENT;
	}
	else if (m == end) {
		method = FILE_END;
	}

	LARGE_INTEGER newPos{};
	if (SetFilePointerEx(fd_, dist, &newPos, method)) {
		ret = newPos.QuadPart;
	}
	return ret;
}

bool file::truncate()
{
	return !!SetEndOfFile(fd_);
}

rwresult file::read2(void *buf, size_t count)
{
	DWORD read = 0;
	if (ReadFile(fd_, buf, clamped_cast<DWORD>(count), &read, nullptr)) {
		return rwresult{static_cast<size_t>(read)};
	}

	DWORD err = GetLastError();
	return rwresult{rwresult::other, err};
}

rwresult file::write2(void const* buf, size_t count)
{
	DWORD written = 0;
	if (WriteFile(fd_, buf, clamped_cast<DWORD>(count), &written, nullptr)) {
		return rwresult{static_cast<size_t>(written)};
	}

	DWORD err = GetLastError();
	switch (err) {
		case ERROR_DISK_FULL:
		case ERROR_DISK_QUOTA_EXCEEDED:
			return rwresult{rwresult::nospace, err};
		default:
			return rwresult{rwresult::other, err};
	}
}

bool file::opened() const
{
	return fd_ != INVALID_HANDLE_VALUE;
}

result remove_file(native_string const& name, bool missing_file_is_error)
{
	if (name.empty()) {
		return {result::invalid, 0};
	}

	if (DeleteFileW(name.c_str()) != 0) {
		return {result::ok};
	}

	DWORD err = GetLastError();
	switch (err) {
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
		if (missing_file_is_error) {
			return {result::nofile, err};
		}
		return {result::ok};
	case ERROR_ACCESS_DENIED:
		return {result::noperm, err};
	default:
		return {result::other, err};
	}
}

bool file::fsync()
{
	return FlushFileBuffers(fd_) != 0;
}

bool file::set_modification_time(datetime const& t)
{
	if (t.empty()) {
		return false;
	}

	FILETIME ft = t.get_filetime();
	if (!ft.dwHighDateTime) {
		return false;
	}

	return SetFileTime(fd_, nullptr, &ft, &ft) == TRUE;
}

datetime file::get_modification_time()
{
	FILETIME ft{};

	if (GetFileTime(fd_, nullptr, nullptr, &ft)) {
		return datetime(ft, datetime::milliseconds);
	};

	return {};
}
#else

file::file(file && op) noexcept
	: fd_{op.fd_}
{
	op.fd_ = -1;
}

file& file::operator=(file && op) noexcept
{
	if (this != &op) {
		close();
		fd_ = op.fd_;
		op.fd_ = -1;
	}
	return *this;
}

result file::open(native_string const& f, mode m, creation_flags d)
{
	close();

	if (f.empty()) {
		return {result::invalid};
	}

	int flags = O_CLOEXEC;
	if (m == reading) {
		flags |= O_RDONLY;
	}
	else {
		flags |= (m == readwrite) ? O_RDWR : O_WRONLY;
		if (m == appending) {
			flags |= O_APPEND;
		}

		if (!(d & nocreate)) {
			flags |= O_CREAT;
		}

		if (d & empty) {
			flags |= O_TRUNC;
		}
		else if (d & fresh) {
			flags |= O_EXCL;
		}
	}
	int mode = S_IRUSR | S_IWUSR;
	if (!(d & (current_user_only | current_user_and_admins_only))) {
		mode |= S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
	}
	fd_ = ::open(f.c_str(), flags, mode);
	if (fd_ == -1) {
		int const err = errno;
		switch (err) {
		case ENOENT:
			return {result::nofile, err};
		case EACCES:
		case EPERM:
		case EROFS:
			return {result::noperm, err};
		case EDQUOT:
		case ENOSPC:
			return {result::nospace, err};
		case EMFILE:
		case ENFILE:
			return {result::resource_limit, err};
		case EEXIST:
			return {result::preexisting, err};
		default:
			return {result::other, err};
		}
	}

#if HAVE_POSIX_FADVISE
	(void)posix_fadvise(fd_, 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);
#endif

	return {result::ok};
}

void file::close()
{
	if (fd_ != -1) {
		::close(fd_);
		fd_ = -1;
	}
}

file::file_t file::detach()
{
	file_t fd = fd_;
	fd_ = -1;
	return fd;
}

int64_t file::size() const
{
	int64_t ret = -1;

	struct stat buf;
	if (!fstat(fd_, &buf)) {
		if (!S_ISCHR(buf.st_mode)) {
			ret = buf.st_size;
		}
	}

	return ret;
}

int64_t file::seek(int64_t offset, seek_mode m)
{
	int64_t ret = -1;

	int whence = SEEK_SET;
	if (m == current) {
		whence = SEEK_CUR;
	}
	else if (m == end) {
		whence = SEEK_END;
	}

	auto newPos = lseek(fd_, offset, whence);
	if (newPos != static_cast<off_t>(-1)) {
		ret = newPos;
	}

	return ret;
}

bool file::truncate()
{
	bool ret = false;

	auto length = lseek(fd_, 0, SEEK_CUR);
	if (length != static_cast<off_t>(-1)) {
		do {
			ret = !ftruncate(fd_, length);
		} while (!ret && (errno == EAGAIN || errno == EINTR));
	}

	return ret;
}

rwresult file::read2(void *buf, size_t count)
{
	ssize_t ret;
	do {
		ret = ::read(fd_, buf, count);
	} while (ret == -1 && (errno == EAGAIN || errno == EINTR));

	if (ret >= 0) {
		return rwresult{static_cast<size_t>(ret)};
	}

	rwresult::raw_t err = errno;
	switch (err) {
	case EBADF:
	case EINVAL:
	case EFAULT:
		return rwresult{rwresult::invalid, err};
	default:
		return rwresult{rwresult::other, err};
	}
}

rwresult file::write2(void const* buf, size_t count)
{
	ssize_t ret;
	do {
		ret = ::write(fd_, buf, count);
	} while (ret == -1 && (errno == EAGAIN || errno == EINTR));

	if (ret >= 0) {
		return rwresult{static_cast<size_t>(ret)};
	}

	rwresult::raw_t err = errno;
	switch (err) {
	case EBADF:
	case EINVAL:
	case EFAULT:
		return rwresult{rwresult::invalid, err};
	case EDQUOT:
	case ENOSPC:
		return rwresult{rwresult::nospace, err};
	default:
		return rwresult{rwresult::other, err};
	}
}

bool file::opened() const
{
	return fd_ != -1;
}

result remove_file(native_string const& name, bool missing_file_is_error)
{
	if (name.empty()) {
		return {result::invalid, 0};
	}

	if (!unlink(name.c_str())) {
		return {result::ok};
	}
	int err = errno;
	switch (errno) {
	case ENOENT:
		if (missing_file_is_error) {
			return {result::nofile, err};
		}
		return {result::ok};
	case EISDIR:
		return {result::nofile, err};
	case EACCES:
	case EPERM:
	case EROFS:
		return {result::noperm, err};
	case EINVAL:
	case ENAMETOOLONG:
		return {result::invalid, err};
	default:
		return {result::other, err};
	}
}

bool file::fsync()
{
#if defined(_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
	return fdatasync(fd_) == 0;
#else
	return ::fsync(fd_) == 0;
#endif
}

bool file::set_modification_time(datetime const& t)
{
	if (t.empty()) {
		return false;
	}

	struct timespec times[2]{};
	times[0].tv_nsec = UTIME_OMIT;
	times[1].tv_sec = t.get_time_t();
	times[1].tv_nsec = t.get_milliseconds() * 1000000;
	return futimens(fd_, times) == 0;
}

datetime file::get_modification_time()
{
	struct stat buf;

	if (fstat(fd_, &buf) == 0) {
#if HAVE_STRUCT_STAT_ST_MTIM
		return datetime(buf.st_mtim.tv_sec, datetime::milliseconds) + fz::duration::from_milliseconds(buf.st_mtim.tv_nsec/1000000);
#else
		return datetime(buf.st_mtime, datetime::seconds);
#endif
	}

	return {};
}
#endif

rwresult read_file(fz::file & f, buffer & out, size_t max_size)
{
	if (std::numeric_limits<size_t>::max() - max_size > out.size()) {
		return rwresult{rwresult::invalid, 0};
	}

	auto s = f.size();
	if (s >= 0) {
		if (cmp_less(max_size, s)) {
			return rwresult{rwresult::nospace, {}};
		}
	}

	size_t old_size = out.size();
	while (max_size) {
		size_t to_read = std::min(size_t(1024 * 128), max_size);
		rwresult read = f.read2(out.get(to_read), to_read);
		if (!read) {
			out.resize(old_size);
			return read;
		}
		if (!read.value_) {
			break;
		}
		out.add(read.value_);
		max_size -= read.value_;
	}

	if (!max_size) {
		// Check for EOF and fail if file is larger.
		uint8_t tmp{};
		rwresult read = f.read2(&tmp, 1);
		if (!read) {
			out.resize(old_size);
			return read;
		}
		if (read.value_) {
			out.resize(old_size);
			return rwresult{rwresult::nospace, {}};
		}
	}

	return rwresult{out.size() - old_size};
}

}
