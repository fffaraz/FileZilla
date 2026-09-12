#include "impersonation_helper.hpp"

#ifdef FZ_WINDOWS

#include "helpers.hpp"

#include "../libfilezilla/format.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/process.hpp"
#include "../libfilezilla/time.hpp"
#include "../libfilezilla/translate.hpp"

#include <initializer_list>

namespace fz::windows::impersonation_helper {

namespace {

constexpr std::uint32_t max_string_size = 64 * 1024;

bool valid_string_size(std::size_t size, std::size_t max_size = max_string_size)
{
	return size <= max_size && !(size % sizeof(wchar_t));
}

std::uint32_t wire_string_size(std::wstring const &s)
{
	return static_cast<std::uint32_t>(s.size() * sizeof(wchar_t));
}

bool valid_string_size(std::wstring const &s, std::size_t max_size = max_string_size)
{
	return valid_string_size(s.size() * sizeof(wchar_t), max_size);
}

}

std::uint32_t header_version(header const &h)
{
	return h.version_and_flags & version_mask;
}

std::uint32_t header_flags(header const &h)
{
	return h.version_and_flags & ~version_mask;
}

bool header_success(header const &h)
{
	return (header_flags(h) & success) != 0;
}

namespace {

bool read_exact(HANDLE h, void *data, std::size_t size)
{
	auto p = static_cast<unsigned char *>(data);
	while (size) {
		auto const chunk = static_cast<DWORD>(std::min<std::size_t>(size, 64 * 1024));
		DWORD read{};
		if (!ReadFile(h, p, chunk, &read, nullptr) || !read) {
			return false;
		}

		p += read;
		size -= read;
	}

	return true;
}

bool write_exact(HANDLE h, void const *data, std::size_t size)
{
	auto p = static_cast<unsigned char const *>(data);
	while (size) {
		auto const chunk = static_cast<DWORD>(std::min<std::size_t>(size, 64 * 1024));
		DWORD written{};
		if (!WriteFile(h, p, chunk, &written, nullptr) || !written) {
			return false;
		}

		p += written;
		size -= written;
	}

	return true;
}

bool read_exact(fz::process &p, void *data, std::size_t size)
{
	auto out = static_cast<unsigned char *>(data);
	while (size) {
		auto const res = p.read(out, size);
		if (!res || !res.value_) {
			return false;
		}

		out += res.value_;
		size -= res.value_;
	}

	return true;
}

bool write_exact(fz::process &p, void const *data, std::size_t size)
{
	auto in = static_cast<unsigned char const *>(data);
	while (size) {
		auto const res = p.write(in, size);
		if (!res || !res.value_) {
			return false;
		}

		in += res.value_;
		size -= res.value_;
	}

	return true;
}

}

reader::reader(HANDLE handle, logger_interface &logger, std::wstring const &name)
	: handle_(handle)
	, logger_(logger)
{
	request_header(name);
}

reader::reader(fz::process &process, logger_interface &logger, std::wstring const &name)
	: process_(&process)
	, logger_(logger)
{
	response_header(name);
}

void reader::request_header(std::wstring const &name)
{
	impersonation_helper::header h;
	field(h);
	if (!*this) {
		logger_.log(logmsg::error, fztranslate("%s: could not read request header."), name);
		return;
	}

	if (h.magic != magic || header_version(h) != version || header_flags(h) != 0) {
		state_ = stream_state::invalid_data;
		logger_.log(logmsg::error, fztranslate("%s: invalid request header."), name);
	}
}

void reader::response_header(std::wstring const &name)
{
	impersonation_helper::header h;
	field(h);
	if (!*this) {
		logger_.log(logmsg::error, fztranslate("%s: could not read response from helper."), name);
		return;
	}

	if (h.magic != magic || header_version(h) != version) {
		state_ = stream_state::invalid_data;
		logger_.log(logmsg::error, fztranslate("%s: helper returned an invalid response."), name);
		return;
	}

	if (!header_success(h)) {
		std::wstring message;
		field(message);
		if (!*this) {
			logger_.log(logmsg::error, fztranslate("%s: could not read error string from helper."), name);
			return;
		}

		state_ = stream_state::remote_error;
		logger_.log(logmsg::error, fztranslate("%s: helper failed: %s"), name, message.empty() ? L"<no details>" : message.c_str());
	}
}

reader &reader::bytes(void *data, std::size_t size)
{
	if (state_ == stream_state::open) {
		bool const success = process_
			? read_exact(*process_, data, size)
			: read_exact(handle_, data, size);

		if (!success) {
			state_ = stream_state::io_error;
		}
	}

	return *this;
}

reader &reader::field(std::wstring &value)
{
	std::uint32_t size{};
	field(size);

	if (state_ == stream_state::open && !valid_string_size(size)) {
		state_ = stream_state::invalid_data;
	}

	if (state_ == stream_state::open) {
		value.assign(size / sizeof(wchar_t), L'\0');
		bytes(value.data(), size);
	}

	return *this;
}

reader::operator bool() const
{
	return state_ == stream_state::open;
}

stream_state reader::state() const
{
	return state_;
}

writer::writer(HANDLE handle, HANDLE ack_handle)
	: handle_(handle)
	, ack_handle_(ack_handle)
{
}

writer::writer(fz::process &process)
	: process_(&process)
{
	header(0);
}

writer::~writer()
{
	if (process_) {
		ack();
		process_->stop(fz::duration::from_seconds(5));
	}
}

writer &writer::bytes(void const *data, std::size_t size)
{
	if (state_ == stream_state::open) {
		bool const success = process_
			? write_exact(*process_, data, size)
			: write_exact(handle_, data, size);

		if (!success) {
			state_ = stream_state::io_error;
		}
	}

	return *this;
}

writer &writer::field(std::wstring const &value)
{
	if (state_ == stream_state::open && !valid_string_size(value)) {
		state_ = stream_state::invalid_data;
	}

	if (state_ == stream_state::open) {
		auto const size = wire_string_size(value);
		field(size);
		bytes(value.data(), size);
	}

	return *this;
}

writer &writer::header(std::uint32_t flags)
{
	impersonation_helper::header h;
	h.magic = magic;
	h.version_and_flags = version | flags;

	field(h);
	return *this;
}

void writer::error(std::wstring const &message)
{
	if (state_ != stream_state::open) {
		return;
	}

	header(0).field(message);
	finish_response();
}

writer &writer::ack()
{
	char ack{};
	return field(ack);
}

void writer::wait_for_ack()
{
	if (ack_handle_ && *this) {
		char ack{};
		if (!read_exact(ack_handle_, &ack, sizeof(ack))) {
			state_ = stream_state::io_error;
		}
	}
}

void writer::finish_response()
{
	wait_for_ack();
	if (state_ == stream_state::open) {
		state_ = stream_state::finished;
	}
}

void writer::error(wchar_t const *what, DWORD code)
{
	error(fz::sprintf(fztranslate("%s failed. Last Error: %d."), what, code));
}

void writer::invalid()
{
	error(fztranslate("Invalid request."));
}

writer::operator bool() const
{
	return state_ == stream_state::open;
}

std::wstring current_module_path(void const *symbol)
{
	HMODULE module{};

	if (!GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		static_cast<LPCWSTR>(symbol),
		&module
	)) {
		return {};
	}

	std::wstring path(MAX_PATH, L'\0');

	for (;;) {
		DWORD len = GetModuleFileNameW(module, path.data(), DWORD(path.size()+1));

		if (len <= DWORD(path.size())) {
			path.resize(len);
			break;
		}

		path.resize(path.size() * 2);
	}

	return path;
}

std::wstring compute_rundll32_path()
{
	std::wstring path(MAX_PATH, L'\0');

	// [win32 docs] https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw

	for (;;) {
		UINT len = GetSystemDirectoryW(path.data(), UINT(path.size()+1));

		// [win32 docs] If the function succeeds, the return value is the length, in TCHARs, of the string copied to the buffer, not including the terminating null character.
		if (len <= UINT(path.size())) {
			path.resize(len);
			break;
		}

		// [win32 docs] If the length is greater than the size of the buffer, the return value is the size of the buffer required to hold the path, including the terminating null character.
		path.resize(len-1);
	}

	if (!path.empty()) {
		// [win32 docs] This path does not end with a backslash unless the system directory is the root directory.
		if (path.back() != L'\\') {
			path += L'\\';
		}

		path += L"rundll32.exe";
	}

	return path;
}

std::wstring const &rundll32_path()
{
	static std::wstring const ret = compute_rundll32_path();
	return ret;
}

DWORD enable_process_privileges(std::initializer_list<wchar_t const *> privileges)
{
	if (privileges.size() == 0) {
		return ERROR_SUCCESS;
	}

	fz::windows::unique_handle token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, fz::windows::out_ptr(token))) {
		return GetLastError();
	}

	auto requested = fz::windows::holder<TOKEN_PRIVILEGES>::create(
		sizeof(TOKEN_PRIVILEGES) + (privileges.size() - 1) * sizeof(LUID_AND_ATTRIBUTES)
	);
	requested->PrivilegeCount = static_cast<DWORD>(privileges.size());

	std::size_t i{};
	for (auto privilege : privileges) {
		auto &entry = requested->Privileges[i++];
		if (!LookupPrivilegeValueW(nullptr, privilege, &entry.Luid)) {
			return GetLastError();
		}

		entry.Attributes = SE_PRIVILEGE_ENABLED;
	}

	AdjustTokenPrivileges(token.get(), false, requested.get(), 0, nullptr, nullptr);
	return GetLastError();
}

}

#endif
