#ifndef LIBFILEZILLA_WINDOWS_IMPERSONATION_HELPER_HEADER
#define LIBFILEZILLA_WINDOWS_IMPERSONATION_HELPER_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"

#include <cstdint>
#include <initializer_list>
#include <string>

namespace fz {

class logger_interface;
class process;

namespace windows::impersonation_helper {

constexpr std::uint32_t magic = 0x465a4948; // FZIH
constexpr std::uint32_t version = 1;
constexpr std::uint32_t success = 0x80000000u;
constexpr std::uint32_t version_mask = 0x7fffffffu;

/*
Helper IPC frame, native binary layout:

  uint32 magic              'FZIH'
  uint32 version_and_flags  version in low bits, flags in high bits

The success flag is only set on successful responses. Failed responses have no
helper-specific body; they carry one string field containing the error message.

String field:

  uint32 byte_count
  wchar_t data[byte_count / sizeof(wchar_t)]  no trailing NUL

This is private same-machine IPC between libfilezilla and its rundll32 helper,
not a stable external protocol.
*/
struct header
{
	std::uint32_t magic{};
	std::uint32_t version_and_flags{};
};

std::uint32_t header_version(header const &h);
std::uint32_t header_flags(header const &h);
bool header_success(header const &h);

enum class stream_state
{
	open,
	finished,
	invalid_data,
	io_error,
	remote_error
};

class reader final
{
public:
	reader(HANDLE handle, logger_interface &logger, std::wstring const &name);
	reader(fz::process &process, logger_interface &logger, std::wstring const &name);

	reader(reader const&) = delete;
	reader& operator=(reader const&) = delete;

	template <typename T>
	reader &field(T &value)
	{
		return bytes(&value, sizeof(value));
	}

	reader &field(std::wstring &value);

	explicit operator bool() const;
	stream_state state() const;

private:
	reader &bytes(void *data, std::size_t size);
	void request_header(std::wstring const &name);
	void response_header(std::wstring const &name);

	HANDLE handle_{};
	fz::process *process_{};
	logger_interface &logger_;
	stream_state state_{stream_state::open};
};

class writer final
{
public:
	writer(HANDLE handle, HANDLE ack_handle);
	explicit writer(fz::process &process);
	~writer();

	writer(writer const&) = delete;
	writer& operator=(writer const&) = delete;

	template <typename T>
	writer &field(T const &value)
	{
		return bytes(&value, sizeof(value));
	}

	writer &field(std::wstring const &value);

	template <typename... Ts>
	void success(Ts const &... values)
	{
		if (state_ != stream_state::open) {
			return;
		}

		header(impersonation_helper::success);
		(field(values), ...);
		finish_response();
	}

	void error(std::wstring const &message);
	void error(wchar_t const *what, DWORD code);
	void invalid();

	explicit operator bool() const;

private:
	writer &bytes(void const *data, std::size_t size);
	writer &header(std::uint32_t flags);
	writer &ack();
	void finish_response();
	void wait_for_ack();

	HANDLE handle_{};
	HANDLE ack_handle_{};
	fz::process *process_{};
	stream_state state_{stream_state::open};
};

std::wstring current_module_path(void const *symbol);
std::wstring const &rundll32_path();

DWORD enable_process_privileges(std::initializer_list<wchar_t const *> privileges);

}

}

#endif

#endif
