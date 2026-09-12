#include "../lib/libfilezilla/impersonation.hpp"
#include "../lib/libfilezilla/logger.hpp"
#include "../lib/libfilezilla/process.hpp"
#include "../lib/libfilezilla/string.hpp"

#include <cstdlib>
#include <array>
#include <iostream>
#include <string>
#include <vector>

#ifdef FZ_WINDOWS
#include "../lib/libfilezilla/glue/windows.hpp"
#endif

namespace {

struct options
{
	fz::native_string user;
	std::string uid;
	fz::native_string password;
	std::vector<fz::native_string> spawn_command;
#ifdef FZ_WINDOWS
	fz::impersonation_desktop::mode desktop;
	std::string desktop_mode{"automatic"};
	std::wstring desktop_name_prefix;
	fz::impersonation_profile_mode profile{fz::impersonation_profile_mode::require};
	std::string profile_mode{"require"};
	bool drop_admin_privileges{true};
#endif
	bool have_password{};
	bool help{};
	bool redirect{true};
	bool spawn{true};
};

void usage()
{
	std::cerr
		<< "Usage:\n"
		<< "  impersonation (--user USER | --uid UID) [--password PASSWORD | --password-env NAME] [--no-spawn]\n"
		<< "  impersonation (--user USER | --uid UID) [--password PASSWORD | --password-env NAME] [--spawn [COMMAND [ARG...]]]\n"
#ifdef FZ_WINDOWS
		<< "                      [--desktop automatic|isolated|named NAME] [--desktop-prefix PREFIX]\n"
		<< "                      [--profile skip|require-if-roaming|require] [--keep-admin-privileges]\n"
#endif
		<< "                      [--no-redirect]\n"
		<< "\n"
		<< "If no password is supplied, the demo requests a passwordless impersonation token.\n";
}

fz::native_string env_native(char const *name)
{
	if (auto value = std::getenv(name)) {
		return fz::to_native(value);
	}

	return {};
}

bool parse(int argc, char **argv, options &opts)
{
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		auto next = [&]() -> char const * {
			if (i + 1 >= argc) {
				std::cerr << "Missing value for " << arg << "\n";
				return {};
			}

			return argv[++i];
		};

		if (arg == "--user") {
			if (auto v = next()) {
				opts.user = fz::to_native(v);
			}
			else {
				return false;
			}
		}
		else if (arg == "--uid") {
			if (auto v = next()) {
				opts.uid = v;
			}
			else {
				return false;
			}
		}
		else if (arg == "--password") {
			if (auto v = next()) {
				opts.password = fz::to_native(v);
				opts.have_password = true;
			}
			else {
				return false;
			}
		}
		else if (arg == "--password-env") {
			if (auto v = next()) {
				opts.password = env_native(v);
				opts.have_password = true;
			}
			else {
				return false;
			}
		}
		else if (arg == "--desktop") {
#ifdef FZ_WINDOWS
			auto mode = next();
			if (!mode) {
				return false;
			}

			opts.desktop_mode = mode;
			if (opts.desktop_mode == "automatic") {
				opts.desktop = fz::impersonation_desktop::automatic{};
			}
			else if (opts.desktop_mode == "isolated") {
				opts.desktop = fz::impersonation_desktop::isolated{};
			}
			else if (opts.desktop_mode == "named") {
				auto name = next();
				if (!name) {
					return false;
				}

				opts.desktop = fz::impersonation_desktop::named{fz::to_native(name)};
			}
			else {
				std::cerr << "Unknown desktop mode: " << opts.desktop_mode << "\n";
				return false;
			}
#else
			std::cerr << "--desktop is only supported on Windows\n";
			return false;
#endif
		}
		else if (arg == "--profile") {
#ifdef FZ_WINDOWS
			auto mode = next();
			if (!mode) {
				return false;
			}

			opts.profile_mode = mode;
			if (opts.profile_mode == "skip") {
				opts.profile = fz::impersonation_profile_mode::skip;
			}
			else if (opts.profile_mode == "require-if-roaming") {
				opts.profile = fz::impersonation_profile_mode::require_if_roaming;
			}
			else if (opts.profile_mode == "require") {
				opts.profile = fz::impersonation_profile_mode::require;
			}
			else {
				std::cerr << "Unknown profile mode: " << opts.profile_mode << "\n";
				return false;
			}
#else
			std::cerr << "--profile is only supported on Windows\n";
			return false;
#endif
		}
		else if (arg == "--desktop-prefix") {
#ifdef FZ_WINDOWS
			if (auto v = next()) {
				opts.desktop_name_prefix = fz::to_native(v);
			}
			else {
				return false;
			}
#else
			std::cerr << "--desktop-prefix is only supported on Windows\n";
			return false;
#endif
		}
		else if (arg == "--keep-admin-privileges") {
#ifdef FZ_WINDOWS
			opts.drop_admin_privileges = false;
#else
			std::cerr << "--keep-admin-privileges is only supported on Windows\n";
			return false;
#endif
		}
		else if (arg == "--no-spawn") {
			opts.spawn = false;
		}
		else if (arg == "--no-redirect") {
			opts.redirect = false;
		}
		else if (arg == "--spawn") {
			opts.spawn = true;

			for (++i; i < argc; ++i) {
				opts.spawn_command.emplace_back(fz::to_native(argv[i]));
			}

			break;
		}
		else if (arg == "--help" || arg == "-h") {
			opts.help = true;
			return true;
		}
		else {
			std::cerr << "Unknown option: " << arg << "\n";
			return false;
		}
	}

	if (!opts.help && opts.user.empty() && opts.uid.empty()) {
		std::cerr << "Missing --user or --uid\n";
		return false;
	}

	if (!opts.user.empty() && !opts.uid.empty()) {
		std::cerr << "--user and --uid cannot be used together\n";
		return false;
	}

	return true;
}

void set_default_command(options &opts)
{
	if (!opts.spawn_command.empty()) {
		return;
	}

#ifdef FZ_WINDOWS
	opts.spawn_command.emplace_back(fzT("C:\\Windows\\System32\\whoami.exe"));
	opts.spawn_command.emplace_back(fzT("/user"));
#else
	opts.spawn_command.emplace_back(fzT("/usr/bin/id"));
	opts.spawn_command.emplace_back(fzT("-u"));
	opts.spawn_command.emplace_back(fzT("-n"));
#endif
}

bool run_command(fz::impersonation_token const &token, options &opts, fz::logger_interface &logger)
{
	set_default_command(opts);

	auto command = opts.spawn_command.front();
	std::vector<fz::native_string> args;
	args.assign(opts.spawn_command.begin() + 1, opts.spawn_command.end());

	std::cout << "  command: " << fz::to_string(command);
	for (auto const &arg : args) {
		std::cout << " " << fz::to_string(arg);
	}
	std::cout << "\n";

	fz::process process;
	auto const redirection = opts.redirect ? fz::process::io_redirection::redirect : fz::process::io_redirection::none;
	if (!process.spawn(token, command, args, redirection, logger)) {
		std::cerr << "  spawn: FAILED\n";
		return false;
	}

#ifdef FZ_WINDOWS
	HANDLE exit_code_handle{};
	if (!DuplicateHandle(GetCurrentProcess(), static_cast<HANDLE>(process.handle()), GetCurrentProcess(), &exit_code_handle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
		std::cerr << "  exit code: cannot duplicate process handle, error " << GetLastError() << "\n";
	}
#endif

	if (opts.redirect) {
		std::cout << "  output:\n";

		std::array<char, 4096> buffer;
		for (;;) {
			auto const read = process.read(buffer.data(), buffer.size());
			if (!read) {
				std::cerr << "  read: FAILED\n";
				process.kill();
				return false;
			}

			if (!read.value_) {
				break;
			}

			std::cout.write(buffer.data(), static_cast<std::streamsize>(read.value_));
		}
	}

	if (!process.stop(fz::duration::from_seconds(10))) {
		std::cerr << "  wait: timed out; killing child\n";
		process.kill();
		return false;
	}

#ifdef FZ_WINDOWS
	DWORD exit_code{};
	if (exit_code_handle && GetExitCodeProcess(exit_code_handle, &exit_code)) {
		std::cout << "  exit code: " << exit_code << " (0x" << std::hex << exit_code << std::dec << ")\n";
	}
	else {
		std::cerr << "  exit code: unavailable, error " << GetLastError() << "\n";
	}
	if (exit_code_handle) {
		CloseHandle(exit_code_handle);
	}
#endif

	return true;
}

}

int main(int argc, char **argv)
{
	options opts;
	if (!parse(argc, argv, opts)) {
		usage();
		return 2;
	}
	if (opts.help) {
		usage();
		return 0;
	}

	fz::stdout_logger logger;
	logger.set_all(static_cast<fz::logmsg::type>(~uint64_t{}));

	using capability = fz::impersonation_capability;
	using capability_state = fz::impersonation_capability_state;
	auto const capabilities = fz::impersonation_token::get_capabilities({
		capability::password,
		capability::passwordless,
		capability::user_profile
	});
	auto const state = [&](capability c) {
		switch (capabilities[c]) {
		case capability_state::not_requested:
			return "not requested";
		case capability_state::not_applicable:
			return "not applicable";
		case capability_state::indeterminate:
			return "indeterminate";
		case capability_state::unavailable:
			return "unavailable";
		case capability_state::available:
			return "available";
		}

		return "unknown";
	};

	std::cout << "Process capabilities:\n";
	std::cout << "  password-based impersonation: " << state(capability::password) << "\n";
	std::cout << "  passwordless impersonation: " << state(capability::passwordless) << "\n";
	std::cout << "  user profile: " << state(capability::user_profile) << "\n";

	std::cout << "\nToken request:\n";
	if (!opts.uid.empty()) {
		std::cout << "  uid: " << opts.uid << "\n";
	}
	else {
		std::cout << "  user: " << fz::to_string(opts.user) << "\n";
	}
	std::cout << "  mode: " << (opts.have_password ? "password" : "passwordless") << "\n";
#ifdef FZ_WINDOWS
	if (!opts.desktop_name_prefix.empty()) {
		if (opts.desktop_mode != "isolated") {
			std::cerr << "--desktop-prefix requires --desktop isolated\n";
			return 2;
		}

		opts.desktop = fz::impersonation_desktop::isolated{opts.desktop_name_prefix};
	}

	std::cout << "  desktop: " << opts.desktop_mode << "\n";
	std::cout << "  profile: " << opts.profile_mode << "\n";
	if (!opts.desktop_name_prefix.empty()) {
		std::cout << "  desktop prefix: " << fz::to_utf8(opts.desktop_name_prefix) << "\n";
	}
	std::cout << "  drop admin privileges: " << (opts.drop_admin_privileges ? "yes" : "no") << "\n";
#endif

	fz::impersonation_options impersonation_opts;
#ifdef FZ_WINDOWS
	impersonation_opts.desktop = opts.desktop;
	impersonation_opts.profile = opts.profile;
	impersonation_opts.drop_admin_privileges = opts.drop_admin_privileges;
#endif

	auto token = [&]() {
		if (!opts.uid.empty() && opts.have_password) {
			return fz::impersonation_token(fz::user::id{opts.uid}, opts.password, logger, impersonation_opts);
		}

		if (!opts.uid.empty()) {
			return fz::impersonation_token(fz::user::id{opts.uid}, fz::impersonation_options::pwless, logger, impersonation_opts);
		}

		if (opts.have_password) {
			return fz::impersonation_token(opts.user, opts.password, logger, impersonation_opts);
		}

		return fz::impersonation_token(opts.user, fz::impersonation_options::pwless, logger, impersonation_opts);
	}();

	std::cout << "\nToken result:\n";
	if (!token) {
		std::cout << "  token: FAILED\n";
		return 1;
	}

	std::cout << "  token: OK\n";
	std::cout << "  username: " << fz::to_string(token.username()) << "\n";
	std::cout << "  home: " << fz::to_string(token.home()) << "\n";
	std::cout << "  uid: " << token.uid() << "\n";

	std::cout << "\nToken application:\n";
	if (!opts.spawn) {
		std::cout << "  skipped\n";
		return 0;
	}

	return run_command(token, opts, logger) ? 0 : 1;
}
