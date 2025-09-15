#include <libfilezilla/process.hpp>
#include <libfilezilla/util.hpp>
#include <libfilezilla/glue/unix.hpp>
#include <libfilezilla/file.hpp>
#include <libfilezilla/buffer.hpp>
#include <libfilezilla/impersonation.hpp>

#include <deque>
#include <iostream>

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

namespace {
// Helper function to extract a directory from argv[0] so that the
// demos can be run independent of the current working directory.
fz::native_string get_program_dir(int argc, char ** argv)
{
	std::string_view path;
	if (argc > 0) {
		path = argv[0];
		auto delim = path.find_last_of("/");
		if (delim == std::string::npos) {
			path = std::string_view();
		}
		else {
			path = path.substr(0, delim + 1);
		}
	}

	return fz::to_native(path);
}
}

int main(int argc, char *argv[])
{
	if (argc == 3 && !strcmp(argv[1], "MAGIC_VALUE!")) {
		std::cerr << "Child: Running with euid " << geteuid() << "\n";
		int sockfd = fz::to_integral<int>(argv[2]);

		// Wait until after parent has dropped its privileges
		char v;
		assert(recv(sockfd, &v, 1, 0) == 1);

		std::cerr << "Child: Opening /tmp/test.txt\n";
		fz::file f;
		if (!f.open("/tmp/test.txt", fz::file::writing, fz::file::empty | fz::file::current_user_only)) {
			std::cerr << "Could not open /tmp/test.txt\n";
			abort();
		}
		int fd = f.detach();
		fz::buffer b;
		b.append("okay\n");
		while (!b.empty()) {
			int error{};
			std::cerr << "Child: Sending descriptor " << fd << " to parent\n";
			int res = fz::send_fd(sockfd, b, fd, error);
			if (res < 0) {
				abort();
			}
			if (fd != -1) {
				close(fd);
			}
			fd = -1;
		}

		return 0;
	}

	auto user = getenv("USER");
	auto pass = getenv("PASS");
	if (!user || !*user || !pass || !*pass) {
		std::cerr << "Pass username and password in the USER and PASS environment variables\n";
		abort();
	}

	std::cerr << "Parent: running with euid " << geteuid() << "\n";
	if (geteuid() != 0) {
		std::cerr << "  Warning: Consider running as root or impersonation will fail.\n";
	}

	fz::impersonation_token t(user, pass);
	if (!t) {
		std::cerr << "Parent: Could not get token\n";
		return 0;
	}

	int spair[2];
	fz::create_socketpair(spair);

	fz::process p;

	auto redir = fz::process::io_redirection::none; // For demo purposes. Use redirect or closeall in actual code.
	bool spawned = p.spawn(t, get_program_dir(argc, argv) + "impersonation", {"MAGIC_VALUE!", fz::to_string(spair[1])}, {spair[1]}, redir);
	std::cerr << "Parent: Spawned child? " << (spawned ? "Yes\n" : "No\n");
	if (!spawned) {
		abort();
	}
	close(spair[1]);

	// Drop privileges
	fz::impersonation_token nobody("nobody", fz::impersonation_options::pwless);
	if (!nobody) {
		std::cerr << "Parent: Could not get token for \"nobody\"\n";
		abort();
	}
	if (!fz::set_process_impersonation(nobody)) {
		std::cerr << "Parent: Could not drop privileges to \"nobody\"\n";
		abort();
	}
	else {
		std::cout << "Parent: Dropped privileges, euid is now " << geteuid() << std::endl;
	}

	char v{};
	assert(send(spair[0], &v, 1, 0) == 1);

	fz::buffer b;
	std::deque<int> fds;

	bool success{};
	while (true) {
		int fd, error;
		int ret = fz::read_fd(spair[0], b, fd, error);
		if (ret < 0) {
			abort();
		}
		if (fd != -1) {
			fds.push_back(fd);
		}

		if (!ret) {
			assert(success);
			assert(fds.empty());
			break;
		}

		if (b.size() > 4) {
			assert(!memcmp(b.get(), "okay\n", 5));
			assert(!fds.empty());
			std::cerr << "Parent: Got file descriptor " << fds.front() << " from child!\n";
			fz::file f(fds.front());
			fds.pop_front();

			auto written = f.write2("Hello world!\n", 13);
			assert(written && written.value_ == 13);
			std::cerr << "Parent: Wrote data to file\n";
			b.consume(5);

			success = true;
		}
	}

	fz::file inaccessible("/tmp/test.txt", fz::file::reading);
	assert(!inaccessible.opened());
	std::cerr << "Parent: As expected, parent cannot open /tmp/test.txt\n";

	return 0;
}
