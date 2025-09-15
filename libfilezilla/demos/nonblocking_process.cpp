/**
 * This is the demo for non-blocking communication with a child process.
 * For understanding, first start with the blocking communication in process.cpp
 */
#include <libfilezilla/buffer.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/thread_pool.hpp>
#include <libfilezilla/process.hpp>

#include <iostream>
#include <string>

namespace {
// Helper function to extract a directory from argv[0] so that the
// demos can be run independent of the current working directory.
fz::native_string get_program_dir(int argc, char ** argv)
{
	std::string_view path;
	if (argc > 0) {
		path = argv[0];
#ifdef FZ_WINDOWS
		auto delim = path.find_last_of("/\\");
#else
		auto delim = path.find_last_of("/");
#endif
		if (delim == std::string::npos) {
			path = std::string_view();
		}
		else {
			path = path.substr(0, delim + 1);
		}
	}

	return fz::to_native(path);
}

#ifdef FZ_WINDOWS
auto suffix = fzT(".exe");
#else
auto suffix = fzT("");
#endif
}

class runner final : public fz::event_handler
{
public:
	runner(fz::thread_pool & pool, fz::event_loop & loop)
		: fz::event_handler(loop)
		, process_(pool, *this)
	{}

	~runner()
	{
		remove_handler();
		process_.kill();
	}

	virtual void operator()(fz::event_base const& ev) override
	{
		fz::dispatch<fz::process_event>(ev, this, &runner::on_process_event);
	}

	void on_process_event(fz::process *, fz::process_event_flag flag)
	{
		if (flag == fz::process_event_flag::read) {
			on_read();
		}
	}

	void on_read()
	{
		// We don't want to do anything else while waiting, so we don't need a thread to receive data asynchronously
		std::string input;
		while (!done_) {
			char buf[100];
			fz::rwresult r = process_.read(buf, 100);
			if (!r) {
				if (r.error_ == fz::rwresult::wouldblock) {
					return;
				}
				std::cerr << "Could not read from process" << std::endl;
				exit(1);
			}
			else if (!r.value_) {
				std::cerr << "Unexpected EOF from process" << std::endl;
				exit(1);
			}

			input += std::string(buf, r.value_);

			// Extract complete lines from the input
			auto delim = input.find_first_of("\r\n");
			while (delim != std::string::npos) {
				std::string line = input.substr(0, delim);
				input = input.substr(delim + 1);
				delim = input.find_first_of("\r\n");

				if (!line.empty()) {
					std::cout << "Received line from process: " << line << std::endl;
					if (line == "woof") {
						done_ = true;

						// Send a line to the process
						if (!process_.write("0\n")) {
							std::cerr << "Sending data to the process failed. Looks like it could not be started or has quit early." << std::endl;
							exit(1);
						}
						std::cout << "Told process to quit." << std::endl;
					}
				}
			}
		}

		while (true) {
			char buf[100];
			fz::rwresult r = process_.read(buf, 100);
			if (!r) {
				if (r.error_ == fz::rwresult::wouldblock) {
					return;
				}
				std::cerr << "Could not read from process" << std::endl;
				exit(1);
			}
			else if (!r.value_) {
				std::cerr << "Received the expected EOF from process" << std::endl;
				break;
			}
		}

		event_loop_.stop();
	}

	fz::process process_;
	bool done_{};
};


int main(int argc, char *argv[])
{
	fz::thread_pool pool;
	fz::event_loop loop(fz::event_loop::threadless);

	runner h(pool, loop);

	// Start the timer_fizzbuzz demo which should be in the same directory as the process demo
	if (!h.process_.spawn(get_program_dir(argc, argv) + fzT("timer_fizzbuzz") + suffix)) {
		std::cerr << "Could not spawn process" << std::endl;
		return 1;
	}
	std::cout << "Spawned process" << std::endl;

	// Send a line to the process
	fz::buffer buf;
	buf.append("6\n");
	while (!buf.empty()) {
		fz::rwresult r = h.process_.write(buf.get(), buf.size());
		if (!r) {
			std::cerr << "Sending data to the process failed. Looks like it could not be started or has quit early." << std::endl;
			return 1;
		}
		buf.consume(r.value_);
	}

	std::cout << "Waiting on process to print woof..." << std::endl;

	loop.run();
}
