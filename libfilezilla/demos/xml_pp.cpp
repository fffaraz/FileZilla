#include <libfilezilla/time.hpp>
#include <libfilezilla/xml.hpp>

#include <iostream>
#include <unistd.h>

using namespace std::literals;

#ifdef FZ_WINDOWS
#include <windows.h>
#endif

class pretty_printer_out : public fz::xml::pretty_printer
{
public:
	void on_line(std::string_view line) {
		std::cout << line << "\n";
	}
};


int main(int argc, char * argv[])
{
#if FZ_WINDOWS
	CPINFOEXW info{};
	if (GetCPInfoExW(CP_UTF8, 0, &info)) {
		SetConsoleCP(info.CodePage);
		SetConsoleOutputCP(info.CodePage);
	}
#endif

	bool print{true};
	for (int i = 1; i < argc; ++i) {
		if (std::string(argv[i]) == "-q"sv) {
			print = false;
		}
	}

	pretty_printer_out printer;
	fz::xml::parser parser;

	if (print) {
		parser.set_callback([&printer](fz::xml::callback_event t, std::string_view path, std::string_view name, std::string && value) { printer.log(t, path, name, value); return true; });
	}

	size_t total{};
	auto const start = fz::datetime::now();
	while (true) {
		char buf[1024];
		int f = read(0, buf, 1024);
		if (f <= 0) {
			if (!parser.finalize()) {
				std::cerr << parser.get_error() << "\n";
				return 1;
			}
			break;
		}
		if (!parser.parse(std::string_view(buf, f))) {
			std::cerr << parser.get_error() << "\n";
			return 1;
		}
		total += f;
	}
	auto const stop = fz::datetime::now();
	for (int i = 1; i < argc; ++i) {
		if (std::string(argv[i]) == "-s"sv) {
			auto const ms = (stop - start).get_milliseconds();
			std::cerr << "Runtime: " << ms << "ms\n";

			if (ms) {
				total *= 1000;
				total /= ms;
				std::cerr << total/1024/1024 << " MiB/s\n";
			}
		}
	}

	return 0;
}

