#include "libfilezilla/tls_params.hpp"

using namespace std::literals;

namespace fz {

bool is_pem(std::string_view blob)
{
	bool got_preamble{};
	for (auto line : strtokenizer(blob, "\n\r"sv, true)) {
		if (!got_preamble) {
			if (!starts_with(line, "-----BEGIN "sv)) {
				continue;
			}
			trim(line);
			if (!ends_with(line, "-----"sv)) {
				continue;
			}
			got_preamble = true;
		}
		else {
			if (!starts_with(line, "-----END "sv)) {
				continue;
			}
			trim(line);
			if (!ends_with(line, "-----"sv)) {
				continue;
			}
			return true;
		}
	}

	return false;
}

}
