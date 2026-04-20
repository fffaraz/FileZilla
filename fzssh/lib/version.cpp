#include "config.hpp"

#include <string>
#include <tuple>

#include "fzssh/visibility.hpp"

namespace fz::ssh {
std::string FZSSH_PUBLIC_SYMBOL get_version_string()
{
	return PACKAGE_VERSION_S;
}

std::tuple<int, int, int, int, std::string> FZSSH_PUBLIC_SYMBOL get_version()
{
	return std::make_tuple(PACKAGE_VERSION_MAJOR, PACKAGE_VERSION_MINOR, PACKAGE_VERSION_MICRO, PACKAGE_VERSION_NANO, std::string(PACKAGE_VERSION_SUFFIX_S));
}
}
