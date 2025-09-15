#include "libfilezilla/event.hpp"
#include "libfilezilla/mutex.hpp"

#include <map>

namespace fz {

size_t get_unique_type_id(std::type_info const& id)
{
	std::string name = id.name();

	static mutex m;
	
	scoped_lock l(m);

	static std::map<std::string, size_t> eventTypes;

	auto it = eventTypes.find(name);
	if (it == eventTypes.end()) {
		eventTypes.insert(std::make_pair(name, eventTypes.size()));
		return eventTypes.size() - 1;
	}
	else {
		return it->second;
	}
}

}
