#ifndef FZSSH_AGENT_HEADER
#define FZSSH_AGENT_HEADER

#include <libfilezilla/event.hpp>

#include "visibility_client.hpp"

#include <memory>

namespace fz {

class event_handler;
class event_loop;
class logger_interface;
class thread_pool;

namespace ssh {

class public_key;
class private_key;

/// Connects to the local SSH agent
class FZSSH_CLIENT_PUBLIC_SYMBOL agent_connection final : public event_source
{
public:
	agent_connection(thread_pool & pool, event_handler& parent, logger_interface & logger);
	~agent_connection();

	agent_connection(agent_connection const&) = delete;
	agent_connection& operator=(agent_connection const&) = delete;

	/// Fetch all available keys
	void get_keys(event_handler& h);

	/// Cancels fetching keys, must call if destroying the handler after get_keys but prio to receiving available_keys_event
	void cancel(event_handler& h);

	class impl;
private:
	std::unique_ptr<impl> impl_;
};

/// \private
struct available_keys_event_type;
/// The list of keys the SSH agent knows about
typedef event_with_source<available_keys_event_type, agent_connection*, std::vector<std::unique_ptr<private_key>>> available_keys_event;

}
}

#endif
