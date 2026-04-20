#ifndef FZSSH_SSH_HEADER
#define FZSSH_SSH_HEADER

#include "visibility.hpp"

#include <libfilezilla/event.hpp>

#include <memory>

namespace fz {
class event_handler;

namespace ssh {

enum class channel_type
{
	shell,
	exec,
	subsystem,
	direct_tcpip // argument is host,port[,originator_ip,originator_port]
};

enum class compatibility_flags : unsigned
{
	none,
	identification_string_not_terminated_by_crlf = 1
};

inline bool operator&(compatibility_flags lhs, compatibility_flags rhs) {
	return (static_cast<std::underlying_type_t<compatibility_flags>>(lhs) & static_cast<std::underlying_type_t<compatibility_flags>>(rhs)) != 0;
}
inline compatibility_flags operator|(compatibility_flags lhs, compatibility_flags rhs) {
	return static_cast<compatibility_flags>(static_cast<std::underlying_type_t<compatibility_flags>>(lhs) | static_cast<std::underlying_type_t<compatibility_flags>>(rhs));
}
inline compatibility_flags& operator|=(compatibility_flags & lhs, compatibility_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}

struct FZSSH_PUBLIC_SYMBOL parameters  {
	std::string kex_;
	std::string cipher_;
	std::string mac_;
	std::string hostkey_signatures_;

	// Productname and version
	std::string softwareversion_;

	compatibility_flags compatibility_flags_{};

	explicit operator bool() const;
};

/// Excludes weak/insecure algorithms
parameters FZSSH_PUBLIC_SYMBOL get_default_parameters();

/// Includes weak/insecure algorithms
parameters FZSSH_PUBLIC_SYMBOL get_parameters_with_all_algorithms();

/// Just the weak/insecure algorithms
parameters FZSSH_PUBLIC_SYMBOL get_insecure_algorithms();

/**
 * @brief resolves parameter sets
 *
 * There are three known placeholders that are expanded to the respective
 * list of algorithms: DEFAULT,ALL,INSECURE
 *
 * Builds from left to right, preserving order. Prefix any element with
 * hyphen-minus to remove from already built list.
 */
parameters FZSSH_PUBLIC_SYMBOL resolve(parameters const& in, bool keep_unknown = false);

/// Adds algorithm to comma-separated string. Avoids duplicates.
void FZSSH_PUBLIC_SYMBOL add_algorithm(std::string& algs, std::string_view const& to_add);

/// Checks if algorithm is in the comma-separated list
bool FZSSH_PUBLIC_SYMBOL known_algorithm(std::string_view const& in, std::string_view const& algs);

struct algorithm_info
{
	std::string kex_;
	std::string cipher_c2s_;
	std::string cipher_s2c_;
	std::string mac_c2s_;
	std::string mac_s2c_;
	std::string hostkey_signature_;
};

bool FZSSH_PUBLIC_SYMBOL operator==(algorithm_info const& lhs, algorithm_info const& rhs);

class transport;
class FZSSH_PUBLIC_SYMBOL session : public event_source
{
public:
	virtual ~session();

	/// Gets currently negotiated algorithms. Note that algorithms can change with every (re-)key exchange
	algorithm_info current_algorithms();

	/// Including protoverion, softwareversion and optional comments
	std::string peer_identification();

protected:
	std::unique_ptr<transport> impl_;
};

struct session_done_event_type;
typedef event_with_source<session_done_event_type, session*> session_done_event;

struct algorithms_changed_event_type;
typedef event_with_source<algorithms_changed_event_type, session*, algorithm_info> algorithms_changed_event;

struct keyboard_interactive_prompt
{
	std::string prompt_;
	bool echo_{};
};

using keyboard_interactive_prompts = std::vector<keyboard_interactive_prompt>;

}
}

#endif
