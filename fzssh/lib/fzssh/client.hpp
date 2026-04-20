#ifndef FZSSH_CLIENT_HEADER
#define FZSSH_CLIENT_HEADER

#include "pubkey.hpp"
#include "ssh.hpp"
#include "visibility_client.hpp"

namespace fz {
class logger_interface;
class socket;
class socket_interface;

namespace ssh {

class private_key;

class FZSSH_CLIENT_PUBLIC_SYMBOL client_parameters final : public parameters
{
public:
	client_parameters();

	/// If set to true, only a single channel can be opened and no-flow-control ext-info is set to "p"
	bool single_channel_{false};
};

class FZSSH_CLIENT_PUBLIC_SYMBOL client final : public session
{
public:
	client(client_parameters const& params, std::string_view username, socket_interface &, event_handler & h, logger_interface & logger);
	virtual ~client();

	/// Make sure to destroy all channels prior to destroying the client
	std::unique_ptr<socket_interface> open_channel(channel_type type, std::string_view const& name);

	/// Call after getting hostkey_verification_event
	void hostkey_decision(bool accept);

	/// For authentication with keys, algorithms not in this list are not available
	std::string accepted_pubkey_algorithms();

	/// Can be called after getting auth_requested_event.
	/// If left empty, fzssh picks a suitable algorithm based on the key and the server's preferences
	void auth_with_key(std::unique_ptr<private_key> const& key, bool with_signature, std::string_view const& signature_algorithm = {});

	/// This merely checks whether the server would accept a signature created with the corresponding private key
	/// If left empty, fzssh picks a suitable algorithm based on the key and the server's preferences
	void auth_with_key(std::unique_ptr<public_key> const& key, std::string_view const& signature_algorithm = {});

	/// Can be called after getting auth_requested_event
	void auth_with_password(std::string_view const& pw);

	/// Can be called after getting auth_requested_event. If server accepts to use keyboard-interactive auth, it will send prompts, wait for //TODO
	void auth_keyboard_interactive();

	/// \brief Can be called after getting auth_keyboard_interactive_prompt_event
	///
	/// Number of respones must be equal to number of prompts
	void auth_keyboard_interactive_response(std::vector<std::string> const& responses);
};

/// \private
struct hostkey_verification_event_type;
/// Sent during the initial key exchange and on every subsequent re-keying if the host key changes. Reply to with hostkey_decision
typedef event_with_source<hostkey_verification_event_type, client*, std::unique_ptr<public_key>, algorithm_info> hostkey_verification_event;

/// \private
struct auth_done_event_type;
/// Authentication has succeeded. Proceed to open channels.
typedef event_with_source<auth_done_event_type, client*> auth_done_event;

/// \private
struct auth_requested_event_type;
/// The server requires authentication
typedef event_with_source<auth_requested_event_type, client*, std::string /*methods*/, bool /*is_continuation*/> auth_requested_event;

/// \private
struct auth_public_key_okay_event_type;
/// Sent after auth_with_key without signature if the server would accept the key
typedef event_with_source<auth_public_key_okay_event_type, client*> auth_public_key_okay_event;

/// \private
struct auth_signature_failure_event_type;
/// A private key operation has failed, e.g. if the SSH agent failed, or user supplied wrong pin for harware token.
/// Try again, or proceed with a different key or auth method.
typedef event_with_source<auth_signature_failure_event_type, client*> auth_signature_failure_event;

struct auth_keyboard_interactive_prompt_event_type;
typedef event_with_source<auth_keyboard_interactive_prompt_event_type, client*, std::string /*name*/, std::string /*instruction*/, std::vector<keyboard_interactive_prompt> /*prompts*/> auth_keyboard_interactive_prompt_event;

}
}

#endif

