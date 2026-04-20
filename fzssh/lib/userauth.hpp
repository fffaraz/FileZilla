#ifndef FZSSH_USERAUTH_HEADER
#define FZSSH_USERAUTH_HEADER

#include "fzssh/ssh.hpp"
#include "transport.hpp"

#include <list>

namespace fz::ssh {

class private_key;

bool FZSSH_PUBLIC_SYMBOL is_accepted_signature_algorithm(std::string_view supported, std::string_view alg);

class FZSSH_PUBLIC_SYMBOL userauth
{
public:
	userauth(transport & t);
	virtual ~userauth();

	continuation process_binary_packet(message_id id, std::string_view packet);

	virtual continuation process_auth_banner(std::string_view) { return continuation::error_badside; }
	virtual continuation process_auth_request(std::string_view) { return continuation::error_badside; }
	virtual continuation process_auth_success(std::string_view) { return continuation::error_badside; }
	virtual continuation process_auth_failure(std::string_view) { return continuation::error_badside; }
	virtual continuation process_auth_pubkey_ok(std::string_view) { return continuation::error_badside; }
	virtual continuation process_auth_info_request(std::string_view) { return continuation::error_badside; }
	virtual continuation process_auth_info_response(std::string_view) { return continuation::error_badside; }

	virtual message_id get_method_flag() = 0;

	std::string accepted_pk_auth_signatures_;

protected:
	std::string user_;

	transport & transport_;
	logger_interface & logger_;

	bool done_{};
};

}

#endif

