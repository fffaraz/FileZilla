#ifndef LIBFILEZILLA_HTTP_DIGEST_HEADER
#define LIBFILEZILLA_HTTP_DIGEST_HEADER

/** \file
 * \brief HTTP digest authorization
 */

#include "headers.hpp"

namespace fz {

class logger_interface;
class uri;

namespace http {

typedef fz::http::headers auth_params;
typedef std::map<std::string, auth_params, fz::less_insensitive_ascii> auth_challenges;

/// Parses challenges from the WWW-Authenticate response header
auth_challenges FZ_PUBLIC_SYMBOL parse_auth_challenges(std::string const& header);

/// Builds the digest going into the Authorization: request header
std::string FZ_PUBLIC_SYMBOL build_digest_authorization(auth_params const& params, unsigned int & nonce_counter, std::string const& verb, uri const& uri, std::string const& user, std::string const& password, fz::logger_interface & logger);

}
}

#endif
