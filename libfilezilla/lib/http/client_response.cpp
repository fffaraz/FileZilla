#include "../libfilezilla/http/client_response.hpp"

namespace fz::http::client {

bool response::reset()
{
	flags_ = 0;
	code_ = 0;
	reason_.clear();
	headers_.clear();
	body_.clear();
	return true;
}

}
