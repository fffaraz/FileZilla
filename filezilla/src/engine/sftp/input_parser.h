#ifndef FILEZILLA_ENGINE_SFTP_INPUTPARSER_HEADER
#define FILEZILLA_ENGINE_SFTP_INPUTPARSER_HEADER

class CSftpControlSocket;

#include "event.h"

#include <libfilezilla/buffer.hpp>

namespace fz {
class process;
}

class SftpInputParser final
{
public:
	SftpInputParser(CSftpControlSocket & owner, fz::process& proc);
	~SftpInputParser();

	int OnData();

protected:

	size_t lines(sftpEvent eventType) const;

	fz::process& process_;
	CSftpControlSocket& owner_;

	fz::buffer recv_buffer_;
	size_t pending_lines_{};
	size_t search_offset_{};
	std::unique_ptr<CSftpEvent> event_{};
	std::unique_ptr<CSftpListEvent> listEvent_{};
};

#endif
