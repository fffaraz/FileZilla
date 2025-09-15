#ifndef FILEZILLA_ENGINE_SFTP_CWD_HEADER
#define FILEZILLA_ENGINE_SFTP_CWD_HEADER

#include "sftpcontrolsocket.h"

class CSftpChangeDirOpData final : public CChangeDirOpData, public CSftpOpData
{
public:
	CSftpChangeDirOpData(CSftpControlSocket & controlSocket)
		: CChangeDirOpData(L"CSftpChangeDirOpData")
		, CSftpOpData(controlSocket)
	{}

	virtual int Send() override;
	virtual int ParseResponse() override;
	
	virtual int SubcommandResult(int, COpData const&) override
	{
		return FZ_REPLY_CONTINUE;
	}
};

#endif
