#ifndef FILEZILLA_ENGINE_FTP_CWD_HEADER
#define FILEZILLA_ENGINE_FTP_CWD_HEADER

#include "ftpcontrolsocket.h"

class CFtpChangeDirOpData final : public COpData, public CFtpOpData
{
public:
	CFtpChangeDirOpData(CFtpControlSocket & controlSocket)
		: COpData(PrivCommand::cwd, L"CFtpChangeDirOpData"sv)
		, CFtpOpData(controlSocket)
	{}

	virtual int Send() override;
	virtual int ParseResponse() override;

	virtual int SubcommandResult(int, COpData const&) override
	{
		return FZ_REPLY_CONTINUE;
	}

	bool tried_cdup_{};
	bool tryMkdOnFail_{};
	bool link_discovery_{};

	CServerPath path_;
	std::wstring subDir_;
	CServerPath target_;
};

#endif
