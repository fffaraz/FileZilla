#ifndef FILEZILLA_ENGINE_SFTP_CONNECT_HEADER
#define FILEZILLA_ENGINE_SFTP_CONNECT_HEADER

#include "sftpcontrolsocket.h"

class CSftpConnectOpData final : public COpData, public CSftpOpData
{
public:
	CSftpConnectOpData(CSftpControlSocket & controlSocket)
		: COpData(Command::connect, L"CSftpConnectOpData")
		, CSftpOpData(controlSocket)
		, keyfile_(keyfiles_.cend())
	{}

	virtual int Send() override;
	virtual int ParseResponse() override;
	virtual int Reset(int result) override;

	std::wstring lastChallenge;
	CInteractiveLoginNotification::type lastChallengeType{ CInteractiveLoginNotification::interactive };
	bool criticalFailure{};

	std::vector<std::wstring> keyfiles_;
	std::vector<std::wstring>::const_iterator keyfile_;
};

#endif
