#ifndef FILEZILLA_ENGINE_SFTP_CONNECT_HEADER
#define FILEZILLA_ENGINE_SFTP_CONNECT_HEADER

#include "sftpcontrolsocket.h"

class SshAuth;

class CSftpConnectOpData final : public COpData, public CSftpOpData
{
public:
	CSftpConnectOpData(CSftpControlSocket & controlSocket)
		: COpData(Command::connect, L"CSftpConnectOpData")
		, CSftpOpData(controlSocket)
	{}

	virtual ~CSftpConnectOpData();

	virtual int Send() override;
	virtual int ParseResponse() override { return FZ_REPLY_INTERNALERROR; }

	void on_sftp_ready(fz::ssh::sftp::sftp_client*);
	SshAuth* auth() const { return auth_.get(); }

private:
	void on_authenticated();

	fz::monotonic_clock sftp_subsystem_request_time_;
	std::unique_ptr<SshAuth> auth_;
};

#endif
