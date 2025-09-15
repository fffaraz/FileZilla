#ifndef FILEZILLA_ENGINE_SFTP_SFTPCONTROLSOCKET_HEADER
#define FILEZILLA_ENGINE_SFTP_SFTPCONTROLSOCKET_HEADER

#include "../controlsocket.h"

#include <libfilezilla/rate_limiter.hpp>
#include <libfilezilla/process.hpp>

class SftpInputParser;
struct sftp_message;
struct sftp_list_message;

class CSftpControlSocket final : public CControlSocket, public fz::bucket
{
public:
	CSftpControlSocket(CFileZillaEnginePrivate & engine);
	virtual ~CSftpControlSocket();

	virtual void Connect(CServer const& server, Credentials const& credentials) override;
	virtual void List(CServerPath const& path = CServerPath(), std::wstring const& subDir = std::wstring(), int flags = 0) override;
	void ChangeDir(CServerPath const& path = CServerPath(), std::wstring const& subDir = std::wstring(), bool link_discovery = false);
	virtual void FileTransfer(CFileTransferCommand const& cmd) override;
	virtual void Delete(CServerPath const& path, std::vector<std::wstring>&& files) override;
	virtual void RemoveDir(CServerPath const& path = CServerPath(), std::wstring const& subDir = std::wstring()) override;
	virtual void Mkdir(CServerPath const& path, transfer_flags const& flags = {}) override;
	virtual void Rename(CRenameCommand const& command) override;
	virtual void Chmod(CChmodCommand const& command) override;
	virtual void Cancel() override;

	virtual bool SetAsyncRequestReply(CAsyncRequestNotification *pNotification) override;

protected:
	virtual void Push(std::unique_ptr<COpData> && pNewOpData) override;

	// Replaces filename"with"quotes with
	// "filename""with""quotes"
	std::wstring QuoteFilename(std::wstring const& filename);

	virtual int DoClose(int nErrorCode = FZ_REPLY_DISCONNECTED | FZ_REPLY_ERROR) override;

	void ProcessReply(int result, std::wstring const& reply);

	int SendCommand(std::wstring const& cmd, std::wstring const& show = std::wstring());
	int AddToSendBuffer(std::wstring const& cmd);
	int AddToSendBuffer(std::string const& cmd);
	int SendToProcess();

	virtual void wakeup(fz::direction::type const d) override;
	void OnQuotaRequest(fz::direction::type const d);

	std::unique_ptr<fz::process> process_;
	std::unique_ptr<SftpInputParser> input_parser_;

	virtual void operator()(fz::event_base const& ev) override;
	void OnSftpEvent(sftp_message const& message);
	void OnProcessEvent(fz::process* p, fz::process_event_flag const& f);
	void OnSftpListEvent(sftp_list_message const& message);

	std::wstring m_requestPreamble;
	std::wstring m_requestInstruction;

	CSftpEncryptionNotification m_sftpEncryptionDetails;

	int result_{};
	std::wstring response_;

	fz::buffer send_buffer_;

	friend class CProtocolOpData<CSftpControlSocket>;
	friend class CSftpChangeDirOpData;
	friend class CSftpChmodOpData;
	friend class CSftpConnectOpData;
	friend class CSftpDeleteOpData;
	friend class CSftpFileTransferOpData;
	friend class CSftpListOpData;
	friend class CSftpMkdirOpData;
	friend class CSftpRemoveDirOpData;
	friend class CSftpRenameOpData;
};

typedef CProtocolOpData<CSftpControlSocket> CSftpOpData;

#endif
