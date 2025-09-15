#include "../filezilla.h"

#include "chmod.h"
#include "connect.h"
#include "cwd.h"
#include "delete.h"
#include "event.h"
#include "filetransfer.h"
#include "list.h"
#include "input_parser.h"
#include "mkd.h"
#include "rename.h"
#include "rmd.h"
#include "sftpcontrolsocket.h"

#include "../directorycache.h"
#include "../directorylistingparser.h"
#include "../engineprivate.h"
#include "../pathcache.h"
#include "../proxy.h"
#include "../servercapabilities.h"

#include "../../include/engine_options.h"

#include <libfilezilla/event_loop.hpp>
#include <libfilezilla/process.hpp>

#include <algorithm>

#include <assert.h>

#ifndef FZ_WINDOWS
#include <unistd.h>
#endif

struct SftpRateAvailableEventType;
typedef fz::simple_event<SftpRateAvailableEventType, fz::direction::type> SftpRateAvailableEvent;

CSftpControlSocket::CSftpControlSocket(CFileZillaEnginePrivate & engine)
	: CControlSocket(engine, true)
{
	m_useUTF8 = true;
}

CSftpControlSocket::~CSftpControlSocket()
{
	remove_bucket();
	remove_handler();
	DoClose();
}

void CSftpControlSocket::Connect(CServer const& server, Credentials const& credentials)
{
	if (server.GetEncodingType() == ENCODING_CUSTOM) {
		log(logmsg::debug_info, L"Using custom encoding: %s", server.GetCustomEncoding());
		m_useUTF8 = false;
	}

	currentServer_ = server;
	credentials_ = credentials;

	Push(std::make_unique<CSftpConnectOpData>(*this));
}

void CSftpControlSocket::OnSftpEvent(sftp_message const& message)
{
	if (!currentServer_) {
		return;
	}

	if (!input_parser_) {
		return;
	}

	switch (message.type)
	{
	case sftpEvent::Reply:
		log_raw(logmsg::reply, message.text[0]);
		ProcessReply(FZ_REPLY_OK, message.text[0]);
		break;
	case sftpEvent::Done:
		{
			int result;
			if (message.text[0] == L"1") {
				result = FZ_REPLY_OK;
			}
			else if (message.text[0] == L"2") {
				result = FZ_REPLY_CRITICALERROR;
			}
			else {
				result = FZ_REPLY_ERROR;
			}
			ProcessReply(result, std::wstring());
		}
		break;
	case sftpEvent::Error:
		log_raw(logmsg::error, message.text[0]);
		break;
	case sftpEvent::Verbose:
		log_raw(logmsg::debug_info, message.text[0]);
		break;
	case sftpEvent::Info:
		log_raw(logmsg::command, message.text[0]); // Not exactly the right message type, but it's a silent one.
		break;
	case sftpEvent::Status:
		log_raw(logmsg::status, message.text[0]);
		break;
	case sftpEvent::Recv:
		RecordActivity(activity_logger::recv, fz::to_integral<uint64_t>(message.text[0]));
		break;
	case sftpEvent::Send:
		RecordActivity(activity_logger::send, fz::to_integral<uint64_t>(message.text[0]));
		break;
	case sftpEvent::Transfer:
		{
			auto value = fz::to_integral<int64_t>(message.text[0]);

			bool tmp;
			CTransferStatus status = engine_.transfer_status_.Get(tmp);
			if (!status.empty()) {
				if (!operations_.empty() && operations_.back()->opId == Command::transfer) {
					auto & data = static_cast<CSftpFileTransferOpData &>(*operations_.back());
					if (!data.download()) {
						engine_.transfer_status_.Update(value);	
					}
					if (!status.madeProgress) {
						if (data.download()) {
							if (value > 0) {
								engine_.transfer_status_.SetMadeProgress();
							}
						}
						else {
							if (status.currentOffset > status.startOffset + 65565) {
								engine_.transfer_status_.SetMadeProgress();
							}
						}
					}
				}
			}
		}
		break;
	case sftpEvent::AskHostkey:
	case sftpEvent::AskHostkeyChanged:
		{
			auto port = fz::to_integral<int>(message.text[1]);
			if (port <= 0 || port > 65535) {
				DoClose(FZ_REPLY_INTERNALERROR);
				break;
			}
			SendAsyncRequest(std::make_unique<CHostKeyNotification>(message.text[0], port, m_sftpEncryptionDetails, message.type == sftpEvent::AskHostkeyChanged));
		}
		break;
	case sftpEvent::AskHostkeyBetteralg:
		log(logmsg::error, L"Got sftpReqHostkeyBetteralg when we shouldn't have. Aborting connection.");
		DoClose(FZ_REPLY_INTERNALERROR);
		break;
	case sftpEvent::AskPassword:
		if (operations_.empty() || operations_.back()->opId != Command::connect) {
			log(logmsg::debug_warning, L"sftpReqPassword outside connect operation, ignoring.");
			break;
		}
		else {
			auto & data = static_cast<CSftpConnectOpData&>(*operations_.back());

			std::wstring const challengeIdentifier = m_requestPreamble + L"\n" + m_requestInstruction + L"\n" + message.text[0];

			CInteractiveLoginNotification::type t = CInteractiveLoginNotification::interactive;
			if (credentials_.logonType_ == LogonType::interactive || m_requestPreamble == L"SSH key passphrase") {
				if (m_requestPreamble == L"SSH key passphrase") {
					t = CInteractiveLoginNotification::keyfile;
				}

				std::wstring challenge;
				if (!m_requestPreamble.empty() && t != CInteractiveLoginNotification::keyfile) {
					challenge += m_requestPreamble + L"\n";
				}
				if (!m_requestInstruction.empty()) {
					challenge += m_requestInstruction + L"\n";
				}
				if (message.text[0] != L"Password:") {
					challenge += message.text[0];
				}
				auto notification = std::make_unique<CInteractiveLoginNotification>(t, challenge, data.lastChallenge == challengeIdentifier);
				notification->server = currentServer_;
				notification->handle_ = handle_;
				notification->credentials = credentials_;

				SendAsyncRequest(std::move(notification));
			}
			else {
				if (!data.lastChallenge.empty() && data.lastChallengeType != CInteractiveLoginNotification::keyfile) {
					// Check for same challenge. Will most likely fail as well, so abort early.
					if (data.lastChallenge == challengeIdentifier) {
						log(logmsg::error, _("Authentication failed."));
					}
					else {
						log(logmsg::error, _("Server sent an additional login prompt. You need to use the interactive login type."));
					}
					DoClose(FZ_REPLY_CRITICALERROR | FZ_REPLY_PASSWORDFAILED);
					return;
				}

				std::wstring const pass = (credentials_.logonType_ == LogonType::anonymous) ? L"anonymous@example.com" : credentials_.GetPass();
				std::wstring show = L"Pass: ";
				show.append(pass.size(), '*');
				SendCommand(pass, show);
			}
			data.lastChallenge = challengeIdentifier;
			data.lastChallengeType = t;
		}
		break;
	case sftpEvent::RequestPreamble:
		m_requestPreamble = message.text[0];
		break;
	case sftpEvent::RequestInstruction:
		m_requestInstruction = message.text[0];
		break;
	case sftpEvent::UsedQuotaRecv:
		OnQuotaRequest(fz::direction::inbound);
		break;
	case sftpEvent::UsedQuotaSend:
		OnQuotaRequest(fz::direction::outbound);
		break;
	case sftpEvent::KexAlgorithm:
		m_sftpEncryptionDetails.kexAlgorithm = message.text[0];
		break;
	case sftpEvent::KexHash:
		m_sftpEncryptionDetails.kexHash = message.text[0];
		break;
	case sftpEvent::KexCurve:
		m_sftpEncryptionDetails.kexCurve = message.text[0];
		break;
	case sftpEvent::CipherClientToServer:
		m_sftpEncryptionDetails.cipherClientToServer = message.text[0];
		break;
	case sftpEvent::CipherServerToClient:
		m_sftpEncryptionDetails.cipherServerToClient = message.text[0];
		break;
	case sftpEvent::MacClientToServer:
		m_sftpEncryptionDetails.macClientToServer = message.text[0];
		break;
	case sftpEvent::MacServerToClient:
		m_sftpEncryptionDetails.macServerToClient = message.text[0];
		break;
	case sftpEvent::Hostkey:
		{
			auto tokens = fz::strtok_view(message.text[0], ' ');
			if (!tokens.empty()) {
				m_sftpEncryptionDetails.hostKeyFingerprint = tokens.back();
				tokens.pop_back();
			}
			for (auto const& token : tokens) {
				if (!m_sftpEncryptionDetails.hostKeyAlgorithm.empty()) {
					m_sftpEncryptionDetails.hostKeyAlgorithm += ' ';
				}
				m_sftpEncryptionDetails.hostKeyAlgorithm += token;
			}
		}
		break;
	case sftpEvent::io_nextbuf:
		if (!operations_.empty() && operations_.back()->opId == Command::transfer) {
			auto & data = static_cast<CSftpFileTransferOpData&>(*operations_.back());
			data.OnNextBufferRequested(fz::to_integral<uint64_t>(message.text[0]));
		}
		break;
	case sftpEvent::io_open:
		if (!operations_.empty() && operations_.back()->opId == Command::transfer) {
			auto & data = static_cast<CSftpFileTransferOpData&>(*operations_.back());
			data.OnOpenRequested(fz::to_integral<uint64_t>(message.text[0]));
		}
		break;
	case sftpEvent::io_size:
		if (!operations_.empty() && operations_.back()->opId == Command::transfer) {
			auto & data = static_cast<CSftpFileTransferOpData&>(*operations_.back());
			data.OnSizeRequested();
		}
		break;
	case sftpEvent::io_finalize:
		if (!operations_.empty() && operations_.back()->opId == Command::transfer) {
			auto & data = static_cast<CSftpFileTransferOpData&>(*operations_.back());
			data.OnFinalizeRequested(fz::to_integral<uint64_t>(message.text[0]));
		}
		break;
	default:
		log(logmsg::debug_warning, L"Message type %d not handled", message.type);
		break;
	}
}

void CSftpControlSocket::OnSftpListEvent(sftp_list_message const& message)
{
	if (!currentServer_) {
		return;
	}

	if (!input_parser_) {
		return;
	}

	if (operations_.empty() || operations_.back()->opId != Command::list) {
		log(logmsg::debug_warning, L"sftpEvent::Listentry outside list operation, ignoring.");
		return;
	}
	else {
		int res = static_cast<CSftpListOpData&>(*operations_.back()).ParseEntry(std::move(message.text), message.mtime, std::move(message.name));
		if (res != FZ_REPLY_WOULDBLOCK) {
			ResetOperation(res);
		}
	}
}

int CSftpControlSocket::SendCommand(std::wstring const& cmd, std::wstring const& show)
{
	SetWait(true);

	log_raw(logmsg::command, show.empty() ? cmd : show);

	// Check for newlines in command
	// a command like "ls\nrm foo/bar" is dangerous
	if (cmd.find('\n') != std::wstring::npos ||
		cmd.find('\r') != std::wstring::npos)
	{
		log(logmsg::debug_warning, L"Command containing newline characters, aborting.");
		return FZ_REPLY_INTERNALERROR;
	}

	return AddToSendBuffer(cmd + L"\n");
}

int CSftpControlSocket::AddToSendBuffer(std::wstring const& cmd)
{
	std::string const str = ConvToServer(cmd);
	if (str.empty()) {
		log(logmsg::error, _("Could not convert command to server encoding"));
		return FZ_REPLY_ERROR;
	}

	return AddToSendBuffer(str);
}

int CSftpControlSocket::AddToSendBuffer(std::string const& cmd)
{
	if (!process_) {
		return FZ_REPLY_INTERNALERROR;
	}


	bool const can_send = send_buffer_.empty();

	send_buffer_.append(cmd);

	if (can_send) {
		return SendToProcess();
	}
	else {
		return FZ_REPLY_WOULDBLOCK;
	}

	return FZ_REPLY_WOULDBLOCK;
}

bool CSftpControlSocket::SetAsyncRequestReply(CAsyncRequestNotification *pNotification)
{
	log(logmsg::debug_verbose, L"CSftpControlSocket::SetAsyncRequestReply");

	RequestId const requestId = pNotification->GetRequestID();
	switch(requestId)
	{
	case reqId_fileexists:
		{
			auto *pFileExistsNotification = static_cast<CFileExistsNotification *>(pNotification);
			return SetFileExistsAction(pFileExistsNotification);
		}
	case reqId_hostkey:
	case reqId_hostkeyChanged:
		{
			if (GetCurrentCommandId() != Command::connect ||
				!currentServer_)
			{
				log(logmsg::debug_info, L"SetAsyncRequestReply called to wrong time");
				return false;
			}

			auto *pHostKeyNotification = static_cast<CHostKeyNotification *>(pNotification);
			std::wstring show;
			if (requestId == reqId_hostkey) {
				show = _("Trust new Hostkey:");
			}
			else {
				show = _("Trust changed Hostkey:");
			}
			show += ' ';
			if (!pHostKeyNotification->m_trust) {
				SendCommand(std::wstring(), show + _("No"));
				if (operations_.back()->opId == Command::connect) {
					auto &data = static_cast<CSftpConnectOpData &>(*operations_.back());
					data.criticalFailure = true;
				}
			}
			else if (pHostKeyNotification->m_alwaysTrust) {
				SendCommand(L"y", show + _("Yes"));
			}
			else {
				SendCommand(L"n", show + _("Once"));
			}
		}
		break;
	case reqId_interactiveLogin:
		{
			if (operations_.empty() || operations_.back()->opId != Command::connect) {
				log(logmsg::debug_info, L"No or invalid operation in progress, ignoring request reply %d", pNotification->GetRequestID());
				return false;
			}

			auto *pInteractiveLoginNotification = static_cast<CInteractiveLoginNotification *>(pNotification);

			if (!pInteractiveLoginNotification->passwordSet) {
				DoClose(FZ_REPLY_CANCELED);
				return false;
			}
			std::wstring const& pass = pInteractiveLoginNotification->credentials.GetPass();
			if (pInteractiveLoginNotification->GetType() != CInteractiveLoginNotification::keyfile) {
				credentials_.SetPass(pass);
			}
			std::wstring show = L"Pass: ";
			show.append(pass.size(), '*');
			SendCommand(pass, show);
		}
		break;
	default:
		log(logmsg::debug_warning, L"Unknown async request reply id: %d", requestId);
		return false;
	}

	return true;
}

void CSftpControlSocket::List(CServerPath const& path, std::wstring const& subDir, int flags)
{
	Push(std::make_unique<CSftpListOpData>(*this, path, subDir, flags));
}

void CSftpControlSocket::ChangeDir(CServerPath const& path, std::wstring const& subDir, bool link_discovery)
{
	auto pData = std::make_unique<CSftpChangeDirOpData>(*this);
	pData->path_ = path;
	pData->subDir_ = subDir;
	pData->link_discovery_ = link_discovery;

	if (!operations_.empty() && operations_.back()->opId == Command::transfer &&
		!static_cast<CSftpFileTransferOpData&>(*operations_.back()).download())
	{
		pData->tryMkdOnFail_ = true;
		assert(subDir.empty());
	}

	Push(std::move(pData));
}

void CSftpControlSocket::ProcessReply(int result, std::wstring const& reply)
{
	result_ = result;
	response_.clear();

	if (operations_.empty()) {
		log(logmsg::debug_info, L"Skipping reply without active operation.");
		return;
	}

	if (reply.size() > 65536) {
		log(fz::logmsg::error, _("Received too long response line, closing connection."));
		DoClose(FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED);
		return;
	}

	response_ = reply;

	auto & data = *operations_.back();
	log(logmsg::debug_verbose, L"%s::ParseResponse() in state %d", data.name_, data.opState);
	int res = data.ParseResponse();
	if (res == FZ_REPLY_OK) {
		ResetOperation(FZ_REPLY_OK);
	}
	else if (res == FZ_REPLY_CONTINUE) {
		SendNextCommand();
	}
	else if (res & FZ_REPLY_DISCONNECTED) {
		DoClose(res);
	}
	else if (res & FZ_REPLY_ERROR) {
		if (data.opId == Command::connect) {
			DoClose(res | FZ_REPLY_DISCONNECTED);
		}
		else {
			ResetOperation(res);
		}
	}
}
void CSftpControlSocket::FileTransfer(CFileTransferCommand const& cmd)
{
	Push(std::make_unique<CSftpFileTransferOpData>(*this, cmd));
}

int CSftpControlSocket::DoClose(int nErrorCode)
{
	remove_bucket();
	if (process_) {
		process_->kill();
	}

	if (input_parser_) {
		input_parser_.reset();

		auto threadEventsFilter = [](fz::event_base const& ev) -> bool {
			if (ev.derived_type() == CSftpEvent::type() || ev.derived_type() == CSftpListEvent::type()) {
				return true;
			}
			return false;
		};

		filter_events(threadEventsFilter);
	}
	process_.reset();

	m_sftpEncryptionDetails = CSftpEncryptionNotification();

	return CControlSocket::DoClose(nErrorCode);
}

void CSftpControlSocket::Cancel()
{
	if (GetCurrentCommandId() != Command::none) {
		DoClose(FZ_REPLY_CANCELED);
	}
}

void CSftpControlSocket::Mkdir(CServerPath const& path, transfer_flags const&)
{
	auto pData = std::make_unique<CSftpMkdirOpData>(*this);
	pData->path_ = path;
	Push(std::move(pData));
}

std::wstring CSftpControlSocket::QuoteFilename(std::wstring const& filename)
{
	return L"\"" + fz::replaced_substrings(filename, L"\"", L"\"\"") + L"\"";
}

void CSftpControlSocket::Delete(const CServerPath& path, std::vector<std::wstring>&& files)
{
	// CFileZillaEnginePrivate should have checked this already
	assert(!files.empty());

	log(logmsg::debug_verbose, L"CSftpControlSocket::Delete");

	auto pData = std::make_unique<CSftpDeleteOpData>(*this);
	pData->path_ = path;
	pData->files_ = std::move(files);
	Push(std::move(pData));
}

void CSftpControlSocket::RemoveDir(CServerPath const& path, std::wstring const& subDir)
{
	log(logmsg::debug_verbose, L"CSftpControlSocket::RemoveDir");

	auto pData = std::make_unique<CSftpRemoveDirOpData>(*this);
	pData->path_ = path;
	pData->subDir_ = subDir;
	Push(std::move(pData));
}

void CSftpControlSocket::Chmod(CChmodCommand const& command)
{
	Push(std::make_unique<CSftpChmodOpData>(*this, command));
}

void CSftpControlSocket::Rename(CRenameCommand const& command)
{
	Push(std::make_unique<CSftpRenameOpData>(*this, command));
}

void CSftpControlSocket::wakeup(fz::direction::type const d)
{
	send_event<SftpRateAvailableEvent>(d);
}

void CSftpControlSocket::OnQuotaRequest(fz::direction::type const d)
{
	if (!process_) {
		return;
	}

	fz::rate::type bytes = available(d);
	if (bytes == fz::rate::unlimited) {
		AddToSendBuffer(fz::sprintf("-%d-\n", d));
	}
	else if (bytes > 0) {
		int b;
		if (bytes > static_cast<size_t>(std::numeric_limits<int>::max())) {
			b = std::numeric_limits<int>::max();
		}
		else {
			b = static_cast<int>(bytes);
		}
		AddToSendBuffer(fz::sprintf("-%d%d,%d\n", d, b, engine_.GetOptions().get_int(d ? OPTION_SPEEDLIMIT_OUTBOUND : OPTION_SPEEDLIMIT_INBOUND)));
		consume(d, static_cast<fz::rate::type>(b));
	}
}

void CSftpControlSocket::operator()(fz::event_base const& ev)
{
	if (fz::dispatch<fz::process_event, CSftpEvent, CSftpListEvent, SftpRateAvailableEvent>(ev, this,
		&CSftpControlSocket::OnProcessEvent,
		&CSftpControlSocket::OnSftpEvent,
		&CSftpControlSocket::OnSftpListEvent,
		&CSftpControlSocket::OnQuotaRequest)) {
		return;
	}

	CControlSocket::operator()(ev);
}

void CSftpControlSocket::Push(std::unique_ptr<COpData> && pNewOpData)
{
	CControlSocket::Push(std::move(pNewOpData));
	if (operations_.size() == 1 && operations_.back()->opId != Command::connect) {
		if (!process_) {
			std::unique_ptr<COpData> connOp = std::make_unique<CSftpConnectOpData>(*this);
			connOp->topLevelOperation_ = true;
			CControlSocket::Push(std::move(connOp));
		}
	}
}

int CSftpControlSocket::SendToProcess()
{
	if (!process_) {
		return FZ_REPLY_INTERNALERROR;
	}
	while (!send_buffer_.empty()) {
		fz::rwresult res = process_->write(send_buffer_.get(), send_buffer_.size());
		if (res) {
			send_buffer_.consume(res.value_);
		}
		else if (res.error_ == fz::rwresult::wouldblock) {
			break;
		}
		else {
			log(logmsg::error, _("Could not send command to fzsftp executable"));
			return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
		}
	}
	return FZ_REPLY_WOULDBLOCK;
}

void CSftpControlSocket::OnProcessEvent(fz::process*, fz::process_event_flag const& f)
{
	if (f == fz::process_event_flag::write) {
		int res = SendToProcess();
		if (res != FZ_REPLY_WOULDBLOCK) {
			DoClose(res);
		}
	}
	else {
		int res = input_parser_->OnData();
		if (res != FZ_REPLY_WOULDBLOCK) {
			DoClose(res);
		}
	}
}
