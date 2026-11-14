#include "../filezilla.h"

#include "chmod.h"
#include "connect.h"
#include "delete.h"
#include "filetransfer.h"
#include "list.h"
#include "mkd.h"
#include "rename.h"
#include "rmd.h"
#include "sftpcontrolsocket.h"

#include "../../include/engine_options.h"
#include "../ssh/ssh_auth.h"

#include <fzssh/client.hpp>

#include <libfilezilla/hash.hpp>

CSftpControlSocket::CSftpControlSocket(CFileZillaEnginePrivate & engine)
	: CRealControlSocket(engine)
{
}

CSftpControlSocket::~CSftpControlSocket()
{
	remove_handler();
	DoClose();
}

void CSftpControlSocket::Connect(CServer const& server, Credentials const& credentials)
{
	m_useUTF8 = server.GetEncodingType() == ENCODING_UTF8;
	if (!m_useUTF8) {
		log(logmsg::debug_info, L"Using custom encoding: %s", server.GetCustomEncoding());
	}

	currentServer_ = server;
	credentials_ = credentials;

	Push(std::make_unique<CSftpConnectOpData>(*this));
}

void CSftpControlSocket::FileTransfer(CFileTransferCommand const& cmd)
{
	Push(std::make_unique<CSftpFileTransferOpData>(*this, cmd));
}

void CSftpControlSocket::Delete(CServerPath const& path, std::vector<std::wstring>&& files)
{
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

int CSftpControlSocket::DoClose(int nErrorCode)
{
	sftp_.reset();
	ssh_.reset();
	awaiting_pong_ = false;
	pending_hostkey_request_.reset();
	return CRealControlSocket::DoClose(nErrorCode);
}

bool CSftpControlSocket::SetAsyncRequestReply(CAsyncRequestNotification *pNotification)
{
	log(logmsg::debug_verbose, L"CSftpControlSocket::SetAsyncRequestReply");

	if (!ssh_) {
		DoClose(FZ_REPLY_CRITICALERROR);
		return false;
	}

	RequestId const requestId = pNotification->GetRequestID();
	switch(requestId)
	{
	case reqId_fileexists:
		{
			auto *pFileExistsNotification = static_cast<CFileExistsNotification *>(pNotification);
			return SetFileExistsAction(pFileExistsNotification);
		}
	case reqId_hostkey:
		{
			auto & req = static_cast<CHostKeyNotification&>(*pNotification);
			if (req.trust_) {
				log_raw(logmsg::status, _("Hostkey is trusted"));
			}

			ssh_->hostkey_decision(req.trust_);
		}
		break;
	default:
		log(logmsg::debug_warning, L"Unknown async request reply id: %d", requestId);
		return false;
	}

	return true;
}

void CSftpControlSocket::OnConnect()
{
	SetAlive();
	log(logmsg::debug_info, L"TCP connection established"sv);
	SendNextCommand();
}

std::wstring CSftpControlSocket::QuoteFilename(std::wstring const& filename)
{
	return L"\"" + fz::replaced_substrings(filename, L"\"", L"\"\"") + L"\"";
}

void CSftpControlSocket::operator()(fz::event_base const& ev)
{
	if (!operations_.empty() && operations_.back()->opId == Command::connect) {
		CSftpConnectOpData* op = static_cast<CSftpConnectOpData*>(operations_.back().get());
		if (auto* auth = op->auth()) {
			(*auth)(ev);
		}
		fz::dispatch<fz::ssh::sftp::sftp_client::ready_event>(ev, op, &CSftpConnectOpData::on_sftp_ready);
	}

	fz::dispatch<fz::ssh::hostkey_verification_event, fz::ssh::session_done_event, fz::ssh::sftp::sftp_client::done_event, fz::ssh::pong_event>(
		ev, this,
		&CSftpControlSocket::on_hostkey_verification,
		&CSftpControlSocket::on_session_done,
		&CSftpControlSocket::on_sftp_done,
		&CSftpControlSocket::on_pong
	);


	CRealControlSocket::operator()(ev);
}

void CSftpControlSocket::Push(std::unique_ptr<COpData> && pNewOpData)
{
	CControlSocket::Push(std::move(pNewOpData));
	if (operations_.size() == 1 && operations_.back()->opId != Command::connect) {
		if (!ssh_) {
			std::unique_ptr<COpData> connOp = std::make_unique<CSftpConnectOpData>(*this);
			connOp->topLevelOperation_ = true;
			CControlSocket::Push(std::move(connOp));
		}
	}
}

void CSftpControlSocket::on_hostkey_verification(fz::ssh::session*, std::unique_ptr<fz::ssh::public_key> & key, fz::ssh::algorithm_info & algs)
{
	engine_.AddNotification(std::make_unique<CSftpEncryptionNotification>(algs, key->fingerprint(fz::hash_algorithm::sha256, true)));

	auto reply = [&](CAsyncRequestNotification* req) {
		pending_hostkey_request_.reset();
		SetAsyncRequestReply(req);
	};
	pending_hostkey_request_ = SendAsyncRequest(std::make_unique<CHostKeyNotification>(currentServer_, handle_, std::move(key), std::move(algs)), async_request_type::parallel, reply);
}

void CSftpControlSocket::on_session_done(fz::ssh::session*)
{
	DoClose();
}

void CSftpControlSocket::on_sftp_done(fz::ssh::sftp::sftp_client*)
{
	DoClose();
}

void CSftpControlSocket::List(CServerPath const& path, int flags)
{
	Push(std::make_unique<CSftpListOpData>(*this, path, flags));
}

void CSftpControlSocket::Mkdir(CServerPath const& path, transfer_flags const&)
{
	Push(std::make_unique<CSftpMkdirOpData>(*this, path));
}

void CSftpControlSocket::SetSocketBufferSizes()
{
	if (socket_) {
		const int size_read = engine_.GetOptions().get_int(OPTION_SOCKET_BUFFERSIZE_RECV);
		socket_->set_buffer_sizes(size_read, -1);
		return;
	}
}

void CSftpControlSocket::ping()
{
	if (ssh_ && !awaiting_pong_) {
		ssh_->ping();
		awaiting_pong_ = true;
	}
}

void CSftpControlSocket::on_pong(fz::ssh::client*, std::optional<fz::duration> const& rtt)
{
	awaiting_pong_ = false;
	if (rtt) {
		auto v = 7 * srtt_.get_milliseconds() + rtt->get_milliseconds() + srtt_remainder_;
		srtt_ = fz::duration::from_milliseconds(std::max(v / 8, int64_t(1)));
		srtt_remainder_ = v % 8;
	}

	last_rtt_update_ = fz::monotonic_clock::now();
	if (!operations_.empty()) {
		auto op = dynamic_cast<CSftpOpData*>(operations_.back().get());
		if (op) {
			op->on_pong();
		}
	}
}

CSftpOpData::~CSftpOpData()
{
	remove_handler();
	if (sftp_) {
		sftp_->cancel(this);
	}
}

namespace {
std::string sanitize_status_message(std::string_view msg)
{
	std::string ret;
	for (auto s : fz::strtokenizer(msg, "\r\n\t ", true)) {
		if (!ret.empty()) {
			ret += ' ';
		}
		ret += s;
	}

	return ret;
}
}

CSftpOpData::continuation CSftpOpData::process_status(fz::ssh::sftp::status_code code, std::string_view description)
{
	if (code == fz::ssh::sftp::status_code::SSH_FX_OK) {
		return do_process_status(code, {});
	}

	std::wstring msg;

	auto desc = sanitize_status_message(description);
	if (desc.empty()) {
		msg = fz::sprintf(fztranslate("Received error %s without any further description"), fz::ssh::sftp::to_string(code));
	}
	else {
		msg = fz::sprintf(fztranslate("Received error %s with description '%s'"), fz::ssh::sftp::to_string(code), desc);
	}

	return do_process_status(code, msg);
}

void CSftpOpData::trigger_reset(int res)
{
	if (sftp_) {
		sftp_->cancel(this);
	}
	send_event<reset_event>(res);
}

void CSftpOpData::trigger_next()
{
	send_event<next_event>();
}

void CSftpOpData::operator()(fz::event_base const& ev)
{
	fz::dispatch<reset_event, next_event>(ev, this,
		&CSftpOpData::on_reset_event,
		&CSftpOpData::on_next_event);
}

void CSftpOpData::on_reset_event(int res)
{
	if (res & FZ_REPLY_DISCONNECTED) {
		controlSocket_.DoClose(res);
	}
	else {
		controlSocket_.ResetOperation(res);
	}
}

void CSftpOpData::on_next_event()
{
	controlSocket_.SendNextCommand();
}
