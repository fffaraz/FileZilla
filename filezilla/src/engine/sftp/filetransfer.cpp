#include "../filezilla.h"

#include "../directorycache.h"
#include "filetransfer.h"

#include "../../include/engine_options.h"

#include <libfilezilla/local_filesys.hpp>
#include <libfilezilla/process.hpp>

#include <assert.h>

namespace {
enum filetransferStates
{
	filetransfer_init = 0,
	filetransfer_waitcwd,
	filetransfer_waitlist,
	filetransfer_mtime,
	filetransfer_transfer,
	filetransfer_chmtime
};
}

CSftpFileTransferOpData::~CSftpFileTransferOpData()
{
	remove_handler();
	reader_.reset();
}

int CSftpFileTransferOpData::Send()
{
	if (opState == filetransfer_init) {
		if (download()) {
			std::wstring filename = remotePath_.FormatFilename(remoteFile_);
			log(logmsg::status, _("Starting download of %s"), filename);
		}
		else {
			log(logmsg::status, _("Starting upload of %s"), localName_);
		}

		localFileSize_ = download() ? writer_factory_.size() : reader_factory_.size();
		localFileTime_ = download() ? writer_factory_.mtime() : reader_factory_.mtime();


		opState = filetransfer_waitcwd;

		if (remotePath_.GetType() == DEFAULT) {
			remotePath_.SetType(currentServer_.GetType());
		}

		controlSocket_.ChangeDir(remotePath_);
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == filetransfer_transfer) {
		// Bit convoluted, but we need to guarantee that local filenames are passed as UTF-8 to fzsftp,
		// whereas we need to use server encoding for remote filenames.
		std::string cmd;
		std::wstring logstr;
		if (resume_) {
			cmd = "re";
			logstr = L"re";
		}
		if (download()) {
			engine_.transfer_status_.Init(remoteFileSize_, resume_ ? localFileSize_ : 0, false);
			cmd += "get ";
			logstr += L"get ";
			
			std::string remoteFile = controlSocket_.ConvToServer(controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_, !tryAbsolutePath_)));
			if (remoteFile.empty()) {
				log(logmsg::error, _("Could not convert command to server encoding"));
				return FZ_REPLY_ERROR;
			}
			cmd += remoteFile + " ";
			logstr += controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_, !tryAbsolutePath_)) + L" "; 
			
			std::wstring localFile = controlSocket_.QuoteFilename(localName_);
			cmd += fz::to_utf8(localFile);
			logstr += localFile;
		}
		else {
			engine_.transfer_status_.Init(localFileSize_, resume_ ? remoteFileSize_ : 0, false);
			cmd += "put ";
			logstr += L"put ";

			std::wstring localFile = controlSocket_.QuoteFilename(localName_);
			cmd += fz::to_utf8(localFile) + " ";
			logstr += localFile + L" ";

			std::string remoteFile = controlSocket_.ConvToServer(controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_, !tryAbsolutePath_)));
			if (remoteFile.empty()) {
				log(logmsg::error, _("Could not convert command to server encoding"));
				return FZ_REPLY_ERROR;
			}
			cmd += remoteFile;
			logstr += controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_, !tryAbsolutePath_));
		}
		engine_.transfer_status_.SetStartTime();
		transferInitiated_ = true;
		controlSocket_.SetWait(true);

		controlSocket_.log_raw(logmsg::command, logstr);
		return controlSocket_.AddToSendBuffer(cmd + "\r\n");
	}
	else if (opState == filetransfer_mtime) {
		std::wstring quotedFilename = controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_, !tryAbsolutePath_));
		return controlSocket_.SendCommand(L"mtime " + quotedFilename);
	}
	else if (opState == filetransfer_chmtime) {
		assert(!localFileTime_.empty());
		if (download()) {
			log(logmsg::debug_info, L"  filetransfer_chmtime during download");
			return FZ_REPLY_INTERNALERROR;
		}

		std::wstring quotedFilename = controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_, !tryAbsolutePath_));

		fz::datetime t = localFileTime_;
		t -= fz::duration::from_minutes(currentServer_.GetTimezoneOffset());

		// Y2K38
		time_t ticks = t.get_time_t();
		std::wstring seconds = fz::sprintf(L"%d", ticks);
		return controlSocket_.SendCommand(L"chmtime " + seconds + L" " + quotedFilename);
	}

	return FZ_REPLY_INTERNALERROR;
}

int CSftpFileTransferOpData::ParseResponse()
{
	if (opState == filetransfer_transfer) {
		writer_.reset();
		if (controlSocket_.result_ == FZ_REPLY_OK && options_.get_int(OPTION_PRESERVE_TIMESTAMPS)) {
			if (download()) {
				if (!remoteFileTime_.empty()) {
					if (!writer_factory_->set_mtime(remoteFileTime_)) {
						log(logmsg::debug_warning, L"Could not set modification time");
					}
				}
			}
			else {
				if (!localFileTime_.empty()) {
					opState = filetransfer_chmtime;
					return FZ_REPLY_CONTINUE;
				}
			}
		}
		return controlSocket_.result_;
	}
	else if (opState == filetransfer_mtime) {
		if (controlSocket_.result_ == FZ_REPLY_OK && !controlSocket_.response_.empty()) {
			time_t seconds = 0;
			bool parsed = true;
			for (auto const& c : controlSocket_.response_) {
				if (c < '0' || c > '9') {
					parsed = false;
					break;
				}
				seconds *= 10;
				seconds += c - '0';
			}
			if (parsed) {
				fz::datetime fileTime = fz::datetime(seconds, fz::datetime::seconds);
				if (!fileTime.empty()) {
					remoteFileTime_ = fileTime;
					remoteFileTime_+= fz::duration::from_minutes(currentServer_.GetTimezoneOffset());
				}
			}
		}
		opState = filetransfer_transfer;
		int res = controlSocket_.CheckOverwriteFile();
		if (res != FZ_REPLY_OK) {
			return res;
		}

		return FZ_REPLY_CONTINUE;
	}
	else if (opState == filetransfer_chmtime) {
		if (download()) {
			log(logmsg::debug_info, L"  filetransfer_chmtime during download");
			return FZ_REPLY_INTERNALERROR;
		}
		return FZ_REPLY_OK;
	}
	else {
		log(logmsg::debug_info, L"  Called at improper time: opState == %d", opState);
	}

	return FZ_REPLY_INTERNALERROR;
}

int CSftpFileTransferOpData::SubcommandResult(int prevResult, COpData const&)
{
	if (opState == filetransfer_waitcwd) {
		if (prevResult == FZ_REPLY_OK) {
			CDirentry entry;
			bool dirDidExist;
			bool matchedCase;
			bool found = engine_.GetDirectoryCache().LookupFile(entry, currentServer_, tryAbsolutePath_ ? remotePath_ : currentPath_, remoteFile_, dirDidExist, matchedCase);
			if (!found) {
				if (!dirDidExist) {
					opState = filetransfer_waitlist;
				}
				else if (download() && options_.get_int(OPTION_PRESERVE_TIMESTAMPS)) {
					opState = filetransfer_mtime;
				}
				else {
					opState = filetransfer_transfer;
				}
			}
			else {
				if (entry.is_unsure()) {
					opState = filetransfer_waitlist;
				}
				else {
					if (matchedCase) {
						remoteFileSize_ = entry.size;
						if (entry.has_date()) {
							remoteFileTime_ = entry.time;
						}

						if (download() && !entry.has_time() &&
							options_.get_int(OPTION_PRESERVE_TIMESTAMPS))
						{
							opState = filetransfer_mtime;
						}
						else {
							opState = filetransfer_transfer;
						}
					}
					else {
						opState = filetransfer_mtime;
					}
				}
			}
			if (opState == filetransfer_waitlist) {
				controlSocket_.List(CServerPath(), L"", LIST_FLAG_REFRESH);
				return FZ_REPLY_CONTINUE;
			}
			else if (opState == filetransfer_transfer) {
				int res = controlSocket_.CheckOverwriteFile();
				if (res != FZ_REPLY_OK) {
					return res;
				}
			}
		}
		else {
			tryAbsolutePath_ = true;
			opState = filetransfer_mtime;
		}
	}
	else if (opState == filetransfer_waitlist) {
		if (prevResult == FZ_REPLY_OK) {
			CDirentry entry;
			bool dirDidExist;
			bool matchedCase;
			bool found = engine_.GetDirectoryCache().LookupFile(entry, currentServer_, tryAbsolutePath_ ? remotePath_ : currentPath_, remoteFile_, dirDidExist, matchedCase);
			if (!found) {
				if (!dirDidExist) {
					opState = filetransfer_mtime;
				}
				else if (download() &&
					options_.get_int(OPTION_PRESERVE_TIMESTAMPS))
				{
					opState = filetransfer_mtime;
				}
				else {
					opState = filetransfer_transfer;
				}
			}
			else {
				if (matchedCase && !entry.is_unsure()) {
					remoteFileSize_ = entry.size;
					if (entry.has_date()) {
						remoteFileTime_ = entry.time;
					}

					if (download() && !entry.has_time() &&
						options_.get_int(OPTION_PRESERVE_TIMESTAMPS))
					{
						opState = filetransfer_mtime;
					}
					else {
						opState = filetransfer_transfer;
					}
				}
				else {
					opState = filetransfer_mtime;
				}
			}
			if (opState == filetransfer_transfer) {
				int res = controlSocket_.CheckOverwriteFile();
				if (res != FZ_REPLY_OK) {
					return res;
				}
			}
		}
		else {
			opState = filetransfer_mtime;
		}
	}
	else {
		log(logmsg::debug_warning, L"  Unknown opState (%d)", opState);
		return FZ_REPLY_INTERNALERROR;
	}

	return FZ_REPLY_CONTINUE;
}

void CSftpFileTransferOpData::OnOpenRequested(uint64_t offset)
{
	if (reader_ || writer_) {
		controlSocket_.AddToSendBuffer("-0\n");
		return;
	}

	if (download()) {
		if (resume_) {
			offset = writer_factory_.size();
			if (offset == fz::aio_base::nosize) {
				controlSocket_.AddToSendBuffer("-1\n");
				return;
			}
		}
		else {
			offset = 0;
		}
		writer_ = controlSocket_.OpenWriter(writer_factory_, offset, true);
		if (!writer_) {
			controlSocket_.AddToSendBuffer("--\n");
			return;
		}
	}
	else {
		reader_ = reader_factory_->open(*controlSocket_.buffer_pool_, offset, fz::aio_base::nosize, controlSocket_.max_buffer_count());
		if (!reader_) {
			controlSocket_.AddToSendBuffer("--\n");
			return;
		}
	}
	auto info = controlSocket_.buffer_pool_->shared_memory_info();
#ifdef FZ_WINDOWS
	HANDLE target;
	if (!DuplicateHandle(GetCurrentProcess(), std::get<0>(info), controlSocket_.process_->handle(), &target, 0, false, DUPLICATE_SAME_ACCESS)) {
		DWORD error = GetLastError();
		log(logmsg::debug_warning, L"DuplicateHandle failed with %u", error);
		controlSocket_.ResetOperation(FZ_REPLY_ERROR);
		return;
	}
	controlSocket_.AddToSendBuffer(fz::sprintf("-%u %u %u\n", reinterpret_cast<uintptr_t>(target), std::get<2>(info), offset));
#else
	controlSocket_.AddToSendBuffer(fz::sprintf("-%d %u %u\n", std::get<0>(info), std::get<2>(info), offset));
#endif
	base_address_ = std::get<1>(info);
}


void CSftpFileTransferOpData::OnNextBufferRequested(uint64_t processed)
{
	if (reader_) {
		fz::aio_result r;
		std::tie(r, buffer_) = reader_->get_buffer(*this);
		if (r == fz::aio_result::wait) {
			return;
		}
		if (r == fz::aio_result::error) {
			controlSocket_.AddToSendBuffer("--1\n");
			return;
		}
		if (buffer_->size()) {
			controlSocket_.AddToSendBuffer(fz::sprintf("-%d %d\n", buffer_->get() - base_address_, buffer_->size()));
		}
		else {
			controlSocket_.AddToSendBuffer(fz::sprintf("-0\n"));
		}
	}
	else if (writer_) {
		buffer_->resize(processed);
		auto r = writer_->add_buffer(std::move(buffer_), *this);
		if (r == fz::aio_result::ok) {
			buffer_ = controlSocket_.buffer_pool_->get_buffer(*this);
			if (!buffer_) {
				r = fz::aio_result::wait;
			}
		}
		if (r == fz::aio_result::wait) {
			return;
		}
		if (r == fz::aio_result::error) {
			controlSocket_.AddToSendBuffer("--1\n");
			return;
		}
		controlSocket_.AddToSendBuffer(fz::sprintf("-%d %d\n", buffer_->get() - base_address_, buffer_->capacity()));
	}
	else {
		controlSocket_.AddToSendBuffer("--1\n");
		return;
	}
}

void CSftpFileTransferOpData::OnFinalizeRequested(uint64_t lastWrite)
{
	finalizing_ = true;
	buffer_->resize(lastWrite);
	auto r = writer_->add_buffer(std::move(buffer_), *this);
	if (r == fz::aio_result::ok) {
		r = writer_->finalize(*this);
	}
	if (r == fz::aio_result::wait) {
		return;
	}
	else if (r == fz::aio_result::ok) {
		controlSocket_.AddToSendBuffer(fz::sprintf("-1\n"));
	}
	else {
		controlSocket_.AddToSendBuffer(fz::sprintf("-0\n"));
	}
}

void CSftpFileTransferOpData::OnSizeRequested()
{
	uint64_t size = fz::aio_base::nosize;
	if (reader_) {
		size = reader_->size();
	}
	else if (writer_) {
		size = writer_factory_->size();
	}
	if (size == fz::aio_base::nosize) {
		controlSocket_.AddToSendBuffer("--1\n");
	}
	else {
		controlSocket_.AddToSendBuffer(fz::sprintf("-%d\n", size));
	}
}

void CSftpFileTransferOpData::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::aio_buffer_event>(ev, this,
		&CSftpFileTransferOpData::OnBufferAvailability
	);
}

void CSftpFileTransferOpData::OnBufferAvailability(fz::aio_waitable const* w)
{
	if (w == reader_.get()) {
		OnNextBufferRequested(0);
	}
	else if (w == writer_.get()) {
		if (finalizing_) {
			OnFinalizeRequested(0);
		}
		else {
			OnNextBufferRequested(0);
		}
	}
}
