#include "../filezilla.h"

#include "../directorycache.h"
#include "filetransfer.h"

#include "../../include/engine_options.h"

#include <libfilezilla/local_filesys.hpp>
#include <libfilezilla/process.hpp>

#include <assert.h>

using namespace std::literals;

namespace {
enum filetransferStates
{
	filetransfer_init = 0,
	filetransfer_list,
	filetransfer_stat,
	filetransfer_mkdir,
	filetransfer_checkoverwrite,
	filetransfer_transfer,
};

struct can_send_event_type{};
typedef fz::simple_event<can_send_event_type> can_send_event;
}

CSftpFileTransferOpData::~CSftpFileTransferOpData()
{
	remove_handler();
	reader_.reset();
	if (sftp_) {
		sftp_->cancel_wait(this);
	}
}

int CSftpFileTransferOpData::Send()
{
	if (!sftp_) {
		return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
	}

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

		return CheckRemoteFile(false);
	}
	else if (opState == filetransfer_checkoverwrite) {
		opState = filetransfer_transfer;
		int res = controlSocket_.CheckOverwriteFile();
		if (res != FZ_REPLY_OK) {
			return res;
		}
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == filetransfer_list) {
		controlSocket_.List(remotePath_, LIST_FLAG_REFRESH);
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == filetransfer_transfer) {
		// Bit convoluted as we need to use server encoding for remote filenames.
		std::string remoteFile;
		std::wstring logstr;
		if (resume_) {
			logstr = L"re";
		}
		fz::ssh::sftp::file_flags flags{};
		if (download()) {
			engine_.transfer_status_.Init(remoteFileSize_, resume_ ? localFileSize_ : 0, false);
			logstr += L"get ";

			remoteFile = controlSocket_.ConvToServer(remotePath_.FormatFilename(remoteFile_));
			if (remoteFile.empty()) {
				log(logmsg::error, _("Could not convert command to server encoding"));
				return FZ_REPLY_ERROR;
			}
			logstr += controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_)) + L" ";

			std::wstring localFile = controlSocket_.QuoteFilename(localName_);
			logstr += localFile;

			flags = fz::ssh::sftp::file_flags::SSH_FXF_READ;

			if (!controlSocket_.can_use_socket_rtt_) {
				measure_rtt_ = true;
				if (!controlSocket_.awaiting_pong_) {
					if (fz::monotonic_clock::now() - controlSocket_.last_rtt_update_ > fz::duration::from_seconds(1)) {
						controlSocket_.ping();
					}
					else {
						ping_timer_ = add_timer(controlSocket_.last_rtt_update_ + fz::duration::from_seconds(1));
					}
				}
			}
		}
		else {
			engine_.transfer_status_.Init(localFileSize_, resume_ ? remoteFileSize_ : 0, false);
			logstr += L"put ";

			std::wstring localFile = controlSocket_.QuoteFilename(localName_);
			logstr += localFile + L" ";

			remoteFile = controlSocket_.ConvToServer(remotePath_.FormatFilename(remoteFile_));
			if (remoteFile.empty()) {
				log(logmsg::error, _("Could not convert command to server encoding"));
				return FZ_REPLY_ERROR;
			}
			logstr += controlSocket_.QuoteFilename(remotePath_.FormatFilename(remoteFile_));

			flags = fz::ssh::sftp::file_flags::SSH_FXF_WRITE;
			if (!resume_) {
				flags |= fz::ssh::sftp::file_flags::SSH_FXF_CREAT | fz::ssh::sftp::file_flags::SSH_FXF_TRUNC;
			}

			request_offset_ = resume_ ? remoteFileSize_ : 0;
			reader_ = reader_factory_->open(*controlSocket_.buffer_pool_, request_offset_, fz::aio_base::nosize, controlSocket_.max_buffer_count());
			if (!reader_) {
				return FZ_REPLY_ERROR;
			}
		}
		engine_.transfer_status_.SetStartTime();
		transferInitiated_ = true;
		controlSocket_.SetWait(true);

		controlSocket_.log_raw(logmsg::command, logstr);
		sftp_->open(this, remoteFile, flags);
		return FZ_REPLY_WOULDBLOCK;
	}
	else if (opState == filetransfer_stat) {
		std::string remoteFile = controlSocket_.ConvToServer(remotePath_.FormatFilename(remoteFile_));
		if (remoteFile.empty()) {
			log(logmsg::error, _("Could not convert command to server encoding"));
			return FZ_REPLY_ERROR;
		}
		sftp_->stat(this, remoteFile);
		return FZ_REPLY_WOULDBLOCK;
	}
	else if (opState == filetransfer_mkdir) {
		controlSocket_.Mkdir(remotePath_);
		return FZ_REPLY_CONTINUE;
	}

	return FZ_REPLY_INTERNALERROR;
}

int CSftpFileTransferOpData::CheckRemoteFile(bool after_listing)
{
	CDirentry entry;
	bool dirDidExist;
	bool matchedCase;
	bool found = engine_.GetDirectoryCache().LookupFile(entry, currentServer_, remotePath_, remoteFile_, dirDidExist, matchedCase);
	if (!found) {
		if (!dirDidExist) {
			if (!after_listing) {
				opState = filetransfer_list;
			}
			else {
				if (!download() && remotePath_.HasParent()) {
					opState = filetransfer_mkdir;
				}
				else {
					opState = filetransfer_stat;
				}
			}
		}
		else if (download() && options_.get_int(OPTION_PRESERVE_TIMESTAMPS)) {
			opState = filetransfer_stat;
		}
		else {
			opState = filetransfer_checkoverwrite;
		}
	}
	else {
		if (entry.is_unsure()) {
			if (!after_listing) {
				opState = filetransfer_list;
			}
			else {
				opState = filetransfer_stat;
			}
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
					opState = filetransfer_stat;
				}
				else {
					opState = filetransfer_checkoverwrite;
				}
			}
			else {
				opState = filetransfer_stat;
			}
		}
	}

	return FZ_REPLY_CONTINUE;
}

int CSftpFileTransferOpData::SubcommandResult(int prevResult, COpData const&)
{
	if (opState == filetransfer_list) {
		if (prevResult == FZ_REPLY_OK) {
			return CheckRemoteFile(true);
		}
		else {
			if (!download() && remotePath_.HasParent()) {
				opState = filetransfer_mkdir;
			}
			else {
				opState = filetransfer_stat;
			}
			return FZ_REPLY_CONTINUE;
		}
	}
	else if (opState == filetransfer_mkdir) {
		// Ignore errors

		opState = filetransfer_stat;
		return FZ_REPLY_CONTINUE;
	}

	log(logmsg::debug_warning, L"  Unknown opState (%d)", opState);
	return FZ_REPLY_INTERNALERROR;
}

void CSftpFileTransferOpData::operator()(fz::event_base const& ev)
{
	if (fz::dispatch<fz::aio_buffer_event, fz::ssh::sftp::outbuf_empty_event, fz::timer_event>(ev, this,
		&CSftpFileTransferOpData::OnBufferAvailability,
		&CSftpFileTransferOpData::on_can_send,
		&CSftpFileTransferOpData::OnTimer
	)) {
		return;
	}

	CSftpOpData::operator()(ev);
}

void CSftpFileTransferOpData::OnBufferAvailability(fz::aio_waitable const* w)
{
	if (w == reader_.get()) {
		on_can_send(nullptr);
	}
	else if (w == writer_.get()) {
		if (finalizing_) {
			finalize();
		}
		else {
			auto r = get_next_download_buffer();
			if (r == fz::aio_result::ok) {
				sftp_->unblock_read();
				request_data();
			}
		}
	}
}

int CSftpFileTransferOpData::Reset(int result)
{
	if (sftp_ && !handle_.empty()) {
		sftp_->close(nullptr, handle_);
	}
	handle_.clear();
	return result;
}

void CSftpFileTransferOpData::finalize()
{
	finalizing_ = true;
	auto r = writer_->add_buffer(std::move(buffer_), *this);
	if (r == fz::aio_result::ok) {
		r = writer_->finalize(*this);
	}
	if (r == fz::aio_result::error) {
		trigger_reset(FZ_REPLY_ERROR);
	}
	else if (r == fz::aio_result::ok) {
		if (options_.get_int(OPTION_PRESERVE_TIMESTAMPS) && remoteFileTime_) {
			if (!writer_->set_mtime(remoteFileTime_)) {
				log(logmsg::debug_warning, L"Could not set modification time");
			}
		}
		trigger_reset(FZ_REPLY_OK);
	}
}

fz::aio_result CSftpFileTransferOpData::get_next_upload_buffer()
{
	fz::aio_result r;
	std::tie(r, buffer_) = reader_->get_buffer(*this);
	if (r == fz::aio_result::wait) {
		return r;
	}
	if (r == fz::aio_result::error) {
		trigger_reset(FZ_REPLY_ERROR);
		return r;
	}
	return r;
}

fz::aio_result CSftpFileTransferOpData::get_next_download_buffer()
{
	auto r = writer_->add_buffer(std::move(buffer_), *this);
	if (r == fz::aio_result::ok) {
		buffer_ = controlSocket_.buffer_pool_->get_buffer(*this);
		if (!buffer_) {
			r = fz::aio_result::wait;
		}
	}
	if (r == fz::aio_result::error) {
		trigger_reset(FZ_REPLY_ERROR);
	}
	return r;
}

CSftpOpData::continuation CSftpFileTransferOpData::process_handle(std::string_view handle)
{
	controlSocket_.SetAlive();

	handle_ = handle;

	if (download()) {
		if (resume_) {
			request_offset_ = writer_factory_.size();
			if (request_offset_ == fz::aio_base::nosize) {
				log(fz::logmsg::error, fztranslate("Cannot resume, could not get size of local file"));
				trigger_reset(FZ_REPLY_ERROR);
				return continuation::next;
			}
		}
		else {
			request_offset_ = 0;
		}

		writer_ = controlSocket_.OpenWriter(writer_factory_, request_offset_, true);
		if (!writer_) {
			trigger_reset(FZ_REPLY_ERROR);
			return continuation::next;
		}

		fz::aio_result r = get_next_download_buffer();
		if (r == fz::aio_result::wait) {
			return continuation::wait;
		}
		else if (r == fz::aio_result::ok) {
			request_data();
		}
	}
	else {
#ifdef FZ_WINDOWS
		// For send buffer tuning
		sendbuf_timer_ = add_timer(fz::duration::from_seconds(1), false);
#endif

		send_event<fz::ssh::sftp::outbuf_empty_event>(nullptr);
	}

	return continuation::next;
}

void CSftpFileTransferOpData::request_data()
{
	update_max_pending();

	size_t i{};
	for (i = 0; i < 2 && sftp_->pending_requests() < queue_size_ && sftp_->can_send_packets(); ++i) {
		sftp_->read(this, handle_, request_offset_, blocksize_);
		request_offset_ += blocksize_;
	}
}

CSftpOpData::continuation CSftpFileTransferOpData::process_data(std::string_view data)
{
	controlSocket_.SetAlive();

	if (data.size() > blocksize_) {
		log(fz::logmsg::error, L"Server sent a block of data larger than requested."sv);
		return continuation::error;
	}

	if (data.size() != blocksize_) {
		if (short_read_) {
			// Instead of error, we could disable pipelining. As the file may not be seekable, this would require re-opening the file and restarting from the beginning
			log(fz::logmsg::error, fztranslate("Got a short read not at the end of a file, this is not permissiable on normal files"));
			trigger_reset(FZ_REPLY_CRITICALERROR);
			return continuation::next;
		}
		short_read_ = true;
	}

	buffer_->append(data);
	goodput_.amount_ += data.size();

	if (buffer_->capacity() - buffer_->size() < blocksize_) {
		auto r = get_next_download_buffer();
		if (r == fz::aio_result::wait) {
			return continuation::wait;
		}
		else if (r == fz::aio_result::error) {
			return continuation::next;
		}
	}

	request_data();

	return continuation::next;
}

CSftpOpData::continuation CSftpFileTransferOpData::do_process_status(fz::ssh::sftp::status_code code, std::wstring_view msg)
{
	controlSocket_.SetAlive();

	if (download()) {
		if (opState == filetransfer_stat) {
			log(logmsg::error, fztranslate("Could not get file attributes: %s"), msg);
			trigger_reset(FZ_REPLY_ERROR);
		}
		else if (!handle_.empty()) {
			if (code == fz::ssh::sftp::status_code::SSH_FX_EOF) {
				sftp_->cancel(this);
				finalize();
			}
			else {
				log(logmsg::error, fztranslate("Could not read from remote file: %s"), msg);
				trigger_reset(FZ_REPLY_ERROR);
			}
		}
		else {
			log(logmsg::error, fztranslate("Could not open remote file: %s"), msg);
			trigger_reset(FZ_REPLY_ERROR);
		}
	}
	else {
		if (opState == filetransfer_stat) {
			// Ignore errors. At worse, overwrite check won't see that file already exists.
			// This behavior is similar to the FTP(S) implementation.
			//
			// We could potentially use SSH_FXF_EXCL, but that raises two different questions:
			// - What is the error code? There's nothing to distinguish between "already exists"
			//   and other errors.
			// - Potential lack of server support for this rarely used flag

			log(logmsg::debug_warning, "Could not get file attributes: %s"sv, msg);
			opState = filetransfer_checkoverwrite;
			trigger_next();
		}
		else if (code == fz::ssh::sftp::status_code::SSH_FX_OK) {
			engine_.transfer_status_.SetMadeProgress();
			if (finalizing_ && !sftp_->pending_requests()) {
				trigger_reset(FZ_REPLY_OK);
			}
			return continuation::next;
		}
		else if (handle_.empty() && !finalizing_) {
			log(logmsg::error, fztranslate("Could not open remote file: %s"), msg);
			trigger_reset(FZ_REPLY_ERROR);
		}
		else {
			if (called_fsetstat_ && sftp_->pending_requests() == 1) {
				log(logmsg::error, fztranslate("Could not set remote file time: %s"), msg);
			}
			else {
				log(logmsg::error, fztranslate("Could not write to remote file: %s"), msg);
				trigger_reset(FZ_REPLY_ERROR);
			}
		}
	}

	return continuation::next;
}

CSftpOpData::continuation CSftpFileTransferOpData::process_attributes(fz::ssh::sftp::attributes & attrs)
{
	if (opState != filetransfer_stat) {
		log(logmsg::debug_warning, L"  Unknown opState (%d)", opState);
		trigger_reset(FZ_REPLY_INTERNALERROR);
		return continuation::error;
	}

	if (attrs.modified_) {
		remoteFileTime_ = *attrs.modified_;
		remoteFileTime_+= fz::duration::from_minutes(currentServer_.GetTimezoneOffset());
	}
	if (attrs.size_) {
		remoteFileSize_ = *attrs.size_;
	}

	opState = filetransfer_checkoverwrite;
	trigger_next();
	return continuation::next;
}

void CSftpFileTransferOpData::on_can_send(fz::ssh::sftp::sftp_client*)
{
	if (buffer_->empty()) {
		auto r = get_next_upload_buffer();
		if (r != fz::aio_result::ok) {
			return;
		}
		if (buffer_->empty()) {
			finalizing_ = true;
			if (options_.get_int(OPTION_PRESERVE_TIMESTAMPS)) {
				fz::datetime  mtime = reader_->mtime();
				if (!mtime) {
					mtime = reader_factory_.mtime();
				}
				if (mtime) {
					mtime -= fz::duration::from_minutes(currentServer_.GetTimezoneOffset());
					fz::ssh::sftp::attributes attr;
					attr.modified_ = mtime;
					sftp_->fsetstat(this, handle_, attr);
					called_fsetstat_ = true;
				}
			}
			sftp_->close(this, handle_);
			handle_.clear();
			return;
		}
	}
	if (!sftp_->can_send_packets(*this)) {
		return;
	}

	auto size = std::min(blocksize_, buffer_->size());
	sftp_->write(this, handle_, request_offset_, buffer_->to_view().substr(0, size));
	request_offset_ += size;
	buffer_->consume(size);

	engine_.transfer_status_.Update(size);

	resend_current_event();
}

void CSftpFileTransferOpData::OnTimer(fz::timer_id id)
{
	if (id == ping_timer_) {
		ping_timer_ = 0;
		controlSocket_.ping();
	}
#if FZ_WINDOWS
	else if (id == sendbuf_timer_) {
		auto *socket = controlSocket_.socket_.get();
		if (socket && socket->is_connected()) {
			int const ideal_send_buffer = socket->ideal_send_buffer_size();
			if (ideal_send_buffer != -1) {
				socket->set_buffer_sizes(-1, ideal_send_buffer);
			}
		}
	}
#endif
}

void CSftpFileTransferOpData::update_max_pending()
{
	auto const now = fz::monotonic_clock::now();
	if (!goodput_.since_) {
		goodput_.since_ = now;
		return;
	}
	auto elapsed = now - goodput_.since_;
	if (elapsed < fz::duration::from_seconds(1)) {
		return;
	}

	size_t constexpr max_queue_size = 1024 * 16;

	// Get bytes/s
	size_t goodput = goodput_.amount_ * 1000 / elapsed.get_milliseconds();

	static auto const abnormal_srtt_threshold = fz::duration::from_milliseconds(500);

	auto const probe_increment = [&]{
		best_goodput_ = goodput;
		previous_best_queue_size_ = queue_size_;
		queue_size_ += std::min(max_queue_size - queue_size_, std::max(queue_size_ / 8, size_t(8)));
	};

	if (controlSocket_.can_use_socket_rtt_) {
		auto rtt = controlSocket_.socket_->srtt();
		if (rtt) {
			controlSocket_.srtt_ = std::max(fz::duration::from_milliseconds(1), *rtt);
		}
	}

	size_t ideal_queue_size{};
	if (mode_ != mode::steady) {
		auto const enter_steadystate = [&]{
			failed_probes_ = 0;
			queue_size_ = previous_best_queue_size_;
			mode_ = mode::steady;
			last_probe_ = fz::monotonic_clock::now();
		};

		if (controlSocket_.srtt_ >= abnormal_srtt_threshold) {
			enter_steadystate();
		}
		else {
			unsigned const max_failures = ((mode_ == mode::startup) ? 1 : 0);

			if (goodput >= best_goodput_ + best_goodput_ / 16) {
				failed_probes_ = 0;
				mode_ = mode::startup;
				probe_increment();
			}
			else if (++failed_probes_ > max_failures) {
				enter_steadystate();
			}
		}
	}
	else {
		bool const should_probe =
			controlSocket_.srtt_ < abnormal_srtt_threshold &&
			(now - last_probe_) >= fz::duration::from_seconds(30);

		if (should_probe) {
			mode_ = mode::probe;
			probe_increment();
		}
		else {
			ideal_queue_size = goodput_.amount_ * controlSocket_.srtt_.get_milliseconds() / elapsed.get_milliseconds() / blocksize_;

			// Always add a bit extra to account for the various buffers at each layer of the processing pipeline on either side of the connection
			size_t target_queue_size = std::min(ideal_queue_size + 8, max_queue_size);

			queue_size_ = (queue_size_ * 7 + target_queue_size) / 8;
		}
	}

	log(fz::logmsg::debug_info, "Updated queue size to %u pending requests. Ideal: %u, Mode: %u, srtt: %ums, goodput: %uKiB/s"sv, queue_size_, ideal_queue_size, mode_, controlSocket_.srtt_.get_milliseconds(), goodput / 1024);

	goodput_.amount_ = 0;
	goodput_.since_ = now;
}

void CSftpFileTransferOpData::on_pong()
{
	if (measure_rtt_ && !ping_timer_) {
		ping_timer_ = add_timer(fz::monotonic_clock::now() + fz::duration::from_seconds(1));
	}
}

