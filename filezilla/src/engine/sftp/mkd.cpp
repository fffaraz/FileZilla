#include "../filezilla.h"

#include "../directorycache.h"
#include "mkd.h"

/* Directory creation works like this:
 * First find the most common parent directory if it exists. This step is pipelined.
 * Starting from the most common parent, or the root in its absence, create the path, one
 * segment at a time. Ignore errors on segments other than the last.
 */

namespace {
enum mkdStates
{
	mkd_stat,
	mkd_mkd,
};
}

int CSftpMkdirOpData::Send()
{
	if (!sftp_) {
		return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
	}

	if (opState == mkd_stat) {
		if (!path_.HasParent()) {
			return FZ_REPLY_SYNTAXERROR;
		}

		if (!opLock_) {
			opLock_ = controlSocket_.Lock(locking_reason::mkdir, path_);
		}
		if (opLock_.waiting()) {
			return FZ_REPLY_WOULDBLOCK;
		}

		if (controlSocket_.operations_.size() == 1) {
			log(logmsg::status, _("Creating directory '%s'..."), path_.GetPath());
		}

		auto p = path_;
		while (p.HasParent()) {
			paths_.push_back(p);
			p.MakeParent();
		}

		for (auto const& path : paths_) {
			auto rawPath = controlSocket_.ConvToServer(path.GetPath());
			if (rawPath.empty()) {
				return FZ_REPLY_ERROR;
			}
			sftp_->stat(this, rawPath);
		}

		return FZ_REPLY_WOULDBLOCK;
	}

	return FZ_REPLY_INTERNALERROR;
}

CSftpOpData::continuation CSftpMkdirOpData::do_process_status(fz::ssh::sftp::status_code code, std::wstring_view msg)
{
	if (opState == mkd_stat) {
		if (++pos_ == paths_.size()) {
			opState = mkd_mkd;
			sftp_->mkdir(this, controlSocket_.ConvToServer(paths_[--pos_].GetPath()), {});
		}

		return continuation::next;
	}
	else if (opState == mkd_mkd) {
		bool success = code == fz::ssh::sftp::status_code::SSH_FX_OK;

		if (success) {
			while (paths_.size() > pos_) {
				auto const& p = paths_.back();
				engine_.GetDirectoryCache().UpdateFile(currentServer_, p.GetParent(), p.GetLastSegment(), true, CDirectoryCache::dir);
				controlSocket_.SendDirectoryListingNotification(p.GetParent(), false);
				paths_.pop_back();
			}
		}
		if (!pos_) {
			if (success) {
				log(fz::logmsg::status, _("Directory creation succeeded."), msg);
				trigger_reset(FZ_REPLY_OK);
			}
			else {
				log(fz::logmsg::error, _("Could not create directory: %s"), msg);
				trigger_reset(FZ_REPLY_ERROR);
			}
		}
		else {
			sftp_->mkdir(this, controlSocket_.ConvToServer(paths_[--pos_].GetPath()), {});
		}

		return continuation::next;
	}

	trigger_reset(FZ_REPLY_INTERNALERROR);
	return continuation::error;
}

CSftpOpData::continuation CSftpMkdirOpData::process_attributes(fz::ssh::sftp::attributes & attrs)
{
	if (opState == mkd_stat) {
		if (attrs.is_directory()) {
			sftp_->cancel(this);

			while (paths_.size() > pos_) {
				auto const& p = paths_.back();
				engine_.GetDirectoryCache().UpdateFile(currentServer_, p.GetParent(), p.GetLastSegment(), true, CDirectoryCache::dir);
				controlSocket_.SendDirectoryListingNotification(p.GetParent(), false);
				paths_.pop_back();
			}

			if (!pos_) {
				if (controlSocket_.operations_.size() == 1) {
					log(fz::logmsg::status, _("Directory already exists."));
				}
				trigger_reset(FZ_REPLY_OK);
				return continuation::next;
			}
		}

		if (attrs.is_directory() || ++pos_ == paths_.size()) {
			opState = mkd_mkd;
			sftp_->mkdir(this, controlSocket_.ConvToServer(paths_[--pos_].GetPath()), {});
		}
		return continuation::next;
	}

	trigger_reset(FZ_REPLY_INTERNALERROR);
	return continuation::error;
}

