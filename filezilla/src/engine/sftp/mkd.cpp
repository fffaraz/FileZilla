#include "../filezilla.h"

#include "../directorycache.h"
#include "mkd.h"

namespace {
enum mkdStates
{
	mkd_init = 0,
	mkd_findparent,
	mkd_mkdsub,
	mkd_cwdsub,
	mkd_tryfull
};
}

/* Directory creation works like this: First find a parent directory into
 * which we can CWD, then create the subdirs one by one. If either part
 * fails, try MKD with the full path directly.
 */

int CSftpMkdirOpData::Send()
{
	if (!opLock_) {
		opLock_ = controlSocket_.Lock(locking_reason::mkdir, path_);
	}
	if (opLock_.waiting()) {
		return FZ_REPLY_WOULDBLOCK;
	}

	switch (opState)
	{
	case mkd_init:
		if (controlSocket_.operations_.size() == 1) {
			log(logmsg::status, _("Creating directory '%s'..."), path_.GetPath());
		}

		if (!currentPath_.empty()) {
			// Unless the server is broken, a directory already exists if current directory is a subdir of it.
			if (currentPath_ == path_ || currentPath_.IsSubdirOf(path_, false)) {
				return FZ_REPLY_OK;
			}

			if (currentPath_.IsParentOf(path_, false)) {
				commonParent_ = currentPath_;
			}
			else {
				commonParent_ = path_.GetCommonParent(currentPath_);
			}
		}

		if (!path_.HasParent()) {
			opState = mkd_tryfull;
		}
		else {
			currentMkdPath_ = path_.GetParent();
			segments_.push_back(path_.GetLastSegment());

			if (currentMkdPath_ == currentPath_) {
				opState = mkd_mkdsub;
			}
			else {
				opState = mkd_findparent;
			}
		}
		return FZ_REPLY_CONTINUE;
	case mkd_findparent:
	case mkd_cwdsub:
		currentPath_.clear();
		return controlSocket_.SendCommand(L"cd " + controlSocket_.QuoteFilename(currentMkdPath_.GetPath()));
	case mkd_mkdsub:
		return controlSocket_.SendCommand(L"mkdir " + controlSocket_.QuoteFilename(segments_.back()));
	case mkd_tryfull:
		return controlSocket_.SendCommand(L"mkdir " + controlSocket_.QuoteFilename(path_.GetPath()));
	default:
		log(logmsg::debug_warning, L"unknown op state: %d", opState);
	}

	return FZ_REPLY_INTERNALERROR;
}

int CSftpMkdirOpData::ParseResponse()
{
	bool successful = controlSocket_.result_ == FZ_REPLY_OK;
	switch (opState)
	{
	case mkd_findparent:
		if (successful) {
			currentPath_ = currentMkdPath_;
			opState = mkd_mkdsub;
		}
		else if (currentMkdPath_ == commonParent_) {
			opState = mkd_tryfull;
		}
		else if (currentMkdPath_.HasParent()) {
			segments_.push_back(currentMkdPath_.GetLastSegment());
			currentMkdPath_ = currentMkdPath_.GetParent();
		}
		else {
			opState = mkd_tryfull;
		}
		return FZ_REPLY_CONTINUE;
	case mkd_mkdsub:
		if (successful) {
			if (segments_.empty()) {
				log(logmsg::debug_warning, L"  segments_ is empty");
				return FZ_REPLY_INTERNALERROR;
			}
			engine_.GetDirectoryCache().UpdateFile(currentServer_, currentMkdPath_, segments_.back(), true, CDirectoryCache::dir);
			controlSocket_.SendDirectoryListingNotification(currentMkdPath_, false);

			currentMkdPath_.AddSegment(segments_.back());
			segments_.pop_back();

			if (segments_.empty()) {
				return FZ_REPLY_OK;
			}
			else {
				opState = mkd_cwdsub;
			}
		}
		else {
			opState = mkd_tryfull;
		}
		return FZ_REPLY_CONTINUE;
	case mkd_cwdsub:
		if (successful) {
			currentPath_ = currentMkdPath_;
			opState = mkd_mkdsub;
		}
		else {
			opState = mkd_tryfull;
		}
		return FZ_REPLY_CONTINUE;
	case mkd_tryfull:
		return successful ? FZ_REPLY_OK : FZ_REPLY_ERROR;
	default:
		log(logmsg::debug_warning, L"unknown op state: %d", opState);
	}

	return FZ_REPLY_INTERNALERROR;
}
