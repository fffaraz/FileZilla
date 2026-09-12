#include "../filezilla.h"

#include "../directorycache.h"
#include "../pathcache.h"
#include "list.h"

#include <assert.h>

namespace {
enum listStates
{
	list_init = 0,
	list_realpath,
	list_waitlock,
	list_stat_and_open,
	list_open,
	list_list
};
}

int CSftpListOpData::Send()
{
	if (!sftp_) {
		return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
	}

	if (opState == list_init) {
		refresh_ = (flags_ & LIST_FLAG_REFRESH) != 0;

		if (path_.empty()) {
			log(logmsg::status, _("Retrieving directory listing..."));
		}
		else {
			log(logmsg::status, _("Retrieving directory listing of \"%s\"..."), path_.GetPath());
		}

		if (!path_.empty()) {
			auto target = engine_.GetPathCache().Lookup(currentServer_, path_, L"");
			if (!target.empty() && target != path_) {
				path_ = target;
				log(logmsg::status, _("Canonicalized path is \"%s\""), path_.GetPath());
				opState = list_waitlock;
				return FZ_REPLY_CONTINUE;
			}
		}
		opState = list_realpath;
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == list_realpath) {
		if (path_.empty()) {
			sftp_->realpath(this, "."sv);
		}
		else {
			std::string path = controlSocket_.ConvToServer(path_.GetPath());
			if (path.empty()) {
				return FZ_REPLY_ERROR;
			}
			sftp_->realpath(this, path);
		}
		return FZ_REPLY_WOULDBLOCK;
	}
	else if (opState == list_waitlock) {
		if (path_.empty()) {
			return FZ_REPLY_INTERNALERROR;
		}

		// Check if we can use already existing listing
		CDirectoryListing listing;
		bool is_outdated = false;
		bool found = engine_.GetDirectoryCache().Lookup(listing, currentServer_, path_, false, is_outdated);
		if (found && !is_outdated &&
			(!refresh_ || (opLock_ && listing.m_firstListTime >= time_before_locking_)))
		{
			controlSocket_.SendDirectoryListingNotification(listing.path, false);
			return FZ_REPLY_OK;
		}

		if (!opLock_) {
			opLock_ = controlSocket_.Lock(locking_reason::list, path_);
			time_before_locking_ = fz::monotonic_clock::now();
		}
		if (opLock_.waiting()) {
			return FZ_REPLY_WOULDBLOCK;
		}

		opState = list_stat_and_open;
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == list_stat_and_open) {
		listing_parser_ = std::make_unique<CDirectoryListingParser>(&controlSocket_, currentServer_, listingEncoding::unknown);
		std::string path = controlSocket_.ConvToServer(path_.GetPath());
		if (path.empty()) {
			return FZ_REPLY_ERROR;
		}
		sftp_->stat(this, path);
		sftp_->opendir(this, path);
		return FZ_REPLY_WOULDBLOCK;
	}

	log(logmsg::debug_warning, L"Unknown opState in CSftpListOpData::Send()");
	return FZ_REPLY_INTERNALERROR;
}

int CSftpListOpData::Reset(int result)
{
	if (sftp_ && !handle_.empty()) {
		sftp_->close(nullptr, handle_);
	}
	handle_.clear();

	return result;
}

CSftpOpData::continuation CSftpListOpData::process_handle(std::string_view handle)
{
	if (opState == list_open) {
		handle_ = handle;

		// Pipeline requests
		for (size_t i = 0; i < 4; ++i) {
			sftp_->readdir(this, handle_);
		}

		opState = list_list;
		return continuation::next;
	}

	trigger_reset(FZ_REPLY_INTERNALERROR);
	return continuation::error;
}

CSftpOpData::continuation CSftpListOpData::do_process_status(fz::ssh::sftp::status_code code, std::wstring_view msg)
{
	if (opState == list_realpath) {
		if (path_.empty()) {
			log(logmsg::error, _("Could not obtain initial remote path, trying root directory instead: %s"), msg);
			path_.SetPath(L"/");
		}
		opState = list_waitlock;
		realpath_failed_ = true;
		trigger_next();
		return continuation::next;
	}
	else if (opState == list_stat_and_open) {
		opState = list_open;
		return continuation::next;
	}
	else if (opState == list_open) {
		int error = FZ_REPLY_ERROR;
		if (flags_ & LIST_FLAG_LINK) {
			log(logmsg::debug_info, L"Symlink does not link to a directory, probably a file");
			error = FZ_REPLY_LINKNOTDIR;
		}
		else {
			if (is_directory_) {
				controlSocket_.SendDirectoryListingNotification(path_, true);
			}
		}
		log(logmsg::error, _("Could not open directory: %s"), msg);
		trigger_reset(error);
		return continuation::next;
	}
	else if (opState == list_list) {
		if (code == fz::ssh::sftp::status_code::SSH_FX_EOF) {
			if (!listing_parser_) {
				log(logmsg::debug_warning, L"listing_parser_ is empty");
				trigger_reset(FZ_REPLY_INTERNALERROR);
				return continuation::error;
			}

			if (realpath_failed_) {
				engine_.GetPathCache().Store(currentServer_, path_, path_);
			}

			directoryListing_ = listing_parser_->Parse(path_);
			engine_.GetDirectoryCache().Store(directoryListing_, currentServer_);
			controlSocket_.SendDirectoryListingNotification(path_, false);
			trigger_reset(FZ_REPLY_OK);
		}
		else {
			log(logmsg::error, _("Could not read directory: %s"), msg);
			controlSocket_.SendDirectoryListingNotification(path_, true);
			trigger_reset(FZ_REPLY_ERROR);
		}
		return continuation::next;
	}

	trigger_reset(FZ_REPLY_INTERNALERROR);
	return continuation::error;
}

CSftpOpData::continuation CSftpListOpData::process_attributes(fz::ssh::sftp::attributes & a)
{
	if (opState == list_stat_and_open) {
		if (a.is_directory()) {
			is_directory_ = true;
		}
		opState = list_open;
		return continuation::next;
	}

	trigger_reset(FZ_REPLY_INTERNALERROR);
	return continuation::error;
}

CSftpOpData::continuation CSftpListOpData::process_name(fz::ssh::sftp::entry & e, bool more)
{
	if (opState == list_realpath) {
		auto target = controlSocket_.ParsePath(controlSocket_.ConvToLocal(e.name_.data(), e.name_.size()));
		if (target.empty()) {
			trigger_reset(FZ_REPLY_ERROR);
			return continuation::next;
		}

		if (target != path_) {
			if  (path_.empty()) {
				log(logmsg::debug_warning, "Initial remote directory: %s"sv, target.GetPath());
			}
			else {
				log(logmsg::status, _("Canonical path is \"%s\""), target.GetPath());
				engine_.GetPathCache().Store(currentServer_, target, path_);
			}
			path_ = target;
		}

		opState = list_waitlock;
		trigger_next();

		return continuation::next;
	}
	else if (opState == list_list) {
		std::wstring name = controlSocket_.ConvToLocal(e.name_.data(), e.name_.size());
		std::wstring longname = controlSocket_.ConvToLocal(e.longname_.data(), e.longname_.size());

		if (!more) {
			sftp_->readdir(this, handle_);
		}

		if (!listing_parser_) {
			log(logmsg::debug_warning, L"listing_parser_ is null");
			trigger_reset(FZ_REPLY_INTERNALERROR);
			return continuation::error;
		}

		std::optional<int> flags;
		if (e.perms_) {
			flags.emplace();
			if (e.is_directory()) {
				*flags |= CDirentry::flag_dir;
			}
			if (e.is_symlink()) {
				*flags |= CDirentry::flag_dir | CDirentry::flag_link;
			}
		}

		listing_parser_->AddLine(std::move(longname), std::move(name), e.modified_ ? *e.modified_ : fz::datetime(), e.size_, flags);
		return continuation::next;
	}

	trigger_reset(FZ_REPLY_INTERNALERROR);
	return continuation::error;
}
