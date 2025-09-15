#include "../filezilla.h"

#include "../directorycache.h"
#include "list.h"

#include <assert.h>

namespace {
enum listStates
{
	list_init = 0,
	list_waitcwd,
	list_waitlock,
	list_list
};
}

int CSftpListOpData::Send()
{
	if (opState == list_init) {
		if (path_.GetType() == DEFAULT) {
			path_.SetType(currentServer_.GetType());
		}
		refresh_ = (flags_ & LIST_FLAG_REFRESH) != 0;
		fallback_to_current_ = !path_.empty() && (flags_ & LIST_FLAG_FALLBACK_CURRENT) != 0;

		auto newPath = CServerPath::GetChanged(currentPath_, path_, subDir_);
		if (newPath.empty()) {
			log(logmsg::status, _("Retrieving directory listing..."));
		}
		else {
			log(logmsg::status, _("Retrieving directory listing of \"%s\"..."), newPath.GetPath());
		}

		controlSocket_.ChangeDir(path_, subDir_, (flags_ & LIST_FLAG_LINK) != 0);
		opState = list_waitcwd;
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == list_waitlock) {
		assert(subDir_.empty()); // We did do ChangeDir before trying to lock

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
			opLock_ = controlSocket_.Lock(locking_reason::list, currentPath_);
			time_before_locking_ = fz::monotonic_clock::now();
		}
		if (opLock_.waiting()) {
			return FZ_REPLY_WOULDBLOCK;
		}

		opState = list_list;
		return FZ_REPLY_CONTINUE;
	}
	else if (opState == list_list) {
		listing_parser_ = std::make_unique<CDirectoryListingParser>(&controlSocket_, currentServer_, listingEncoding::unknown);
		return controlSocket_.SendCommand(L"ls");
	}

	log(logmsg::debug_warning, L"Unknown opState in CSftpListOpData::Send()");
	return FZ_REPLY_INTERNALERROR;
}

int CSftpListOpData::ParseResponse()
{
	if (opState == list_list) {
		if (controlSocket_.result_ != FZ_REPLY_OK) {
			return FZ_REPLY_ERROR;
		}

		if (!listing_parser_) {
			log(logmsg::debug_warning, L"listing_parser_ is empty");
			return FZ_REPLY_INTERNALERROR;
		}

		directoryListing_ = listing_parser_->Parse(currentPath_);
		engine_.GetDirectoryCache().Store(directoryListing_, currentServer_);
		controlSocket_.SendDirectoryListingNotification(currentPath_, false);

		return FZ_REPLY_OK;
	}

	log(logmsg::debug_warning, L"ListParseResponse called at improper time: %d", opState);
	return FZ_REPLY_INTERNALERROR;
}

int CSftpListOpData::SubcommandResult(int prevResult, COpData const&)
{
	if (opState != list_waitcwd) {
		return FZ_REPLY_INTERNALERROR;
	}

	if (prevResult != FZ_REPLY_OK) {
		if (fallback_to_current_) {
			// List current directory instead
			fallback_to_current_ = false;
			path_.clear();
			subDir_.clear();
			controlSocket_.ChangeDir();
			return FZ_REPLY_CONTINUE;
		}
		else {
			return prevResult;
		}
	}

	path_ = currentPath_;
	subDir_.clear();
	opState = list_waitlock;
	return FZ_REPLY_CONTINUE;
}

int CSftpListOpData::ParseEntry(std::wstring && entry, uint64_t mtime, std::wstring && name)
{
	if (opState != list_list) {
		controlSocket_.log_raw(logmsg::listing, entry);
		log(logmsg::debug_warning, L"CSftpListOpData::ParseEntry called at improper time: %d", opState);
		return FZ_REPLY_INTERNALERROR;
	}

	if (entry.size() > 65536 || name.size() > 65536) {
		log(fz::logmsg::error, _("Received too long response line from server, closing connection."));
		return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
	}


	if (!listing_parser_) {
		controlSocket_.log_raw(logmsg::listing, entry);
		log(logmsg::debug_warning, L"listing_parser_ is null");
		return FZ_REPLY_INTERNALERROR;
	}

	fz::datetime time;
	if (mtime) {
		time = fz::datetime(static_cast<time_t>(mtime), fz::datetime::seconds);
	}
	listing_parser_->AddLine(std::move(entry), std::move(name), time);

	return FZ_REPLY_WOULDBLOCK;
}
