#include "../filezilla.h"

#include "delete.h"
#include "../directorycache.h"

int CSftpDeleteOpData::Send()
{
	std::wstring const& file = files_.back();
	if (file.empty()) {
		log(logmsg::debug_info, L"Empty filename");
		return FZ_REPLY_INTERNALERROR;
	}

	std::wstring filename = path_.FormatFilename(file);
	if (filename.empty()) {
		log(logmsg::error, _("Filename cannot be constructed for directory %s and filename %s"), path_.GetPath(), file);
		return FZ_REPLY_ERROR;
	}

	if (time_.empty()) {
		time_ = fz::datetime::now();
	}

	engine_.GetDirectoryCache().InvalidateFile(currentServer_, path_, file);

	return controlSocket_.SendCommand(L"rm " + controlSocket_.QuoteFilename(filename));
}

int CSftpDeleteOpData::ParseResponse()
{
	if (controlSocket_.result_ != FZ_REPLY_OK) {
		deleteFailed_ = true;
	}
	else {
		std::wstring const& file = files_.back();

		engine_.GetDirectoryCache().RemoveFile(currentServer_, path_, file);

		auto const now = fz::datetime::now();
		if (!time_.empty() && (now - time_).get_seconds() >= 1) {
			controlSocket_.SendDirectoryListingNotification(path_, false);
			time_ = now;
			needSendListing_ = false;
		}
		else {
			needSendListing_ = true;
		}
	}

	files_.pop_back();

	if (!files_.empty()) {
		return FZ_REPLY_CONTINUE;
	}

	return deleteFailed_ ? FZ_REPLY_ERROR : FZ_REPLY_OK;
}

int CSftpDeleteOpData::SubcommandResult(int, COpData const&)
{
	return FZ_REPLY_INTERNALERROR;
}

int CSftpDeleteOpData::Reset(int result)
{
	if (needSendListing_ && !(result & FZ_REPLY_DISCONNECTED)) {
		controlSocket_.SendDirectoryListingNotification(path_, false);
	}
	return result;
}
