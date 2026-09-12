#ifndef FILEZILLA_ENGINE_SFTP_LIST_HEADER
#define FILEZILLA_ENGINE_SFTP_LIST_HEADER

#include "../directorylistingparser.h"
#include "sftpcontrolsocket.h"

class CSftpListOpData final : public CListOpData, public CSftpOpData
{
public:
	CSftpListOpData(CSftpControlSocket & controlSocket, CServerPath const& path, int flags)
		: CListOpData(path, L"CSftpListOpData"sv)
		, CSftpOpData(controlSocket)
		, flags_(flags)
	{}

	virtual int Send() override;
	virtual int ParseResponse() override { return FZ_REPLY_INTERNALERROR; }
	virtual int Reset(int result) override;

	virtual continuation process_handle(std::string_view handle) override;
	virtual continuation process_name(fz::ssh::sftp::entry & e, bool more) override;
	virtual continuation process_attributes(fz::ssh::sftp::attributes & a) override;
	virtual continuation do_process_status(fz::ssh::sftp::status_code code, std::wstring_view msg) override;

private:
	std::unique_ptr<CDirectoryListingParser> listing_parser_;

	int flags_{};

	// Set to true to get a directory listing even if a cache
	// lookup can be made after finding out true remote directory
	bool refresh_{};
	bool realpath_failed_{};
	bool is_directory_{};

	CDirectoryListing directoryListing_;

	fz::monotonic_clock time_before_locking_;

	std::string handle_;
};

#endif
