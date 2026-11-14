#ifndef FILEZILLA_ENGINE_SFTP_FILETRANSFER_HEADER
#define FILEZILLA_ENGINE_SFTP_FILETRANSFER_HEADER

#include "sftpcontrolsocket.h"

class CSftpFileTransferOpData final : public CFileTransferOpData, public CSftpOpData
{
public:
	CSftpFileTransferOpData(CSftpControlSocket & controlSocket, CFileTransferCommand const& cmd)
		: CFileTransferOpData(L"CSftpFileTransferOpData", cmd)
		, CSftpOpData(controlSocket)
	{}

	~CSftpFileTransferOpData();

	virtual int Send() override;
	virtual int ParseResponse() override { return FZ_REPLY_INTERNALERROR; }
	virtual int SubcommandResult(int, COpData const&) override;
	virtual int Reset(int result) override;

private:
	virtual continuation process_handle(std::string_view handle) override;
	virtual continuation process_data(std::string_view data) override;
	virtual continuation do_process_status(fz::ssh::sftp::status_code code, std::wstring_view msg) override;
	virtual continuation process_attributes(fz::ssh::sftp::attributes & attrs) override;

	virtual void operator()(fz::event_base const& ev) override;
	void OnBufferAvailability(fz::aio_waitable const* w);
	void on_can_send(fz::ssh::sftp::sftp_client*);
	void OnTimer(fz::timer_id);

	virtual void on_pong() override;

	fz::aio_result get_next_download_buffer();
	fz::aio_result get_next_upload_buffer();
	void finalize();
	void request_data();

	int CheckRemoteFile(bool after_listing);

	uint64_t request_offset_{};

	void update_max_pending();

	std::unique_ptr<fz::reader_base> reader_;
	std::unique_ptr<fz::writer_base> writer_;
	bool finalizing_{};
	bool short_read_{};
	bool called_fsetstat_{};
	bool measure_rtt_{};

	fz::buffer_lease buffer_;

	std::string handle_;

	struct goodhput_measurement {
		fz::monotonic_clock since_;
		uint64_t amount_{};
	} goodput_;

	fz::timer_id ping_timer_{};
#if FZ_WINDOWS
	fz::timer_id sendbuf_timer_{};
#endif

	constexpr static size_t blocksize_{32768};

	enum class mode {
		startup,
		steady,
		probe
	} mode_{};

	uint64_t best_goodput_{};
	size_t queue_size_{16};
	size_t previous_best_queue_size_{16};
	unsigned failed_probes_{};
	fz::monotonic_clock last_probe_;
};

#endif
