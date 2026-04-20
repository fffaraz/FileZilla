#ifndef FZSSH_SFTP_CLIENT_HEADER
#define FZSSH_SFTP_CLIENT_HEADER

#include "../visibility_client.hpp"
#include "sftp.hpp"

#include <libfilezilla/event.hpp>
#include <memory>

namespace fz {

class event_handler;
class event_loop;
class socket_interface;

namespace ssh::sftp {

struct entry : public attributes
{
	// Names are in UTF8
	std::string_view name_;
	std::string_view longname_;
};

class FZSSH_CLIENT_PUBLIC_SYMBOL response_handler
{
protected:
	virtual ~response_handler() = default;

public:
	virtual continuation process_status(status_code /*status*/, std::string_view /*message*/) { return continuation::next; }

	// Handles are opaque (server-determined)
	virtual continuation process_handle(std::string_view /*handle*/) { return continuation::next; }
	virtual continuation process_data(std::string_view /*data*/) { return continuation::next; }

	virtual continuation process_name(entry & /*e*/, bool /*more*/) { return continuation::next; }

	virtual continuation process_attributes(attributes & /*attrs*/) { return continuation::next; }

	// Got a bad packet from the server, but the session as a whole can continue
	virtual continuation failure() { return continuation::next; }
};

class sftp_client_impl;
class FZSSH_CLIENT_PUBLIC_SYMBOL sftp_client final
{
public:
	sftp_client(std::unique_ptr<socket_interface> && channel, event_handler & handler, logger_interface & logger);

	~sftp_client();

	void unblock_read();
	bool is_retrying_process();

	void cancel(response_handler* handler);
	void cancel_wait(fz::event_handler* handler);

	size_t pending_requests();

	bool can_send_packets();
	bool can_send_packets(event_handler & waiter);

	// Guarantees: All answers are delivered in request order. Cannot get answer type that doesn't match the request type.

	// Filenames are in UTF8
	void realpath(response_handler* handler, std::string_view name);

	// Handles are opaque (server-determined)
	void close(response_handler* handler, std::string_view handle);

	void opendir(response_handler* handler, std::string_view name);
	void readdir(response_handler* handler, std::string_view handle);

	void open(response_handler* handler, std::string_view name, file_flags flags, std::optional<attributes> const& initial_attributes = std::nullopt);
	void read(response_handler* handler, std::string_view handle, uint64_t offset, uint32_t size);
	void write(response_handler* handler, std::string_view handle, uint64_t offset, std::string_view data);

	void stat(response_handler* handler, std::string_view name);
	void fstat(response_handler* handler, std::string_view handle);

	void setstat(response_handler* handler, std::string_view name, attributes const& attrs);
	void fsetstat(response_handler* handler, std::string_view handle, attributes const& attrs);

	void remove(response_handler* handler, std::string_view name);
	void rename(response_handler* handler, std::string_view oldname, std::string_view newname);
	void mkdir(response_handler* handler, std::string_view name, attributes const& attrs);
	void rmdir(response_handler* handler, std::string_view name);

	void disconnect();

	struct done_event_type;
	typedef simple_event<done_event_type, sftp_client*> done_event;

	/// Sent once protocol version has been negotiated
	struct ready_event_type;
	typedef simple_event<ready_event_type, sftp_client*> ready_event;

private:
	std::unique_ptr<sftp_client_impl> impl_;
};

struct outbuf_empty_event_type;
typedef simple_event<outbuf_empty_event_type, sftp_client*> outbuf_empty_event;

}
}

#endif
