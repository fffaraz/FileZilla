#ifndef LIBFILEZILLA_ASCII_LAYER_HEADER
#define LIBFILEZILLA_ASCII_LAYER_HEADER

#include "buffer.hpp"
#include "socket.hpp"

#include <optional>

/** \file
 * \brief Declares \ref fz::ascii_layer
 */

namespace fz {
/**
 * A socket layer that transforms between line endings.
 *
 * When sending, LF not preceeded by CR is converted into CRLF. Stray CRs are kept.
 * When receiving, CRs followed by LF are removed. As with sending, stray CRs ar kept.
 */
class FZ_PUBLIC_SYMBOL ascii_layer final : public socket_layer, protected fz::event_handler
{
public:
	ascii_layer(event_loop& loop, event_handler* handler, socket_interface& next_layer);
	virtual ~ascii_layer();

	virtual int read(void *buffer, unsigned int size, int& error) override;
	virtual int write(void const* buffer, unsigned int size, int& error) override;

	virtual int shutdown() override;

	virtual void set_event_handler(event_handler* handler, fz::socket_event_flag retrigger_block = fz::socket_event_flag{}) override;

private:
	virtual FZ_PRIVATE_SYMBOL void operator()(fz::event_base const& ev) override;
	void FZ_PRIVATE_SYMBOL on_socket_event(socket_event_source* s, socket_event_flag t, int error);

	std::optional<uint8_t> tmp_read_;
	buffer buffer_;
	bool was_cr_{};
	bool write_blocked_by_send_buffer_{};
	bool waiting_read_{};
};
}

#endif
