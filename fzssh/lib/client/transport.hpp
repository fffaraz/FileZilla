#ifndef FZSSH_CLIENT_TRANSPORT_HEADER
#define FZSSH_CLIENT_TRANSPORT_HEADER

#include "../transport.hpp"
#include "../fzssh/client.hpp"

namespace fz::ssh {

class client_transport final : public transport
{
public:
	client_transport(session& sess, client_parameters const& params, std::string_view username, socket_interface & s, event_handler & h, logger_interface & logger);
	~client_transport();

	virtual continuation process_dh_gex_group(std::string_view packet) override;
	virtual continuation process_dh_reply(std::string_view name, std::string_view packet) override;
	virtual continuation process_service_accept(std::string_view packet) override;

	virtual continuation finalize_kexinit(std::string_view peer_hostkeys, bool bad_guess) override;

	virtual continuation process_ext_info(std::string_view name, std::string_view value) override;

	continuation init_dh();
	virtual bool setup_hostkey() override;
	virtual std::string_view host_pubkey() const override;

	void hostkey_decision(bool accept);

	virtual continuation on_auth_success() override;

	std::unique_ptr<public_key> host_pubkey_;
	std::string previous_hostkey_;
};

}

#endif
