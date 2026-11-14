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

	virtual void check_peer_compatibility(bool preliminary) override;
	virtual continuation process_ext_info(std::string_view name, std::string_view value) override;

	virtual continuation process_local_extension(message_id id, std::string_view packet) override;

	continuation process_pong(std::string_view packet);
	void continue_process_pong(std::string_view data);

	continuation init_dh();
	virtual bool setup_hostkey() override;
	virtual std::string_view host_pubkey() const override;

	void hostkey_decision(bool accept);

	virtual continuation on_auth_success() override;

	std::unique_ptr<public_key> host_pubkey_;
	std::string previous_hostkey_;

	void ping();

private:
	void stop_ping(std::optional<duration> const& rtt);
	void send_ping(bool from_ping);

	virtual void operator()(event_base const& ev) override;
	void on_timer(timer_id);

	enum class ping_mode {
		unsupported,
		fallback,
		supported
	};
	struct ping_state {
		ping_mode mode_{ping_mode::unsupported};

		timer_id timer_{};
		fz::monotonic_clock start_;
		uint32_t data_{};
		size_t retries_{};
		bool sent_{};
		bool interrupted_by_keying_{};
	} ping_state_;
};

}

#endif
