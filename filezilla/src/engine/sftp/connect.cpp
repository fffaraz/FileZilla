#include "../filezilla.h"
#include "../ssh/ssh_auth.h"

#include "connect.h"

#include <fzssh/client.hpp>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

namespace sftpConnectStates {
enum type {
	init,
	connection
};
}

CSftpConnectOpData::~CSftpConnectOpData()
{
	auth_.reset();
	remove_handler();
}

int CSftpConnectOpData::Send()
{
	switch (opState) {
	case sftpConnectStates::init:
		{
			opState = sftpConnectStates::connection;
			int ret = controlSocket_.DoConnect(currentServer_.GetHost(), currentServer_.GetPort());
			if (ret == FZ_REPLY_WOULDBLOCK) {
				// Enable TCP_NODELAY, speeds things up a bit.
				controlSocket_.socket_->set_flags(fz::socket::flag_nodelay | fz::socket::flag_keepalive, true);
			}
			return ret;
		}
	case sftpConnectStates::connection:
		{
			fz::ssh::client_parameters params;
			params.kex_ += ",diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1"sv;
			params.cipher_ += ",aes256-cbc,aes192-cbc,aes128-cbc"sv;
			params.hostkey_signatures_ += ",ssh-rsa"sv;
			params.single_channel_ = true;
			params.softwareversion_ = "FileZilla"sv;
			params.softwareversion_ += ' ';
			params.softwareversion_ += PACKAGE_VERSION;
			for (auto & c : params.softwareversion_) {
				if (c == ' ' || c == '-') {
					c = '_';
				}
			}

			if (currentServer_.GetExtraParameter("allow_non_crlf_identification_string"sv) == L"1") {
				params.compatibility_flags_ |= fz::ssh::compatibility_flags::identification_string_not_terminated_by_crlf;
			}

			std::string user = (controlSocket_.credentials_.logonType_ == LogonType::anonymous) ? "anonymous" : fz::to_utf8(currentServer_.GetUser());
			controlSocket_.ssh_ = std::make_unique<fz::ssh::client>(params, user, *controlSocket_.active_layer_, controlSocket_, controlSocket_.logger_);
			auth_ = std::make_unique<SshAuth>(
				*this,
				controlSocket_,
				currentServer_,
				controlSocket_.GetHandle(),
				controlSocket_.credentials_,
				controlSocket_.ssh_,
				[this] { on_authenticated(); },
				[this](int result) { trigger_reset(result); }
			);
			opState = sftpConnectStates::connection;
			return FZ_REPLY_WOULDBLOCK;
		}
	default:
		break;
	}
	return FZ_REPLY_INTERNALERROR;
}

void CSftpConnectOpData::on_authenticated()
{
	log(logmsg::command, _("Requesting SFTP subsystem"));

	auto si = controlSocket_.ssh_->open_channel(fz::ssh::channel_type::subsystem, "sftp"sv);

	fz::ssh::sftp::compatibility_flags flags{};
	if (currentServer_.GetExtraParameter("ignore_unknown_flags_in_attributes"sv) == L"1") {
		flags |= fz::ssh::sftp::compatibility_flags::ignore_unknown_flags_in_attributes;
	}

	sftp_subsystem_request_time_ = fz::monotonic_clock::now();
	sftp_ = std::make_unique<fz::ssh::sftp::sftp_client>(std::move(si), controlSocket_, controlSocket_.logger_, flags);
}

void CSftpConnectOpData::on_sftp_ready(fz::ssh::sftp::sftp_client*)
{
	log(logmsg::reply, _("SFTP subsystem initialized"));
	auto const now = fz::monotonic_clock::now();

	controlSocket_.srtt_ = std::max(sftp_->initial_rtt(), fz::duration::from_milliseconds(1));
	controlSocket_.srtt_remainder_ = 0;

	controlSocket_.can_use_socket_rtt_ = false;
	if (!controlSocket_.proxy_layer_) {
		auto rtt = controlSocket_.socket_->srtt();
		if (rtt) {
			fz::duration diff = *rtt - controlSocket_.srtt_;
			if (std::abs(diff.get_milliseconds()) <= 20) {
				controlSocket_.can_use_socket_rtt_ = true;
			}
		}
	}

	controlSocket_.last_rtt_update_ = now;
	trigger_reset(FZ_REPLY_OK);
}

