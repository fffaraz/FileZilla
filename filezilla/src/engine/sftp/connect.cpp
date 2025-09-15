#include "../filezilla.h"

#include "connect.h"
#include "event.h"
#include "input_parser.h"
#include "../proxy.h"

#include "../../include/engine_options.h"

#include <libfilezilla/local_filesys.hpp>
#include <libfilezilla/process.hpp>

#ifndef FZ_WINDOWS
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libfilezilla/util.hpp>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#endif

namespace {
enum connectStates
{
	connect_init,
	connect_proxy,
	connect_keys,
	connect_open
};
}

int CSftpConnectOpData::Send()
{
	switch (opState)
	{
	case connect_init:
		{
			log(logmsg::status, _("Connecting to %s..."), currentServer_.Format(ServerFormat::with_optional_port, controlSocket_.credentials_));

			if (!controlSocket_.buffer_pool_) {
				return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
			}

			engine_.GetRateLimiter().add(&controlSocket_);
			if (!controlSocket_.credentials_.keyFile_.empty()) {
				keyfiles_ = fz::strtok(controlSocket_.credentials_.keyFile_, L"\r\n");
			}
			else {
				keyfiles_ = fz::strtok(options_.get_string(OPTION_SFTP_KEYFILES), L"\r\n");
			}

			keyfiles_.erase(
						std::remove_if(keyfiles_.begin(), keyfiles_.end(),
									   [this](std::wstring const& keyfile) {
							if (fz::local_filesys::get_file_type(fz::to_native(keyfile), true) != fz::local_filesys::file) {
								log(logmsg::status, _("Skipping non-existing key file \"%s\""), keyfile);
								return true;
							}
							return false;
						}), keyfiles_.end());

			keyfile_ = keyfiles_.cbegin();

			auto executable = fz::to_native(options_.get_string(OPTION_FZSFTP_EXECUTABLE));
			if (executable.empty()) {
				executable = fzT("fzsftp");
			}

			log(logmsg::debug_verbose, L"Going to execute %s", executable);

			std::vector<fz::native_string> args = { fzT("-v") };
			if (options_.get_int(OPTION_SFTP_COMPRESSION)) {
				args.push_back(fzT("-C"));
			}

			controlSocket_.process_ = std::make_unique<fz::process>(engine_.GetThreadPool(), controlSocket_);
#ifndef FZ_WINDOWS
			std::vector<int> fds;
			auto info = controlSocket_.buffer_pool_->shared_memory_info();
			fds.push_back(std::get<0>(info));
			if (!controlSocket_.process_->spawn(executable, args, fds)) {
#else
			if (!controlSocket_.process_->spawn(executable, args)) {
#endif
				log(logmsg::debug_warning, L"Could not create process");
				return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
			}

			controlSocket_.input_parser_ = std::make_unique<SftpInputParser>(controlSocket_, *controlSocket_.process_);
		}
		return FZ_REPLY_WOULDBLOCK;
	case connect_proxy:
		{
			int type;
			switch (options_.get_int(OPTION_PROXY_TYPE))
			{
			case static_cast<int>(ProxyType::HTTP):
				type = 1;
				break;
			case static_cast<int>(ProxyType::SOCKS5):
				type = 2;
				break;
			case static_cast<int>(ProxyType::SOCKS4):
				type = 3;
				break;
			default:
				log(logmsg::debug_warning, L"Unsupported proxy type");
				return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
			}

			std::wstring cmd = fz::sprintf(L"proxy %d \"%s\" %d", type,
				options_.get_string(OPTION_PROXY_HOST),
				options_.get_int(OPTION_PROXY_PORT));
			std::wstring user = options_.get_string(OPTION_PROXY_USER);
			if (!user.empty()) {
				cmd += L" \"" + user + L"\"";
			}

			std::wstring show = cmd;
			std::wstring pass = options_.get_string(OPTION_PROXY_PASS);
			if (!pass.empty()) {
				cmd += L" \"" + pass + L"\"";
				show += L" \"" + std::wstring(pass.size(), '*') + L"\"";
			}
			return controlSocket_.SendCommand(cmd, show);
		}
		break;
	case connect_keys:
		return controlSocket_.SendCommand(L"keyfile \"" + *(keyfile_++) + L"\"");
	case connect_open:
		{
			std::wstring user = (controlSocket_.credentials_.logonType_ == LogonType::anonymous) ? L"anonymous" : currentServer_.GetUser();
			return controlSocket_.SendCommand(fz::sprintf(L"open \"%s@%s\" %d", user, controlSocket_.ConvertDomainName(currentServer_.GetHost()), currentServer_.GetPort()));
		}
	default:
		log(logmsg::debug_warning, L"Unknown op state: %d", opState);
		break;
	}

	return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
}

int CSftpConnectOpData::ParseResponse()
{
	if (controlSocket_.result_ != FZ_REPLY_OK) {
		return FZ_REPLY_ERROR | FZ_REPLY_DISCONNECTED;
	}

	switch (opState)
	{
	case connect_init:
		if (controlSocket_.response_ != fz::sprintf(L"fzSftp started, protocol_version=%d", FZSFTP_PROTOCOL_VERSION)) {
			log(logmsg::error, _("fzsftp belongs to a different version of FileZilla"));
			return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
		}
		if (options_.get_int(OPTION_PROXY_TYPE) && !currentServer_.GetBypassProxy()) {
			opState = connect_proxy;
		}
		else if (keyfile_ != keyfiles_.cend()) {
			opState = connect_keys;
		}
		else {
			opState = connect_open;
		}
		break;
	case connect_proxy:
		if (keyfile_ != keyfiles_.cend()) {
			opState = connect_keys;
		}
		else {
			opState = connect_open;
		}
		break;
	case connect_keys:
		if (keyfile_ == keyfiles_.cend()) {
			opState = connect_open;
		}
		break;
	case connect_open:
		engine_.AddNotification(std::make_unique<CSftpEncryptionNotification>(controlSocket_.m_sftpEncryptionDetails));
		return FZ_REPLY_OK;
	default:
		log(logmsg::debug_warning, L"Unknown op state: %d", opState);
		return FZ_REPLY_INTERNALERROR | FZ_REPLY_DISCONNECTED;
	}

	return FZ_REPLY_CONTINUE;
}

int CSftpConnectOpData::Reset(int result)
{
	if (opState == connect_init && (result & FZ_REPLY_CANCELED) != FZ_REPLY_CANCELED) {
		log(logmsg::error, _("fzsftp could not be started"));
	}
	if (criticalFailure) {
		result |= FZ_REPLY_CRITICALERROR;
	}
	return result;
}
