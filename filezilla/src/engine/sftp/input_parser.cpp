#include "../filezilla.h"

#include "event.h"
#include "input_parser.h"
#include "sftpcontrolsocket.h"

#include <libfilezilla/process.hpp>

SftpInputParser::SftpInputParser(CSftpControlSocket& owner, fz::process& proc)
	: process_(proc)
	, owner_(owner)
{
}

SftpInputParser::~SftpInputParser()
{
}

size_t SftpInputParser::lines(sftpEvent eventType) const
{
	switch (eventType)
	{
	case sftpEvent::count:
	case sftpEvent::Unknown:
		break;
	case sftpEvent::UsedQuotaRecv:
	case sftpEvent::UsedQuotaSend:
	case sftpEvent::io_size:
		return 0;
	case sftpEvent::Recv:
	case sftpEvent::Send:
	case sftpEvent::Reply:
	case sftpEvent::Done:
	case sftpEvent::Error:
	case sftpEvent::Verbose:
	case sftpEvent::Info:
	case sftpEvent::Status:
	case sftpEvent::Transfer:
	case sftpEvent::AskPassword:
	case sftpEvent::RequestPreamble:
	case sftpEvent::RequestInstruction:
	case sftpEvent::KexAlgorithm:
	case sftpEvent::KexHash:
	case sftpEvent::KexCurve:
	case sftpEvent::CipherClientToServer:
	case sftpEvent::CipherServerToClient:
	case sftpEvent::MacClientToServer:
	case sftpEvent::MacServerToClient:
	case sftpEvent::Hostkey:
	case sftpEvent::io_open:
	case sftpEvent::io_finalize:
	case sftpEvent::io_nextbuf:
		return 1;
	case sftpEvent::AskHostkey:
	case sftpEvent::AskHostkeyChanged:
	case sftpEvent::AskHostkeyBetteralg:
		return 2;
	case sftpEvent::Listentry:
		return 3;
	}
	return 0;
}

int SftpInputParser::OnData()
{
	bool need_read = true;
	while (true) {
		if (need_read || recv_buffer_.empty())  {
			fz::rwresult res = process_.read(recv_buffer_.get(1024), 1024);
			if (res) {
				if (!res.value_) {
					if (listEvent_ || event_) {
						owner_.log(logmsg::error, _("Got unexpected EOF from child process."));
					}
					else {
						owner_.log(logmsg::debug_info, "Got eof from child process");
					}
					return FZ_REPLY_DISCONNECTED;
				}
				recv_buffer_.add(res.value_);
				need_read = false;
			}
			else if (res.error_ == fz::rwresult::wouldblock) {
				return FZ_REPLY_WOULDBLOCK;
			}
			else {
				owner_.log(logmsg::debug_warning, "Could not read from child process with error %d, raw error %d", res.error_, res.raw_);
				return FZ_REPLY_DISCONNECTED;
			}
		}

		else if (event_ || listEvent_) {
			auto const type = listEvent_ ? sftpEvent::Listentry : std::get<0>(event_->v_).type;
			while (pending_lines_) {
				std::string_view v = recv_buffer_.to_view();
				size_t pos = v.find('\n', search_offset_);
				if (pos == std::string_view::npos) {
					if (recv_buffer_.size() > 4096) {
						owner_.log(logmsg::error, _("Got overlong input line, aborting."));
						return FZ_REPLY_WOULDBLOCK;
					}
					search_offset_ = recv_buffer_.size();
					need_read = true;
					break;
				}
				auto line = v.substr(0, pos);
				if (!line.empty() && line.back() == '\r') {
					line = line.substr(0, line.size() - 1);
				}

				size_t i = lines(type) - pending_lines_--;
				if (event_) {
					std::wstring converted = owner_.ConvToLocal(line.data(), line.size());
					if (line.size() && converted.empty()) {
						owner_.log(logmsg::error, _("Failed to convert reply to local character set."));
						return FZ_REPLY_DISCONNECTED;
					}

					std::get<0>(event_->v_).text[i] = std::move(converted);
				}
				else {
					if (i == 1) {
						std::get<0>(listEvent_->v_).mtime = fz::to_integral<uint64_t>(line);
					}
					else {
						std::wstring converted = owner_.ConvToLocal(line.data(), line.size());
						if (line.size() && converted.empty()) {
							owner_.log(logmsg::error, _("Failed to convert reply to local character set."));
							return FZ_REPLY_DISCONNECTED;
						}
						if (i) {
							std::get<0>(listEvent_->v_).name = std::move(converted);
						}
						else {
							std::get<0>(listEvent_->v_).text = std::move(converted);
						}
					}
				}
				recv_buffer_.consume(pos + 1);
				search_offset_ = 0;
			}
			if (!pending_lines_) {
				if (event_) {
					owner_.send_event(event_.release());
				}
				else {
					owner_.send_event(listEvent_.release());
				}
			}
		}
		else {
			auto const eventType = static_cast<sftpEvent>(*recv_buffer_.get() - '0');
			recv_buffer_.consume(1);

			if (eventType <= sftpEvent::Unknown || eventType >= sftpEvent::count) {
				owner_.log(logmsg::error, _("Unknown eventType %d"), eventType);
				break;
			}

			if (eventType == sftpEvent::Listentry) {
				listEvent_ = std::make_unique<CSftpListEvent>();
			}
			else {
				event_ = std::make_unique<CSftpEvent>();
				std::get<0>(event_->v_).type = eventType;
			}
			pending_lines_ = lines(eventType);
			if (!pending_lines_) {
				owner_.send_event(event_.release());
			}
		}
	}
	return FZ_REPLY_WOULDBLOCK;
}
