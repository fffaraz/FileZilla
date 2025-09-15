#include "libfilezilla/hostname_lookup.hpp"

#ifdef FZ_WINDOWS
#include "libfilezilla/glue/windows.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#endif

#include "libfilezilla/socket.hpp"
#include "libfilezilla/thread_pool.hpp"

#ifndef FZ_WINDOWS
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

namespace fz {

class hostname_lookup::impl
{
public:
	impl(hostname_lookup * parent, thread_pool& pool, event_handler* h)
		: parent_(parent), pool_(pool), handler_(h)
	{
	}

	bool spawn() {
		if (!thread_) {
			thread_ = pool_.spawn([this](){ entry(); });
		}
		return thread_.operator bool();
	}

	void entry();
	void do_lookup(scoped_lock & l);

	mutex mtx_{false};
	hostname_lookup* parent_;
	thread_pool & pool_;
	event_handler* handler_{};
	condition cond_;
	async_task thread_;
	std::string host_;
	address_type family_{};
};

void hostname_lookup::impl::entry()
{
	scoped_lock l(mtx_);
	if (thread_) {
		do {
			cond_.wait(l);
			do_lookup(l);

		} while (thread_);
	}

	l.unlock();
	delete this;
}

int convert_msw_error_code(int error);

void hostname_lookup::impl::do_lookup(scoped_lock& l)
{
	if (host_.empty()) {
		return;
	}

	l.unlock();

	addrinfo hints{};
	switch (family_) {
	case address_type::ipv4:
		hints.ai_family = AF_INET;
		break;
	case address_type::ipv6:
		hints.ai_family = AF_INET6;
		break;
	default:
		hints.ai_family = AF_UNSPEC;
		break;
	}
	hints.ai_socktype = SOCK_STREAM;
#ifdef AI_IDN
	hints.ai_flags |= AI_IDN;
#endif

	addrinfo* addressList{};
	int res = getaddrinfo(host_.c_str(), nullptr, &hints, &addressList);

	l.lock();

	if (!thread_) {
		if (!res) {
			freeaddrinfo(addressList);
		}
		return;
	}

	std::vector<std::string> addrs;
	if (res) {
#ifdef FZ_WINDOWS
		res = convert_msw_error_code(res);
#endif
	}
	else {
		for (addrinfo* addr = addressList; addr && !res; addr = addr->ai_next) {
			auto s = socket::address_to_string(addr->ai_addr, addr->ai_addrlen, false);
			if (!s.empty()) {
				addrs.emplace_back(std::move(s));
			}
		}
	}

	freeaddrinfo(addressList);

	handler_->send_event<hostname_lookup_event>(parent_, res, std::move(addrs));
	host_.clear();
}

hostname_lookup::hostname_lookup(thread_pool& pool, event_handler& evt_handler)
	: impl_(new impl(this, pool, &evt_handler))
{
}

bool hostname_lookup::lookup(native_string const& host, address_type family)
{
	if (host.empty()) {
		return false;
	}

	scoped_lock l(impl_->mtx_);
	if (!impl_->host_.empty()) {
		return false;
	}

	if (!impl_->spawn()) {
		return false;
	}

	impl_->host_ = fz::to_string(host);
	impl_->family_ = family;
	impl_->cond_.signal(l);
	return true;
}

namespace {
void filter_hostname_events(fz::hostname_lookup* lookup, fz::event_handler* handler)
{
	auto filter = [&](event_base const& ev) -> bool {
		if (ev.derived_type() != hostname_lookup_event::type()) {
			return false;
		}
		return std::get<0>(static_cast<hostname_lookup_event const&>(ev).v_) == lookup;
	};

	handler->filter_events(filter);
}
}

hostname_lookup::~hostname_lookup()
{
	scoped_lock l(impl_->mtx_);
	if (!impl_->thread_) {
		l.unlock();
		delete impl_;
	}
	else {
		filter_hostname_events(this, impl_->handler_);

		impl_->thread_.detach();
		impl_->cond_.signal(l);
	}
}

void hostname_lookup::reset()
{
	scoped_lock l(impl_->mtx_);
	if (!impl_->thread_) {
		return;
	}

	filter_hostname_events(this, impl_->handler_);
	if (!impl_->host_.empty()) {
		impl_->thread_.detach();
		impl_->cond_.signal(l);
		impl_ = new impl(this, impl_->pool_, impl_->handler_);
	}
}

}
