#include "../lib/libfilezilla/hash.hpp"
#include "../lib/libfilezilla/logger.hpp"
#include "../lib/libfilezilla/socket.hpp"
#include "../lib/libfilezilla/thread_pool.hpp"
#include "../lib/libfilezilla/tls_layer.hpp"
#include "../lib/libfilezilla/util.hpp"

#include "test_utils.hpp"

#include <optional>
#include <string.h>

using namespace std::literals;

class socket_test final : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(socket_test);
	CPPUNIT_TEST(test_duplex);
	CPPUNIT_TEST(test_duplex_tls);
	CPPUNIT_TEST(test_tls_resumption);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp() {}
	void tearDown() {}

	void test_duplex();
	void test_duplex_tls();

	void do_test_tls_resumption(std::optional<fz::tls_ver> ver, bool server_no_ticket, bool client_no_ticket, bool use_hostname);
	void do_test_tls_resumption(std::optional<fz::tls_ver> ver, bool server_no_ticket, bool client_no_ticket);
	void test_tls_resumption();
};

CPPUNIT_TEST_SUITE_REGISTRATION(socket_test);

namespace {
struct logger : public fz::logger_interface
{
	virtual void do_log(fz::logmsg::type, std::wstring &&) {
	}
};

auto const& get_key_and_cert()
{
	static auto key_and_cert = fz::tls_layer::generate_selfsigned_certificate(fz::native_string(), "CN=libfilezilla test", {});
	return key_and_cert;
}

struct base : public fz::event_handler
{
	base(fz::event_loop & loop, std::vector<uint8_t> const& tls_session_parameters, std::optional<fz::tls_ver> ver = {})
		: fz::event_handler(loop)
		, tls_session_parameters_(tls_session_parameters)
		, tls_ver_(ver)
	{
	}

	void fail(int line, int error = 0)
	{
		fz::scoped_lock l(m_);
		si_ = nullptr;
		tls_.reset();
		s_.reset();
		if (failed_.empty()) {
			failed_ = fz::sprintf("error in line %d"sv, line);
			if (error) {
				failed_ += fz::sprintf(", error code %d"sv, error);
			}
			if (tls_ver_) {
				failed_ += fz::sprintf(", tls ver 1.%d"sv, *tls_ver_);
			}
			if (!tls_session_parameters_.empty()) {
				failed_ += ", attempting resume"sv;
			}
		}
		cond_.signal(l);
	}

	void check_done()
	{
		if (shut_ && eof_) {
			if (tls_) {
				tls_session_parameters_ = tls_->get_session_parameters();
			}
			fz::scoped_lock l(m_);
			cond_.signal(l);
			si_ = nullptr;
			tls_.reset();
			s_.reset();
		}
	}

	void on_socket_event_base(fz::socket_event_source * source, fz::socket_event_flag type, int error)
	{
		if (error || source != si_) {
			fail(__LINE__, error);
			return;
		}

		if (type == fz::socket_event_flag::connection && tls_) {
			if (tls_->resumed_session() == tls_session_parameters_.empty()) {
				fail(__LINE__, error);
				return;
			}
		}

		if (type == fz::socket_event_flag::read) {
			for (int i = 0; i < fz::random_number(1, 20); ++i) {
				unsigned char buf[1024];

				int error;
				int r = si_->read(buf, 1024, error);
				if (!r) {
					int res = si_->shutdown_read();
					if (!res) {
						eof_ = true;
						check_done();
					}
					else if (res != EAGAIN) {
						fail(__LINE__, res);
					}
					return;
				}
				else if (r == -1) {
					if (error != EAGAIN) {
						fail(__LINE__, error);
					}
					return;
				}
				else {
					if (handshake_only_) {
						fail(__LINE__, error);
						return;
					}
					received_ += r;
					received_hash_.update(buf, r);
				}
			}

			send_event(new fz::socket_event(si_, fz::socket_event_flag::read, 0));
		}
		else if (type == fz::socket_event_flag::write || type == fz::socket_event_flag::connection) {
			if (handshake_only_ || (sent_ > 1024 * 1024 * 10 && (fz::monotonic_clock::now() - start_) > fz::duration::from_seconds(5))) {
				int res = si_->shutdown();
				if (res && res != EAGAIN) {
					fail(__LINE__, res);
				}
				else if (!res) {
					shut_ = true;
					check_done();
				}

				return;
			}
			for (int i = 0; i < fz::random_number(1, 20); ++i) {
				auto buf = fz::random_bytes(1024);
				int error;
				int sent = si_->write(buf.data(), buf.size(), error);
				if (sent <= 0) {
					if (error != EAGAIN) {
						fail(__LINE__, error);
					}
					return;
				}
				else {
					sent_ += sent;
					sent_hash_.update(buf.data(), sent);
				}
			}
			send_event(new fz::socket_event(si_, fz::socket_event_flag::write, 0));
		}
	}

	fz::hash_accumulator sent_hash_{fz::hash_algorithm::md5};
	fz::hash_accumulator received_hash_{fz::hash_algorithm::md5};

	logger logger_;

	fz::mutex m_;
	fz::condition cond_;

	fz::thread_pool pool_;

	std::unique_ptr<fz::socket> s_;
	std::unique_ptr<fz::tls_layer> tls_;
	fz::socket_interface* si_{};

	std::string failed_;
	bool eof_{};
	bool shut_{};
	bool handshake_only_{};
	std::vector<uint8_t> tls_session_parameters_;
	std::optional<fz::tls_ver> tls_ver_;
	int64_t sent_{};
	int64_t received_{};
	fz::monotonic_clock start_{fz::monotonic_clock::now()};
};

struct client final : public base
{
	client(fz::event_loop & loop, bool tls = false, std::vector<uint8_t> const& tls_session_parameters = {}, std::optional<fz::tls_ver> ver = {}, bool no_tickets = false, fz::native_string const& hostname = {})
		: base(loop, tls_session_parameters, ver)
	{
		s_ = std::make_unique<fz::socket>(pool_, this);
		if (tls) {
			tls_ = std::make_unique<fz::tls_layer>(loop, this, *s_, nullptr, logger_);
			if (tls_ver_) {
				tls_->set_min_tls_ver(*tls_ver_);
				tls_->set_max_tls_ver(*tls_ver_);
			}
			auto const& cert = get_key_and_cert().second;
			fz::tls_client_flags flags{};
			if (no_tickets) {
				flags |= fz::tls_client_flags::debug_no_tickets;
			}
			if (!tls_->client_handshake(std::vector<uint8_t>(cert.cbegin(), cert.cend()), tls_session_parameters_, hostname, flags)) {
				fail(__LINE__);
			}
			si_ = tls_.get();
		}
		else {
			si_ = s_.get();
		}
	}

	virtual ~client() {
		remove_handler();
	}

	virtual void operator()(fz::event_base const& ev) override {
		fz::dispatch<fz::socket_event>(ev, this, &client::on_socket_event);
	}

	void on_socket_event(fz::socket_event_source * source, fz::socket_event_flag type, int error)
	{
		on_socket_event_base(source, type, error);
	}
};

struct server final : public base
{
	server(fz::event_loop & loop, bool tls = false, std::vector<uint8_t> const& tls_session_parameters = {}, std::optional<fz::tls_ver> ver = {}, bool no_tickets = false)
		: base(loop, tls_session_parameters, ver)
		, use_tls_(tls)
		, no_tickets_(no_tickets)
	{
		l_.bind("127.0.0.1");
		int res = l_.listen(fz::address_type::ipv4);
		if (res) {
			fail(__LINE__, res);
		}
	}

	virtual ~server() {
		remove_handler();
	}

	virtual void operator()(fz::event_base const& ev) override {
		fz::dispatch<fz::socket_event>(ev, this, &server::on_socket_event);
	}

	void on_socket_event(fz::socket_event_source * source, fz::socket_event_flag type, int error)
	{
		if (source == &l_) {
			if (s_) {
				fail(__LINE__);
			}
			else if (error) {
				fail(__LINE__, error);
			}
			else {
				int error;
				s_ = l_.accept(error, use_tls_ ? nullptr : this);
				if (!s_) {
					fail(__LINE__, error);
				}
				if (use_tls_) {
					tls_ = std::make_unique<fz::tls_layer>(event_loop_, this, *s_, nullptr, logger_);
					if (tls_ver_) {
						tls_->set_min_tls_ver(*tls_ver_);
						tls_->set_max_tls_ver(*tls_ver_);
					}
					tls_->set_certificate(get_key_and_cert().first, get_key_and_cert().second, fz::native_string());
					si_ = tls_.get();
					fz::tls_server_flags flags{};
					if (no_tickets_) {
						flags |= fz::tls_server_flags::debug_no_tickets;
					}
					if (!tls_->server_handshake(tls_session_parameters_, {}, flags)) {
						fail(__LINE__);
					}
				}
				else {
					si_ = s_.get();
					on_socket_event_base(si_, fz::socket_event_flag::write, 0);
				}
			}
		}
		else {
			on_socket_event_base(source, type, error);
		}
	}

	fz::listen_socket l_{pool_, this};
	bool use_tls_{};
	bool no_tickets_{};
};
}

void socket_test::test_duplex()
{
	// Full duplex socket test of random data exchanged in both directions for 5 seconds.
	fz::event_loop server_loop;
	server s(server_loop);

	int error;
	int port  = s.l_.local_port(error);
	CPPUNIT_ASSERT(port != -1);

	fz::native_string ip = fz::to_native(s.l_.local_ip());
	CPPUNIT_ASSERT(!ip.empty());

	fz::event_loop client_loop;
	client c(client_loop);

	CPPUNIT_ASSERT(!c.si_->connect(ip, port));

	{
		fz::scoped_lock l(c.m_);
		CPPUNIT_ASSERT(c.cond_.wait(l, fz::duration::from_minutes(10)));
	}

	ASSERT_EQUAL(std::string(), c.failed_);
	{
		fz::scoped_lock l(s.m_);
		CPPUNIT_ASSERT(s.cond_.wait(l, fz::duration::from_minutes(1)));
	}
	ASSERT_EQUAL(std::string(), s.failed_);

	CPPUNIT_ASSERT(c.sent_hash_.digest() == s.received_hash_.digest());
	CPPUNIT_ASSERT(s.sent_hash_.digest() == c.received_hash_.digest());
}

void socket_test::test_duplex_tls()
{
	// Full duplex socket test of random data exchanged in both directions for 5 seconds, but this time wit TLS on top.

	CPPUNIT_ASSERT(!get_key_and_cert().first.empty());
	CPPUNIT_ASSERT(!get_key_and_cert().second.empty());

	fz::event_loop server_loop;
	server s(server_loop, true);

	int error;
	int port  = s.l_.local_port(error);
	CPPUNIT_ASSERT(port != -1);

	fz::native_string ip = fz::to_native(s.l_.local_ip());
	CPPUNIT_ASSERT(!ip.empty());

	fz::event_loop client_loop;
	client c(client_loop, true);

	CPPUNIT_ASSERT(c.si_);
	CPPUNIT_ASSERT(!c.si_->connect(ip, port));

	{
		fz::scoped_lock l(c.m_);
		CPPUNIT_ASSERT(c.cond_.wait(l, fz::duration::from_minutes(10)));
	}
	ASSERT_EQUAL(std::string(), c.failed_);

	{
		fz::scoped_lock l(s.m_);
		CPPUNIT_ASSERT(s.cond_.wait(l, fz::duration::from_minutes(1)));
	}
	ASSERT_EQUAL(std::string(), s.failed_);

	CPPUNIT_ASSERT(c.sent_ == s.received_);
	CPPUNIT_ASSERT(s.sent_ == c.received_);

	CPPUNIT_ASSERT(c.sent_hash_.digest() == s.received_hash_.digest());
	CPPUNIT_ASSERT(s.sent_hash_.digest() == c.received_hash_.digest());
}

void socket_test::do_test_tls_resumption(std::optional<fz::tls_ver> ver, bool server_no_ticket, bool client_no_ticket)
{
	do_test_tls_resumption(ver, server_no_ticket, client_no_ticket, false);
	do_test_tls_resumption(ver, server_no_ticket, client_no_ticket, true);
}

void socket_test::do_test_tls_resumption(std::optional<fz::tls_ver> ver, bool server_no_ticket, bool client_no_ticket, bool use_hostname)
{
	std::vector<uint8_t> server_parameters;
	std::vector<uint8_t> client_parameters;

	for (size_t i = 0; i < 2; ++i) {
		CPPUNIT_ASSERT(!get_key_and_cert().first.empty());
		CPPUNIT_ASSERT(!get_key_and_cert().second.empty());

		fz::event_loop server_loop;
		server s(server_loop, true, server_parameters, ver, server_no_ticket);
		s.handshake_only_ = true;

		int error;
		int port  = s.l_.local_port(error);
		CPPUNIT_ASSERT(port != -1);

		fz::native_string ip = fz::to_native(s.l_.local_ip());
		CPPUNIT_ASSERT(!ip.empty());

		fz::event_loop client_loop;
		client c(client_loop, true, client_parameters, ver, client_no_ticket, use_hostname ? fzT("localhost") : fzT(""));
		c.handshake_only_ = true;

		CPPUNIT_ASSERT(c.si_);
		CPPUNIT_ASSERT(!c.si_->connect(ip, port, fz::address_type::ipv4));

		{
			fz::scoped_lock l(c.m_);
			CPPUNIT_ASSERT(c.cond_.wait(l, fz::duration::from_minutes(10)));
		}
		ASSERT_EQUAL(std::string(), c.failed_);

		{
			fz::scoped_lock l(s.m_);
			CPPUNIT_ASSERT(s.cond_.wait(l, fz::duration::from_minutes(1)));
		}
		ASSERT_EQUAL(std::string(), s.failed_);

		client_parameters = c.tls_session_parameters_;
		server_parameters = s.tls_session_parameters_;
		CPPUNIT_ASSERT(client_parameters.size() > 10);
		CPPUNIT_ASSERT(server_parameters.size() > 10);
	}
}

void socket_test::test_tls_resumption()
{
	do_test_tls_resumption({}, false, false);

	// 1.3 alwas uses tickets for resumption
	do_test_tls_resumption(fz::tls_ver::v1_3, false, false);

	// Test all posssible combinations of TLS <= 1.2 and either side supporting tickets
	for (size_t i = 0; i < 4; ++i) {
		do_test_tls_resumption(fz::tls_ver::v1_2, i & 0x1, i & 0x2);
		do_test_tls_resumption(fz::tls_ver::v1_1, i & 0x1, i & 0x2);
		do_test_tls_resumption(fz::tls_ver::v1_0, i & 0x1, i & 0x2);
	}
}
