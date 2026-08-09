#include "../fzssh/agent.hpp"
#include "../fzssh/privkey.hpp"

#include "../buffer_util.hpp"

#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/logger.hpp>
#include <libfilezilla/socket.hpp>
#include <libfilezilla/thread_pool.hpp>

#include <optional>

#include <set>

#if FZ_WINDOWS
#include <libfilezilla/glue/async_pipe.hpp>
#include <libfilezilla/glue/windows.hpp>
#include <wincrypt.h>
#define SECURITY_WIN32
#include <security.h>
#include <lmcons.h>
#endif

using namespace std::literals;

namespace fz::ssh {

// https://datatracker.ietf.org/doc/draft-ietf-sshm-ssh-agent/
#define SSH_AGENT_FAILURE 5
#define SSH_AGENTC_REQUEST_IDENTITIES 11
#define SSH_AGENT_IDENTITIES_ANSWER 12
#define SSH_AGENTC_SIGN_REQUEST 13
#define SSH_AGENT_SIGN_RESPONSE 14

#define SSH_AGENT_RSA_SHA2_256 2
#define SSH_AGENT_RSA_SHA2_512 4

namespace {
class agent_public_key final : public public_key
{
public:
	agent_public_key(std::string_view name, std::string_view blob)
		: name_(name)
	{
		key_ = blob;
	}

	virtual std::string_view name() const override {
		return name_;
	}

	virtual std::unique_ptr<public_key> clone() const override {
		if (key_.empty()) {
			return {};
		}
		auto ret = std::make_unique<agent_public_key>(name_, key_);
		ret->comment_ = comment_;
		return ret;
	}

	std::string_view name_;

	virtual bool parse(std::string_view key) override { key_ = key; return !key_.empty(); }
	virtual bool parse_putty(std::string_view /*key*/) override { return false; }
	virtual bool verify(std::string_view const& /*data*/, std::string_view /*sig*/) const override { return false; }
};

class single_agent_connection;
class agent_private_key final : public private_key
{
public:
	agent_private_key(std::weak_ptr<single_agent_connection> conn, std::string_view const& name, std::string_view const& pubblob, bool opaque);
	virtual ~agent_private_key();

	virtual std::string_view name() const override { return name_; }
	virtual bool sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm, event_handler& h) override;
	virtual void cancel(event_handler& h) override;

	virtual std::unique_ptr<private_key> clone() const override;
	virtual std::unique_ptr<public_key> pubkey() const override;

	std::weak_ptr<single_agent_connection> conn_{};
	std::string const name_;

	event_handler* h_{};

	bool opaque_{};
};

class single_agent_connection : public event_handler, public std::enable_shared_from_this<single_agent_connection>
{
public:
	single_agent_connection(agent_connection* agent, thread_pool & pool, fz::event_handler& parent, logger_interface& log, std::string_view name, agent_compatibility_flags flags)
		: event_handler(parent, child_event_handler)
		, agent_(agent)
		, pool_(pool)
		, logger_(log)
		, name_(name)
		, flags_(flags)
	{
	}

	virtual ~single_agent_connection() = default;

	void get_keys(fz::event_handler& h);
	void cancel_get_keys(fz::event_handler& h);
	void cancel_sign(agent_private_key* key);

	void sign(agent_private_key* key, std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm);

	enum class state {
		idle,
		get_keys,
		signing
	};
	state state_{};
	agent_private_key* key_{};

protected:
	virtual bool connected() = 0;
	virtual bool connect() = 0;
	virtual void reset_connection() = 0;

	void fail(bool reset_conn);
	virtual void send() = 0;

	void process_input();
	void process_identities(std::string_view data);
	void process_signature(std::string_view data);

	fz::buffer outbuf_;
	fz::buffer inbuf_;

	bool can_send_{};

	event_handler* handler_{};

	agent_connection* agent_;
	thread_pool & pool_;
	logger_interface& logger_;

	std::string name_;
	agent_compatibility_flags flags_{};
};

class socket_agent_connection : public single_agent_connection
{
public:
	socket_agent_connection(agent_connection* agent, thread_pool & pool, fz::event_handler& parent, logger_interface& log, 	agent_compatibility_flags flags)
		: single_agent_connection(agent, pool, parent, log, "SSH_AUTH_SOCK"sv, flags)
	{}

	~socket_agent_connection()
	{
		remove_handler();
	}

	virtual bool connected() override
	{
		return !!s_;
	}

	virtual bool connect() override;

	virtual void reset_connection() override;

private:
	virtual void operator()(fz::event_base const& ev) override;
	void on_socket_event(fz::socket_event_source*, fz::socket_event_flag type, int error);
	virtual void send() override;
	void on_read();

	std::optional<socket> s_;
};

void socket_agent_connection::reset_connection()
{
	s_.reset();
}

bool socket_agent_connection::connect()
{
	if (s_) {
		return true;
	}

	auto path = getenv("SSH_AUTH_SOCK");
	if (!path || !*path) {
		logger_.log(logmsg::debug_info, "Cannot connect to agent: SSH_AUTH_SOCKET not set"sv);
		fail(true);
		return false;
	}

	logger_.log(logmsg::debug_info, "Connecting to agent (%s) on Unix Domain Socket"sv, name_);

	s_.emplace(pool_, this);
	int res = s_->connect(fz::to_native(path), 0, address_type::unix);
	if (res) {
		logger_.log(logmsg::error, "Could not connect to agent (%s): Socket error %d"sv, name_, res);
		fail(true);
		return false;
	}

	return true;
}

void socket_agent_connection::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::socket_event>(ev, this, &socket_agent_connection::on_socket_event);
}

void socket_agent_connection::on_socket_event(fz::socket_event_source*, fz::socket_event_flag type, int error)
{
	if (error) {
		logger_.log(logmsg::error, "Connection to agent (%s) failed with socket error %d (%s)"sv, name_, error, socket_error_string(error));
		fail(true);
		return;
	}

	if (type == socket_event_flag::write || type == socket_event_flag::connection) {
		can_send_ = true;
		send();
	}
	else if (type == socket_event_flag::read) {
		on_read();
	}
}

void socket_agent_connection::send()
{
	while (s_ && can_send_ && !outbuf_.empty()) {
		int error{};
		int written = s_->write(outbuf_.get(), outbuf_.size(), error);
		if (written <= 0) {
			can_send_ = false;
			if (error != EAGAIN) {
				logger_.log(logmsg::error, "Could not write to agent socket: Socket error %d"sv, error);
				fail(true);
			}
			return;
		}
		outbuf_.consume(written);
	}
}

void socket_agent_connection::on_read()
{
	while (s_) {
		if (inbuf_.size() > 1024 * 1024) {
			logger_.log(logmsg::error, "Agent response too large, closing connection"sv);
			fail(true);
			return;
		}

		int error;
		int r = s_->read(inbuf_.get(1024), 1024, error);
		if (r <= 0) {
			if (error != EAGAIN) {
				logger_.log(state_ == state::idle ? logmsg::debug_warning : logmsg::error, "Got error %d reading from agent socket"sv);
				fail(true);
			}
			return;
		}
		inbuf_.add(r);

		process_input();
	}
}

#if FZ_WINDOWS
class pipe_agent_connection : public single_agent_connection
{
public:
	pipe_agent_connection(agent_connection* agent, thread_pool & pool, fz::event_handler& parent, logger_interface& log, std::string_view name, std::wstring_view const& pipename, agent_compatibility_flags flags)
		: single_agent_connection(agent, pool, parent, log, name, flags)
		, pipename_(pipename)
	{}

	~pipe_agent_connection()
	{
		remove_handler();
	}

	virtual bool connected() override
	{
		return !!pipe_;
	}

	virtual bool connect() override;

	virtual void reset_connection() override;

private:
	virtual void operator()(fz::event_base const& ev) override;
	void on_pipe_event(fz::async_pipe*, fz::pipe_event_flag type);
	virtual void send() override;
	void on_read();

	std::optional<async_pipe> pipe_;
	std::wstring const pipename_;
};

bool pipe_agent_connection::connect()
{
	if (pipe_) {
		return true;
	}

	if (pipename_.empty()) {
		return false;
	}

	pipe_.emplace(pool_, *this);
	if (!pipe_->connect_named_pipe(pipename_)) {
		logger_.log(logmsg::debug_warning, "Could not connect to agent (%s) on named pipe."sv, name_);
		fail(true);
		return false;
	}
	logger_.log(logmsg::debug_info, "Connecting to agent (%s) on named pipe."sv, name_);
	can_send_ = true;
	return true;
}

void pipe_agent_connection::reset_connection()
{
	pipe_.reset();
}

void pipe_agent_connection::operator()(fz::event_base const& ev)
{
	fz::dispatch<fz::pipe_event>(ev, this, &pipe_agent_connection::on_pipe_event);
}

void pipe_agent_connection::on_pipe_event(fz::async_pipe*, fz::pipe_event_flag type)
{
	if (type == pipe_event_flag::write) {
		can_send_ = true;
		send();
	}
	else if (type == pipe_event_flag::read) {
		on_read();
	}
}

void pipe_agent_connection::send()
{
	while (pipe_ && can_send_ && !outbuf_.empty()) {
		auto res = pipe_->write(outbuf_.get(), outbuf_.size());
		if (!res || !res.value_) {
			can_send_ = false;
			if (res.error_ != rwresult::wouldblock) {
				logger_.log(logmsg::error, "Could not write to agent pipe: Windows error %d"sv, res.raw_);
				fail(true);
			}
			return;
		}
		outbuf_.consume(res.value_);
	}
}

void pipe_agent_connection::on_read()
{
	while (pipe_) {
		if (inbuf_.size() > 1024 * 1024) {
			logger_.log(logmsg::error, "Agent response too large, closing connection"sv);
			fail(true);
			return;
		}

		auto res = pipe_->read(inbuf_.get(1024), 1024);
		if (!res || !res.value_) {
			if (res.error_ != rwresult::wouldblock) {
				logger_.log(state_ == state::idle ? logmsg::debug_warning : logmsg::error, "Got error %d reading from agent pipe"sv);
				fail(true);
			}
			return;
		}

		inbuf_.add(res.value_);

		process_input();
	}
}

#endif


agent_private_key::agent_private_key(std::weak_ptr<single_agent_connection> conn, std::string_view const& name, std::string_view const& pubblob, bool opaque)
	: conn_(std::move(conn))
	, name_(name)
	, opaque_(opaque)
{
	pub_.append(pubblob);
}

agent_private_key::~agent_private_key()
{
	auto c = conn_.lock();
	if (c && c->key_ == this) {
		c->key_ = nullptr;
	}
}

bool agent_private_key::sign(std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm, event_handler& h)
{
	auto c = conn_.lock();
	if (h_ || !c || c->state_ != single_agent_connection::state::idle) {
		return false;
	}
	h_ = &h;

	c->sign(this, data, signature_algorithm);

	return true;
}

void agent_private_key::cancel(event_handler& h)
{
	private_key::cancel(h);
	if (&h != h_) {
		return;
	}
	h_ = nullptr;

	auto c = conn_.lock();
	if (c) {
		c->cancel_sign(this);
	}
}

std::unique_ptr<private_key> agent_private_key::clone() const
{
	return std::make_unique<agent_private_key>(conn_, name_, pub_.to_view(), opaque_);
}

std::unique_ptr<public_key> agent_private_key::pubkey() const
{
	if (opaque_) {
		return std::make_unique<agent_public_key>(name(), pub_.to_view());
	}
	else {
		return private_key::pubkey();
	}
}

void single_agent_connection::get_keys(event_handler & h)
{
	if (state_ != state::idle) {
		return;
	}

	handler_ = &h;
	state_ = state::get_keys;

	write_uint32(outbuf_, 1);
	outbuf_.append(SSH_AGENTC_REQUEST_IDENTITIES);

	if (!connect()) {
		return;
	}
	send();
}

void single_agent_connection::cancel_get_keys(event_handler &h)
{
	h.remove_events(agent_);
	if (handler_ == &h) {
		handler_ = nullptr;
		fail(true);
	}
}

void single_agent_connection::cancel_sign(agent_private_key* k)
{
	if (k == key_) {
		key_ = nullptr;
		fail(true);
	}
}

void single_agent_connection::process_input()
{
	if (state_ == state::idle) {
		logger_.log(logmsg::debug_verbose, "Got data from agent (%s) when idle, closing connection"sv, name_);
		fail(true);
	}
	if (inbuf_.size() < 4) {
		return;
	}
	size_t size = read_uint32(inbuf_.get());
	if (!size || inbuf_.size() < size + 4) {
		return;
	}

	auto type = inbuf_[4];
	std::string_view data = inbuf_.to_view().substr(5, size - 1);

	switch (type) {
	case SSH_AGENT_IDENTITIES_ANSWER:
		process_identities(data);
		break;
	case SSH_AGENT_FAILURE:
		logger_.log(logmsg::error, "Request to agent (%s) failed"sv, name_);
		fail(false);
		break;
	case SSH_AGENT_SIGN_RESPONSE:
		process_signature(data);
		break;
	default:
		logger_.log(logmsg::error, "Got unexpected response type %d from agent (%s), closing connection."sv, type, name_);
		fail(true);
		break;
	}

	if (!inbuf_.empty()) {
		inbuf_.consume(size + 4);
	}
}

void single_agent_connection::process_identities(std::string_view data)
{
	if (state_ != state::get_keys) {
		logger_.log(logmsg::error, "Got unexpected response from agent (%s), closing connection."sv, name_);
		fail(true);
		return;
	}

	uint32_t count{};
	if (!extract_uint32(data, count)) {
		logger_.log(logmsg::error, "Could not extract number of keys, closing agent connection."sv);
		fail(true);
		return;
	}
	if (count > 200) {
		logger_.log(logmsg::error, "Agent (%s) has too many keys, closing connection"sv, name_);
		fail(true);
		return;
	}

	std::vector<std::unique_ptr<private_key>> keys;

	logger_.log(logmsg::debug_verbose, "Agent (%s) has %u keys"sv, name_, count);

	for (size_t i = 0; i < count; ++i) {
		auto blob = extract_string(data, string_type::blob, false);
		auto comment = extract_string(data, string_type::utf8, true);
		if (!blob || !comment) {
			logger_.log(logmsg::error, "Could not extract key and comment for key %u, closing socket."sv, i);
			fail(true);
			return;
		}

		std::string_view v = *blob;
		auto alg = extract_string(v, string_type::ascii, false);
		if (!alg) {
			logger_.log(logmsg::error, "Could not extract key algorithm for key %u, closing socket."sv, i);
			fail(true);
			return;
		}

		bool opaque{};
		auto key = create_public_key(*alg);
		if (!key) {
			if (flags_ & agent_compatibility_flags::allow_keys_with_unknown_types) {
				logger_.log(logmsg::debug_warning, "Key %u from agent has unknown type '%s'"sv, i, *alg);
				key = std::make_unique<agent_public_key>(*alg, *blob);
				opaque = true;
			}
			else {
				logger_.log(logmsg::debug_warning, "Ignoring key %u from agent with unknown type '%s'"sv, i, *alg);
				continue;
			}
		}
		else if (!key->parse(*blob)) {
			logger_.log(logmsg::debug_warning, "Could not load key %u from agent of type %s", i, *alg);
			continue;
		}

		auto pkey = std::make_unique<agent_private_key>(weak_from_this(), key->name(), key->pubkey_blob(), opaque);
		pkey->comment_ = *comment;

		logger_.log(logmsg::debug_info, "Successfully loaded public key %u of type '%s' from agent (%s)"sv, i, *alg, name_);
		keys.emplace_back(std::move(pkey));
	}

	if (handler_) {
		handler_->send_event<available_keys_event>(agent_, std::move(keys));
		handler_ = nullptr;
	}
	state_ = state::idle;
}

void single_agent_connection::fail(bool reset_conn)
{
	inbuf_.clear();
	outbuf_.clear();
	if (state_ == state::get_keys) {
		if (handler_) {
			std::vector<std::unique_ptr<private_key>> keys;
			handler_->send_event<available_keys_event>(agent_, std::move(keys));
			handler_ = nullptr;
		}
	}
	else if (state_ == state::signing) {
		if (key_) {
			if (key_->h_) {
				key_->h_->send_event<signature_event>(*key_, fz::buffer{});
			}
			key_ = nullptr;
		}
	}
	state_ = state::idle;

	if (reset_conn) {
		reset_connection();
	}
}

void single_agent_connection::sign(agent_private_key* key, std::basic_string_view<uint8_t> const& data, std::string_view signature_algorithm)
{
	if (state_ != state::idle) {
		return;
	}

	state_ = state::signing;
	key_ = key;

	write_uint32(outbuf_, 1 + 4 + key->pubkey_blob().size() + 4 + data.size() + 4);
	outbuf_.append(SSH_AGENTC_SIGN_REQUEST);
	write_string(outbuf_, key->pubkey_blob());
	write_string(outbuf_, data);
	uint32_t flags{};
	if (signature_algorithm == "rsa-sha2-256"sv) {
		flags |= SSH_AGENT_RSA_SHA2_256;
	}
	else if (signature_algorithm == "rsa-sha2-512"sv) {
		flags |= SSH_AGENT_RSA_SHA2_512;
	}
	write_uint32(outbuf_, flags);

	if (!connect()) {
		return;
	}
	send();
}

void single_agent_connection::process_signature(std::string_view data)
{
	if (state_ != state::signing) {
		logger_.log(logmsg::error, "Got unexpected response from agent (%s), closing connection."sv, name_);
		fail(true);
		return;
	}

	auto sig = extract_string(data, string_type::blob, false);
	if (!sig) {
		logger_.log(logmsg::error, "Could not extract signature from agent (%s)"sv, name_);
		fail(true);
		return;
	}

	if (key_) {
		if (key_->h_) {
			fz::buffer b;
			b.append(*sig);
			key_->h_->send_event<signature_event>(*key_, std::move(b));
		}
		key_ = nullptr;
	}
	state_ = state::idle;
}
}


#if FZ_WINDOWS
namespace {
std::wstring get_putty_obfuscated_name()
{
	char buf[CRYPTPROTECTMEMORY_BLOCK_SIZE];
	memset(buf, 0, CRYPTPROTECTMEMORY_BLOCK_SIZE);
	strcpy(buf, "Pageant");

	// PuTTY ignores if this function fails, so we must do the same
	(void)CryptProtectMemory(buf, CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_CROSS_PROCESS);

	fz::hash_accumulator acc(fz::hash_algorithm::sha256);
	acc.update_with_length(std::string_view(buf, CRYPTPROTECTMEMORY_BLOCK_SIZE));
	return fz::hex_encode<std::wstring>(acc.digest());
}

std::wstring get_username()
{
	DWORD len{};
	if (GetUserNameExW(NameUserPrincipal, nullptr, &len) || GetLastError() == ERROR_MORE_DATA) {
		std::wstring name;
		name.resize(len + 1);
		if (GetUserNameExW(NameUserPrincipal, name.data(), &len)) {
			name.resize(len);
			auto pos = name.find('@');
			if (pos != std::wstring::npos) {
				name.resize(pos);
			}
			return name;
		}
	}

	std::wstring name;
	len = UNLEN;
	name.resize(len);
	if (GetUserNameW(name.data(), &len)) {
		name.resize(len - 1);
		return name;
	}

	return {};
}

std::wstring get_putty_pipename()
{
	auto username = get_username();
	auto secret = get_putty_obfuscated_name();
	if (username.empty() || secret.empty()) {
		return {};
	}
	return fz::sprintf(L"pageant.%s.%s"sv, username, secret);
}
}
#endif

class agent_connection::impl : public fz::event_handler
{
public:
	impl(agent_connection* agent, thread_pool & pool, fz::event_handler& parent, logger_interface& log, agent_compatibility_flags flags);
	~impl()
	{
		remove_handler();
	}

	void get_keys(fz::event_handler& h);
	void cancel(fz::event_handler& h);

	void operator()(fz::event_base const& ev)
	{
		dispatch<available_keys_event>(ev, this, &impl::on_available_keys);
	}

	void on_available_keys(agent_connection*, std::vector<std::unique_ptr<private_key>> & keys)
	{
		if (!pending_ || !handler_) {
			return;
		}
		for (auto & k : keys) {
			if (!fingerprints_.insert(k->fingerprint()).second) {
				++discarded_;
				continue;
			}
			keys_.emplace_back(std::move(k));
		}
		if (!(--pending_)) {
			if (discarded_) {
				logger_.log(logmsg::debug_info, "Got %d distinct keys from agent (discarded duplicates: %u)"sv, keys.size(), discarded_);
			}
			else {
				logger_.log(logmsg::debug_info, "Got %d distinct keys from agent"sv, keys.size());
			}

			handler_->send_event<available_keys_event>(agent_, std::move(keys_));
			keys_.clear();
			fingerprints_.clear();
			pending_ = 0;
			discarded_ = 0;
			handler_ = nullptr;
		}
	}

private:
	logger_interface& logger_;
	agent_connection* agent_{};
	fz::event_handler* handler_{};

	std::vector<std::shared_ptr<single_agent_connection>> connections_;
	std::vector<std::unique_ptr<private_key>> keys_;
	std::set<std::string> fingerprints_;
	size_t pending_{};
	size_t discarded_{};
};

agent_connection::impl::impl(agent_connection* agent, thread_pool & pool, fz::event_handler& parent, logger_interface& log, agent_compatibility_flags flags)
	: event_handler(parent, child_event_handler)
	, logger_(log)
	, agent_(agent)
{
	connections_.emplace_back(std::make_unique<socket_agent_connection>(agent, pool, parent, log, flags));
#if FZ_WINDOWS
	auto putty_pipe = get_putty_pipename();
	if (!putty_pipe.empty()) {
		connections_.emplace_back(std::make_shared<pipe_agent_connection>(agent, pool, parent, log, "Pageant"sv, putty_pipe, flags));
	}
	connections_.emplace_back(std::make_shared<pipe_agent_connection>(agent, pool, parent, log, "OpenSSH Authentication Agent"sv, L"openssh-ssh-agent"sv, flags));
#endif
}

void agent_connection::impl::get_keys(fz::event_handler& h)
{
	cancel(h);
	handler_ = &h;
	for (auto & c : connections_) {
		c->get_keys(*this);
	}
	keys_.clear();
	fingerprints_.clear();
	pending_ = connections_.size();
	discarded_ = 0;
}

void agent_connection::impl::cancel(fz::event_handler& h)
{
	h.remove_events(agent_);
	if (&h != handler_) {
		return;
	}

	keys_.clear();
	fingerprints_.clear();
	pending_ = 0;
	discarded_ = 0;
	handler_ = nullptr;
	for (auto & c : connections_) {
		c->cancel_get_keys(*this);
	}
}


agent_connection::agent_connection(thread_pool & pool, fz::event_handler& parent, logger_interface & log, agent_compatibility_flags flags)
	: impl_(std::make_unique<impl>(this, pool, parent, log, flags))
{
}

agent_connection::~agent_connection()
{
	impl_->remove_handler();
}

void agent_connection::get_keys(event_handler & h)
{
	impl_->get_keys(h);
}

void agent_connection::cancel(event_handler & h)
{
	impl_->cancel(h);
}

}
