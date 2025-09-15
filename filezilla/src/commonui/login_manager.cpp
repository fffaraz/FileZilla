#include "login_manager.h"

#include <algorithm>


std::list<login_manager::t_passwordcache>::iterator login_manager::FindItem(CServer const& server, std::wstring const& challenge)
{
	return std::find_if(m_passwordCache.begin(), m_passwordCache.end(), [&](t_passwordcache const& item)
		{
			return item.host == server.GetHost() && item.port == server.GetPort() && item.user == server.GetUser() && item.challenge == challenge;
		}
	);
}

bool login_manager::GetPassword(Site & site, bool silent)
{
	bool const needsUser = ProtocolHasUser(site.server.GetProtocol()) && site.server.GetUser().empty() && (site.credentials.logonType_ == LogonType::ask || site.credentials.logonType_ == LogonType::interactive);

	if (site.credentials.logonType_ != LogonType::ask && !site.credentials.encrypted_ && !needsUser) {
		return true;
	}

	if (site.credentials.encrypted_) {
		auto priv = GetDecryptor(site.credentials.encrypted_);
		if (priv) {
			return unprotect(site.credentials, priv);
		}

		if (!silent) {
			return query_unprotect_site(site);
		}
	}
	else {
		auto it = FindItem(site.server, std::wstring());
		if (it != m_passwordCache.end()) {
			site.credentials.SetPass(it->password);
			return true;
		}

		if (!silent) {
			return query_credentials(site, std::wstring(), false, true);
		}
	}

	return false;
}


bool login_manager::GetPassword(Site & site, bool silent, std::wstring const& challenge, bool otp, bool canRemember)
{
	if (canRemember) {
		auto it = FindItem(site.server, challenge);
		if (it != m_passwordCache.end()) {
			site.credentials.SetPass(it->password);
			return true;
		}
	}
	if (silent) {
		return false;
	}

	return query_credentials(site, challenge, otp, canRemember);
}

void login_manager::CachedPasswordFailed(CServer const& server, std::wstring const& challenge)
{
	auto it = FindItem(server, challenge);
	if (it != m_passwordCache.end()) {
		m_passwordCache.erase(it);
	}
}

void login_manager::RememberPassword(Site & site, std::wstring const& challenge)
{
	if (site.credentials.logonType_ == LogonType::anonymous) {
		return;
	}

	auto it = FindItem(site.server, challenge);
	if (it != m_passwordCache.end()) {
		it->password = site.credentials.GetPass();
	}
	else {
		t_passwordcache entry;
		entry.host = site.server.GetHost();
		entry.port = site.server.GetPort();
		entry.user = site.server.GetUser();
		entry.password = site.credentials.GetPass();
		entry.challenge = challenge;
		m_passwordCache.push_back(entry);
	}
}

fz::private_key login_manager::GetDecryptor(fz::public_key const& pub, bool * forgotten)
{
	auto it = decryptors_.find(pub);
	if (it != decryptors_.cend()) {
		if (!it->second && forgotten) {
			*forgotten = true;
		}
		return it->second;
	}

	for (auto const& pw : decryptorPasswords_) {
		auto priv = fz::private_key::from_password(pw, pub.salt_);
		if (priv && priv.pubkey() == pub) {
			decryptors_[pub] = priv;
			return priv;
		}
	}

	return fz::private_key();
}

void login_manager::Remember(fz::private_key const& key, std::string_view const& pass)
{
	if (key) {
		decryptors_[key.pubkey()] = key;
	}

	if (!pass.empty()) {
		for (auto const& pw : decryptorPasswords_) {
			if (pw == pass) {
				return;
			}
		}
		decryptorPasswords_.emplace_back(pass);
	}
}

void login_manager::RememberAsForgotten(fz::public_key const& pub_key)
{
	if (pub_key) {
		decryptors_.emplace(std::make_pair(pub_key, fz::private_key()));
	}
}
