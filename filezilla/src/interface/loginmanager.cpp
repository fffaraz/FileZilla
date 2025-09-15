#include "filezilla.h"
#include "loginmanager.h"
#include "dialogex.h"
#include "filezillaapp.h"
#include "Options.h"
#include "textctrlex.h"

CLoginManager CLoginManager::m_theLoginManager;


bool CLoginManager::query_unprotect_site(Site & site)
{
	assert(site.credentials.encrypted_);

	wxDialogEx pwdDlg;
	if (!pwdDlg.Create(wxGetApp().GetTopWindow(), -1, _("Enter master password"))) {
		return false;
	}
	auto & lay = pwdDlg.layout();
	auto * main = lay.createMain(&pwdDlg, 1);

	main->Add(new wxStaticText(&pwdDlg, -1, _("Please enter your master password to decrypt the password for this server:")));

	auto* inner = lay.createFlex(2);
	main->Add(inner);

	std::wstring const& name = site.GetName();
	if (!name.empty()) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("Name:")));
		inner->Add(new wxStaticText(&pwdDlg, -1, LabelEscape(name)));
	}

	if (site.server.GetProtocol() == STORJ || site.server.GetProtocol() == STORJ_GRANT) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("Satellite:")));
	}
	else {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("Host:")));
	}
	inner->Add(new wxStaticText(&pwdDlg, -1, LabelEscape(site.Format(ServerFormat::with_optional_port))));

	if (!site.server.GetUser().empty()) {
		if (site.server.GetProtocol() == STORJ) {
			inner->Add(new wxStaticText(&pwdDlg, -1, _("API Key:")));
		}
		else {
			inner->Add(new wxStaticText(&pwdDlg, -1, _("User:")));
		}
		inner->Add(new wxStaticText(&pwdDlg, -1, LabelEscape(site.server.GetUser())));
	}

	inner = lay.createFlex(2);
	main->Add(inner);

	inner->Add(new wxStaticText(&pwdDlg, -1, _("Key identifier:")));
	inner->Add(new wxStaticText(&pwdDlg, -1, fz::to_wstring(site.credentials.encrypted_.to_base64().substr(0, 8))));

	inner->Add(new wxStaticText(&pwdDlg, -1, _("Master &Password:")), lay.valign);

	auto* password = new wxTextCtrlEx(&pwdDlg, -1, wxString(), wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
	password->SetMinSize(wxSize(150, -1));
	password->SetFocus();
	inner->Add(password, lay.valign);

	main->AddSpacer(0);
	auto* remember = new wxCheckBox(&pwdDlg, -1, _("&Remember master password until FileZilla is closed"));
	remember->SetValue(true);
	main->Add(remember);

	auto* buttons = lay.createButtonSizer(&pwdDlg, main, true);

	auto ok = new wxButton(&pwdDlg, wxID_OK, _("&OK"));
	ok->SetDefault();
	buttons->AddButton(ok);

	auto cancel = new wxButton(&pwdDlg, wxID_CANCEL, _("Cancel"));
	buttons->AddButton(cancel);

	buttons->Realize();

	pwdDlg.GetSizer()->Fit(&pwdDlg);
	pwdDlg.GetSizer()->SetSizeHints(&pwdDlg);

	while (true) {
		if (pwdDlg.ShowModal() != wxID_OK) {
			return false;
		}

		auto pass = fz::to_utf8(password->GetValue().ToStdWstring());
		auto key = fz::private_key::from_password(pass, site.credentials.encrypted_.salt_);

		if (key.pubkey() != site.credentials.encrypted_) {
			wxMessageBoxEx(_("Wrong master password entered, it cannot be used to decrypt this item."), _("Invalid input"), wxICON_EXCLAMATION);
			continue;
		}

		if (!unprotect(site.credentials, key)) {
			wxMessageBoxEx(_("Failed to decrypt server password."), _("Invalid input"), wxICON_EXCLAMATION);
			continue;
		}

		if (remember->IsChecked()) {
			Remember(key);
		}
		break;
	}

	return true;
}

bool CLoginManager::query_credentials(Site & site, std::wstring const& challenge, bool otp, bool canRemember)
{
	assert(!site.credentials.encrypted_);

	bool needs_user{};
	bool needs_pass{};
	bool needs_otp{};

	wxString title;
	wxString header;
	if (site.server.GetUser().empty() && ProtocolHasUser(site.server.GetProtocol())) {
		needs_user = true;
		if (site.credentials.logonType_ == LogonType::interactive) {
			title = _("Enter username");
			header = _("Please enter a username for this server:");
			canRemember = false;
		}
		else {
			title = _("Enter username and password");
			header = _("Please enter username and password for this server:");
			needs_pass = true;
		}
	}
	else {
		if (otp) {
			needs_otp = true;
			title = _("Enter the 2FA code");
			header = _("Please enter the 2FA code for this server:");
			needs_pass = site.credentials.logonType_ == LogonType::interactive;
		}
		else {
			needs_pass = true;
			title = _("Enter password");
			header = _("Please enter a password for this server:");
		}
	}

	wxDialogEx pwdDlg;
	if (!pwdDlg.Create(wxGetApp().GetTopWindow(), -1, title)) {
		return false;
	}
	auto& lay = pwdDlg.layout();
	auto* main = lay.createMain(&pwdDlg, 1);

	main->Add(new wxStaticText(&pwdDlg, -1, header));

	auto* inner = lay.createFlex(2);
	main->Add(inner);

	std::wstring const& name = site.GetName();
	if (!name.empty()) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("Name:")));
		inner->Add(new wxStaticText(&pwdDlg, -1, LabelEscape(name)));
	}

	inner->Add(new wxStaticText(&pwdDlg, -1, _("Host:")));
	inner->Add(new wxStaticText(&pwdDlg, -1, LabelEscape(site.Format(ServerFormat::with_optional_port))));

	if (!site.server.GetUser().empty()) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("User:")));
		inner->Add(new wxStaticText(&pwdDlg, -1, LabelEscape(site.server.GetUser())));
	}

	if (!challenge.empty() && !otp) {
		std::wstring displayChallenge = fz::trimmed(challenge);
#ifdef FZ_WINDOWS
		fz::replace_substrings(displayChallenge, L"\n", L"\r\n");
#endif
		main->AddSpacer(0);
		main->Add(new wxStaticText(&pwdDlg, -1, _("Challenge:")));
		auto* challengeText = new wxTextCtrlEx(&pwdDlg, -1, displayChallenge, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY);
		challengeText->SetMinSize(wxSize(lay.dlgUnits(240), lay.dlgUnits(60)));
		challengeText->SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_BTNFACE));
		main->Add(challengeText, lay.grow);
	}

	main->AddSpacer(0);

	inner = lay.createFlex(2);
	main->Add(inner);

	wxTextCtrl* newUser{};
	if (needs_user) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("&User:")), lay.valign);
		newUser = new wxTextCtrlEx(&pwdDlg, -1, wxString());
		newUser->SetMinSize(wxSize(150, -1));
		newUser->SetFocus();
		inner->Add(newUser, lay.valign);
	}

	wxTextCtrl* password{};
	wxTextCtrl* key{}; // for storj
	if (needs_pass) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("&Password:")), lay.valign);
		password = new wxTextCtrlEx(&pwdDlg, -1, wxString(), wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
		password->SetMinSize(wxSize(150, -1));
		if (!newUser) {
			password->SetFocus();
		}
		inner->Add(password, lay.valign);

		if (site.server.GetProtocol() == STORJ) {
			inner->Add(new wxStaticText(&pwdDlg, -1, _("Encryption &key:")), lay.valign);
			key = new wxTextCtrlEx(&pwdDlg, -1);
			key->SetMinSize(wxSize(150, -1));
			inner->Add(key, lay.valign);
		}
	}

	wxTextCtrl* otpCode{};
	if (needs_otp) {
		inner->Add(new wxStaticText(&pwdDlg, -1, _("&Token code:")), lay.valign);
		otpCode = new wxTextCtrlEx(&pwdDlg, -1, wxString());
		otpCode->SetMinSize(wxSize(150, -1));
		inner->Add(otpCode, lay.valign);
	}

	wxCheckBox* remember{};
	if (canRemember && needs_pass) {
		main->AddSpacer(0);
		remember = new wxCheckBox(&pwdDlg, -1, _("&Remember password until FileZilla is closed"));
		remember->SetValue(true);
		main->Add(remember);
	}

	auto* buttons = lay.createButtonSizer(&pwdDlg, main, true);

	auto ok = new wxButton(&pwdDlg, wxID_OK, _("&OK"));
	ok->SetDefault();
	buttons->AddButton(ok);

	auto cancel = new wxButton(&pwdDlg, wxID_CANCEL, _("Cancel"));
	buttons->AddButton(cancel);

	buttons->Realize();

	pwdDlg.GetSizer()->Fit(&pwdDlg);
	pwdDlg.GetSizer()->SetSizeHints(&pwdDlg);

	while (true) {
		if (pwdDlg.ShowModal() != wxID_OK) {
			return false;
		}

		if (newUser) {
			auto user = newUser->GetValue().ToStdWstring();
			if (user.empty()) {
				wxMessageBoxEx(_("No username given."), _("Invalid input"), wxICON_EXCLAMATION);
				continue;
			}
			site.server.SetUser(user);
		}

/* FIXME?
	if (site.server.GetProtocol() == STORJ) {
		std::wstring encryptionKey = key->GetValue().ToStdWstring();
		if (encryptionKey.empty()) {
			wxMessageBoxEx(_("No encryption key given."), _("Invalid input"), wxICON_EXCLAMATION);
			continue;
		}
	}
*/
		if (password) {
			std::wstring pass = password->GetValue().ToStdWstring();
			if (site.server.GetProtocol() == STORJ) {
				std::wstring encryptionKey = key->GetValue().ToStdWstring();
				pass += L"|" + encryptionKey;
			}
			site.credentials.SetPass(pass);
		}

		if (remember && remember->IsChecked()) {
			RememberPassword(site, challenge);
		}

		if (otpCode) {
			auto code = otpCode->GetValue().ToStdWstring();
			if (code.empty()) {
				wxMessageBoxEx(_("No code given."), _("Invalid input"), wxICON_EXCLAMATION);
				continue;
			}
			site.credentials.SetExtraParameter(site.server.GetProtocol(), "otp_code", code);
		}

		break;
	}

	return true;
}


bool CLoginManager::AskDecryptor(fz::public_key const& pub, bool allowForgotten, bool allowCancel)
{
	if (this == &CLoginManager::Get()) {
		return false;
	}

	if (!pub) {
		return false;
	}

	bool forgotten{};
	auto priv = GetDecryptor(pub, &forgotten);
	if (priv || (allowForgotten && forgotten)) {
		return true;
	}

	wxDialogEx pwdDlg;
	if (!pwdDlg.Create(wxGetApp().GetTopWindow(), -1, _("Enter master password"))) {
		return false;
	}
	auto& lay = pwdDlg.layout();
	auto* main = lay.createMain(&pwdDlg, 1);

	main->Add(new wxStaticText(&pwdDlg, -1, _("Please enter your current master password to change the password settings.")));

	auto* inner = lay.createFlex(2);
	main->Add(inner);

	inner->Add(new wxStaticText(&pwdDlg, -1, _("Key identifier:")));
	inner->Add(new wxStaticText(&pwdDlg, -1, fz::to_wstring(pub.to_base64().substr(0, 8))));

	inner->Add(new wxStaticText(&pwdDlg, -1, _("Master &Password:")), lay.valign);

	auto* password = new wxTextCtrlEx(&pwdDlg, -1, wxString(), wxDefaultPosition, wxDefaultSize, wxTE_PASSWORD);
	password->SetMinSize(wxSize(150, -1));
	password->SetFocus();
	inner->Add(password, lay.valign);

	wxCheckBox* forgot{};
	if (allowForgotten) {
		main->AddSpacer(0);
		forgot = new wxCheckBox(&pwdDlg, -1, _("I &forgot my master password. Delete all passwords stored with this key."));
		main->Add(forgot);
	}

	auto* buttons = lay.createButtonSizer(&pwdDlg, main, true);

	auto ok = new wxButton(&pwdDlg, wxID_OK, _("&OK"));
	ok->SetDefault();
	buttons->AddButton(ok);

	if (allowCancel) {
		auto cancel = new wxButton(&pwdDlg, wxID_CANCEL, _("Cancel"));
		buttons->AddButton(cancel);
	}

	buttons->Realize();

	pwdDlg.GetSizer()->Fit(&pwdDlg);
	pwdDlg.GetSizer()->SetSizeHints(&pwdDlg);

	while (true) {
		if (pwdDlg.ShowModal() != wxID_OK) {
			if (allowCancel) {
				return false;
			}
			continue;
		}

		if (allowForgotten && forgot->GetValue()) {
			decryptors_[pub] = fz::private_key();
		}
		else {
			auto pass = fz::to_utf8(password->GetValue().ToStdWstring());
			auto key = fz::private_key::from_password(pass, pub.salt_);

			if (key.pubkey() != pub) {
				wxMessageBoxEx(_("Wrong master password entered, it cannot be used to decrypt the stored passwords."), _("Invalid input"), wxICON_EXCLAMATION);
				continue;
			}
			decryptors_[pub] = key;
			decryptorPasswords_.emplace_back(std::move(pass));
		}
		break;
	}

	return true;
}
