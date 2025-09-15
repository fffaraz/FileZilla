#include "filezilla.h"
#include "verifyhostkeydialog.h"
#include "dialogex.h"
#include "themeprovider.h"

#include <wx/statbox.h>

#include "../commonui/ipcmutex.h"

#include <libfilezilla/format.hpp>

std::vector<CVerifyHostkeyDialog::t_keyData> CVerifyHostkeyDialog::m_sessionTrustedKeys;

void CVerifyHostkeyDialog::ShowVerificationDialog(wxWindow* parent, CHostKeyNotification& notification)
{
	notification.m_trust = false;
	notification.m_alwaysTrust = false;

	bool const unknown = notification.GetRequestID() == reqId_hostkey;

	wxDialogEx dlg;

	if (!dlg.Create(parent, nullID, unknown ? _("Unknown host key") : _("Host key mismatch"))) {
		wxBell();
		return;
	}

	auto & lay = dlg.layout();
	auto top = lay.createMain(&dlg, 2);

	top->Add(new wxStaticBitmap(&dlg, nullID, wxArtProvider::GetBitmap(unknown ? wxART_INFORMATION : wxART_WARNING, wxART_OTHER, wxSize(32, 32))), 0, wxALL, lay.dlgUnits(2));

	auto main = lay.createFlex(1);
	top->Add(main);

	if (!unknown) {
		main->Add(new wxStaticText(&dlg, nullID, _("Warning: Potential security breach!")));
	}

	auto desc = new wxStaticText(&dlg, nullID, wxString());
	wxString t;
	if (unknown) {
		t = _("The server's host key is unknown. You have no guarantee that the server is the computer you think it is.");
	}
	else {
		t = _("The server's host key does not match the key that has been cached. This means that either the administrator has changed the host key, or you are actually trying to connect to another computer pretending to be the server.");
	}
	dlg.WrapText(desc, t, lay.dlgUnits(200));
	desc->SetLabel(t);
	main->Add(desc);

	if (!unknown) {
		main->Add(new wxStaticText(&dlg, nullID, _("If the host key change was not expected, please contact the server administrator.")));
	}

	std::wstring const host = fz::sprintf(L"%s:%d", notification.GetHost(), notification.GetPort());

	auto [box, inner] = lay.createStatBox(main, _("Details"), 2);

	inner->Add(new wxStaticText(box, nullID, _("Host:")));
	inner->Add(new wxStaticText(box, nullID, LabelEscape(host)));
	inner->Add(new wxStaticText(box, nullID, _("Hostkey algorithm:")));
	inner->Add(new wxStaticText(box, nullID, notification.hostKeyAlgorithm.empty() ? _("Unknown") : wxString(LabelEscape(notification.hostKeyAlgorithm))));
	inner->Add(new wxStaticText(box, nullID, _("Fingerprints:")));
	inner->Add(new wxStaticText(box, nullID, LabelEscape(notification.hostKeyFingerprint)));

	main->Add(new wxStaticText(&dlg, nullID, unknown ? _("Trust this host and carry on connecting?") : _("Trust the new key and carry on connecting?")));
	auto always = new wxCheckBox(&dlg, nullID, unknown ? _("&Always trust this host, add this key to the cache") : _("Update cached key for this host"));
	main->Add(always);

	auto buttons = lay.createButtonSizer(&dlg, main, false);

	auto ok = new wxButton(&dlg, wxID_OK, _("&OK"));
	ok->SetDefault();
	buttons->AddButton(ok);

	auto cancel = new wxButton(&dlg, wxID_CANCEL, _("Cancel"));
	buttons->AddButton(cancel);

	buttons->Realize();

	dlg.GetSizer()->Fit(&dlg);
	dlg.GetSizer()->SetSizeHints(&dlg);

	int res = dlg.ShowModal();

	if (res == wxID_OK) {
		notification.m_trust = true;
		notification.m_alwaysTrust = always->GetValue();

		t_keyData data;
		data.host = host;
		data.fingerprint = notification.hostKeyFingerprint;
		m_sessionTrustedKeys.push_back(data);
		return;
	}
}

bool CVerifyHostkeyDialog::IsTrusted(CHostKeyNotification const& notification)
{
	std::wstring const host = fz::sprintf(L"%s:%d", notification.GetHost(), notification.GetPort());

	for (auto const& trusted : m_sessionTrustedKeys) {
		if (trusted.host == host && trusted.fingerprint == notification.hostKeyFingerprint) {
			return true;
		}
	}

	return false;
}
