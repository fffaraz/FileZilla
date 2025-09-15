#include "filezilla.h"
#include "sftp_crypt_info_dlg.h"
#include "dialogex.h"

#include <wx/statbox.h>

void CSftpEncryptioInfoDialog::ShowDialog(CSftpEncryptionNotification* pNotification)
{
	wxDialogEx dlg;
	if (!dlg.Create(nullptr, nullID, _("Encryption details"))) {
		return;
	}

	auto & lay = dlg.layout();
	auto main = lay.createMain(&dlg, 1);

	{
		auto [box, inner] = lay.createStatBox(main, _("Key exchange"), 2);
		inner->Add(new wxStaticText(box, nullID, _("Algorithm:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->kexAlgorithm)));
		if (!pNotification->kexCurve.empty()) {
			inner->Add(new wxStaticText(box, nullID, _("Curve:")));
			inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->kexCurve)));
		}
		inner->Add(new wxStaticText(box, nullID, _("Hash:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->kexHash)));
	}
	{
		auto [box, inner] = lay.createStatBox(main, _("Server host key"), 2);
		inner->Add(new wxStaticText(box, nullID, _("Algorithm:")));
		inner->Add(new wxStaticText(box, nullID, pNotification->hostKeyAlgorithm.empty() ? _("Unknown") : LabelEscape(pNotification->hostKeyAlgorithm)));
		inner->Add(new wxStaticText(box, nullID, _("Fingerprints:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->hostKeyFingerprint)));
	}
	{
		auto [box, inner] = lay.createStatBox(main, _("Encryption"), 2);
		inner->Add(new wxStaticText(box, nullID, _("Client to server cipher:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->cipherClientToServer)));
		inner->Add(new wxStaticText(box, nullID, _("Client to server MAC:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->macClientToServer)));
		inner->Add(new wxStaticText(box, nullID, _("Server to client cipher:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->cipherServerToClient)));
		inner->Add(new wxStaticText(box, nullID, _("Server to client MAC:")));
		inner->Add(new wxStaticText(box, nullID, LabelEscape(pNotification->macServerToClient)));
	}

	auto buttons = lay.createButtonSizer(&dlg, main, false);
	auto ok = new wxButton(&dlg, wxID_OK, _("OK"));
	ok->SetDefault();
	buttons->AddButton(ok);
	buttons->Realize();

	dlg.GetSizer()->Fit(&dlg);
	dlg.GetSizer()->SetSizeHints(&dlg);

	dlg.ShowModal();
}
