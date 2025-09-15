#include "../filezilla.h"
#include "../Options.h"
#include "settingsdialog.h"
#include "optionspage.h"
#include "optionspage_connection_sftp.h"
#include "../filezillaapp.h"
#include "../fzputtygen_interface.h"
#include "../inputdialog.h"
#if USE_MAC_SANDBOX
#include "../osx_sandbox_userdirs.h"
#endif

#include <wx/filedlg.h>
#include <wx/listctrl.h>
#include <wx/statbox.h>

struct COptionsPageConnectionSFTP::impl
{
	std::unique_ptr<CFZPuttyGenInterface> fzpg_;

	wxListCtrl* keys_{};
	wxButton* add_{};
	wxButton* remove_{};

	wxCheckBox* compression_{};
};

COptionsPageConnectionSFTP::COptionsPageConnectionSFTP()
	: impl_(std::make_unique<impl>())
{
	impl_->fzpg_ = std::make_unique<CFZPuttyGenInterface>(this);
}

COptionsPageConnectionSFTP::~COptionsPageConnectionSFTP()
{
}

bool COptionsPageConnectionSFTP::CreateControls(wxWindow* parent)
{
	auto const& lay = m_pOwner->layout();

	Create(parent);
	auto main = lay.createFlex(1);
	main->AddGrowableCol(0);
	main->AddGrowableRow(0);
	SetSizer(main);

	{
		auto [box, inner] = lay.createStatBox(main, _("Public Key Authentication"), 1);
		inner->AddGrowableCol(0);
		inner->AddGrowableRow(2);
		inner->Add(new wxStaticText(box, nullID, _("To support public key authentication, FileZilla needs to know the private keys to use.")));
		inner->Add(new wxStaticText(box, nullID, _("Private &keys:")));
		impl_->keys_ = new wxListCtrl(box, nullID, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxBORDER_SUNKEN);
		impl_->keys_->Bind(wxEVT_LIST_ITEM_SELECTED, &COptionsPageConnectionSFTP::OnSelChanged, this);
		impl_->keys_->Bind(wxEVT_LIST_ITEM_DESELECTED, &COptionsPageConnectionSFTP::OnSelChanged, this);
		inner->Add(impl_->keys_, lay.grow);

		auto row = lay.createGrid(2);
		inner->Add(row, lay.halign);
		impl_->add_ = new wxButton(box, nullID, _("&Add key file..."));
		impl_->add_->Bind(wxEVT_BUTTON, &COptionsPageConnectionSFTP::OnAdd, this);
		row->Add(impl_->add_, lay.valign);
		impl_->remove_ = new wxButton(box, nullID, _("&Remove key"));
		impl_->remove_->Bind(wxEVT_BUTTON, &COptionsPageConnectionSFTP::OnRemove, this);
		row->Add(impl_->remove_, lay.valign);

#ifdef __WXMSW__
		inner->Add(new wxStaticText(box, nullID, _("Alternatively you can use the Pageant tool from PuTTY to manage your keys, FileZilla does recognize Pageant.")));
#else
		inner->Add(new wxStaticText(box, nullID, _("Alternatively you can use your system's SSH agent. To do so, make sure the SSH_AUTH_SOCK environment variable is set.")));
#endif
	}
	{
		auto [box, inner] = lay.createStatBox(main, _("Other SFTP options"), 1);

		impl_->compression_ = new wxCheckBox(box, nullID, _("&Enable compression"));
		inner->Add(impl_->compression_);
	}
	return true;
}

bool COptionsPageConnectionSFTP::LoadPage()
{
	impl_->keys_->InsertColumn(0, _("Filename"), wxLIST_FORMAT_LEFT, 150);
	impl_->keys_->InsertColumn(1, _("Comment"), wxLIST_FORMAT_LEFT, 100);
	impl_->keys_->InsertColumn(2, _("Data"), wxLIST_FORMAT_LEFT, 350);

	// Generic wxListCtrl has gross minsize
	wxSize size = impl_->keys_->GetMinSize();
	size.x = 1;
	impl_->keys_->SetMinSize(size);

	std::wstring keyFiles = m_pOptions->get_string(OPTION_SFTP_KEYFILES);
	auto tokens = fz::strtok(keyFiles, L"\r\n");
	for (auto const& token : tokens) {
		AddKey(token, true);
	}

	bool failure = false;

	SetCtrlState();

	impl_->compression_->SetValue(m_pOptions->get_int(OPTION_SFTP_COMPRESSION) != 0);

	return !failure;
}

bool COptionsPageConnectionSFTP::SavePage()
{
	// Don't save keys on process error
	if (!impl_->fzpg_->ProcessFailed()) {
		std::wstring keyFiles;
		for (int i = 0; i < impl_->keys_->GetItemCount(); ++i) {
			if (!keyFiles.empty()) {
				keyFiles += L"\n";
			}
			keyFiles += impl_->keys_->GetItemText(i).ToStdWstring();
		}
		m_pOptions->set(OPTION_SFTP_KEYFILES, keyFiles);
	}

	m_pOptions->set(OPTION_SFTP_COMPRESSION, impl_->compression_->GetValue() ? 1 : 0);

	return true;
}

void COptionsPageConnectionSFTP::OnAdd(wxCommandEvent&)
{
	wxFileDialog dlg(this, _("Select file containing private key"), wxString(), wxString(), wxFileSelectorDefaultWildcardStr, wxFD_OPEN | wxFD_FILE_MUST_EXIST);
	if (dlg.ShowModal() != wxID_OK) {
		return;
	}

	std::wstring const file = dlg.GetPath().ToStdWstring();

	if (AddKey(dlg.GetPath().ToStdWstring(), false)) {
#if USE_MAC_SANDBOX
		OSXSandboxUserdirs::Get().AddFile(file);
#endif
	}
}

void COptionsPageConnectionSFTP::OnRemove(wxCommandEvent&)
{
	int index = impl_->keys_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
	if (index == -1) {
		return;
	}

	impl_->keys_->DeleteItem(index);
}

bool COptionsPageConnectionSFTP::AddKey(std::wstring keyFile, bool silent)
{
	std::wstring comment, data;
	if (!impl_->fzpg_->LoadKeyFile(keyFile, silent, comment, data)) {
		if (silent) {
			int index = impl_->keys_->InsertItem(impl_->keys_->GetItemCount(), keyFile);
			impl_->keys_->SetItem(index, 1, comment);
			impl_->keys_->SetItem(index, 2, data);
		}
		return false;
	}

	if (KeyFileExists(keyFile)) {
		if (!silent) {
			wxMessageBoxEx(_("Selected file is already loaded"), _("Cannot load key file"), wxICON_INFORMATION);
		}
		return false;
	}

	int index = impl_->keys_->InsertItem(impl_->keys_->GetItemCount(), keyFile);
	impl_->keys_->SetItem(index, 1, comment);
	impl_->keys_->SetItem(index, 2, data);

	return true;
}

bool COptionsPageConnectionSFTP::KeyFileExists(std::wstring const& keyFile)
{
	for (int i = 0; i < impl_->keys_->GetItemCount(); ++i) {
		if (impl_->keys_->GetItemText(i) == keyFile) {
			return true;
		}
	}
	return false;
}

void COptionsPageConnectionSFTP::SetCtrlState()
{
	int index = impl_->keys_->GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
	impl_->remove_->Enable(index != -1);
}

void COptionsPageConnectionSFTP::OnSelChanged(wxListEvent&)
{
	SetCtrlState();
}
