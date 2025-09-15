#include "filezilla.h"
#include "chmoddialog.h"
#include "textctrlex.h"

#include <wx/statbox.h>

struct CChmodDialog::impl
{
	wxCheckBox* checkBoxes[9]{};

	wxString oldNumeric_;
	bool lastChangedNumeric_{};

	wxCheckBox* recursive_{};
	wxTextCtrlEx* numeric_{};

	wxRadioButton* applyAll_{};
	wxRadioButton* applyFiles_{};
	wxRadioButton* applyDirs_{};
};

CChmodDialog::CChmodDialog(ChmodData & data)
	: data_(data)
	, impl_(std::make_unique<impl>())
{
}

CChmodDialog::~CChmodDialog() = default;

bool CChmodDialog::Create(wxWindow* parent, int fileCount, int dirCount,
	wxString const& name, const char permissions[9])
{
	memcpy(data_.permissions_, permissions, 9);

	SetExtraStyle(wxWS_EX_BLOCK_EVENTS);
	SetParent(parent);

	wxString title;
	if (!dirCount) {
		if (fileCount == 1) {
			title = wxString::Format(_("Please select the new attributes for the file \"%s\"."), name);
		}
		else {
			title = _("Please select the new attributes for the selected files.");
		}
	}
	else {
		if (!fileCount) {
			if (dirCount == 1) {
				title = wxString::Format(_("Please select the new attributes for the directory \"%s\"."), name);
			}
			else {
				title = _("Please select the new attributes for the selected directories.");
			}
		}
		else {
			title = _("Please select the new attributes for the selected files and directories.");
		}
	}

	if (!wxDialogEx::Create(parent, nullID, _("Change file attributes"), wxDefaultPosition, wxDefaultSize)) {
		return false;
	}

	auto& lay = layout();
	auto main = lay.createMain(this, 1);

	WrapText(this, title, lay.dlgUnits(160));
	main->Add(new wxStaticText(this, nullID, title));

	{
		auto [box, inner] = lay.createStatBox(main, _("Owner permissions"), 3);
		impl_->checkBoxes[0] = new wxCheckBox(box, nullID, _("&Read"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[0]);
		impl_->checkBoxes[1] = new wxCheckBox(box, nullID, _("&Write"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[1]);
		impl_->checkBoxes[2] = new wxCheckBox(box, nullID, _("&Execute"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[2]);
	}
	{
		auto [box, inner] = lay.createStatBox(main, _("Group permissions"), 3);
		impl_->checkBoxes[3] = new wxCheckBox(box, nullID, _("Re&ad"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[3]);
		impl_->checkBoxes[4] = new wxCheckBox(box, nullID, _("W&rite"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[4]);
		impl_->checkBoxes[5] = new wxCheckBox(box, nullID, _("E&xecute"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[5]);
	}
	{
		auto [box, inner] = lay.createStatBox(main, _("Public permissions"), 3);
		impl_->checkBoxes[6] = new wxCheckBox(box, nullID, _("Rea&d"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[6]);
		impl_->checkBoxes[7] = new wxCheckBox(box, nullID, _("Wr&ite"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[7]);
		impl_->checkBoxes[8] = new wxCheckBox(box, nullID, _("Exe&cute"), wxDefaultPosition, wxDefaultSize, wxCHK_3STATE | wxCHK_ALLOW_3RD_STATE_FOR_USER);
		inner->Add(impl_->checkBoxes[8]);
	}

	auto row = lay.createFlex(2);
	main->Add(row);

	row->Add(new wxStaticText(this, nullID, _("&Numeric value:")), lay.valign);
	impl_->numeric_ = new wxTextCtrlEx(this, nullID, wxString(), wxDefaultPosition, lay.defTextCtrlSize);
	row->Add(impl_->numeric_, lay.valign);
	impl_->numeric_->SetFocus();
	impl_->numeric_->Bind(wxEVT_TEXT, &CChmodDialog::OnNumericChanged, this);

	wxString desc = _("You can use an x at any position to keep the permission the original files have.");
	WrapText(this, desc, lay.dlgUnits(160));
	main->Add(new wxStaticText(this, nullID, desc), lay.valign);

	if (dirCount) {
		main->AddSpacer(0);

		impl_->recursive_ = new wxCheckBox(this, nullID, _("Rec&urse into subdirectories"));
		impl_->recursive_->Bind(wxEVT_CHECKBOX, &CChmodDialog::OnRecurseChanged, this);
		main->Add(impl_->recursive_);

		auto inner = lay.createFlex(1);
		main->Add(inner, 0, wxLEFT, lay.indent);

		impl_->applyAll_ = new wxRadioButton(this, nullID, _("A&pply to all files and directories"), wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
		inner->Add(impl_->applyAll_);
		impl_->applyFiles_ = new wxRadioButton(this, nullID, _("Apply to &files only"));
		inner->Add(impl_->applyFiles_);
		impl_->applyDirs_ = new wxRadioButton(this, nullID, _("App&ly to directories only"));
		inner->Add(impl_->applyDirs_);

		impl_->applyAll_->SetValue(true);
		impl_->applyAll_->Disable();
		impl_->applyFiles_->Disable();
		impl_->applyDirs_->Disable();
	}

	for (int i = 0; i < 9; ++i) {
		impl_->checkBoxes[i]->Bind(wxEVT_COMMAND_CHECKBOX_CLICKED, &CChmodDialog::OnCheckboxClick, this);

		switch (permissions[i])
		{
		default:
		case 0:
			impl_->checkBoxes[i]->Set3StateValue(wxCHK_UNDETERMINED);
			break;
		case 1:
			impl_->checkBoxes[i]->Set3StateValue(wxCHK_UNCHECKED);
			break;
		case 2:
			impl_->checkBoxes[i]->Set3StateValue(wxCHK_CHECKED);
			break;
		}
	}

	auto buttons = lay.createButtonSizer(this, main, true);

	auto ok = new wxButton(this, wxID_OK, _("&OK"));
	ok->SetDefault();
	ok->Bind(wxEVT_BUTTON, &CChmodDialog::OnOK, this);
	buttons->AddButton(ok);

	auto cancel = new wxButton(this, wxID_CANCEL, _("Cancel"));
	cancel->Bind(wxEVT_BUTTON, [this](wxCommandEvent const&) { EndModal(wxID_CANCEL); });
	buttons->AddButton(cancel);

	buttons->Realize();

	GetSizer()->Fit(this);
	GetSizer()->SetSizeHints(this);

	wxCommandEvent evt;
	OnCheckboxClick(evt);

	return true;
}

void CChmodDialog::OnOK(wxCommandEvent&)
{
	data_.applyType_ = 0;
	if (impl_->recursive_) {
		if (impl_->applyFiles_->GetValue()) {
			data_.applyType_ = 1;
		}
		else if (impl_->applyDirs_->GetValue()) {
			data_.applyType_ = 2;
		}
	}

	data_.numeric_ = impl_->numeric_->GetValue().ToStdWstring();
	EndModal(wxID_OK);
}

void CChmodDialog::OnCheckboxClick(wxCommandEvent&)
{
	impl_->lastChangedNumeric_ = false;
	for (int i = 0; i < 9; ++i) {
		wxCheckBoxState state = impl_->checkBoxes[i]->Get3StateValue();
		switch (state)
		{
		default:
		case wxCHK_UNDETERMINED:
			data_.permissions_[i] = 0;
			break;
		case wxCHK_UNCHECKED:
			data_.permissions_[i] = 1;
			break;
		case wxCHK_CHECKED:
			data_.permissions_[i] = 2;
			break;
		}
	}

	wxString numericValue;
	for (int i = 0; i < 3; ++i) {
		if (!data_.permissions_[i * 3] || !data_.permissions_[i * 3 + 1] || !data_.permissions_[i * 3 + 2]) {
			numericValue += 'x';
			continue;
		}

		numericValue += wxString::Format(_T("%d"), (data_.permissions_[i * 3] - 1) * 4 + (data_.permissions_[i * 3 + 1] - 1) * 2 + (data_.permissions_[i * 3 + 2] - 1) * 1);
	}

	
	wxString oldValue = impl_->numeric_->GetValue();

	impl_->numeric_->ChangeValue(oldValue.Left(oldValue.size() - 3) + numericValue);
	impl_->oldNumeric_ = numericValue;
}

void CChmodDialog::OnNumericChanged(wxCommandEvent&)
{
	impl_->lastChangedNumeric_ = true;

	wxString numeric = impl_->numeric_->GetValue();
	if (numeric.size() < 3) {
		return;
	}

	numeric = numeric.Right(3);
	for (int i = 0; i < 3; ++i) {
		if ((numeric[i] < '0' || numeric[i] > '9') && numeric[i] != 'x') {
			return;
		}
	}
	for (int i = 0; i < 3; ++i) {
		if (!impl_->oldNumeric_.empty() && numeric[i] == impl_->oldNumeric_[i]) {
			continue;
		}
		if (numeric[i] == 'x') {
			data_.permissions_[i * 3] = 0;
			data_.permissions_[i * 3 + 1] = 0;
			data_.permissions_[i * 3 + 2] = 0;
		}
		else {
			int value = numeric[i] - '0';
			data_.permissions_[i * 3] = (value & 4) ? 2 : 1;
			data_.permissions_[i * 3 + 1] = (value & 2) ? 2 : 1;
			data_.permissions_[i * 3 + 2] = (value & 1) ? 2 : 1;
		}
	}

	impl_->oldNumeric_ = numeric;

	for (int i = 0; i < 9; ++i) {
		switch (data_.permissions_[i])
		{
		default:
		case 0:
			impl_->checkBoxes[i]->Set3StateValue(wxCHK_UNDETERMINED);
			break;
		case 1:
			impl_->checkBoxes[i]->Set3StateValue(wxCHK_UNCHECKED);
			break;
		case 2:
			impl_->checkBoxes[i]->Set3StateValue(wxCHK_CHECKED);
			break;
		}
	}
}

bool CChmodDialog::Recursive() const
{
	return impl_ && impl_->recursive_ && impl_->recursive_->GetValue();
}

void CChmodDialog::OnRecurseChanged(wxCommandEvent&)
{
	impl_->applyAll_->Enable(impl_->recursive_->GetValue());
	impl_->applyFiles_->Enable(impl_->recursive_->GetValue());
	impl_->applyDirs_->Enable(impl_->recursive_->GetValue());
}
