#ifndef FILEZILLA_INTERFACE_CHMODDIALOG_HEADER
#define FILEZILLA_INTERFACE_CHMODDIALOG_HEADER

#include "dialogex.h"
#include "../commonui/chmod_data.h"

class CChmodDialog final : public wxDialogEx
{
public:
	CChmodDialog(ChmodData & data);
	~CChmodDialog();

	bool Create(wxWindow* parent, int fileCount, int dirCount,
				wxString const& name, const char permissions[9]);

	bool Recursive() const;

protected:

	void OnOK(wxCommandEvent&);
	void OnRecurseChanged(wxCommandEvent&);

	void OnCheckboxClick(wxCommandEvent&);
	void OnNumericChanged(wxCommandEvent&);

	ChmodData & data_;

	struct impl;
	std::unique_ptr<impl> impl_;
};

#endif
