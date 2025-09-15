#include "filezilla.h"
#include "timeformatting.h"
#include "Options.h"

#include "option_change_event_handler.h"

namespace {

class Impl final : public wxEvtHandler, public COptionChangeEventHandler
{
public:
	Impl()
		: COptionChangeEventHandler(this)
	{
		InitFormat();

		COptions::Get()->watch(OPTION_DATE_FORMAT, this);
		COptions::Get()->watch(OPTION_TIME_FORMAT, this);
	}

	~Impl()
	{
		//COptions::Get()->unwatch_all(this);
	}

	void InitFormat()
	{
		std::wstring dateFormat = COptions::Get()->get_string(OPTION_DATE_FORMAT);
		std::wstring timeFormat = COptions::Get()->get_string(OPTION_TIME_FORMAT);

		if (dateFormat == L"1") {
			m_dateFormat = L"%Y-%m-%d";
		}
		else if (!dateFormat.empty() && dateFormat[0] == '2') {
			dateFormat = dateFormat.substr(1);
			if (fz::datetime::verify_format(dateFormat)) {
				m_dateFormat = dateFormat;
			}
			else {
				m_dateFormat = L"%x";
			}
		}
		else {
			m_dateFormat = L"%x";
		}

		m_dateTimeFormat = m_dateFormat;
		m_dateTimeFormat += ' ';

		if (timeFormat == L"1") {
			m_dateTimeFormat += L"%H:%M";
		}
		else if (!timeFormat.empty() && timeFormat[0] == '2') {
			timeFormat = timeFormat.substr(1);
			if (fz::datetime::verify_format(timeFormat)) {
				m_dateTimeFormat += timeFormat;
			}
			else {
				m_dateTimeFormat += L"%X";
			}
		}
		else {
			m_dateTimeFormat += L"%X";
		}
	}

	virtual void OnOptionsChanged(watched_options const&)
	{
		InitFormat();
	}

	std::wstring m_dateFormat;
	std::wstring m_dateTimeFormat;
};

Impl& GetImpl()
{
	static Impl impl;
	return impl;
}
}

wxString CTimeFormat::Format(fz::datetime const& time)
{
	wxString ret;
	if (!time.empty()) {
		if (time.get_accuracy() > fz::datetime::days) {
			ret = FormatDateTime(time);
		}
		else {
			ret = FormatDate(time);
		}
	}
	return ret;
}

wxString CTimeFormat::FormatDateTime(fz::datetime const& time)
{
	Impl& impl = GetImpl();

	return time.format(impl.m_dateTimeFormat, fz::datetime::local);
}

wxString CTimeFormat::FormatDate(fz::datetime const& time)
{
	Impl& impl = GetImpl();

	return time.format(impl.m_dateFormat, fz::datetime::local);
}
