#ifndef FILEZILLA_INTERFACE_ASYNCREQUESTQUEUE_HEADER
#define FILEZILLA_INTERFACE_ASYNCREQUESTQUEUE_HEADER

#include "context_control.h"

#include <wx/timer.h>

#include <list>

class cert_store;
class COptionsBase;
class CQueueView;

class CAsyncRequestQueue final : public wxEvtHandler, protected CGlobalStateEventHandler
{
public:
	CAsyncRequestQueue(wxTopLevelWindow * parent, COptionsBase & options, cert_store & certStore);
	~CAsyncRequestQueue();

	bool AddRequest(CFileZillaEngine *pEngine, std::unique_ptr<CAsyncRequestNotification> && pNotification);
	void ClearPending(CFileZillaEngine const* const pEngine);
	void RecheckDefaults();

	void SetQueue(CQueueView *pQueue);

	void TriggerProcessing();

protected:
	virtual void OnStateChange(CState* pState, t_statechange_notifications notification, std::wstring const&, const void*) override;

	// Returns false if main window doesn't have focus or is minimized.
	// Request attention if needed
	bool CheckWindowState();

	wxTopLevelWindow *parent_{};
	CQueueView *m_pQueueView{};

	COptionsBase & options_;
	cert_store & certStore_;

	bool ProcessNextRequest();
	bool ProcessDefaults(CFileZillaEngine *pEngine, std::unique_ptr<CAsyncRequestNotification> & pNotification);

	struct t_queueEntry
	{
		t_queueEntry(CFileZillaEngine *e, std::unique_ptr<CAsyncRequestNotification>&& n)
			: pEngine(e)
			, pNotification(std::move(n))
		{
		}

		CFileZillaEngine *pEngine{};
		std::unique_ptr<CAsyncRequestNotification> pNotification;
	};
	std::list<t_queueEntry> m_requestList;

	bool ProcessFileExistsNotification(t_queueEntry &entry);

	bool SendReply(t_queueEntry & entry);

	DECLARE_EVENT_TABLE()
	void OnProcessQueue(wxCommandEvent &event);
	void OnTimer(wxTimerEvent& event);

	// Reentrancy guard
	bool m_inside_request{};

	wxTimer m_timer;
};

#endif
