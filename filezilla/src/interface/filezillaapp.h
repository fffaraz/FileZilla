#ifndef FILEZILLA_INTERFACE_FILEZILLAAPP_HEADER
#define FILEZILLA_INTERFACE_FILEZILLAAPP_HEADER

#include "../include/local_path.h"
#include "../include/engine_options.h"

#include <vector>

class CCommandLine;
class COptions;
class CThemeProvider;
class CWrapEngine;

#if FZ_MAC
#define USE_UILOCALE 1
#endif

class CFileZillaApp : public wxApp
{
public:
	CFileZillaApp();
	virtual ~CFileZillaApp();

	virtual bool OnInit();
	virtual int OnExit();

	// Always (back)slash-terminated
	CLocalPath GetResourceDir() const { return m_resourceDir; }
	CLocalPath GetLocalesDir() const { return m_localesDir; }

	std::wstring GetSettingsFile(std::wstring const& name) const;

#if ENABLE_STORJ
	void CheckExistsFzstorj();
#endif

	void InitLocale();
	int GetCurrentLanguage() const;
	wxString GetCurrentLanguageCode() const;

	void DisplayEncodingWarning();

	CWrapEngine* GetWrapEngine();

	const CCommandLine* GetCommandLine() const { return m_pCommandLine.get(); }

	void ShowStartupProfile();
	void AddStartupProfileRecord(std::string_view const& msg);

protected:
#if ENABLE_STORJ
	void CheckExistsTool(std::wstring const& tool, std::wstring const& buildRelPath, char const* env, engineOptions setting, std::wstring const& description);
#endif

	bool LoadResourceFiles();
	void LoadLocales();
	int ProcessCommandLine();

#if USE_UILOCALE
	bool SetLocale(std::wstring language, wxLanguageInfo const** info);
	virtual wxLayoutDirection GetLayoutDirection() const override;

	int lang_{wxLANGUAGE_ENGLISH};
	std::wstring lang_code_;
	wxLayoutDirection layout_direction_{wxLayout_LeftToRight};
#else
	bool SetLocale(int language);

	std::unique_ptr<wxLocale> m_pLocale;
#endif

	CLocalPath m_resourceDir;
	CLocalPath m_localesDir;

#if wxUSE_DEBUGREPORT && wxUSE_ON_FATAL_EXCEPTION
	virtual void OnFatalException();
#endif

	std::unique_ptr<COptions> options_;
	std::unique_ptr<CWrapEngine> m_pWrapEngine;

	std::unique_ptr<CCommandLine> m_pCommandLine;

	fz::monotonic_clock m_profile_start;
	std::vector<std::pair<fz::monotonic_clock, std::string>> m_startupProfile;

	std::unique_ptr<CThemeProvider> themeProvider_;
};

DECLARE_APP(CFileZillaApp)

#endif
