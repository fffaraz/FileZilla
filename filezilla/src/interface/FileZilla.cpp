#include "filezilla.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif
#include "filezillaapp.h"
#include "Mainfrm.h"
#include "Options.h"
#include "wrapengine.h"
#include "buildinfo.h"
#include "cmdline.h"
#include "welcome_dialog.h"
#include "msgbox.h"
#include "themeprovider.h"
#include "wxfilesystem_blob_handler.h"
#include "renderer.h"
#include "../commonui/fz_paths.h"
#include "../include/version.h"
#include <libfilezilla/local_filesys.hpp>
#include <libfilezilla/translate.hpp>
#include <wx/evtloop.h>

#ifdef WITH_LIBDBUS
#include "../dbus/session_manager.h"
#endif

#if defined(__WXMAC__) || defined(__UNIX__)
#include <wx/stdpaths.h>
#elif defined(__WXMSW__)
#include <shobjidl.h>
#endif

#if USE_UILOCALE
#include <wx/uilocale.h>
#endif

#include "locale_initializer.h"

#ifdef USE_MAC_SANDBOX
#include "osx_sandbox_userdirs.h"
#endif

using namespace std::literals;

#if !defined(__WXGTK__) && !defined(__MINGW32__)
IMPLEMENT_APP(CFileZillaApp)
#else
IMPLEMENT_APP_NO_MAIN(CFileZillaApp)
#endif //__WXGTK__

#if !wxUSE_PRINTF_POS_PARAMS
  #error Please build wxWidgets with support for positional arguments.
#endif

CFileZillaApp::CFileZillaApp()
{
	m_profile_start = fz::monotonic_clock::now();
	AddStartupProfileRecord("CFileZillaApp::CFileZillaApp()"sv);
}

CFileZillaApp::~CFileZillaApp()
{
	themeProvider_.reset();
}

namespace {
std::wstring translator(char const* const t)
{
	return wxGetTranslation(t).ToStdWstring();
}

std::wstring translator_pf(char const* const singular, char const* const plural, int64_t n)
{
	// wxGetTranslation does not support 64bit ints on 32bit systems.
	if (n < 0) {
		n = -n;
	}
	return wxGetTranslation(singular, plural, (sizeof(unsigned int) < 8 && n > 1000000000) ? (1000000000 + n % 1000000000) : n).ToStdWstring();
}
}

bool CFileZillaApp::OnInit()
{
	AddStartupProfileRecord("CFileZillaApp::OnInit()"sv);

	SetAppDisplayName("FileZilla");

	// Turn off idle events, we don't need them
	wxIdleEvent::SetMode(wxIDLE_PROCESS_SPECIFIED);

	wxUpdateUIEvent::SetMode(wxUPDATE_UI_PROCESS_SPECIFIED);

	fz::set_translators(translator, translator_pf);

#ifdef __WXMSW__
	SetCurrentProcessExplicitAppUserModelID(L"FileZilla.Client.AppID");
#endif

	//wxSystemOptions is slow, if a value is not set, it keeps querying the environment
	//each and every time...
	wxSystemOptions::SetOption(_T("filesys.no-mimetypesmanager"), 0);
	wxSystemOptions::SetOption(_T("window-default-variant"), _T(""));
#ifdef __WXMSW__
	wxSystemOptions::SetOption(_T("no-maskblt"), 0);
	wxSystemOptions::SetOption(_T("msw.window.no-clip-children"), 0);
	wxSystemOptions::SetOption(_T("msw.font.no-proof-quality"), 0);
	wxSystemOptions::SetOption(_T("msw.remap"), 0);
	wxSystemOptions::SetOption(_T("msw.staticbox.optimized-paint"), 0);
#endif
#ifdef __WXMAC__
	wxSystemOptions::SetOption(_T("mac.listctrl.always_use_generic"), 1);
	wxSystemOptions::SetOption(_T("mac.textcontrol-use-spell-checker"), 0);
#endif

	InitRenderer();

	int cmdline_result = ProcessCommandLine();
	if (!cmdline_result) {
		return false;
	}

	LoadLocales();

	if (cmdline_result < 0) {
		if (m_pCommandLine) {
			m_pCommandLine->DisplayUsage();
		}
		return false;
	}

	AddStartupProfileRecord("CFileZillaApp::OnInit(): Loading options"sv);
	options_ = std::make_unique<COptions>();

	InitLocale();

#ifndef _DEBUG
	const wxString& buildType = CBuildInfo::GetBuildType();
	if (buildType == _T("nightly")) {
		wxMessageBoxEx(_T("You are using a nightly development version of FileZilla 3, do not expect anything to work.\r\nPlease use the official releases instead.\r\n\r\n\
Unless explicitly instructed otherwise,\r\n\
DO NOT post bugreports,\r\n\
DO NOT use it in production environments,\r\n\
DO NOT distribute the binaries,\r\n\
DO NOT complain about it\r\n\
USE AT OWN RISK"), _T("Important Information"));
	}
	else {
		std::wstring v = GetEnv("FZDEBUG");
		if (v != L"1") {
			options_->set(OPTION_LOGGING_DEBUGLEVEL, 0);
			options_->set(OPTION_LOGGING_RAWLISTING, 0);
		}
	}
#endif

	if (!LoadResourceFiles()) {
		return false;
	}

	themeProvider_ = std::make_unique<CThemeProvider>(*options_);

#if ENABLE_STORJ
	CheckExistsFzstorj();
#endif

#ifdef WITH_LIBDBUS
	CSessionManager::Init();
#endif

	// Load the text wrapping engine
	m_pWrapEngine = std::make_unique<CWrapEngine>();
	m_pWrapEngine->LoadCache(*options_);

	bool welcome_skip = false;
#ifdef USE_MAC_SANDBOX
	OSXSandboxUserdirs::Get().Load();

	if (OSXSandboxUserdirs::Get().GetDirs().empty()) {
		CWelcomeDialog welcome(*options_, nullptr);
		welcome.Run(nullptr, false);
		welcome_skip = true;

		OSXSandboxUserdirsDialog dlg;
		dlg.Run(nullptr, true);
		if (OSXSandboxUserdirs::Get().GetDirs().empty()) {
			return false;
		}
    }
#endif

	CMainFrame *frame = new CMainFrame(*options_);
	frame->Show(true);
	SetTopWindow(frame);

	if (!welcome_skip) {
		auto welcome = new CWelcomeDialog(*options_, frame);
		welcome->RunDelayed();
	}

	frame->ProcessCommandLine();

	ShowStartupProfile();

	return true;
}

int CFileZillaApp::OnExit()
{
	CContextManager::Get()->NotifyGlobalHandlers(STATECHANGE_QUITNOW);

	options_->Save();

#ifdef WITH_LIBDBUS
	CSessionManager::Uninit();
#endif

	if (GetMainLoop() && wxEventLoopBase::GetActive() != GetMainLoop()) {
		// There's open dialogs and such and we just have to quit _NOW_.
		// We cannot continue as wx proceeds to destroy all windows, which interacts
		// badly with nested event loops, virtually always causing a crash.
		// I very much prefer clean shutdown but it's impossible in this situation. Sad.
		_exit(0);
	}

	return wxApp::OnExit();
}

bool CFileZillaApp::LoadResourceFiles()
{
	AddStartupProfileRecord("CFileZillaApp::LoadResourceFiles"sv);
	m_resourceDir = GetFZDataDir({L"resources/defaultfilters.xml"}, L"share/filezilla");

	wxImage::AddHandler(new wxPNGHandler());

	if (m_resourceDir.empty()) {
		wxString msg = _("Could not find the resource files for FileZilla, closing FileZilla.\nYou can specify the data directory of FileZilla by setting the FZ_DATADIR environment variable.");
		wxMessageBoxEx(msg, _("FileZilla Error"), wxOK | wxICON_ERROR);
		return false;
	}
	else {
		m_resourceDir.AddSegment(_T("resources"));
	}

	// Useful for XRC files with embedded image data.
	wxFileSystem::AddHandler(new wxFileSystemBlobHandler);

	return true;
}

#if USE_UILOCALE
namespace {
std::wstring GetTranslationName(wxLocaleIdent const& lid)
{
	std::wstring ret = lid.GetLanguage().ToStdWstring();
	std::wstring region = lid.GetRegion().ToStdWstring();
	if (!ret.empty() && !region.empty()) {
		ret += '_';
		ret += region;
		std::wstring modifier = lid.GetModifier().ToStdWstring();
		if (!modifier.empty()) {
			ret += '@';
			ret += modifier;
		}
	}
	return ret;
}
}

void CFileZillaApp::LoadLocales()
{
	setlocale(LC_COLLATE, "");
	wxUILocale::UseDefault();

	AddStartupProfileRecord("CFileZillaApp::LoadLocales"sv);
	m_localesDir = GetFZDataDir({L"locales/de/filezilla.mo"}, std::wstring());
	if (!m_localesDir.empty()) {
		m_localesDir.AddSegment(_T("locales"));
	}
#ifndef __WXMAC__
	else {
		m_localesDir = GetFZDataDir({L"de/filezilla.mo", L"de/LC_MESSAGES/filezilla.mo"}, L"share/locale", false);
	}
#endif
	if (!m_localesDir.empty()) {
		wxFileTranslationsLoader::AddCatalogLookupPathPrefix(m_localesDir.GetPath());
	}

	SetLocale(GetTranslationName(wxUILocale::GetCurrent().GetLocaleId()), nullptr);
}

bool CFileZillaApp::SetLocale(std::wstring language, wxLanguageInfo const** outInfo)
{
	if (language.empty() || language == L"en"sv || language == L"en_US"sv) {
		wxTranslations::Set(nullptr);
		lang_ = wxLANGUAGE_ENGLISH;
		lang_code_ = L"en_US"sv;
		layout_direction_ = wxLayout_LeftToRight;
		return true;
	}

	wxTranslations* ts = new wxTranslations;
	wxArrayString languages = ts->GetAvailableTranslations(L"filezilla");

	if (languages.Index(language) == wxNOT_FOUND) {
		size_t pos = language.find('_');
		if (pos != std::wstring::npos) {
			language = language.substr(0, pos);
			if (languages.Index(language) == wxNOT_FOUND) {
				language.clear();
			}
		}
	}

	wxLanguageInfo const* info = language.empty() ? nullptr : wxUILocale::FindLanguageInfo(language);
	if (outInfo) {
		*outInfo = info;
	}
	if (!language.empty() && info) {
		lang_code_ = language;
		lang_ = info->Language;
		layout_direction_ = info->LayoutDirection;
		ts->SetLanguage(language);
		ts->AddCatalog(L"filezilla");
		ts->AddCatalog(L"libfilezilla");
		wxTranslations::Set(ts);
		return true;
	}
	else {
		lang_ = wxLANGUAGE_ENGLISH;
		lang_code_ = L"en_US"sv;
		layout_direction_ = wxLayout_LeftToRight;

		delete ts;
		wxTranslations::Set(nullptr);
		return false;
	}
}

void CFileZillaApp::InitLocale()
{
	AddStartupProfileRecord("CFileZillaApp::InitLocale()"sv);
	std::wstring const language = options_->get_string(OPTION_LANGUAGE);
	if (!language.empty()) {
		wxLanguageInfo const* info{};
		if (SetLocale(language, &info)) {
			if (lang_code_ != language) {
				options_->set(OPTION_LANGUAGE, lang_code_);
			}
		}
		else {
			options_->set(OPTION_LANGUAGE, std::wstring());

			SetLocale(GetTranslationName(wxUILocale::GetCurrent().GetLocaleId()), nullptr);

			if (info && !info->Description.empty()) {
				wxMessageBoxEx(wxString::Format(_("Failed to set language to %s (%s), using default system language"), info->Description, language), _("Failed to change language"), wxICON_EXCLAMATION);
			}
			else {
				wxMessageBoxEx(wxString::Format(_("Failed to set language to %s, using default system language"), language), _("Failed to change language"), wxICON_EXCLAMATION);
			}
		}
	}
}

int CFileZillaApp::GetCurrentLanguage() const
{
	return lang_;
}

wxString CFileZillaApp::GetCurrentLanguageCode() const
{
	return lang_code_;
}

wxLayoutDirection CFileZillaApp::GetLayoutDirection() const
{
	return layout_direction_;
}

#else
void CFileZillaApp::LoadLocales()
{
	AddStartupProfileRecord("CFileZillaApp::LoadLocales"sv);
	m_localesDir = GetFZDataDir({L"locales/de/filezilla.mo"}, std::wstring());
	if (!m_localesDir.empty()) {
		m_localesDir.AddSegment(_T("locales"));
	}
#ifndef __WXMAC__
	else {
		m_localesDir = GetFZDataDir({L"de/filezilla.mo", L"de/LC_MESSAGES/filezilla.mo"}, L"share/locale", false);
	}
#endif
	if (!m_localesDir.empty()) {
		wxLocale::AddCatalogLookupPathPrefix(m_localesDir.GetPath());
	}

	SetLocale(wxLANGUAGE_DEFAULT);
}

bool CFileZillaApp::SetLocale(int language)
{
	// First check if we can load the new locale
	auto pLocale = std::make_unique<wxLocale>();
	wxLogNull log;
	pLocale->Init(language, 0);
	if (!pLocale->IsOk()) {
		return false;
	}

	// Load catalog. Only fail if a non-default language has been selected
	if (!pLocale->AddCatalog(_T("filezilla")) && language != wxLANGUAGE_DEFAULT && pLocale->GetCanonicalName().substr(0, 2) != L"en") {
		return false;
	}
	pLocale->AddCatalog(_T("libfilezilla"));

	if (m_pLocale) {
		// Now unload old locale
		// We unload new locale as well, else the internal locale chain in wxWidgets get's broken.
		pLocale.reset();
		m_pLocale.reset();

		// Finally load new one
		pLocale = std::make_unique<wxLocale>();
		pLocale->Init(language, 0);
		if (!pLocale->IsOk()) {
			return false;
		}
		else if (!pLocale->AddCatalog(_T("filezilla")) && language != wxLANGUAGE_DEFAULT && pLocale->GetCanonicalName().substr(0, 2) != L"en") {
			return false;
		}
		pLocale->AddCatalog(_T("libfilezilla"));
	}
	m_pLocale = std::move(pLocale);

	return true;
}

void CFileZillaApp::InitLocale()
{
	AddStartupProfileRecord("CFileZillaApp::InitLocale()"sv);
	wxString language = options_->get_string(OPTION_LANGUAGE);
	const wxLanguageInfo* pInfo = wxLocale::FindLanguageInfo(language);
	if (!language.empty()) {
#ifdef __WXGTK__
		if (CInitializer::error) {
			wxString error;

			wxLocale *loc = wxGetLocale();
			const wxLanguageInfo* currentInfo = loc ? loc->GetLanguageInfo(loc->GetLanguage()) : 0;
			if (!loc || !currentInfo) {
				if (!pInfo) {
					error.Printf(_("Failed to set language to %s, using default system language."),
						language);
				}
				else {
					error.Printf(_("Failed to set language to %s (%s), using default system language."),
						pInfo->Description, language);
				}
			}
			else {
				wxString currentName = currentInfo->CanonicalName;

				if (!pInfo) {
					error.Printf(_("Failed to set language to %s, using default system language (%s, %s)."),
						language, loc->GetLocale(),
						currentName);
				}
				else {
					error.Printf(_("Failed to set language to %s (%s), using default system language (%s, %s)."),
						pInfo->Description, language, loc->GetLocale(),
						currentName);
				}
			}

			error += _T("\n");
			error += _("Please make sure the requested locale is installed on your system.");
			wxMessageBoxEx(error, _("Failed to change language"), wxICON_EXCLAMATION);

			options_->set(OPTION_LANGUAGE, _T(""));
		}
#else
		if (!pInfo || !SetLocale(pInfo->Language)) {
			for (language = GetFallbackLocale(language); !language.empty(); language = GetFallbackLocale(language)) {
				const wxLanguageInfo* fallbackInfo = wxLocale::FindLanguageInfo(language);
				if (fallbackInfo && SetLocale(fallbackInfo->Language)) {
					options_->set(OPTION_LANGUAGE, language.ToStdWstring());
					return;
				}
			}
			options_->set(OPTION_LANGUAGE, std::wstring());
			if (pInfo && !pInfo->Description.empty()) {
				wxMessageBoxEx(wxString::Format(_("Failed to set language to %s (%s), using default system language"), pInfo->Description, language), _("Failed to change language"), wxICON_EXCLAMATION);
			}
			else {
				wxMessageBoxEx(wxString::Format(_("Failed to set language to %s, using default system language"), language), _("Failed to change language"), wxICON_EXCLAMATION);
			}
		}
#endif
	}
}

int CFileZillaApp::GetCurrentLanguage() const
{
	if (!m_pLocale) {
		return wxLANGUAGE_ENGLISH;
	}

	return m_pLocale->GetLanguage();
}

wxString CFileZillaApp::GetCurrentLanguageCode() const
{
	if (!m_pLocale) {
		return wxString();
	}

	return m_pLocale->GetCanonicalName();
}
#endif

#if wxUSE_DEBUGREPORT && wxUSE_ON_FATAL_EXCEPTION
void CFileZillaApp::OnFatalException()
{
}
#endif

void CFileZillaApp::DisplayEncodingWarning()
{
	static bool displayedEncodingWarning = false;
	if (displayedEncodingWarning) {
		return;
	}

	displayedEncodingWarning = true;

	wxMessageBoxEx(_("A local filename could not be decoded.\nPlease make sure the LC_CTYPE (or LC_ALL) environment variable is set correctly.\nUnless you fix this problem, files might be missing in the file listings.\nNo further warning will be displayed this session."), _("Character encoding issue"), wxICON_EXCLAMATION);
}

CWrapEngine* CFileZillaApp::GetWrapEngine()
{
	return m_pWrapEngine.get();
}

#if ENABLE_STORJ
void CFileZillaApp::CheckExistsFzstorj()
{
	AddStartupProfileRecord("FileZillaApp::CheckExistsFzstorj"sv);
	CheckExistsTool(L"fzstorj", L"../storj/", "FZ_FZSTORJ", OPTION_FZSTORJ_EXECUTABLE, fztranslate("Storj support"));
}

void CFileZillaApp::CheckExistsTool(std::wstring const& tool, std::wstring const& buildRelPath, char const* env, engineOptions setting, std::wstring const& description)
{
	std::wstring const executable = FindTool(tool, buildRelPath, env);

	if (executable.empty()) {
		std::wstring program = tool;
#if FZ_WINDOWS
		program += L".exe";
#endif
		wxMessageBoxEx(fz::sprintf(fztranslate("%s could not be found. Without this component of FileZilla, %s will not work.\n\nPossible solutions:\n- Make sure %s is in a directory listed in your PATH environment variable.\n- Set the full path to %s in the %s environment variable."), program, description, program, program, env),
			_("File not found"), wxICON_ERROR | wxOK);
	}
	options_->set(setting, executable);
}
#endif

#ifdef __WXMSW__
extern "C" BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM)
{
	HWND child = FindWindowEx(hwnd, 0, 0, _T("FileZilla process identificator 3919DB0A-082D-4560-8E2F-381A35969FB4"));
	if (child) {
		::PostMessage(hwnd, WM_ENDSESSION, (WPARAM)TRUE, (LPARAM)ENDSESSION_LOGOFF);
	}

	return TRUE;
}
#endif

int CFileZillaApp::ProcessCommandLine()
{
	AddStartupProfileRecord("CFileZillaApp::ProcessCommandLine"sv);
	m_pCommandLine = std::make_unique<CCommandLine>(argc, argv);
	int res = m_pCommandLine->Parse() ? 1 : -1;

	if (res > 0) {
		if (m_pCommandLine->HasSwitch(CCommandLine::close)) {
#ifdef __WXMSW__
			EnumWindows((WNDENUMPROC)EnumWindowCallback, 0);
#endif
			return 0;
		}

		if (m_pCommandLine->HasSwitch(CCommandLine::version)) {
			wxString out = wxString::Format(_T("FileZilla %s"), GetFileZillaVersion());
			if (!CBuildInfo::GetBuildType().empty()) {
				out += _T(" ") + CBuildInfo::GetBuildType() + _T(" build");
			}
			out += _T(", compiled on ") + CBuildInfo::GetBuildDateString();

			printf("%s\n", (const char*)out.mb_str());
			return 0;
		}
	}

	return res;
}

void CFileZillaApp::AddStartupProfileRecord(std::string_view const& msg)
{
	if (!m_profile_start) {
		return;
	}

	m_startupProfile.emplace_back(fz::monotonic_clock::now(), msg);
}

void CFileZillaApp::ShowStartupProfile()
{
	if (m_profile_start && m_pCommandLine && m_pCommandLine->HasSwitch(CCommandLine::debug_startup)) {
		AddStartupProfileRecord("CFileZillaApp::ShowStartupProfile"sv);
		wxString msg = _T("Profile:\n");

		size_t const max_digits = fz::to_string((m_startupProfile.back().first - m_profile_start).get_milliseconds()).size();

		int64_t prev{};
		for (auto const& p : m_startupProfile) {
			auto const diff = p.first - m_profile_start;
			auto absolute = std::to_wstring(diff.get_milliseconds());
			if (absolute.size() < max_digits) {
				msg.append(max_digits - absolute.size(), wchar_t(0x2007)); // FIGURE SPACE
			}
			msg += absolute;
			msg += L" ";

			auto relative = std::to_wstring(diff.get_milliseconds() - prev);
			if (relative.size() < max_digits) {
				msg.append(max_digits - relative.size(), wchar_t(0x2007)); // FIGURE SPACE
			}
			msg += relative;
			msg += L" ";

			msg += fz::to_wstring(p.second);
			msg += L"\n";

			prev = diff.get_milliseconds();
		}
		wxMessageBoxEx(msg);
	}

	m_profile_start = fz::monotonic_clock();
	m_startupProfile.clear();
}

std::wstring CFileZillaApp::GetSettingsFile(std::wstring const& name) const
{
	return options_->get_string(OPTION_DEFAULT_SETTINGSDIR) + name + _T(".xml");
}

#if defined(__MINGW32__)
extern "C" {
__declspec(dllexport) // This forces ld to not strip relocations so that ASLR can work on MSW.
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR, int nCmdShow)
{
	wxDISABLE_DEBUG_SUPPORT();
	return wxEntry(hInstance, hPrevInstance, NULL, nCmdShow);
}
}
#endif

