#include "libfilezilla/time.hpp"

#include "libfilezilla/format.hpp"

#ifndef FZ_WINDOWS
#include <errno.h>
#include <sys/time.h>
#endif

#include <wchar.h>

//#include <cassert>
#define TIME_ASSERT(x) //assert(x)

namespace fz {

datetime::datetime(zone z, int year, int month, int day, int hour, int minute, int second, int millisecond)
{
	set(z, year, month, day, hour, minute, second, millisecond);
}

datetime::datetime(time_t t, accuracy a)
	: t_(static_cast<int64_t>(t) * 1000)
	, a_(a)
{
	TIME_ASSERT(clamped());
	TIME_ASSERT(a != milliseconds);
}

namespace {
template<typename C>
void skip(C const*& it, C const* const end)
{
	while (it != end && (*it < '0' || *it > '9')) {
		++it;
	}
}

template<typename T, typename C>
bool parse(C const*& it, C const* end, int count, T & v, int offset)
{
	skip(it, end);

	if (end - it < count) {
		return false;
	}

	T w = 0;

	C const* const stop = it + count;
	while (it != stop) {
		if (*it < '0' || *it > '9') {
			return false;
		}
		w *= 10;
		w += *it - '0';
		++it;
	}

	w += offset;

	v = w;
	return true;
}

template<typename String>
bool do_set(datetime& dt, String const& str, datetime::zone z)
{
	if (str.empty()) {
		dt.clear();
		return false;
	}

	auto const* it = str.data();
	auto const* end = it + str.size();

#ifdef FZ_WINDOWS
	SYSTEMTIME st{};
	if (!parse(it, end, 4, st.wYear, 0) ||
		!parse(it, end, 2, st.wMonth, 0) ||
		!parse(it, end, 2, st.wDay, 0))
	{
		dt.clear();
		return false;
	}

	datetime::accuracy a = datetime::days;
	if (parse(it, end, 2, st.wHour, 0)) {
		a = datetime::hours;
		if (parse(it, end, 2, st.wMinute, 0)) {
			a = datetime::minutes;
			if (parse(it, end, 2, st.wSecond, 0)) {
				a = datetime::seconds;
				if (parse(it, end, 3, st.wMilliseconds, 0)) {
					a = datetime::milliseconds;
				}
			}
		}
	}
	return dt.set(st, a, z);
#else
	tm t{};
	if (!parse(it, end, 4, t.tm_year, -1900) ||
		!parse(it, end, 2, t.tm_mon, -1) ||
		!parse(it, end, 2, t.tm_mday, 0))
	{
		dt.clear();
		return false;
	}

	datetime::accuracy a = datetime::days;
	int64_t ms{};
	if (parse(it, end, 2, t.tm_hour, 0)) {
		a = datetime::hours;
		if (parse(it, end, 2, t.tm_min, 0)) {
			a = datetime::minutes;
			if (parse(it, end, 2, t.tm_sec, 0)) {
				a = datetime::seconds;
				if (parse(it, end, 3, ms, 0)) {
					a = datetime::milliseconds;
				}
			}
		}
	}
	bool success = dt.set(t, a, z);
	if (success) {
		dt += duration::from_milliseconds(ms);
	}
	return success;
#endif
}
}

datetime::datetime(std::string_view const& str, zone z)
{
	do_set(*this, str, z);
}

datetime::datetime(std::wstring_view const& str, zone z)
{
	do_set(*this, str, z);
}

datetime datetime::now()
{
#ifdef FZ_WINDOWS
	FILETIME ft{};
	GetSystemTimeAsFileTime(&ft);
	return datetime(ft, milliseconds);
#else
	datetime ret;
	timeval tv = { 0, 0 };
	if (gettimeofday(&tv, nullptr) == 0) {
		ret.t_ = static_cast<int64_t>(tv.tv_sec) * 1000 + tv.tv_usec / 1000;
		ret.a_ = milliseconds;
	}
	return ret;
#endif
}

bool datetime::operator<(datetime const& op) const
{
	if (t_ == invalid) {
		return op.t_ != invalid;
	}
	else if (op.t_ == invalid) {
		return false;
	}

	if (t_ < op.t_) {
		return true;
	}
	if (t_ > op.t_) {
		return false;
	}

	return a_ < op.a_;
}

bool datetime::operator<=(datetime const& op) const
{
	if (t_ == invalid) {
		return true;
	}
	else if (op.t_ == invalid) {
		return false;
	}

	if (t_ < op.t_) {
		return true;
	}
	if (t_ > op.t_) {
		return false;
	}

	return a_ <= op.a_;
}

bool datetime::operator==(datetime const& op) const
{
	return t_ == op.t_ && a_ == op.a_;
}

bool datetime::clamped()
{
	bool ret = true;
	tm t = get_tm(utc);
	if (a_ < milliseconds && get_milliseconds() != 0) {
		ret = false;
	}
	else if (a_ < seconds && t.tm_sec) {
		ret = false;
	}
	else if (a_ < minutes && t.tm_min) {
		ret = false;
	}
	else if (a_ < hours && t.tm_hour) {
		ret = false;
	}
	return ret;
}

int datetime::compare(datetime const& op) const
{
	if (t_ == invalid) {
		return (op.t_ == invalid) ? 0 : -1;
	}
	else if (op.t_ == invalid) {
		return 1;
	}

	if (a_ == op.a_) {
		// First fast path: Same accuracy
		int ret = 0;
		if (t_ < op.t_) {
			ret = -1;
		}
		else if (t_ > op.t_) {
			ret = 1;
		}
		TIME_ASSERT(compare_slow(op) == ret);
		return ret;
	}

	// Second fast path: Lots of difference, at least 2 days
	int64_t diff = t_ - op.t_;
	if (diff > 60 * 60 * 24 * 1000 * 2) {
		TIME_ASSERT(compare_slow(op) == 1);
		return 1;
	}
	else if (diff < -60 * 60 * 24 * 1000 * 2) {
		TIME_ASSERT(compare_slow(op) == -1);
		return -1;
	}

	return compare_slow(op);
}

int datetime::compare_slow(datetime const& op) const
{
	tm const t1 = get_tm(utc);
	tm const t2 = op.get_tm(utc);
	if (t1.tm_year < t2.tm_year) {
		return -1;
	}
	else if (t1.tm_year > t2.tm_year) {
		return 1;
	}
	if (t1.tm_mon < t2.tm_mon) {
		return -1;
	}
	else if (t1.tm_mon > t2.tm_mon) {
		return 1;
	}
	if (t1.tm_mday < t2.tm_mday) {
		return -1;
	}
	else if (t1.tm_mday > t2.tm_mday) {
		return 1;
	}

	accuracy a = (a_ < op.a_) ? a_ : op.a_;

	if (a < hours) {
		return 0;
	}
	if (t1.tm_hour < t2.tm_hour) {
		return -1;
	}
	else if (t1.tm_hour > t2.tm_hour) {
		return 1;
	}

	if (a < minutes) {
		return 0;
	}
	if (t1.tm_min < t2.tm_min) {
		return -1;
	}
	else if (t1.tm_min > t2.tm_min) {
		return 1;
	}

	if (a < seconds) {
		return 0;
	}
	if (t1.tm_sec < t2.tm_sec) {
		return -1;
	}
	else if (t1.tm_sec > t2.tm_sec) {
		return 1;
	}

	if (a < milliseconds) {
		return 0;
	}
	auto ms1 = get_milliseconds();
	auto ms2 = op.get_milliseconds();
	if (ms1 < ms2) {
		return -1;
	}
	else if (ms1 > ms2) {
		return 1;
	}

	return 0;
}

datetime& datetime::operator+=(duration const& op)
{
	if (!empty()) {
		if (a_ < hours) {
			t_ += op.get_days() * 24 * 3600 * 1000;
		}
		else if (a_ < minutes) {
			t_ += op.get_hours() * 3600 * 1000;
		}
		else if (a_ < seconds) {
			t_ += op.get_minutes() * 60 * 1000;
		}
		else if (a_ < milliseconds) {
			t_ += op.get_seconds() * 1000;
		}
		else {
			t_ += op.get_milliseconds();
		}
	}
	return *this;
}

datetime& datetime::operator-=(duration const& op)
{
	*this += -op;
	return *this;
}

bool datetime::set(zone z, int year, int month, int day, int hour, int minute, int second, int millisecond)
{
	accuracy a;
	if (hour == -1) {
		a = days;
		TIME_ASSERT(minute == -1);
		TIME_ASSERT(second == -1);
		TIME_ASSERT(millisecond == -1);
		hour = minute = second = millisecond = 0;
	}
	else if (minute == -1) {
		a = hours;
		TIME_ASSERT(second == -1);
		TIME_ASSERT(millisecond == -1);
		minute = second = millisecond = 0;
	}
	else if (second == -1) {
		a = minutes;
		TIME_ASSERT(millisecond == -1);
		second = millisecond = 0;
	}
	else if (millisecond == -1) {
		a = seconds;
		millisecond = 0;
	}
	else {
		a = milliseconds;
	}

#ifdef FZ_WINDOWS
	SYSTEMTIME st{};
	st.wYear = year;
	st.wMonth = month;
	st.wDay = day;
	st.wHour = hour;
	st.wMinute = minute;
	st.wSecond = second;
	st.wMilliseconds = millisecond;

	return set(st, a, z);
#else

	tm t{};
	t.tm_isdst = -1;
	t.tm_year = year - 1900;
	t.tm_mon = month - 1;
	t.tm_mday = day;
	t.tm_hour = hour;
	t.tm_min = minute;
	t.tm_sec = second;

	bool const success = set(t, a, z);

	if (success) {
		t_ += millisecond;
	}

	return success;
#endif
}

bool datetime::set(std::string_view const& str, zone z)
{
	return do_set(*this, str, z);
}

bool datetime::set(std::wstring_view const& str, zone z)
{
	return do_set(*this, str, z);
}

#ifdef FZ_WINDOWS

namespace {
bool do_set(datetime & dt, SYSTEMTIME const& st, datetime::accuracy a, datetime::zone z)
{
	FILETIME ft{};
	if (a >= datetime::hours && z == datetime::local) {
		SYSTEMTIME st2{};
		if (!TzSpecificLocalTimeToSystemTime(nullptr, &st, &st2)) {
			return false;
		}
		if (!SystemTimeToFileTime(&st2, &ft)) {
			return false;
		}
	}
	else if (!SystemTimeToFileTime(&st, &ft)) {
		return false;
	}
	return dt.set(ft, a);
}
}

bool datetime::set(SYSTEMTIME const& st, accuracy a, zone z)
{
	clear();

	bool success = do_set(*this, st, a, z);
	if (!success) {
		// Check for alternate midnight format
		if (st.wHour == 24 && !st.wMinute && !st.wSecond && !st.wMilliseconds) {
			SYSTEMTIME st2 = st;
			st2.wHour = 23;
			st2.wMinute = 59;
			st2.wSecond = 59;
			st2.wMilliseconds = 999;
			success = do_set(*this, st2, a, z);
			if (success) {
				t_ += 1;
			}
		}
	}
	return success;
}

namespace {
template<typename T>
int64_t make_int64_t(T hi, T lo)
{
	return (static_cast<int64_t>(hi) << 32) + static_cast<int64_t>(lo);
}

// This is the offset between FILETIME epoch in 100ns and the Unix epoch in ms.
int64_t const EPOCH_OFFSET_IN_MSEC = 11644473600000ll;
}

bool datetime::set(FILETIME const& ft, accuracy a)
{
	if (ft.dwHighDateTime || ft.dwLowDateTime) {
		// See http://trac.wxwidgets.org/changeset/74423 and http://trac.wxwidgets.org/ticket/13098
		// Directly converting to time_t

		int64_t t = make_int64_t(ft.dwHighDateTime, ft.dwLowDateTime);
		t /= 10000; // Convert hundreds of nanoseconds to milliseconds.
		t -= EPOCH_OFFSET_IN_MSEC;
		if (t != invalid) {
			t_ = t;
			a_ = a;
			TIME_ASSERT(clamped());
			return true;
		}
	}
	clear();
	return false;
}

#else

bool datetime::set(tm& t, accuracy a, zone z)
{
	time_t tt;

	errno = 0;

	if (a >= hours && z == local) {
		tt = mktime(&t);
	}
	else {
		tt = timegm(&t);
	}

	if (tt != time_t(-1) || !errno) {
		t_ = static_cast<int64_t>(tt) * 1000;
		a_ = a;

		TIME_ASSERT(clamped());

		return true;
	}

	clear();
	return false;
}

#endif

bool datetime::imbue_time(int hour, int minute, int second, int millisecond)
{
	if (empty() || a_ > days) {
		return false;
	}

	if (second == -1) {
		a_ = minutes;
		TIME_ASSERT(millisecond == -1);
		second = millisecond = 0;
	}
	else if (millisecond == -1) {
		a_ = seconds;
		millisecond = 0;
	}
	else {
		a_ = milliseconds;
	}

	if (hour < 0 || hour >= 24) {
		// Allow alternate midnight representation
		if (hour != 24 || minute != 0 || second != 0 || millisecond != 0) {
			return false;
		}
	}
	if (minute < 0 || minute >= 60) {
		return false;
	}
	if (second < 0 || second >= 60) {
		return false;
	}
	if (millisecond < 0 || millisecond >= 1000) {
		return false;
	}

	t_ += (hour * 3600 + minute * 60 + second) * 1000 + millisecond;
	return true;
}

bool datetime::empty() const
{
	return t_ == invalid;
}

void datetime::clear()
{
	a_ = days;
	t_ = invalid;
}

#ifdef __VISUALC__

#include <mutex.h>

namespace {

// Sadly wcsftime has shitty error handling, instead of returning 0 and setting errrno, it invokes some crt debug machinary.
// Fortunately we don't build the official FZ binaries with Visual Studio.
extern "C" void NullInvalidParameterHandler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t)
{
}

struct CrtAssertSuppressor
{
	CrtAssertSuppressor()
	{
		scoped_lock l(m_);

		if (!refs_++) {
			oldError = _CrtSetReportMode(_CRT_ERROR, 0);
			oldAssert = _CrtSetReportMode(_CRT_ASSERT, 0);
			oldHandler = _set_invalid_parameter_handler(NullInvalidParameterHandler);
		}
	}

	~CrtAssertSuppressor()
	{
		scoped_lock l(m_);

		if (!--refs_) {
			_set_invalid_parameter_handler(oldHandler);
			_CrtSetReportMode(_CRT_ASSERT, oldAssert);
			_CrtSetReportMode(_CRT_ERROR, oldError);
		}
	}

	static int oldError;
	static int oldAssert;
	static _invalid_parameter_handler oldHandler;

	static mutex m_;
	static int refs_;
};

int CrtAssertSuppressor::oldError{};
int CrtAssertSuppressor::oldAssert{};
_invalid_parameter_handler CrtAssertSuppressor::oldHandler{};

mutex CrtAssertSuppressor::m_{};
int CrtAssertSuppressor::refs_{};

}
#endif

bool datetime::verify_format(std::string const& fmt)
{
	tm const t = datetime::now().get_tm(utc);
	char buf[4096];

#ifdef __VISUALC__
	CrtAssertSuppressor suppressor;
#endif

	return strftime(buf, sizeof(buf) / sizeof(char), fmt.c_str(), &t) != 0;
}

bool datetime::verify_format(std::wstring const& fmt)
{
	tm const t = datetime::now().get_tm(utc);
	wchar_t buf[4096];

#ifdef __VISUALC__
	CrtAssertSuppressor suppressor;
#endif

	return wcsftime(buf, sizeof(buf) / sizeof(wchar_t), fmt.c_str(), &t) != 0;
}

duration operator-(datetime const& a, datetime const& b)
{
	TIME_ASSERT(a.IsValid());
	TIME_ASSERT(b.IsValid());

	return duration::from_milliseconds(a.t_ - b.t_);
}

std::string datetime::format(std::string const& fmt, zone z) const
{
	tm t = get_tm(z);

	int const count = 1000;
	char buf[count];

#ifdef __VISUALC__
	CrtAssertSuppressor suppressor;
#endif
	strftime(buf, count - 1, fmt.c_str(), &t);
	buf[count - 1] = 0;

	return buf;
}

std::wstring datetime::format(std::wstring const& fmt, zone z) const
{
	tm t = get_tm(z);

	int const count = 1000;
	wchar_t buf[count];

#ifdef __VISUALC__
	CrtAssertSuppressor suppressor;
#endif
	wcsftime(buf, count - 1, fmt.c_str(), &t);
	buf[count - 1] = 0;

	return buf;
}

time_t datetime::get_time_t() const
{
	return t_ / 1000;
}

tm datetime::get_tm(zone z) const
{
	tm ret{};
#ifdef FZ_WINDOWS
	// gmtime_s/localtime_s don't work with negative times
	auto constexpr y2k38_limit = ((int64_t(2) << 31) - 86400) * 1000;
	if (t_ < 86400000 || (sizeof(time_t) == 4 && t_ >= y2k38_limit)) {
		FILETIME ft = get_filetime();
		SYSTEMTIME st;
		if (FileTimeToSystemTime(&ft, &st)) {

			if (a_ >= hours && z == local) {
				SYSTEMTIME st2;
				if (SystemTimeToTzSpecificLocalTime(nullptr, &st, &st2)) {
					st = st2;
				}
			}

			ret.tm_year = st.wYear - 1900;
			ret.tm_mon = st.wMonth - 1;
			ret.tm_mday = st.wDay;
			ret.tm_wday = st.wDayOfWeek;
			ret.tm_hour = st.wHour;
			ret.tm_min = st.wMinute;
			ret.tm_sec = st.wSecond;
			ret.tm_yday = -1;
		}
	}
	else {
		time_t t = get_time_t();
		// Special case: If having only days, don't perform conversion
		if (z == utc || a_ == days) {
			gmtime_s(&ret, &t);
		}
		else {
			localtime_s(&ret, &t);
		}
	}
#else
	time_t t = get_time_t();
	if (z == utc || a_ == days) {
		gmtime_r(&t, &ret);
	}
	else {
		localtime_r(&t, &ret);
	}
#endif
	return ret;
}

#ifdef FZ_WINDOWS

datetime::datetime(FILETIME const& ft, accuracy a)
{
	set(ft, a);
}

FILETIME datetime::get_filetime() const
{
	FILETIME ret{};
	if (!empty()) {
		int64_t t = t_;

		t += EPOCH_OFFSET_IN_MSEC;
		t *= 10000;

		ret.dwHighDateTime = t >> 32;
		ret.dwLowDateTime = t & 0xffffffffll;
	}

	return ret;
}

#endif

std::string datetime::get_rfc822() const
{
	if (empty()) {
		return std::string();
	}
	tm const t = get_tm(datetime::zone::utc);
	if (t.tm_wday < 0 || t.tm_wday > 6 || t.tm_mon < 0 || t.tm_mon > 11) {
		return std::string();
	}

	static const char* months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	static const char* wdays[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

	return sprintf("%s, %02d %s %d %02d:%02d:%02d GMT", wdays[t.tm_wday], t.tm_mday, months[t.tm_mon], t.tm_year + 1900,
		t.tm_hour, t.tm_min, t.tm_sec);
}

using namespace std::literals;

namespace {
template<typename String>
bool do_set_rfc822(datetime& dt, String const& str)
{
	auto const tokens = strtok_view(str, fzS(typename String::value_type, ", :-"));
	if (tokens.size() >= 7) {
		auto getMonth = [](auto const& m) {
			if (m == fzS(typename String::value_type, "Jan")) return 1;
			if (m == fzS(typename String::value_type, "Feb")) return 2;
			if (m == fzS(typename String::value_type, "Mar")) return 3;
			if (m == fzS(typename String::value_type, "Apr")) return 4;
			if (m == fzS(typename String::value_type, "May")) return 5;
			if (m == fzS(typename String::value_type, "Jun")) return 6;
			if (m == fzS(typename String::value_type, "Jul")) return 7;
			if (m == fzS(typename String::value_type, "Aug")) return 8;
			if (m == fzS(typename String::value_type, "Sep")) return 9;
			if (m == fzS(typename String::value_type, "Oct")) return 10;
			if (m == fzS(typename String::value_type, "Nov")) return 11;
			if (m == fzS(typename String::value_type, "Dec")) return 12;
			return 0;
		};

		int day = to_integral<int>(tokens[1]);
		int month;
		if (!day) {
			day = to_integral<int>(tokens[2]);
			month = getMonth(tokens[1]);
		}
		else {
			month = getMonth(tokens[2]);
		}

		int year = to_integral<int>(tokens[6]);
		int hour;
		int minute;
		int second;
		if (year < 1000) {
			year = to_integral<int>(tokens[3]);
			if (year < 1000) {
				year += 1900;
			}
			hour = to_integral<int>(tokens[4]);
			minute = to_integral<int>(tokens[5]);
			second = to_integral<int>(tokens[6]);
		}
		else {
			hour = to_integral<int>(tokens[3]);
			minute = to_integral<int>(tokens[4]);
			second = to_integral<int>(tokens[5]);
		}

		bool set = dt.set(datetime::utc, year, month, day, hour, minute, second);
		if (set && tokens.size() >= 8) {
			int minutes{};
			if (tokens[7].size() == 5 && tokens[7][0] == '+') {
				minutes = -fz::to_integral<int>(tokens[7].substr(1, 2), -10000) * 60 + fz::to_integral<int>(tokens[7].substr(3), -10000);
			}
			else if (tokens[7].size() == 4) {
				minutes = fz::to_integral<int>(tokens[7].substr(0, 2), 10000) * 60 + fz::to_integral<int>(tokens[7].substr(2), 10000);
			}
			if (minutes < 10000) {
				dt += fz::duration::from_minutes(minutes);
			}
		}

		return set;
	}
	else {
		dt.clear();
		return false;
	}
}
}

bool datetime::set_rfc822(std::string_view const& str)
{
	return do_set_rfc822(*this, str);
}

bool datetime::set_rfc822(std::wstring_view const& str)
{
	return do_set_rfc822(*this, str);
}

namespace {
template<typename String>
bool do_set_rfc3339(fz::datetime& dt, String str)
{
	if (str.size() < 19) {
		dt.clear();
		return false;
	}

	auto separator_pos = str.find_first_of(fzS(typename String::value_type, "tT ")); // Including space, there is a lowercase 'may' in section 5.6 of the RFC
	if (separator_pos == String::npos) {
		dt.clear();
		return false;
	}

	auto date_part = str.substr(0, separator_pos);
	auto const date_tokens = fz::strtok_view(date_part, fzS(typename String::value_type, "-"));

	auto offset_pos = str.find_first_of(fzS(typename String::value_type, "+-Zz"), separator_pos);

	String time_part;
	if (offset_pos == String::npos) {
		// Allow the offset part to be missing
		time_part = str.substr(separator_pos + 1);
	}
	else {
		time_part = str.substr(separator_pos + 1, offset_pos - separator_pos - 1);
	}

	auto const time_tokens = fz::strtok_view(time_part, fzS(typename String::value_type, ":."));
	if (date_tokens.size() == 3 && (time_tokens.size() == 3 || time_tokens.size() == 4)) {
		int year = fz::to_integral<int>(date_tokens[0]);
		if (year < 1000) {
			if (year < 1000) {
				year += 1900;
			}
		}
		int month = fz::to_integral<int>(date_tokens[1]);
		int day = fz::to_integral<int>(date_tokens[2]);

		int hour = fz::to_integral<int>(time_tokens[0]);
		int minute = fz::to_integral<int>(time_tokens[1]);
		int second = fz::to_integral<int>(time_tokens[2]);

		bool set{};
		if (time_tokens.size() == 4) {
			// Convert fraction, .82 is 820ms
			int ms = fz::to_integral<int>(time_tokens[3].substr(0, 3));
			if (time_tokens[3].size() == 1) {
				ms *= 100;
			}
			else if (time_tokens[3].size() == 2) {
				ms *= 10;
			}
			set = dt.set(fz::datetime::utc, year, month, day, hour, minute, second, ms);
		}
		else {
			set = dt.set(fz::datetime::utc, year, month, day, hour, minute, second);
		}

		if (set && offset_pos != String::npos && str[offset_pos] != 'Z') {
			auto const offset_tokens = fz::strtok_view(str.substr(offset_pos + 1), ':');
			if (offset_tokens.size() != 2) {
				dt.clear();
				return false;
			}

			int minutes = fz::to_integral<int>(offset_tokens[0], 10009) * 60 + fz::to_integral<int>(offset_tokens[1], 10000);
			if (minutes < 10000) {
				if (str[offset_pos] == '+') {
					minutes = -minutes;
				}
				dt += fz::duration::from_minutes(minutes);
			}
		}

		return set;
	}

	dt.clear();
	return false;
}
}

bool datetime::set_rfc3339(std::string_view const& str)
{
	return do_set_rfc3339(*this, str);
}

bool datetime::set_rfc3339(std::wstring_view const& str)
{
	return do_set_rfc3339(*this, str);
}

}
