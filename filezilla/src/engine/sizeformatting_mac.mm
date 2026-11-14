#import <Foundation/NSLocale.h>
#import <Foundation/NSString.h>

#include <libfilezilla/string.hpp>

using namespace std::literals;

std::wstring_view GetThousandsSeparator()
{
	static std::wstring const sep = [](){
		std::wstring sep;

		NSLocale* locale = [NSLocale currentLocale];
		if (locale) {
			sep = fz::to_wstring_from_utf8(locale.groupingSeparator.UTF8String);
		}
		return sep;
	}();
	return sep;
}

std::wstring_view GetRadixSeparator()
{
	static std::wstring const sep = [](){
		std::wstring sep;

		NSLocale* locale = [NSLocale currentLocale];
		if (locale) {
			sep = fz::to_wstring_from_utf8(locale.decimalSeparator.UTF8String);
		}
		if (sep.empty()) {
			sep = '.';
		}
		return sep;
	}();
	return sep;
}

