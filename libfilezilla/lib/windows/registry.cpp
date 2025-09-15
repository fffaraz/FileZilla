#include "../libfilezilla/glue/registry.hpp"
#include "../libfilezilla/string.hpp"

#include <limits>

namespace fz {

regkey::~regkey()
{
	close();
}

regkey::regkey(HKEY const root, std::wstring const& subkey, bool readonly, regview v)
{
	open(root, subkey, readonly, v);
}

void regkey::close()
{
	if (key_) {
		RegCloseKey(*key_);
	}
}

bool regkey::open(HKEY const root, std::wstring const& subkey, bool readonly, regview v)
{
	close();

	HKEY result{};
	bool res{};

	DWORD flags{};
	if (v == regview_32) {
		flags |= KEY_WOW64_32KEY;
	}
	else if (v == regview_64) {
		flags |= KEY_WOW64_64KEY;
	}

	if (readonly) {
		res = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | flags, &result) == ERROR_SUCCESS;
	}
	else {
		res = RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS | flags, nullptr, &result, nullptr) == ERROR_SUCCESS;
	}
	if (res) {
		key_ = result;
	}
	return res;
}

bool regkey::has_value(std::wstring const& name) const
{
	DWORD type{};
	DWORD size{};
	return key_ && RegQueryValueExW(*key_, name.c_str(), nullptr, &type, nullptr, &size) == ERROR_SUCCESS;
}

namespace {
std::wstring read_string(HKEY key, std::wstring const& name, DWORD size)
{
	std::wstring ret;
	ret.resize(size / sizeof(wchar_t));
	DWORD type{};
	if (RegQueryValueExW(key, name.c_str(), nullptr, &type, reinterpret_cast<unsigned char*>(ret.data()), &size) != ERROR_SUCCESS) {
		ret.clear();
	}
	else {
		ret.resize(size / sizeof(wchar_t));
		if (type != REG_BINARY) {
			while (!ret.empty() && !ret.back()) {
				ret.pop_back();
			}
		}
	}

	return ret;
}

uint64_t read_int(HKEY key, std::wstring const& name)
{
	uint64_t v{};
	DWORD size = 8;
	DWORD type{};
	if (RegQueryValueExW(key, name.c_str(), nullptr, &type, reinterpret_cast<unsigned char*>(&v), &size) != ERROR_SUCCESS) {
		v = 0;
	}

	return v;
}
}

std::wstring regkey::value(std::wstring const& name) const
{
	std::wstring ret;

	if (key_) {
		DWORD type{};
		DWORD size{};
		if (RegQueryValueExW(*key_, name.c_str(), nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
			if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_BINARY || type == REG_MULTI_SZ) {
				ret = read_string(*key_, name, size);
			}
			else if (type == REG_DWORD || type == REG_QWORD) {
				ret = fz::to_wstring(read_int(*key_, name));
			}
		}
	}

	return ret;
}

uint64_t regkey::int_value(std::wstring const& name) const
{
	uint64_t ret{};

	if (key_) {
		DWORD type{};
		DWORD size{};
		if (RegQueryValueExW(*key_, name.c_str(), nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
			if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_BINARY || type == REG_MULTI_SZ) {
				ret = fz::to_integral<uint64_t>(read_string(*key_, name, size));
			}
			else if (type == REG_DWORD || type == REG_QWORD) {
				ret = read_int(*key_, name);
			}
		}
	}

	return ret;
}

bool regkey::set_value(std::wstring const& name, std::wstring const& value)
{
	return key_ && RegSetValueExW(*key_, name.c_str(), 0, REG_SZ, reinterpret_cast<unsigned char const*>(value.c_str()), static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}


bool regkey::set_value(std::wstring const& name, uint64_t value)
{
	DWORD size = (value <= std::numeric_limits<DWORD>::max()) ? 4 : 8;
	DWORD type = (value <= std::numeric_limits<DWORD>::max()) ? REG_DWORD : REG_QWORD;
	return key_ && RegSetValueExW(*key_, name.c_str(), 0, type, reinterpret_cast<unsigned char const*>(&value), size) == ERROR_SUCCESS;
}

bool regkey::delete_value(std::wstring const& name)
{
	if (!key_) {
		return false;
	}
	auto ret = RegDeleteValueW(*key_, name.c_str());
	return ret == ERROR_SUCCESS || ret == ERROR_FILE_NOT_FOUND;
}

}
