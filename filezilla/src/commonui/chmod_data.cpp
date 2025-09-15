#include "chmod_data.h"

#include <libfilezilla/string.hpp>

#include <cstring>

bool ChmodData::ConvertPermissions(std::wstring const& rwx, char* permissions)
{
	if (!permissions) {
		return false;
	}

	size_t pos = rwx.find('(');
	if (pos != std::wstring::npos && rwx.back() == ')') {
		// MLSD permissions:
		//   foo (0644)
		return DoConvertPermissions(rwx.substr(pos + 1, rwx.size() - pos - 2), permissions);
	}

	return DoConvertPermissions(rwx, permissions);
}

bool ChmodData::DoConvertPermissions(std::wstring const& rwx, char* permissions)
{
	if (rwx.size() < 3) {
		return false;
	}
	size_t i;
	for (i = 0; i < rwx.size(); ++i) {
		if (rwx[i] < '0' || rwx[i] > '9') {
			break;
		}
	}
	if (i == rwx.size()) {
		// Mode, e.g. 0723
		for (i = 0; i < 3; ++i) {
			int m = rwx[rwx.size() - 3 + i] - '0';

			for (int j = 0; j < 3; ++j) {
				if (m & (4 >> j)) {
					permissions[i * 3 + j] = 2;
				}
				else {
					permissions[i * 3 + j] = 1;
				}
			}
		}

		return true;
	}

	unsigned char const permchars[3] = { 'r', 'w', 'x' };

	if (rwx.size() != 10) {
		return false;
	}

	for (int j = 0; j < 9; ++j) {
		bool set = rwx[j + 1] == permchars[j % 3];
		permissions[j] = set ? 2 : 1;
	}
	if (rwx[3] == 's') {
		permissions[2] = 2;
	}
	if (rwx[6] == 's') {
		permissions[5] = 2;
	}
	if (rwx[9] == 't') {
		permissions[8] = 2;
	}

	return true;
}


std::wstring ChmodData::GetPermissions(const char* previousPermissions, bool dir)
{
	// Construct a new permission string

	if (numeric_.size() < 3) {
		return numeric_;
	}

	for (size_t i = numeric_.size() - 3; i < numeric_.size(); ++i) {
		if ((numeric_[i] < '0' || numeric_[i] > '9') && numeric_[i] != 'x') {
			return numeric_;
		}
	}

	if (!previousPermissions) {
		std::wstring ret = numeric_;
		size_t const size = ret.size();
		if (numeric_[size - 1] == 'x') {
			ret[size - 1] = dir ? '5' : '4';
		}
		if (numeric_[size - 2] == 'x') {
			ret[size - 2] = dir ? '5' : '4';
		}
		if (numeric_[size - 3] == 'x') {
			ret[size - 3] = dir ? '7' : '6';
		}
		// Use default of  (0...0)755 for dirs and
		// 644 for files
		for (size_t i = 0; i < size - 3; ++i) {
			if (numeric_[i] == 'x') {
				ret[i] = '0';
			}
		}
		return ret;
	}

	// 2 set, 1 unset, 0 keep

	const char defaultPerms[9] = { 2, 2, 2, 2, 1, 2, 2, 1, 2 };
	char perms[9];
	memcpy(perms, permissions_, 9);

	std::wstring permission = numeric_.substr(0, numeric_.size() - 3);
	size_t k = 0;
	for (size_t i = numeric_.size() - 3; i < numeric_.size(); ++i, ++k) {
		for (size_t j = k * 3; j < k * 3 + 3; ++j) {
			if (!perms[j]) {
				if (previousPermissions[j]) {
					perms[j] = previousPermissions[j];
				}
				else {
					perms[j] = defaultPerms[j];
				}
			}
		}
		permission += fz::to_wstring((perms[k * 3] - 1) * 4 + (perms[k * 3 + 1] - 1) * 2 + (perms[k * 3 + 2] - 1) * 1);
	}

	return permission;
}
