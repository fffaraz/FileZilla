#ifndef FILEZILLA_COMMONUI_CHMOD_DATA_HEADER
#define FILEZILLA_COMMONUI_CHMOD_DATA_HEADER

#include "visibility.h"
#include <string>

class FZCUI_PUBLIC_SYMBOL ChmodData
{
public:
	int GetApplyType() const { return applyType_; }

	// Converts permission string into a series of chars
	// The permissions parameter has to be able to hold at least
	// 9 characters.
	// Example:
	//   drwxr--r-- gets converted into 222211211
	//   0644 gets converted into 221211211
	//   foo (0273) gets converted into 121222122
	static bool ConvertPermissions(std::wstring const& rwx, char* permissions);

	std::wstring GetPermissions(const char* previousPermissions, bool dir);

	int applyType_{};
	std::wstring numeric_;
	char permissions_[9]{};

private:
	static bool FZCUI_PRIVATE_SYMBOL DoConvertPermissions(std::wstring const& rwx, char* permissions);
};

#endif
