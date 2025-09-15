#include "libfilezilla/file.hpp"
#include "libfilezilla/local_filesys.hpp"
#include "libfilezilla/recursive_remove.hpp"

#if FZ_WINDOWS
#include "libfilezilla/glue/dll.hpp"
#else
#include <unistd.h>
#endif

namespace fz {

bool recursive_remove::remove(const native_string& path)
{
	std::list<native_string> paths;
	paths.push_back(path);
	return remove(paths);
}

#if FZ_WINDOWS
extern "C" {
typedef int (STDAPICALLTYPE *shfileop_t)(LPSHFILEOPSTRUCTW);
}
#endif

bool recursive_remove::remove(std::list<native_string> dirsToVisit)
{
	bool success = true;

	// Under Windows use SHFileOperation to delete files and directories.
	// Under other systems, we have to recurse into subdirectories manually
	// to delete all contents.

#ifdef FZ_WINDOWS
	shdlls& dlls = shdlls::get();
	static auto const shfileop = reinterpret_cast<shfileop_t>(dlls.shell32_["SHFileOperationW"]);
	if (shfileop) {
		// SHFileOperation accepts a list of null-terminated strings. Go through all
		// paths to get the required buffer length

		size_t len = 1; // String list terminated by empty string

		for (auto const& dir : dirsToVisit) {
			len += dir.size() + 1;
		}

		// Allocate memory
		native_string::value_type* pBuffer = new native_string::value_type[len];
		native_string::value_type* p = pBuffer;

		for (auto& dir : dirsToVisit) {
			if (!dir.empty() && local_filesys::is_separator(dir.back())) {
				dir.pop_back();
			}
			if (local_filesys::get_file_type(dir) == local_filesys::unknown) {
				continue;
			}

			wcscpy(p, dir.c_str());
			p += dir.size() + 1;
		}
		if (p != pBuffer) {
			*p = 0;

			// Now we can delete the files in the buffer
			SHFILEOPSTRUCTW op{};
			op.wFunc = FO_DELETE;
			op.pFrom = pBuffer;

			adjust_shfileop(op);
			success = call_shfileop(op);
		}
		delete [] pBuffer;
		return success;
	}
#endif
	if (!confirm()) {
		return false;
	}

	for (auto& dir : dirsToVisit) {
		if (dir.size() > 1 && dir.back() == '/') {
			dir.pop_back();
		}
	}

	// Remember the directories to delete after recursing into them
	std::list<native_string> dirsToDelete;

	local_filesys fs;

	// Process all directories that have to be visited
	while (!dirsToVisit.empty()) {
		auto const iter = dirsToVisit.begin();
		native_string const& path = *iter;

		if (path.empty()) {
			dirsToVisit.erase(iter);
			continue;
		}

		if (fs.get_file_type(path) != local_filesys::dir) {
			if (!remove_file(path, false)) {
				success = false;
			}
			dirsToVisit.erase(iter);
			continue;
		}

		dirsToDelete.splice(dirsToDelete.begin(), dirsToVisit, iter);

		if (!fs.begin_find_files(path, false)) {
			continue;
		}

		// Depending on underlying platform, wxDir does not handle
		// changes to the directory contents very well.
		// See https://trac.filezilla-project.org/ticket/3482
		// To work around this, delete files after enumerating everything in current directory
		std::list<native_string> filesToDelete;

		native_string file;
		while (fs.get_next_file(file)) {
			if (file.empty()) {
				continue;
			}

			native_string const fullName = path + fzT("/") + file;

			if (local_filesys::get_file_type(fullName) == local_filesys::dir) {
				dirsToVisit.push_back(fullName);
			}
			else {
				filesToDelete.push_back(fullName);
			}
		}
		fs.end_find_files();

		// Delete all files and links in current directory enumerated before
		for (auto const& filename : filesToDelete) {
			if (!remove_file(filename, false)) {
				success = false;
			}
		}
	}

	// Delete the now empty directories
	for (auto const& dir : dirsToDelete) {
		if (!remove_dir(dir, false)) {
			success = false;
		}
	}

	return success;
}

#ifdef FZ_WINDOWS
void recursive_remove::adjust_shfileop(SHFILEOPSTRUCT & op)
{
	op.fFlags = FOF_NO_UI | FOF_ALLOWUNDO;
}

bool recursive_remove::call_shfileop(SHFILEOPSTRUCT & op)
{
	shdlls& dlls = shdlls::get();
	static auto const shfileop = reinterpret_cast<shfileop_t>(dlls.shell32_["SHFileOperationW"]);
	return shfileop && shfileop(&op) == 0;
}
#endif

}
