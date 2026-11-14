#ifndef LIBFILEZILLA_LOCAL_FILESYS_HEADER
#define LIBFILEZILLA_LOCAL_FILESYS_HEADER

#include "fsresult.hpp"
#include "libfilezilla.hpp"
#include "time.hpp"
#include "file.hpp"

#ifdef FZ_WINDOWS
#include "glue/windows.hpp"
#else
#include <dirent.h>
#endif

/** \file
 * \brief Declares local_filesys class to enumerate local files and query their metadata such as type, size and modification time.
 */
namespace fz {

/**
 * \brief This class can be used to enumerate the contents of local directories and to query
 * the metadata of files.
 *
 * This class is aware of symbolic links. Under Windows it can handle reparse points as well.
 */
class FZ_PUBLIC_SYMBOL local_filesys final
{
public:
	local_filesys() = default;
	~local_filesys();

	local_filesys(local_filesys const&) = delete;
	local_filesys& operator=(local_filesys const&) = delete;

	local_filesys(local_filesys &&) noexcept;
	local_filesys& operator=(local_filesys &&) noexcept;

	/// Types of files. While 'everything is a file', a filename can refer to a file proper, a directory or a symbolic link.
	enum type {
		unknown = -1,
		file,
		dir,
		link
	};

	/// The system's preferred path separator
	static char const path_separator;

	/// \brief Checks whether given character is a path separator.
	///
	/// On most systems, the forward slash is the only separator. The exception is Windows where both forward and backward slashes are separators, with the latter being preferred.
	static inline bool is_separator(wchar_t c) {
#ifdef FZ_WINDOWS
		return c == '/' || c == '\\';
#else
		return c == '/';
#endif
	}

	/// \brief get_file_type return the type of the passed path.
	///
	/// Can optionally follow symbolic links.
	static type get_file_type(native_string const& path, bool follow_links = false);

	/**
	 * \brief Gets the info for the passed arguments.
	 *
	 * Follows symbolic links and stats the target by default, sets is_link to true if path was
	 * a link.
	 *
	 * The returned type can only be \c type::link if \c follow_links is \c false.
	 */
	static type get_file_info(native_string const& path, bool& is_link, int64_t* size, datetime* modification_time, int* mode, bool follow_links = true);

	/**
	 * \brief Gets the info for the passed arguments.
	 *
	 * Follows symbolic links and stats the target by default, sets is_link to true if path was
	 * a link.
	 *
	 * This overload additionally takes a \ref fz::local_filesys::type reference out parameter, which could be set to \c type::link only if \c follow_links is \c false.
	 */
	static result get_file_info(native_string const& path, bool& is_link, type& type, int64_t* size, datetime* modification_time, int* mode, bool follow_links = true);

	/// Gets size of file, returns -1 on error.
	static int64_t get_size(native_string const& path, bool *is_link = nullptr);

	/// \brief Begins enumerating a directory.
	///
	/// \param dirs_only If true, only directories are enumerated.
	result begin_find_files(native_string path, bool dirs_only = false, bool query_symlink_targets = true);

	/**
	 * \brief Begin enumerating a directory represented by a descriptor.
	 *
	 * Takes ownership of descriptor/handle.
	 */
	result begin_find_files(file::file_t fd, bool dirs_only = false, bool query_symlink_targets = true);

	/// Gets the next file in the directory. Call until it returns false.
	bool get_next_file(native_string& name);

	/**
	 * \brief Gets the next file in the directory. Call until it returns false.
	 *
	 * Stores the metadata in any non-null arguments. Follows symbolic links iff
	 * begin_find_files was called with query_symlink_targets set to true.
	 *
	 * \param is_link will be set to true iff file is a symbolic link.
	 * \param t will receive the type of file. If query_symlink_targets was set it cannot return \c type::link.
	 */
	bool get_next_file(native_string& name, bool &is_link, type & t, int64_t* size, datetime* modification_time, int* mode);

	/// Ends enumerating files. Automatically called in the destructor.
	void end_find_files();

	static datetime get_modification_time(native_string const& path);
	static result set_modification_time(native_string const& path, const datetime& t);

	/** \brief Gets the modification time of an open file or directory.
	 *
	 * The descriptor or handle is borrowed and is not closed by this function.
	 * On Windows, the handle must have FILE_READ_ATTRIBUTES access.
	 *
	 * On failure, t is unchanged and the result retains the native error code.
	 */
	static result get_modification_time(file::file_t fd, datetime& t);

	/** \brief Sets the modification time of an open file or directory.
	 *
	 * The descriptor or handle is borrowed and is not closed by this function.
	 * On Windows, the access time is also updated. If access is denied, the
	 * same object is temporarily reopened with FILE_WRITE_ATTRIBUTES access.
	 * Reopening uses the calling thread's current security context, not the
	 * identity that originally opened the handle. Callers using impersonation
	 * must invoke this function under the intended identity. Reopening can fail
	 * because of access or sharing restrictions; its native error is returned.
	 * The original handle and its file position are unchanged.
	 * On other systems, the access time is unchanged and no reopening occurs.
	 *
	 * An empty timestamp, or a Windows FILETIME with a zero high word, returns
	 * result::invalid with a raw error of zero. Operating system errors retain
	 * their native error code.
	 */
	static result set_modification_time(file::file_t fd, datetime const& t);

	/** \brief Get the immediate target path of a symbolic link.
	 * Only consideres the immediate link. Output may be be relative
	 */
	static native_string get_link_target(native_string const& path);

	/** \brief Get the final target path of a symbolic link (chain)
	 *
	 * Result is absolute.
	 */
	static native_string get_final_link_target(native_string const& path);

	/// Returns the raw descriptor/handle, but retains ownership.
	file::file_t fd();

private:
#ifdef FZ_WINDOWS
	bool FZ_PRIVATE_SYMBOL check_buffer();
	std::vector<unsigned char> buffer_;
	unsigned char* cur_{};
	HANDLE dir_{INVALID_HANDLE_VALUE};
#else
	DIR* dir_{};
#endif

	// State for directory enumeration
	bool dirs_only_{};
	bool query_symlink_targets_{true};
};

enum class mkdir_permissions
{
	/// Normal permissions, on MSW this means inheriting the parent's permissions,
	/// on *nix the current umask is applied.
	normal,

	/// Only current user
	cur_user,

	/// Only current user and administrators
	cur_user_and_admins
};

/**
 * \brief Creates directory if it doesn't yet exist.
 *
 * If current_user_only is set, the directory is created with
 * permissions so that only the current user has access, otherwise
 * the default permissions are used.
 *
 * This function only works with absolute paths.
 *
 * If the directory already exists, ok is returned last_created remains unchanged.
 *
 * \param absolute_path The directory to create
 * \param recurse If true, creation is recursive. If false, only the last segment gets
 *                created, all other components already need to exist.
 * \param permissions When creating the last component, these permissions are applied.
 *                    Does not change existing permissions or permissings of newly
 *                    created parent directories during recursive mkdir.
 * \param last_created If non-null, receives the longest sub-path that was created
 */
result FZ_PUBLIC_SYMBOL mkdir(native_string const& absolute_path, bool recurse, mkdir_permissions permissions = mkdir_permissions::normal, native_string * last_created = nullptr);

/** \brief Removes empty directory
 *
 * For recursive remove, see \ref fz::recursive_remove
 */
result FZ_PUBLIC_SYMBOL remove_dir(native_string const& absolute_path, bool missing_dir_is_error);

/// Options for \ref rename_file, combinable with operator|.
enum class rename_flags : unsigned int {
	/// Rename without copying; cross-filesystem moves return result::cross_device.
	none = 0,

	/// Allow files, but not directories, to be copied across filesystems before deleting the source.
	allow_copy = 0x1,

	/// Reject an existing destination with result::preexisting; see rename_file for atomicity limitations.
	no_replace = 0x2
};

inline bool operator&(rename_flags lhs, rename_flags rhs) {
	return (static_cast<unsigned int>(lhs) & static_cast<unsigned int>(rhs)) != 0;
}

inline rename_flags operator|(rename_flags lhs, rename_flags rhs) {
	return static_cast<rename_flags>(static_cast<unsigned int>(lhs) | static_cast<unsigned int>(rhs));
}

inline rename_flags& operator|=(rename_flags & lhs, rename_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}

/**
 * \brief Rename/move the passed file or directory
 *
 * Can rename both files and directories within the same filesystem. Can
 * optionally move files across filesystems by copying them before deleting
 * the source. Directories cannot be moved across filesystem boundaries.
 *
 * If renaming a file, the target file is overwritten unless
 * rename_flags::no_replace is specified.
 *
 * No-replace renames are atomic where a native API is available. On other
 * systems, the destination is checked before renaming, but another process
 * can create it between the check and the rename, allowing replacement.
 *
 * \param flags Options controlling copying and replacement. See \ref rename_flags.
 */
result FZ_PUBLIC_SYMBOL rename_file(native_string const& source, native_string const& dest, rename_flags flags);

/**
 * \brief Rename/move the passed file or directory
 *
 * Equivalent to the flags overload with rename_flags::allow_copy if allow_copy
 * is true, or rename_flags::none otherwise. Existing target files are overwritten.
 *
 * \param allow_copy If true, files, but not directories, can be moved across
 *                   filesystem boundaries by copying before deleting the source.
 */
result FZ_PUBLIC_SYMBOL rename_file(native_string const& source, native_string const& dest, bool allow_copy = true);

}

#endif
