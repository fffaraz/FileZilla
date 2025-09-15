#ifndef LIBFILEZILLA_LOCAL_FILESYS_HEADER
#define LIBFILEZILLA_LOCAL_FILESYS_HEADER

#include "fsresult.hpp"
#include "libfilezilla.hpp"
#include "time.hpp"

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

#if FZ_WINDOWS
	/**
	 * \brief Begin enumerating a directory represented by a HANDLE
	 *
	 * Takes ownership of the HANDLE.
	 */
	result begin_find_files(HANDLE dir, bool dirs_only = false, bool query_symlink_targets = true);
#else
	/**
	 * \brief Begin enumerating a directory represented by a file descriptor.
	 *
	 * Takes ownership of the descriptor.
	 */
	result begin_find_files(int fd, bool dirs_only = false, bool query_symlink_targets = true);
#endif

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

	/** \brief Get the immediate target path of a symbolic link.
	 * Only consideres the immediate link. Output may be be relative
	 */
	static native_string get_link_target(native_string const& path);

	/** \brief Get the final target path of a symbolic link (chain)
	 *
	 * Result is absolute.
	 */
	static native_string get_final_link_target(native_string const& path);

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

/// \private
[[deprecated]] inline result FZ_PUBLIC_SYMBOL remove_dir(native_string const& absolute_path) {
	return remove_dir(absolute_path, true);
}

/**
 * \brief Rename/move the passed file or directory
 *
 * Can rename both files and directories within same filesystem. Can
 * optionally rename files across filesystems
 *
 * If renaming a file, the target file is overwritten.
 *
 * Directories cannot be renamed/moved across differnet filesystems/mount points
 *
 * param allow_copy If true, files, but not directories, can be moved across
 *                  file system boundaries. It first copies the file before
 *                  deleting the old one.
 */
result FZ_PUBLIC_SYMBOL rename_file(native_string const& source, native_string const& dest, bool allow_copy = true);

}

#endif
