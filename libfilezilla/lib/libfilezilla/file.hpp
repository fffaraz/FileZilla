#ifndef LIBFILEZILLA_FILE_HEADER
#define LIBFILEZILLA_FILE_HEADER

#include "fsresult.hpp"
#include "libfilezilla.hpp"

#ifdef FZ_WINDOWS
#include "glue/windows.hpp"
#endif

/** \file
 * \brief File handling
 */

#include <stdint.h>

namespace fz {

class datetime;

/** \brief Lean class for file access
 *
 * This class uses the system's native file access functions. It is a less convoluted and much faster alternative
 * to the almost useless std::fstream.
 *
 * Supports large files exceeding the 32bit limits.
 */
class FZ_PUBLIC_SYMBOL file final
{
public:
#ifdef FZ_WINDOWS
	typedef HANDLE file_t;
#else
	typedef int file_t;
#endif

	/// Files can be opened for reading, writing, or both
	enum mode {
		reading,
		writing,
		readwrite,
		appending,
	};

	/** \brief Creation flags when opening file for writing.
	 *
	 * Only evaluated when opening existing files for writing
	 * Non-existing files will always be created when writing,
	 * except then nocreate flag is set.
	 *
	 * Opening for reading never creates files.
	 */
	enum creation_flags {
		/// Keep existing data if file exists, otherwise create new
		existing = 0x1,

		/// Truncate file if already existing, otherwise create new
		empty = 0x2,

		/**
		 * If set and a file is created, its permissions will be so
		 * that it is only accessible by the current user.
		 *
		 * Does not modify permissions if the file already exists.
		 */
		current_user_only = 0x4,

		/**
		 * If set and a file is created, its permissions will be so
		 * that it is only accessible by the current user and
		 * the system administrators.
		 *
		 * On *nix, system adminstrators are just root. On MSW
		 * it is the built-in Administrators group.
		 *
		 * Does not modify permissions if the file already exists.
		 */
		current_user_and_admins_only = 0x8,

		/// Opening fails if the file already exists
		fresh = 0x10,

		/// Opening fails if the file does not exist
		nocreate = 0x20
	};

	file() = default;
	file(native_string const& f, mode m, creation_flags d = existing);


	/** \brief Creates file from descriptor
	 *
	 * Takes ownership of descriptor/handle.
	 */
	explicit file(file_t fd);

	~file();

	file(file const&) = delete;
	file& operator=(file const&) = delete;

	file(file && op) noexcept;
	file& operator=(file && op) noexcept;

	bool opened() const;
	explicit operator bool() const { return opened(); }

	/*
	 * \brief Opens the named file with the given mode
	 *
	 * If a (different) file was already opened, it is closed prior to opening the new file.
	 */
	result open(native_string const& f, mode m, creation_flags d = existing);

	void close();

	/// Returns the raw file descriptor, but retains ownership.
	file_t fd() {
		return fd_;
	}

	file_t detach();

	/// Used by \ref seek
	enum seek_mode {
		/// Seek from beginning of file
		begin,

		/// Seek from current position in the file
		current,

		/// Seek from end of file
		end
	};

	/** \brief Gets size of file
	 * \return Size of file or -1 on error
	 */
	int64_t size() const;

	/** \brief Relative seek based on seek mode
	 *
	 * It is possible to seek past the end of the file. Doing so does
	 * not change the size of the file. It will only change on subsequent
	 * writes.
	 *
	 * You can get the current position int the file by passing \c current
	 * as \ref seek_mode with a 0 offset.
	 *
	 * \return -1 on error, otherwise new absolute offset in file
	 * \note On failure, the new position in the file is undefined.
	 */
	int64_t seek(int64_t offset, seek_mode m);

	/** \brief Get Current position in file */
	int64_t position() { return seek(0, current); }

	/** \brief Truncate the file to the current position of the file pointer.
	 *
	 * Despite its name, this function can extend the size of the file
	 * if the current file pointer is past the end of the file.
	 */
	bool truncate();

	/** \brief Read data from file
	 *
	 * Reading from file advances the file pointer with the number of octets read.
	 *
	 * \param buf The buffer that should receive the data. Must be large enough to hold at least \c count octets
	 * \param count The number of octets to read
	 *
	 * \return >0 The number of octets read and placed into \c buf. It may be less than \c count.
	 * \return 0 at EOF
	 * \return -1 on error
	 *
	 * \note Reading less than \c count octets can happen at any time, it does not indicate EOF.
	 */
	rwresult read2(void *buf, size_t count);

	[[deprecated]]
	inline int64_t read(void *buf, int64_t count) {
		rwresult res = read2(buf, static_cast<size_t>(count));
		return res ? res.value_ : -1;
	}

	/** \brief Write data to file
	 *
	 * Writing to file advances the file pointer with the number of octets written
	 *
	 * \param buf The buffer that holds the data to be written. Must hold at least \c count octets
	 * \param count The number of octets to write
	 *
	 * \return >=0 The number of octets written to the file. It may be less than \c count.
	 * \return -1 on error
	 */
	rwresult write2(void const* buf, size_t count);

	[[deprecated]]
	inline int64_t write(void const* buf, int64_t count) {
		rwresult res = write2(buf, static_cast<size_t>(count));
		return res ? res.value_ : -1;
	}

	/** \brief Ensure data is flushed to disk
	 *
	 * \return true Data has been flushed to disk.
	 * \return false Data could not be flushed to disk.
	 */
	bool fsync();

	/** \brief Sets modification time to specified time.
	 *
	 * File must be opened for writing, of the call will fail.
	 */
	bool set_modification_time(datetime const& t);

	/** \brief Gets modification time.
	 *
	 * File must be opened for reading, or the call will fail.
	 */
	datetime get_modification_time();

private:
#ifdef FZ_WINDOWS
	HANDLE fd_{INVALID_HANDLE_VALUE};
#else
	int fd_{-1};
#endif
};

/** \brief remove the specified file.
 *
 * \return true iff the file has been removed or did not exist to begin with.
 */

/** \brief remove the specified file.
 *
 * \param missing_file_is_error If false, trying to remove a non-existing file is treated as success.
 */
result FZ_PUBLIC_SYMBOL remove_file(native_string const& name, bool missing_file_is_error);

/// \private
[[deprecated]] inline bool remove_file(native_string const& name) {
	return bool(remove_file(name, false));
}

inline file::creation_flags operator|(file::creation_flags lhs, file::creation_flags rhs) {
	return static_cast<file::creation_flags>(static_cast<std::underlying_type_t<file::creation_flags>>(lhs) | static_cast<std::underlying_type_t<file::creation_flags>>(rhs));
}
inline file::creation_flags& operator|=(file::creation_flags & lhs, file::creation_flags rhs) {
	lhs = lhs | rhs;
	return lhs;
}

/** \brief Reads the entire source file and appends if to the buffer.
 *
 * If file is larger than max_size, rwresult::nospace is returned.
 *
 * On error, the size of the output buffer remains unchanged.
 */
rwresult FZ_PUBLIC_SYMBOL read_file(fz::file & f, buffer & out, size_t max_size);

}
#endif
