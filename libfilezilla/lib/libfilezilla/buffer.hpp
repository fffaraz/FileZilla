#ifndef LIBFILEZILLA_BUFFER_HEADER
#define LIBFILEZILLA_BUFFER_HEADER

#include "libfilezilla.hpp"

#include <vector>
#include <type_traits>

/** \file
* \brief Declares fz::buffer
*/

namespace fz {

/**
 * \brief The buffer class is a simple buffer where data can be appended at the end and consumed at the front.
 * Think of it as a deque with contiguous storage.
 *
 * This class is useful when buffering data for sending over the network, or for buffering data for further
 * piecemeal processing after having received it.
 *
 * In general, copying/moving data around is expensive and allocations are even more expensive. Using this
 * class helps to limit both to the bare minimum.
 *
 */
class FZ_PUBLIC_SYMBOL buffer final
{
public:
	typedef unsigned char value_type;

	buffer() noexcept = default;

	/// Initially reserves the passed capacity
	explicit buffer(size_t capacity);

	buffer(buffer const& buf);
	buffer(buffer && buf) noexcept;

	~buffer() { delete[] data_; }

	buffer& operator=(buffer const& buf);
	buffer& operator=(buffer && buf) noexcept;

	/// Undefined if buffer is empty
	unsigned char const* get() const { return pos_; }
	unsigned char* get() { return pos_; }

	/// Same as get()
	unsigned char* data() { return pos_; }
	unsigned char const* data() const { return pos_; }

	/** \brief Returns a writable buffer guaranteed to be large enough for write_size bytes, call add when done.
	 *
	 * The returned pointer is pointing just after the data already stored in the buffer.
	 *
	 * Calling this function does not does not affect size().
	 *
	 * \sa append
	 *
	 * \par Example:
	 * \code
	 * fz::buffer buf;
	 * size_t to_read = 44;
	 * int read = recv(fd, buf.get(to_read), to_read, 0); // Read stuff from some socket
	 * if (read > 0)
	 *     buf.add(read); // Adjust size with the amount actually written into the buffer
	 * \endcode
	 *
	 */
	unsigned char* get(size_t write_size);

	/// Increase size by the passed amount. Call this after having obtained a writable buffer with get(size_t write_size)
	void add(size_t added);

	/**
	 * \brief Overload of add for signed types, only adds if value is positive.
	 *
	 * Does nothing on values <= 0, useful for directly passing the ssize_t result of
	 * the system's recv() or read() functions.
	 */
	template<typename T, std::enable_if_t<std::is_signed_v<T>, int> = 0>
	void add(T added) {
		if (added > 0) {
			add(static_cast<size_t>(added));
		}
	}

	/** \brief Removes consumed bytes from the beginning of the buffer.
	 *
	 * Undefined if consumed > size()
	 */
	void consume(size_t consumed);

	size_t size() const { return size_; }

	/**
	 * Does not release the memory.
	 */
	void clear();

	/** \brief Appends the passed data to the buffer.
	 *
	 * The number of reallocations as result to repeated append are amortized O(1)
	 */
	void append(unsigned char const* data, size_t len);
	void append(std::string_view const& str);
	void append(std::basic_string_view<uint8_t> const& data);
	void append(std::vector<uint8_t> const& data);
	void append(fz::buffer const& b);
	void append(unsigned char v);
	void append(size_t len, unsigned char c);

	buffer& operator+=(unsigned char v) {
		append(v);
		return *this;
	}
	buffer& operator+=(std::string_view const& str) {
		append(str);
		return *this;
	}
	buffer& operator+=(std::vector<uint8_t> const& data) {
		append(data);
		return *this;
	}
	buffer& operator+=(fz::buffer const& b) {
		append(b);
		return *this;
	}

	bool empty() const { return size_ == 0; }
	explicit operator bool() const {
		return size_ != 0;
	}

	size_t capacity() const { return capacity_; }
	void reserve(size_t capacity);

	void resize(size_t size);

	/// Gets element at offset i. Does not do bounds checking
	unsigned char operator[](size_t i) const { return pos_[i]; }
	unsigned char & operator[](size_t i) { return pos_[i]; }

	bool operator==(buffer const& rhs) const;

	bool operator!=(buffer const& rhs) const {
		return !(*this == rhs);
	}

	std::string_view to_view() const;

	void wipe();
	void wipe_unused();

private:

	// Invariants:
	//   size_ <= capacity_
	//   data_ <= pos_
	//   pos_ <= data_ + capacity_
	//   pos_ + size_ <= data_ + capacity_
	unsigned char* data_{};
	unsigned char* pos_{};
	size_t size_{};
	size_t capacity_{};
};

inline void FZ_PUBLIC_SYMBOL wipe(buffer & b) {
	b.wipe();
}

inline void FZ_PUBLIC_SYMBOL wipe_unused(buffer & b) {
	b.wipe_unused();
}

}

#endif
