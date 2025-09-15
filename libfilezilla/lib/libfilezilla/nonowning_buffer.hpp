#ifndef LIBFILEZILLA_NONOWNING_BUFFER_HEADER
#define LIBFILEZILLA_NONOWNING_BUFFER_HEADER

#include "libfilezilla.hpp"

/** \file
* \brief Declares fz::nonowning_buffer
*/

namespace fz {

/**
 * \brief Similar to fz::buffer, but does not own memory.
 *
 * Needs to be created with a fixed range of memory owned elsewhere. This
 * memory range needs to remain valid for the lifetime of nonowning_buffer.
 * While nonowning_buffer can change in size, it cannot grow past the size
 * of the passed memory.
 *
 * Note that copying nonowning_buffer is shallow.
 */
class FZ_PUBLIC_SYMBOL nonowning_buffer final
{
public:
	constexpr nonowning_buffer() noexcept = default;

	explicit nonowning_buffer(uint8_t *buffer, size_t capacity) noexcept
		: buffer_(buffer)
		, capacity_(capacity)
	{
	}

	explicit nonowning_buffer(uint8_t *buffer, size_t capacity, size_t size) noexcept
		: buffer_(buffer)
		, capacity_(capacity)
		, size_(size)
	{
		if (size > capacity) {
			abort();
		}
	}

	// Copy is shallow!
	nonowning_buffer(nonowning_buffer const&) = default;
	nonowning_buffer& operator=(nonowning_buffer const&) = default;

	nonowning_buffer(nonowning_buffer &&) noexcept = default;
	nonowning_buffer& operator=(nonowning_buffer &&) noexcept = default;

	~nonowning_buffer() noexcept = default;

	size_t capacity() const { return capacity_; }
	size_t size() const { return size_; }
	bool empty() const { return size_ == 0; }
	explicit operator bool() const { return !empty(); }

	/**
	 * \brief Resizes the buffer.
	 *
	 * If growing, memory isn't cleared.
	 * Aborts if size exceeds capacity.
	 */
	void resize(size_t size);
	void clear() { resize(0); }

	/// Gets element at offset. No safety check
	uint8_t operator[](size_t offset) { return *(buffer_ + start_ + offset); }

	/// Gets buffer
	uint8_t const* get() const { return buffer_ + start_; }
	uint8_t * get() { return buffer_ + start_; }

	/** \brief Returns a writable buffer guaranteed to be large enough for write_size bytes, call add when done.
	 *
	 * The returned pointer is pointing just after the data already stored in the buffer.
	 *
	 * Calling this function does not does not affect size().
	 *
	 * Aborts if requested size is larger than capacity.
	 */
	uint8_t* get(size_t bytes);

	/**
	 * \brief Grows size by passed amount.
	 *
	 * Aborts if new size is larger than capacity.
	 */
	void add(size_t bytes);

	/** \brief Removes consumed bytes from the beginning of the buffer.
	 *
	 * Undefined if consumed > size()
	 */
	void consume(size_t bytes);

	void reset();

	void append(uint8_t const* data, size_t len);
	void append(uint8_t c) { append(&c, 1); }
	void append(std::string_view const& str);

	std::string_view to_view() const;

private:
	uint8_t* buffer_{};
	size_t capacity_{};
	size_t size_{};
	size_t start_{};
};
}

#endif
