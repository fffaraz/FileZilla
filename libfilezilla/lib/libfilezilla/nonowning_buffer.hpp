#ifndef LIBFILEZILLA_NONOWNING_BUFFER_HEADER
#define LIBFILEZILLA_NONOWNING_BUFFER_HEADER

#include "buffer.hpp"

/** \file
* \brief Declares fz::nonowning_buffer
*/

namespace fz {

/**
 * \brief Read and modify buffered bytes in caller-owned storage.
 *
 * The supplied memory range must remain valid for the buffer's lifetime.
 * Capacity is fixed; requests exceeding it abort. Copies and moves are shallow.
 * Destruction leaves the supplied storage allocated and unchanged.
 */
class FZ_PUBLIC_SYMBOL nonowning_buffer final : public buffer_access_interface
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

	~nonowning_buffer() noexcept override;

	size_t capacity() const override { return capacity_; }
	size_t size() const override { return size_; }
	bool empty() const { return size_ == 0; }
	explicit operator bool() const { return !empty(); }

	/**
	 * \brief Resizes the buffer.
	 *
	 * If growing, memory isn't cleared.
	 * Aborts if size exceeds capacity.
	 */
	void resize(size_t size) override;
	void clear() override { resize(0); }

	/// Gets element at offset. No safety check
	uint8_t operator[](size_t offset) { return *(buffer_ + start_ + offset); }

	/** @name Direct access
	 * get() exposes active bytes. get(n) prepares tail space without changing size;
	 * commit the written bytes with add(n). Requests exceeding capacity abort.
	 * @{ */
	uint8_t const* get() const override { return buffer_ ? buffer_ + start_ : nullptr; }
	uint8_t * get() override { return buffer_ ? buffer_ + start_ : nullptr; }
	uint8_t* get(size_t bytes) override;
	void add(size_t bytes) override;
	/** @} */

	/** \brief Removes consumed bytes from the beginning of the buffer.
	 *
	 * Undefined if consumed > size()
	 */
	void consume(size_t bytes) override;

	void reset();

	void append(uint8_t const* data, size_t len) override;
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
