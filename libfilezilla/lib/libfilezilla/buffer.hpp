#ifndef LIBFILEZILLA_BUFFER_HEADER
#define LIBFILEZILLA_BUFFER_HEADER

#include "libfilezilla.hpp"

#include <vector>
#include <type_traits>

/** \file
* \brief Declares fz::buffer
*/

namespace fz {

/// \private
enum class buffer_wipe_policy {
	normal,
	wipe_on_release
};

/** \brief Read and modify a contiguous sequence of buffered bytes.
 *
 * Preparing space, appending, or resizing can move the data and invalidate
 * pointers.
 */
class FZ_PUBLIC_SYMBOL buffer_access_interface
{
public:
	virtual ~buffer_access_interface();

	/** @name Direct access
	 * get() exposes the active bytes. get(n) prepares space after them without
	 * changing size(); fill that space, then commit it with add(n).
	 * @{ */
	virtual unsigned char const* get() const = 0;
	virtual unsigned char* get() = 0;
	virtual unsigned char* get(size_t write_size) = 0;
	virtual void add(size_t added) = 0;
	/** @} */

	/** @name Contents and extent
	 * consume(n) requires n <= size(). clear() retains storage. capacity() includes
	 * consumed space that can be reclaimed. Initialize bytes exposed by resize()
	 * before reading them.
	 * @{ */
	virtual void consume(size_t consumed) = 0;
	virtual size_t size() const = 0;
	virtual void clear() = 0;
	virtual void append(unsigned char const* data, size_t len) = 0;
	virtual size_t capacity() const = 0;
	virtual void resize(size_t size) = 0;
	/** @} */

protected:
	buffer_access_interface() = default;
	// Concrete buffers may copy their state, but callers cannot assign via this base.
	buffer_access_interface(buffer_access_interface const&) = default;
	buffer_access_interface& operator=(buffer_access_interface const&) = default;
};

/** \brief Manage buffered bytes in growable, owned storage. */
class FZ_PUBLIC_SYMBOL buffer_interface : public buffer_access_interface
{
public:
	~buffer_interface() override;

	/** @name Allocation management
	 * reserve(n) ensures at least n bytes of total capacity, preserving contents
	 * and size. clear_and_free() releases storage according to its wiping policy.
	 * @{ */
	virtual void reserve(size_t capacity) = 0;
	virtual void clear_and_free() = 0;
	/** @} */

protected:
	buffer_interface() = default;
	buffer_interface(buffer_interface const&) = default;
	buffer_interface& operator=(buffer_interface const&) = default;
};

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
template<buffer_wipe_policy Policy>
class basic_buffer
{
public:
	using value_type = unsigned char;

	basic_buffer() noexcept = default;

	/// Initially reserves the passed capacity
	explicit basic_buffer(size_t capacity);

	explicit basic_buffer(std::string_view const& data);

	basic_buffer(basic_buffer const& buf);
	basic_buffer(basic_buffer && buf) noexcept;

	basic_buffer& operator=(basic_buffer const& buf);
	basic_buffer& operator=(basic_buffer && buf) noexcept;

	basic_buffer& operator=(std::string_view const& v);

	~basic_buffer();

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

	void clear_and_free();

	/** \brief Appends the passed data to the buffer.
	 *
	 * The number of reallocations as result to repeated append are amortized O(1)
	 */
	void append(unsigned char const* data, size_t len);
	void append(std::string_view const& str);
	void append(std::basic_string_view<uint8_t> const& data);
	void append(std::vector<uint8_t> const& data);
	void append(basic_buffer const& b);
	void append(unsigned char v);
	void append(size_t len, unsigned char c);

	void push_back(unsigned char v) {
		return append(v);
	}

	basic_buffer& operator+=(unsigned char v) {
		append(v);
		return *this;
	}
	basic_buffer& operator+=(std::string_view const& str) {
		append(str);
		return *this;
	}
	basic_buffer& operator+=(std::vector<uint8_t> const& data) {
		append(data);
		return *this;
	}
	basic_buffer& operator+=(basic_buffer const& b) {
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

	bool operator==(basic_buffer const& rhs) const {
		return *this == rhs.to_view();
	}

	bool operator==(std::string_view const& rhs) const;

	bool operator!=(basic_buffer const& rhs) const {
		return !(*this == rhs);
	}
	bool operator!=(std::string_view const& rhs) const {
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

#if BUILDING_LIBFILEZILLA
extern template class FZ_PUBLIC_SYMBOL basic_buffer<buffer_wipe_policy::normal>;
extern template class FZ_PUBLIC_SYMBOL basic_buffer<buffer_wipe_policy::wipe_on_release>;
#endif

namespace buffer_detail {

// The storage engine is non-polymorphic, keeping calls between its operations
// direct. This layer supplies virtual dispatch for external callers and shares
// the forwarding API across storage policies.
//
// Forwarders stay in the header so concrete calls can inline them. Virtual
// destructors are defined in buffer.cpp to anchor vtables outside client code.
template<buffer_wipe_policy Policy>
class owning_buffer : public buffer_interface
{
public:
	using value_type = unsigned char;

	owning_buffer() noexcept = default;
	explicit owning_buffer(size_t capacity) : storage_(capacity) {}
	explicit owning_buffer(std::string_view const& data) : storage_(data) {}
	owning_buffer(owning_buffer const&) = default;
	owning_buffer(owning_buffer&&) noexcept = default;
	owning_buffer& operator=(owning_buffer const&) = default;
	owning_buffer& operator=(owning_buffer&&) noexcept = default;

	owning_buffer& operator=(std::string_view const& data) {
		storage_ = data;
		return *this;
	}

	unsigned char const* get() const override { return storage_.get(); }
	unsigned char* get() override { return storage_.get(); }
	unsigned char* get(size_t size) override { return storage_.get(size); }
	unsigned char* data() { return storage_.data(); }
	unsigned char const* data() const { return storage_.data(); }
	void add(size_t size) override { storage_.add(size); }

	template<typename T, std::enable_if_t<std::is_signed_v<T>, int> = 0>
	void add(T size) { storage_.add(size); }

	void consume(size_t size) override { storage_.consume(size); }
	size_t size() const override { return storage_.size(); }
	bool empty() const { return storage_.empty(); }
	explicit operator bool() const { return bool(storage_); }
	size_t capacity() const override { return storage_.capacity(); }
	void reserve(size_t capacity) override { storage_.reserve(capacity); }
	void resize(size_t size) override { storage_.resize(size); }
	void clear() override { storage_.clear(); }
	void clear_and_free() override { storage_.clear_and_free(); }
	void append(unsigned char const* data, size_t size) override { storage_.append(data, size); }
	void append(std::string_view const& data) { storage_.append(data); }
	void append(std::basic_string_view<uint8_t> const& data) { storage_.append(data); }
	void append(std::vector<uint8_t> const& data) { storage_.append(data); }
	void append(owning_buffer const& data) { storage_.append(data.storage_); }
	void append(unsigned char value) { storage_.append(value); }
	void append(size_t size, unsigned char value) { storage_.append(size, value); }
	void push_back(unsigned char value) { storage_.push_back(value); }

	owning_buffer& operator+=(unsigned char value) {
		storage_ += value;
		return *this;
	}

	owning_buffer& operator+=(std::string_view const& data) {
		storage_ += data;
		return *this;
	}

	owning_buffer& operator+=(std::vector<uint8_t> const& data) {
		storage_ += data;
		return *this;
	}

	owning_buffer& operator+=(owning_buffer const& data) {
		storage_ += data.storage_;
		return *this;
	}

	unsigned char operator[](size_t i) const { return storage_[i]; }
	unsigned char& operator[](size_t i) { return storage_[i]; }
	bool operator==(owning_buffer const& rhs) const { return storage_ == rhs.storage_; }
	bool operator==(std::string_view const& rhs) const { return storage_ == rhs; }
	bool operator!=(owning_buffer const& rhs) const { return storage_ != rhs.storage_; }
	bool operator!=(std::string_view const& rhs) const { return storage_ != rhs; }
	std::string_view to_view() const { return storage_.to_view(); }
	void wipe() { storage_.wipe(); }
	void wipe_unused() { storage_.wipe_unused(); }

protected:
	~owning_buffer() override;

private:
	basic_buffer<Policy> storage_;
};

}

// Consumers instantiate header-defined forwarders when they cannot inline them.
#if BUILDING_LIBFILEZILLA
extern template class FZ_PUBLIC_SYMBOL buffer_detail::owning_buffer<buffer_wipe_policy::normal>;
extern template class FZ_PUBLIC_SYMBOL buffer_detail::owning_buffer<buffer_wipe_policy::wipe_on_release>;
#endif

// An out-of-line destructor suppresses implicit moves. Keep them explicit so
// moving either concrete buffer still transfers ownership instead of copying.
class FZ_PUBLIC_SYMBOL buffer final : public buffer_detail::owning_buffer<buffer_wipe_policy::normal>
{
public:
	using owning_buffer::owning_buffer;
	using owning_buffer::operator=;
	buffer() noexcept = default;
	buffer(buffer const&) = default;
	buffer(buffer&&) noexcept = default;
	buffer& operator=(buffer const&) = default;
	buffer& operator=(buffer&&) noexcept = default;
	~buffer() override;
};

/// Just like buffer, but zeros memory when released or the secure_buffer is cleared.
/// In addition, comparison is constant-time if operands have equal size
class FZ_PUBLIC_SYMBOL secure_buffer final : public buffer_detail::owning_buffer<buffer_wipe_policy::wipe_on_release>
{
public:
	using owning_buffer::owning_buffer;
	using owning_buffer::operator=;
	secure_buffer() noexcept = default;
	secure_buffer(secure_buffer const&) = default;
	secure_buffer(secure_buffer&&) noexcept = default;
	secure_buffer& operator=(secure_buffer const&) = default;
	secure_buffer& operator=(secure_buffer&&) noexcept = default;
	~secure_buffer() override;
};

inline void wipe(buffer & b) {
	b.wipe();
}

inline void wipe_unused(buffer & b) {
	b.wipe_unused();
}

inline void wipe(secure_buffer & b) {
	b.wipe();
}

inline void wipe_unused(secure_buffer & b) {
	b.wipe_unused();
}

}

#endif
