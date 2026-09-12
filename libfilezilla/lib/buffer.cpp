#include "libfilezilla/buffer.hpp"
#include "libfilezilla/util.hpp"

#include <algorithm>
#include <cstdlib>
#include <limits>

#include <string.h>

namespace fz {

template<buffer_wipe_policy Policy>
basic_buffer<Policy>::~basic_buffer()
{
	if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
		wipe();
	}
	delete [] data_;
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>::basic_buffer(size_t capacity)
{
	reserve(capacity);
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>::basic_buffer(std::string_view const& data)
{
	append(data);
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>::basic_buffer(basic_buffer const& buf)
{
	if (buf.size_) {
		data_ = new unsigned char[buf.capacity_];
		memcpy(data_, buf.pos_, buf.size_);
		size_ = buf.size_;
		capacity_ = buf.capacity_;
		pos_ = data_;
	}
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>::basic_buffer(basic_buffer && buf) noexcept
{
	data_ = buf.data_;
	buf.data_ = nullptr;
	pos_ = buf.pos_;
	buf.pos_ = nullptr;
	size_ = buf.size_;
	buf.size_ = 0;
	capacity_ = buf.capacity_;
	buf.capacity_ = 0;
}

template<buffer_wipe_policy Policy>
unsigned char* basic_buffer<Policy>::get(size_t write_size)
{
	if (!write_size) {
		return pos_ ? pos_ + size_ : nullptr;
	}

	if (!data_) {
		size_t const cap = std::max(size_t(1024), write_size);
		data_ = new unsigned char[cap];
		pos_ = data_;
		capacity_ = cap;
		return data_;
	}

	if (capacity_ - (pos_ - data_) - size_ < write_size) {
		size_t const free_after_compact = capacity_ - size_;
		// Note: If changing the compaction threshold, check buffer_test::test_get
		if (free_after_compact >= write_size && free_after_compact >= size_ / 2) {
			memmove(data_, pos_, size_);
			pos_ = data_;
		}
		else {
			if (std::numeric_limits<size_t>::max() - capacity_ < write_size) {
				std::abort();
			}
			size_t const cap = std::max({ size_t(1024), capacity_ * 2, capacity_ + write_size });
			unsigned char* d = new unsigned char[cap];
			if (size_) {
				memcpy(d, pos_, size_);
			}
			if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
				wipe();
			}
			delete[] data_;
			capacity_ = cap;
			data_ = d;
			pos_ = d;
		}
	}
	return pos_ + size_;
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>& basic_buffer<Policy>::operator=(basic_buffer const& buf)
{
	if (this != &buf) {
		unsigned char* d{};
		if (buf.size_) {
			d = new unsigned char[buf.capacity_];
			memcpy(d, buf.pos_, buf.size_);
		}
		if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
			wipe();
		}
		delete[] data_;
		data_ = d;
		size_ = buf.size_;
		capacity_ = data_ ? buf.capacity_ : 0;
		pos_ = data_;
	}

	return *this;
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>& basic_buffer<Policy>::operator=(std::string_view const& buf)
{
	basic_buffer ret(buf);
	*this = std::move(ret);
	return *this;
}

template<buffer_wipe_policy Policy>
basic_buffer<Policy>& basic_buffer<Policy>::operator=(basic_buffer && buf) noexcept
{
	if (this != &buf) {
		if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
			wipe();
		}
		delete[] data_;
		data_ = buf.data_;
		buf.data_ = nullptr;
		pos_ = buf.pos_;
		buf.pos_ = nullptr;
		size_ = buf.size_;
		buf.size_ = 0;
		capacity_ = buf.capacity_;
		buf.capacity_ = 0;
	}

	return *this;
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::add(size_t added)
{
	if (!added) {
		return;
	}
	if (!data_ || capacity_ - (pos_ - data_) - size_ < added) {
		// Hang, draw and quarter the caller.
		std::abort();
	}
	size_ += added;
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::consume(size_t consumed)
{
	if (consumed > size_) {
		std::abort();
	}
	if (consumed == size_) {
		pos_ = data_;
		size_ = 0;
	}
	else {
		size_ -= consumed;
		pos_ += consumed;
	}
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::clear()
{
	if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
		wipe();
	}
	size_ = 0;
	pos_ = data_;
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::clear_and_free()
{
	if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
		wipe();
	}
	delete [] data_;
	size_ = 0;
	capacity_ = 0;
	pos_ = nullptr;
	data_ = nullptr;
}

namespace {
// Stricly speaking not portable, assumes flat-address semantics.
// On platforms where this is not the case, the unit test should fail
static bool pointer_in_range(unsigned char const* p,
							 unsigned char const* first,
							 size_t len) noexcept
{
	auto const pp = reinterpret_cast<std::uintptr_t>(p);
	auto const ff = reinterpret_cast<std::uintptr_t>(first);

	return pp >= ff && pp - ff < len;
}
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(unsigned char const* data, size_t len)
{
	if (!len) {
		return;
	}

	// Do the same initially as basic_buffer<Policy>::get would do, but don't delete the old pointer
	// until after appending in case of append from own memory
	if (!data_) {
		data_ = new unsigned char[len];
		memcpy(data_, data, len);
		pos_ = data_;
		size_ = capacity_ = len;
	}
	else if (capacity_ - (pos_ - data_) - size_ < len) {
		unsigned char* old{};
		[[maybe_unused]] size_t old_capacity{};

		size_t const free_after_compact = capacity_ - size_;
		// Note: If changing the compaction threshold, check buffer_test::test_append
		if (free_after_compact >= len && free_after_compact >= size_ / 2) {
			// Also offset data in case of self-assignment
			if (pointer_in_range(data, pos_, size_)) {
				data -= pos_ - data_;
			}

			memmove(data_, pos_, size_);
			pos_ = data_;
		}
		else {
			if (std::numeric_limits<size_t>::max() - capacity_ < len) {
				std::abort();
			}
			size_t const cap = std::max({ size_t(1024), capacity_ * 2, capacity_ + len });
			unsigned char* d = new unsigned char[cap];
			if (size_) {
				memcpy(d, pos_, size_);
			}
			old = data_;
			old_capacity = capacity_;
			capacity_ = cap;
			data_ = d;
			pos_ = d;
		}
		memcpy(pos_ + size_, data, len);
		size_ += len;
		if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
			fz::wipe(old, old_capacity);
		}
		delete [] old;
	}
	else {
		memcpy(pos_ + size_, data, len);
		size_ += len;
	}
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(std::string_view const& str)
{
	append(reinterpret_cast<unsigned char const*>(str.data()), str.size());
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(std::basic_string_view<uint8_t> const& str)
{
	append(reinterpret_cast<unsigned char const*>(str.data()), str.size());
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(std::vector<uint8_t> const& data)
{
	append(reinterpret_cast<unsigned char const*>(data.data()), data.size());
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(basic_buffer<Policy> const& b)
{
	append(b.get(), b.size());
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(unsigned char v)
{
	append(&v, 1);
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::append(size_t len, unsigned char c)
{
	if (len) {
		memset(get(len), c, len);
		add(len);
	}
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::reserve(size_t capacity)
{
	if (capacity_ >= capacity) {
		return;
	}

	size_t const cap = std::max(size_t(1024), capacity);
	unsigned char* d = new unsigned char[cap];
	if (size_) {
		memcpy(d, pos_, size_);
	}
	if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
		wipe();
	}
	delete[] data_;
	data_ = d;
	capacity_ = cap;
	pos_ = data_;
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::resize(size_t size)
{
	if (!size) {
		clear();
	}
	else if (size < size_) {
		size_ = size;
	}
	else {
		size_t const diff = size - size_;
		memset(get(diff), 0, diff);
		size_ = size;
	}
}

template<buffer_wipe_policy Policy>
bool basic_buffer<Policy>::operator==(std::string_view const& rhs) const
{
	if (size() != rhs.size()) {
		return false;
	}

	if (!size()) {
		return true;
	}

	if constexpr (Policy == buffer_wipe_policy::wipe_on_release) {
		return equal_consttime(to_view(), rhs);
	}
	else {
		return memcmp(get(), rhs.data(), size()) == 0;
	}
}

template<buffer_wipe_policy Policy>
std::string_view basic_buffer<Policy>::to_view() const
{
	if (!size()) {
		return {};
	}

	return {reinterpret_cast<char const*>(get()), size()};
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::wipe()
{
	fz::wipe(data_, capacity_);
}

template<buffer_wipe_policy Policy>
void basic_buffer<Policy>::wipe_unused()
{
	if (!data_) {
		return;
	}
	size_t start = pos_ - data_;
	fz::wipe(data_, start);

	size_t stop = capacity_ - (start + size_);
	fz::wipe(pos_ + size_, stop);
}

template class basic_buffer<buffer_wipe_policy::normal>;
template class basic_buffer<buffer_wipe_policy::wipe_on_release>;

}
