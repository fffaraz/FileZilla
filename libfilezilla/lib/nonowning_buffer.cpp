#include "libfilezilla/nonowning_buffer.hpp"

#include <string.h>

namespace fz {

void nonowning_buffer::resize(size_t size)
{
	if (!size) {
		start_ = 0;
	}
	else if (size > capacity_) {
		abort();
	}
	else if (size > capacity_ - start_) {
		// If here, size_ is less than size
		memmove(buffer_, buffer_ + start_, size_);
		start_ = 0;
	}
	size_ = size;
}

uint8_t* nonowning_buffer::get(size_t bytes)
{
	if (capacity_ - size_ < bytes) {
		abort();
	}
	else if (capacity_ - size_ < bytes + start_) {
		memmove(buffer_, buffer_ + start_, size_);
		start_ = 0;
	}
	return buffer_ + start_ + size_;
}

void nonowning_buffer::add(size_t bytes)
{
	if (capacity_ - start_ - size_ < bytes) {
		abort();
	}
	size_ += bytes;
}

void nonowning_buffer::consume(size_t bytes)
{
	if (bytes > size_) {
		bytes = size_;
	}
	size_ -= bytes;
	if (!size_) {
		start_ = 0;
	}
	else {
		start_ += bytes;
	}
}

void nonowning_buffer::reset()
{
	buffer_ = nullptr;
	capacity_ = 0;
	size_ = 0;
	start_ = 0;
}

void nonowning_buffer::append(uint8_t const* data, size_t len)
{
	if (data && len) {
		memcpy(get(len), data, len);
		size_ += len;
	}
}

std::string_view nonowning_buffer::to_view() const
{
	return std::string_view(reinterpret_cast<char const*>(get()), size());
}

void nonowning_buffer::append(std::string_view const& str)
{
	return append(reinterpret_cast<uint8_t const*>(str.data()), str.size());
}
}
