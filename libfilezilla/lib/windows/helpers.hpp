#ifndef LIBFILEZILLA_WINDOWS_HELPERS_HEADER
#define LIBFILEZILLA_WINDOWS_HELPERS_HEADER

#include "../libfilezilla/libfilezilla.hpp"

#ifdef FZ_WINDOWS

#include "../libfilezilla/glue/windows.hpp"

#include <memory>
#include <new>

namespace fz::windows {

struct handle_closer {
	using pointer = HANDLE;

	void operator()(HANDLE h) const
	{
		if (h && h != INVALID_HANDLE_VALUE) {
			CloseHandle(h);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, handle_closer>;

template<typename T>
struct holder final
{
	holder() = default;
	~holder()
	{
		clear();
	}

	static holder create(size_t s)
	{
		holder h;
		h.v_ = reinterpret_cast<T *>(::operator new[](s, std::align_val_t(alignof(T))));
		h.size_ = s;
		h.delete_ = true;
		return h;
	}

	void clear()
	{
		if (delete_) {
			::operator delete[](reinterpret_cast<void *>(v_), std::align_val_t(alignof(T)));
		}
		size_ = 0;
		v_ = nullptr;
	}

	static holder create(void *v, bool del)
	{
		holder h;
		h.v_ = reinterpret_cast<T *>(v);
		h.size_ = v ? size_t(-1) : 0;
		h.delete_ = del;
		return h;
	}

	holder(holder &&h) noexcept
		: delete_(h.delete_)
		, v_(h.v_)
		, size_(h.size_)
	{
		h.delete_ = false;
		h.v_ = nullptr;
		h.size_ = 0;
	}

	holder &operator=(holder &&h) noexcept
	{
		if (this != &h) {
			clear();
			delete_ = h.delete_;
			v_ = h.v_;
			size_ = h.size_;
			h.delete_ = false;
			h.v_ = nullptr;
			h.size_ = 0;
		}
		return *this;
	}

	size_t size() const { return size_; }

	explicit operator bool() const { return v_ != nullptr; }

	holder(holder const &) = delete;
	holder &operator=(holder const &) = delete;

	T *get() { return v_; }
	T const *get() const { return v_; }
	T &operator*() { return *v_; }
	T *operator->() { return v_; }

private:
	bool delete_{};
	T *v_{};
	size_t size_{};
};

template<typename T>
class out_ptr_t final
{
public:
	using pointer = typename T::pointer;

	explicit out_ptr_t(T &value)
		: value_(value)
	{
		value_.reset(pointer{});
	}

	~out_ptr_t()
	{
		value_.reset(pointer_);
	}

	operator pointer *()
	{
		return &pointer_;
	}

private:
	T &value_;
	pointer pointer_{};
};

template<typename T>
out_ptr_t<T> out_ptr(T &value)
{
	return out_ptr_t<T>(value);
}

}

#endif
#endif
