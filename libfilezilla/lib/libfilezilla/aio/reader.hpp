#ifndef LIBFILEZILLA_AIO_READER_HEADER
#define LIBFILEZILLA_AIO_READER_HEADER

/** \file
 * \brief Classes for reading data asynchronously from files.
 *
 * Also has readers to get data from strings, views and buffers.
 */

#include "aio.hpp"
#include "../file.hpp"
#include "../thread_pool.hpp"

#include <list>

namespace fz {

/** \brief Base class for all readers
 *
 * All readers have a name describing them for logging purposes.
 *
 * The initial state of a freshly opened reader is readable, get_buffer() can be called.
 *
 * See the aio demo program for example usage.
 */
class FZ_PUBLIC_SYMBOL reader_base : public aio_base, public aio_waitable, public event_handler
{
public:
	reader_base(reader_base const&) = delete;
	reader_base& operator=(reader_base const&) = delete;

	void close();

	virtual bool seekable() const { return false; }

	/// If seek fails, the reader is in an undefined state and must be closed
	bool seek(uint64_t offset, uint64_t size = nosize);

	/// Only seekable readers can be rewound.
	bool rewind();

	std::wstring const& name() const { return name_; }

	/// Size of the reader. If the size is indetermined, nosize is returned.
	virtual uint64_t size() const { return size_; }

	/// Last modification time, might be indetermined.
	virtual datetime mtime() const { return {}; }

	/** \brief Gets the next buffer with data from the reader.
	 *
	 * If it returns aio_result::ok, a buffer may be returned as well for the caller
	 * to consume. If no buffer is returned on aio_result::ok, the reader has reached eof.
	 *
	 * If aio_result::error is returned, the reader has failed and can only be closed.
	 *
	 * After getting aio_result::wait, do not call get_buffer again until after the passed
	 * waiter got on_buffer_availability() invoked.
	 */
	std::pair<aio_result, buffer_lease> get_buffer(event_handler & h);

	bool error() const;

protected:
	/**
	 * \brief Constructs a reader.
	 *
	 * The passed \c aio_buffer_pool must live longer than the reader.
	 *
	 * \c max_buffers controls the amount of buffers the reader is prepared to
	 * use at any given time. \sa reader_factory::min_buffer_usage() and
	 * \sa reader_factory::multiple_buffer_usage()
	 */
	reader_base(std::wstring && name, aio_buffer_pool & pool, size_t max_buffers) noexcept
	    : event_handler(pool.loop())
	    , buffer_pool_(pool)
	    , logger_(pool.logger())
	    , name_(name)
	    , max_buffers_(max_buffers ? max_buffers : 1)
	{}

	reader_base(std::wstring_view name, aio_buffer_pool & pool, size_t max_buffers) noexcept
	    : event_handler(pool.loop())
	    , buffer_pool_(pool)
	    , logger_(pool.logger())
	    , name_(name)
	    , max_buffers_(max_buffers ? max_buffers : 1)
	{}

	virtual std::pair<aio_result, buffer_lease> do_get_buffer(scoped_lock & l) = 0;

	/// When this gets called, buffers_ has already been cleared and the waiters have been removed.
	/// start_offset_, size_ and remaining_ have already been set.
	virtual bool do_seek(scoped_lock &) {
		return false;
	}

	virtual void do_close(scoped_lock &) {}

	virtual void operator()(event_base const&) override;
	void on_buffer_availability(aio_waitable const* w);
	virtual void do_on_buffer_availability(fz::scoped_lock & l, aio_waitable const* w) = 0;

	mutable mutex mtx_;
	aio_buffer_pool & buffer_pool_;
	logger_interface & logger_;

	std::wstring const name_;

	size_t const max_buffers_{};
	std::list<buffer_lease> buffers_;

	uint64_t size_{nosize};
	uint64_t max_size_{nosize};
	uint64_t start_offset_{nosize};
	uint64_t remaining_{nosize};

	bool get_buffer_called_{};
	bool error_{};
	bool eof_{};
	bool waiting_{};
};

/// A reader factory
class FZ_PUBLIC_SYMBOL reader_factory
{
public:
	explicit reader_factory(std::wstring const& name)
	    : name_(name)
	{}
	explicit reader_factory(std::wstring && name)
	    : name_(std::move(name))
	{}

	virtual ~reader_factory() noexcept = default;

	/// Clones the factory
	virtual std::unique_ptr<reader_factory> clone() const = 0;

	/** \brief Creates a reader
	 *
	 * The pool must live longer than the returned reader.
	 *
	 * Seekable readers can be opened at any position. If the reader is not
	 * seekable, pass an \c offset of 0 or open will fails.
	 *
	 * \c size can limit the amount of data the reader can returned. Note
	 * that a size limit that exceeds the actual size will result in
	 * reader_base::get_buffer eventually returning an error.
	 */
	virtual std::unique_ptr<reader_base> open(aio_buffer_pool & pool, uint64_t offset = 0, uint64_t size = reader_base::nosize, size_t max_buffers = 0) = 0;

	virtual bool seekable() const { return false; }

	std::wstring name() const { return name_; }

	virtual uint64_t size() const { return reader_base::nosize; }
	virtual datetime mtime() const { return datetime(); }

	/** \brief The reader requires at least this many buffers
	 *
	 * Size your buffer_pool to have a least as many buffers as the sum
	 * of min_buffer_usage() of all involved readers/writers, otherwise
	 * progress may stall due to buffer exhaustion.
	 */
	virtual size_t min_buffer_usage() const { return 1; }

	/** \brief Whether the reader can benefit from multiple buffers
	 *
	 * If false, calling \c open with \c max_buffers larger than
	 * \c min_buffer_usage() offers no benefits.
	 */
	virtual bool multiple_buffer_usage() const { return false; }

	virtual size_t preferred_buffer_count() const { return 1; }

protected:
	reader_factory() = default;
	reader_factory(reader_factory const&) = default;

	std::wstring const name_;
};

/// Holder for reader factories
class FZ_PUBLIC_SYMBOL reader_factory_holder final
{
public:
	reader_factory_holder() = default;
	reader_factory_holder(std::unique_ptr<reader_factory> && factory);
	reader_factory_holder(std::unique_ptr<reader_factory> const& factory);
	reader_factory_holder(reader_factory const& factory);

	reader_factory_holder(reader_factory_holder const& op);
	reader_factory_holder& operator=(reader_factory_holder const& op);

	reader_factory_holder(reader_factory_holder && op) noexcept;
	reader_factory_holder& operator=(reader_factory_holder && op) noexcept;
	reader_factory_holder& operator=(std::unique_ptr<reader_factory> && factory);

	reader_factory const* operator->() const { return impl_.get(); }
	reader_factory* operator->() { return impl_.get(); }
	reader_factory const& operator*() const { return *impl_; }
	reader_factory & operator*() { return *impl_; }

	explicit operator bool() const { return impl_.operator bool(); }

	std::wstring name() const { return impl_ ? impl_->name() : std::wstring(); }
	datetime mtime() const { return impl_ ? impl_->mtime() : datetime(); }
	uint64_t size() const { return impl_ ? impl_->size() : aio_base::nosize; }

private:
	std::unique_ptr<reader_factory> impl_;
};

class thread_pool;

/// Base class for threaded readers
class FZ_PUBLIC_SYMBOL threaded_reader : public reader_base
{
public:
	using reader_base::reader_base;

protected:
	virtual std::pair<aio_result, buffer_lease> do_get_buffer(scoped_lock & l) override;

	void wakeup(scoped_lock & l) {
		cond_.signal(l);
	}

	condition cond_;
	async_task task_;

	bool quit_{};
};

/// File reader
class FZ_PUBLIC_SYMBOL file_reader final : public threaded_reader
{
public:
	/** \brief Constructs file reader.
	 *
	 * The passed \c thread_pool needs to live longer than the reader.
	 */
	file_reader(std::wstring && name, aio_buffer_pool & pool, file && f, thread_pool & tpool, uint64_t offset = 0, uint64_t size = nosize, size_t max_buffers = 4) noexcept;
	file_reader(std::wstring_view name, aio_buffer_pool & pool, file && f, thread_pool & tpool, uint64_t offset = 0, uint64_t size = nosize, size_t max_buffers = 4) noexcept;

	virtual ~file_reader() noexcept;

	virtual bool seekable() const override;

private:
	virtual void FZ_PRIVATE_SYMBOL do_close(scoped_lock & l) override;
	virtual bool FZ_PRIVATE_SYMBOL do_seek(scoped_lock & l) override;

	virtual void FZ_PRIVATE_SYMBOL do_on_buffer_availability(scoped_lock & l, aio_waitable const* w) override;

	void FZ_PRIVATE_SYMBOL entry();

	file file_;
	thread_pool & thread_pool_;
};

/// Factory for \sa file_reader
class FZ_PUBLIC_SYMBOL file_reader_factory final : public reader_factory
{
public:
	file_reader_factory(std::wstring const& file, thread_pool & tpool);

	virtual std::unique_ptr<reader_base> open(aio_buffer_pool & pool, uint64_t offset = 0, uint64_t size = reader_base::nosize, size_t max_buffers = 4) override;
	virtual std::unique_ptr<reader_factory> clone() const override;

	virtual bool seekable() const override { return true; }

	virtual uint64_t size() const override;
	virtual	datetime mtime() const override;

	virtual bool multiple_buffer_usage() const override { return true; }

	virtual size_t preferred_buffer_count() const override { return 4; }
private:
	thread_pool & thread_pool_;
};

/**
 * Does not own the data, uses just one buffer.
 * The memory pointed to by the view must live longer than the reader.
 */
class FZ_PUBLIC_SYMBOL view_reader final : public reader_base
{
public:
	view_reader(std::wstring && name, aio_buffer_pool & pool, std::string_view data) noexcept;

	virtual ~view_reader() noexcept;

	virtual bool seekable() const override { return true; }

private:
	virtual std::pair<aio_result, buffer_lease> FZ_PRIVATE_SYMBOL do_get_buffer(scoped_lock & l) override;
	virtual void FZ_PRIVATE_SYMBOL do_close(scoped_lock & l) override;
	virtual bool FZ_PRIVATE_SYMBOL do_seek(scoped_lock & l) override;

	virtual void FZ_PRIVATE_SYMBOL do_on_buffer_availability(scoped_lock & l, aio_waitable const* w) override;

	std::string_view const view_;
};

/**
 * Factory for \sa view_reader.
 * The memory pointed to by view must live longer than the factory
 * or any readers derived from it
 */
class FZ_PUBLIC_SYMBOL view_reader_factory final : public reader_factory
{
public:
	view_reader_factory(std::wstring && name, std::string_view const& view)
	    : reader_factory(std::move(name))
	    , view_(view)
	{}
	view_reader_factory(std::wstring const& name, std::string_view const& view)
	    : reader_factory(name)
	    , view_(view)
	{}

	virtual std::unique_ptr<reader_base> open(aio_buffer_pool & pool, uint64_t offset = 0, uint64_t size = reader_base::nosize, size_t max_buffers = 1) override;
	virtual std::unique_ptr<reader_factory> clone() const override;

	virtual bool seekable() const override { return true; }

	virtual uint64_t size() const override { return view_.size(); }

private:
	std::string_view const view_;
};

/// String reader, keeps a copy of the string.
class FZ_PUBLIC_SYMBOL string_reader final : public reader_base
{
public:
	string_reader(std::wstring && name, aio_buffer_pool & pool, std::string const& data) noexcept;
	string_reader(std::wstring && name, aio_buffer_pool & pool, std::string && data) noexcept;

	virtual ~string_reader() noexcept;

	virtual bool seekable() const override { return true; }

private:
	virtual std::pair<aio_result, buffer_lease> FZ_PRIVATE_SYMBOL do_get_buffer(scoped_lock & l) override;
	virtual void FZ_PRIVATE_SYMBOL do_close(scoped_lock & l) override;
	virtual bool FZ_PRIVATE_SYMBOL do_seek(scoped_lock & l) override;

	virtual void FZ_PRIVATE_SYMBOL do_on_buffer_availability(scoped_lock & l, aio_waitable const* w) override;

	std::string const data_;
};

/// Factory for \sa string_reader, keeps a copy of the string.
class FZ_PUBLIC_SYMBOL string_reader_factory final : public reader_factory
{
public:
	string_reader_factory(std::wstring const& name, std::string const& data)
	    : reader_factory(name)
	    , data_(data)
	{}
	string_reader_factory(std::wstring && name, std::string && data)
	    : reader_factory(std::move(name))
	    , data_(std::move(data))
	{}

	virtual std::unique_ptr<reader_base> open(aio_buffer_pool & pool, uint64_t offset = 0, uint64_t size = reader_base::nosize, size_t max_buffers = 1) override;
	virtual std::unique_ptr<reader_factory> clone() const override;

	virtual bool seekable() const override { return true; }

	virtual uint64_t size() const override { return data_.size(); }

private:
	std::string const data_;
};

}
#endif
