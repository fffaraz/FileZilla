#ifndef LIBFILEZILLA_AIO_WRITER_HEADER
#define LIBFILEZILLA_AIO_WRITER_HEADER

/** \file
 * \brief Classes for writing data asynchronously into files.
 *
 * Also has a writer for accumulating data into a buffer.
 */

#include "aio.hpp"
#include "../buffer.hpp"
#include "../file.hpp"
#include "../thread_pool.hpp"

#include <list>

namespace fz {

/** \brief Base class for all writers
 *
 * All writers have a name describing them for logging purposes.
 *
 * The initial state of a freshly opened writer is writable, add_buffer() can be called.
 *
 * See the aio demo program for example usage.
 */
class FZ_PUBLIC_SYMBOL writer_base : public aio_base, public aio_waitable
{
public:
	writer_base(writer_base const&) = delete;
	writer_base& operator=(writer_base const&) = delete;

	/// Instructs writer to preallocate storage. May be a noop.
	virtual aio_result preallocate(uint64_t /*size*/) { return aio_result::ok; }

	/** \brief Pass a buffer to be written out
	 *
	 * If aio_result::ok is returned, you can call add_buffer again.
	 *
	 * If aio_result::wait is returned, do not call add_buffer again until
	 * after the passed waiter got on_buffer_availability() invoked.
	 *
	 * If aio_result::error is returned, the writer has failed and can only
	 * be closed.
	 */
	aio_result add_buffer(buffer_lease && b, event_handler & h);

	/** \brief Finalizes the writer
	 *
	 * If aio_result::ok is returned, all pending data has been written out.
	 *
	 * If aio_result::wait is returned, wait until the passed waiter gets
	 * on_buffer_availability() invoked, then call finalize again.
	 *
	 * If aio_result::error is returned, the writer has failed and can only
	 * be closed.
	 */
	aio_result finalize(event_handler & h);

	/// Must be finalized already
	virtual bool set_mtime(datetime const&) { return false; }

	void close();

	/**
	 * Progress callback is only for accounting progress. Never call into
	 * the writer from the callback.
	 *
	 * The progress callback is invoked whenever the writer has written out
	 * some data.
	 *
	 * Idiomatic usage of the the progress callback:
	 *   Update some atomic variables and optionally send an event.
	 */
	using progress_cb_t = std::function<void(writer_base const*, uint64_t written)>;

protected:
	virtual aio_result do_add_buffer(scoped_lock & l, buffer_lease && b) = 0;
	virtual aio_result do_finalize(scoped_lock & l) = 0;

	writer_base(std::wstring && name, aio_buffer_pool & pool, progress_cb_t && progress_cb, size_t max_buffers) noexcept
	    : buffer_pool_(pool)
	    , name_(name)
	    , progress_cb_(std::move(progress_cb))
	    , max_buffers_(max_buffers ? max_buffers : 1)
	{}

	writer_base(std::wstring_view name, aio_buffer_pool & pool, progress_cb_t && progress_cb, size_t max_buffers) noexcept
	    : buffer_pool_(pool)
	    , name_(name)
	    , progress_cb_(std::move(progress_cb))
	    , max_buffers_(max_buffers ? max_buffers : 1)
	{}

	virtual void do_close(scoped_lock &) {}

	mutex mtx_;
	aio_buffer_pool & buffer_pool_;

	std::wstring const name_;

	progress_cb_t progress_cb_;

	size_t const max_buffers_{};
	std::list<buffer_lease> buffers_;

	bool error_{};
	uint8_t finalizing_{};
};

/// A writer factory
class FZ_PUBLIC_SYMBOL writer_factory
{
public:
	explicit writer_factory(std::wstring const& name)
	    : name_(name)
	{}
	explicit writer_factory(std::wstring && name)
	    : name_(std::move(name))
	{}

	virtual ~writer_factory() noexcept = default;

	/// Clones the factory
	virtual std::unique_ptr<writer_factory> clone() const = 0;

	/** \brief Creates a writer
	 *
	 * The pool must live longer than the returned writer.
	 *
	 * Offsetable writers can be opened at any position. If the writer is not
	 * seekable, pass an \c offset of 0 or open will fail.
	 */
	virtual std::unique_ptr<writer_base> open(aio_buffer_pool & pool, uint64_t offset = 0, writer_base::progress_cb_t progress_cb = nullptr, size_t max_buffers = 0) = 0;

	std::wstring const& name() const { return name_; }

	/// If true, writer can be opened from any position, not just the beginning, such as file_writer
	virtual bool offsetable() const { return false; }

	/// Some writers, e.g. for files, may have a pre-existing size
	virtual uint64_t size() const { return writer_base::nosize; }
	virtual datetime mtime() const { return datetime(); }

	/// The writer requires at least this many buffers
	virtual size_t min_buffer_usage() const { return 1; }

	/// Whether the writer can benefit from multiple buffers
	virtual bool multiple_buffer_usage() const { return false; }

	virtual size_t preferred_buffer_count() const { return 1; }

	/** \brief Sets the mtime of the target.
	 *
	 * If there are still writers open for the entity represented by the
	 * factory, the mtime might change again as the writers are closed.
	 */
	virtual bool set_mtime(datetime const&) { return false; }
protected:
	writer_factory() = default;
	writer_factory(writer_factory const&) = default;

private:
	std::wstring const name_;
};

class FZ_PUBLIC_SYMBOL writer_factory_holder final
{
public:
	writer_factory_holder() = default;
	writer_factory_holder(std::unique_ptr<writer_factory> && factory);
	writer_factory_holder(std::unique_ptr<writer_factory> const& factory);
	writer_factory_holder(writer_factory const& factory);

	writer_factory_holder(writer_factory_holder const& op);
	writer_factory_holder& operator=(writer_factory_holder const& op);

	writer_factory_holder(writer_factory_holder && op) noexcept;
	writer_factory_holder& operator=(writer_factory_holder && op) noexcept;
	writer_factory_holder& operator=(std::unique_ptr<writer_factory> && factory);

	writer_factory const* operator->() const { return impl_.get(); }
	writer_factory* operator->() { return impl_.get(); }
	writer_factory const& operator*() const { return *impl_; }
	writer_factory & operator*() { return *impl_; }

	explicit operator bool() const { return impl_.operator bool(); }

	std::wstring name() const { return impl_ ? impl_->name() : std::wstring(); }
	datetime mtime() const { return impl_ ? impl_->mtime() : datetime(); }
	uint64_t size() const { return impl_ ? impl_->size() : aio_base::nosize; }

private:
	std::unique_ptr<writer_factory> impl_;
};



class thread_pool;

/// Base class for threaded writer
class FZ_PUBLIC_SYMBOL threaded_writer : public writer_base
{
public:
	using writer_base::writer_base;

protected:
	virtual aio_result do_add_buffer(scoped_lock & l, buffer_lease && b) override;
	virtual aio_result do_finalize(scoped_lock & l) override;
	void wakeup(scoped_lock & l) {
		cond_.signal(l);
	}

	virtual void do_close(scoped_lock & l) override;

	virtual aio_result continue_finalize(scoped_lock &) {
		return aio_result::ok;
	}

	condition cond_;
	async_task task_;

	bool quit_{};
};

/// File writer
class FZ_PUBLIC_SYMBOL file_writer final : public threaded_writer
{
public:
	file_writer(std::wstring && name, aio_buffer_pool & pool, file && f, thread_pool & tpool, bool fsync = false, progress_cb_t && progress_cb = nullptr, size_t max_buffers = 4) noexcept;
	file_writer(std::wstring_view name, aio_buffer_pool & pool, file && f, thread_pool & tpool, bool fsync = false, progress_cb_t && progress_cb = nullptr, size_t max_buffers = 4) noexcept;

	virtual ~file_writer() override;

	virtual aio_result preallocate(uint64_t size) override;

	virtual bool set_mtime(datetime const&) override;

private:
	virtual void FZ_PRIVATE_SYMBOL do_close(scoped_lock & l) override;
	virtual aio_result FZ_PRIVATE_SYMBOL continue_finalize(scoped_lock & l) override;

	void FZ_PRIVATE_SYMBOL entry();

	file file_;

	bool fsync_{};
	bool preallocated_{};
};

enum class file_writer_flags : unsigned {
	fsync = 0x01,
	permissions_current_user_only = 0x02,
	permissions_current_user_and_admins_only = 0x04
};
inline bool operator&(file_writer_flags lhs, file_writer_flags rhs) {
	return (static_cast<std::underlying_type_t<file_writer_flags>>(lhs) & static_cast<std::underlying_type_t<file_writer_flags>>(rhs)) != 0;
}
inline file_writer_flags operator|(file_writer_flags lhs, file_writer_flags rhs) {
	return static_cast<file_writer_flags>(static_cast<std::underlying_type_t<file_writer_flags>>(lhs) | static_cast<std::underlying_type_t<file_writer_flags>>(rhs));
}

/// Factory for \sa file_writer
class FZ_PUBLIC_SYMBOL file_writer_factory final : public writer_factory
{
public:
	file_writer_factory(std::wstring const& file, thread_pool & tpool, file_writer_flags = {});

	virtual std::unique_ptr<writer_base> open(aio_buffer_pool & pool, uint64_t offset, writer_base::progress_cb_t progress_cb = nullptr, size_t max_buffers = 0) override;
	virtual std::unique_ptr<writer_factory> clone() const override;

	virtual bool offsetable() const override { return true; }

	virtual uint64_t size() const override;
	virtual	datetime mtime() const override;

	virtual bool set_mtime(datetime const& t) override;

	virtual bool multiple_buffer_usage() const override { return true; }

	virtual size_t preferred_buffer_count() const override { return 4; }

private:
	thread_pool & thread_pool_;
	file_writer_flags flags_{};
};

/** A simple buffer writer.
 *
 * The buffer must live longer than the writer. Note that there is no
 * synchronization. Never open two writers for the same buffer in different
 * threads, or access the buffer from any other thread while there is a writer.
 */
class FZ_PUBLIC_SYMBOL buffer_writer final : public writer_base
{
public:
	buffer_writer(buffer & buffer, std::wstring const& name, aio_buffer_pool & pool, size_t size_limit, progress_cb_t && progress_cb = nullptr);

	virtual aio_result preallocate(uint64_t size) override;

private:
	virtual aio_result FZ_PRIVATE_SYMBOL do_add_buffer(scoped_lock & l, buffer_lease && b) override;
	virtual aio_result FZ_PRIVATE_SYMBOL do_finalize(scoped_lock &) override { return error_ ? aio_result::error : aio_result::ok; }

	buffer & buffer_;
	size_t size_limit_{};
};

/** Factory for buffer_writer.
 *
 * The buffer must live longer than the writer. Note that there is no
 * synchronization. Never open two writers for the same buffer in different
 * threads, or access the buffer from any other thread while there is a writer.
 */
class FZ_PUBLIC_SYMBOL buffer_writer_factory final : public writer_factory
{
public:
	buffer_writer_factory(buffer & b, std::wstring const& name, size_t size_limit);

	virtual std::unique_ptr<writer_base> open(aio_buffer_pool & pool, uint64_t offset, writer_base::progress_cb_t progress_cb = nullptr, size_t max_buffers = 0) override;
	virtual std::unique_ptr<writer_factory> clone() const override;

private:
	buffer & buffer_;
	size_t size_limit_{};
};

}

#endif
