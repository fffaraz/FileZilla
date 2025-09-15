#include "../libfilezilla/aio/writer.hpp"
#include "../libfilezilla/buffer.hpp"
#include "../libfilezilla/local_filesys.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/translate.hpp"

namespace fz {

void writer_base::close()
{
	scoped_lock l(mtx_);
	do_close(l);
	remove_waiters();
	buffers_.clear();
}

aio_result writer_base::add_buffer(buffer_lease && buffer, event_handler & h)
{
	scoped_lock l(mtx_);
	if (error_) {
		return aio_result::error;
	}
	if (!buffer || !*buffer) {
		return aio_result::ok;
	}
	auto r = do_add_buffer(l, std::move(buffer));
	if (r == aio_result::wait) {
		add_waiter(h);
	}
	return r;
}

aio_result writer_base::finalize(event_handler & h)
{
	scoped_lock l(mtx_);
	auto r = do_finalize(l);
	if (r == aio_result::wait) {
		add_waiter(h);
	}
	return r;
}


writer_factory_holder::writer_factory_holder(writer_factory_holder const& op)
{
	if (op.impl_) {
		impl_ = op.impl_->clone();
	}
}

writer_factory_holder& writer_factory_holder::operator=(writer_factory_holder const& op)
{
	if (this != &op && op.impl_) {
		impl_ = op.impl_->clone();
	}
	return *this;
}

writer_factory_holder::writer_factory_holder(writer_factory_holder && op) noexcept
{
	impl_ = std::move(op.impl_);
	op.impl_.reset();
}

writer_factory_holder& writer_factory_holder::operator=(writer_factory_holder && op) noexcept
{
	if (this != &op) {
		impl_ = std::move(op.impl_);
		op.impl_.reset();
	}

	return *this;
}

writer_factory_holder::writer_factory_holder(std::unique_ptr<writer_factory> && factory)
	: impl_(std::move(factory))
{
}

writer_factory_holder::writer_factory_holder(std::unique_ptr<writer_factory> const& factory)
	: impl_(factory ? factory->clone() : nullptr)
{
}

writer_factory_holder& writer_factory_holder::operator=(std::unique_ptr<writer_factory> && factory)
{
	if (impl_ != factory) {
		impl_ = std::move(factory);
	}

	return *this;
}

writer_factory_holder::writer_factory_holder(writer_factory const& factory)
	: impl_(factory.clone())
{
}


aio_result threaded_writer::do_add_buffer(scoped_lock & l, buffer_lease && b)
{
	buffers_.emplace_back(std::move(b));

	if (buffers_.size() == 1) {
		wakeup(l);
	}

	if (buffers_.size() >= max_buffers_) {
		return aio_result::wait;
	}
	else {
		return aio_result::ok;
	}
}

aio_result threaded_writer::do_finalize(scoped_lock & l)
{
	if (error_) {
		return aio_result::error;
	}
	if (finalizing_ == 2) {
		return aio_result::ok;
	}
	finalizing_ = 1;
	return continue_finalize(l);
}

aio_result file_writer::continue_finalize(scoped_lock & l)
{
	if (!file_) {
		error_ = true;
		return aio_result::error;
	}

	if (fsync_ && buffers_.empty()) {
		wakeup(l);
	}
	if (!buffers_.empty() || fsync_) {
		return aio_result::wait;
	}
	return aio_result::ok;
}

void threaded_writer::do_close(scoped_lock & l)
{
	quit_ = true;
	cond_.signal(l);
	l.unlock();
	task_.join();
	l.lock();
}

file_writer::file_writer(std::wstring && name, aio_buffer_pool & pool, file && f, thread_pool & tpool, bool fsync, progress_cb_t && progress_cb, size_t max_buffers) noexcept
	: threaded_writer(name, pool, std::move(progress_cb), max_buffers)
    , file_(std::move(f))
	, fsync_(fsync)
{
	if (file_) {
		task_ = tpool.spawn([this]{ entry(); });
	}
	if (!file_ || !task_) {
		file_.close();
		error_ = true;
	}
}

file_writer::file_writer(std::wstring_view name, aio_buffer_pool & pool, file && f, thread_pool & tpool, bool fsync, progress_cb_t && progress_cb, size_t max_buffers) noexcept
	: threaded_writer(name, pool, std::move(progress_cb), max_buffers)
    , file_(std::move(f))
	, fsync_(fsync)
{
	if (file_) {
		task_ = tpool.spawn([this]{ entry(); });
	}
	if (!file_ || !task_) {
		file_.close();
		error_ = true;
	}
}

file_writer::~file_writer()
{
	close();
}

void file_writer::do_close(scoped_lock & l)
{
	threaded_writer::do_close(l);
	if (file_) {
		bool remove{};
		if (!finalizing_&& !file_.position()) {
			// Freshly created file to which nothing has been written.
			remove = true;
		}
		else if (preallocated_) {
			// The file might have been preallocated and the writing stopped before being completed,
			// so always truncate the file before closing it regardless of finalize state.
			file_.truncate();
		}
		file_.close();

		if (remove) {
			buffer_pool_.logger().log(logmsg::debug_verbose, L"Deleting empty file '%s'", name_);
			remove_file(to_native(name_), false);
		}
	}
}

void file_writer::entry()
{
	scoped_lock l(mtx_);
	while (!quit_ && !error_) {
		if (buffers_.empty()) {
			if (finalizing_ == 1) {
				finalizing_ = 2;
				if (fsync_) {
					if (!file_.fsync()) {
						buffer_pool_.logger().log(logmsg::error, fztranslate("Could not sync '%s' to disk."), name_);
						error_ = true;
					}
				}

				signal_availibility();
				break;
			}
			cond_.wait(l);
			continue;
		}
		auto & b = buffers_.front();
		while (!b->empty()) {
			l.unlock();
			rwresult written = file_.write2(b->get(), b->size());
			l.lock();
			if (quit_ || error_) {
				return;
			}
			if (!written || !written.value_) {
				error_ = true;
				return;
			}
			b->consume(static_cast<size_t>(written.value_));
			if (progress_cb_) {
				progress_cb_(this, static_cast<uint64_t>(written.value_));
			}
		}
		bool const signal = buffers_.size() == max_buffers_;
		buffers_.erase(buffers_.begin());
		if (signal) {
			signal_availibility();
		}
	}
}

aio_result file_writer::preallocate(uint64_t size)
{
	scoped_lock l(mtx_);
	if (error_ || !buffers_.empty() || finalizing_) {
		return aio_result::error;
	}

	buffer_pool_.logger().log(logmsg::debug_info, L"Preallocating %d bytes for the file \"%s\"", size, name_);

	auto oldPos = file_.seek(0, file::current);
	if (oldPos < 0) {
		return aio_result::error;
	}

	auto seek_offet = static_cast<int64_t>(oldPos + size);
	if (file_.seek(seek_offet, file::begin) == seek_offet) {
		if (!file_.truncate()) {
			buffer_pool_.logger().log(logmsg::debug_warning, L"Could not preallocate the file");
		}
	}
	if (file_.seek(oldPos, file::begin) != oldPos) {
		buffer_pool_.logger().log(logmsg::error, fztranslate("Could not seek to offset %d within '%s'."), oldPos, name_);
		error_ = true;
		return aio_result::error;
	}
	preallocated_ = true;

	return aio_result::ok;
}

bool file_writer::set_mtime(datetime const& t)
{
	scoped_lock l(mtx_);
	if (error_ || finalizing_ != 2 || !file_) {
		return false;
	}

	return file_.set_modification_time(t);
}

file_writer_factory::file_writer_factory(std::wstring const& file, thread_pool & tpool, file_writer_flags flags)
	: writer_factory(file)
	, thread_pool_(tpool)
	, flags_(flags)
{
}

namespace {
// Specific to opening for writing.
std::wstring get_description(fz::result const& res)
{
	switch (res.error_) {
	case result::noperm:
		return fztranslate("Permission denied.");
	case result::nofile:
		return fztranslate("Target directory does not exist, or name refers to a directory.");
	case result::nospace:
		return fztranslate("Not enough space on device.");
	case result::invalid:
		return fztranslate("Invalid filename.");
	default:
		return sprintf(fztranslate("Unknown error %u (%u)."), res.error_, res.raw_);
	}
}
}

std::unique_ptr<writer_base> file_writer_factory::open(aio_buffer_pool & pool, uint64_t offset, writer_base::progress_cb_t progress_cb, size_t max_buffers)
{
	if (!max_buffers) {
		max_buffers = preferred_buffer_count();
	}

	file::creation_flags flags = offset ? file::existing : file::empty;
	if (flags_ & file_writer_flags::permissions_current_user_only) {
		flags |= file::current_user_only;
	}
	else if (flags_ & file_writer_flags::permissions_current_user_and_admins_only) {
		flags |= file::current_user_and_admins_only;
	}
	file f;
	auto res = f.open(to_native(name()), file::writing, flags);
	if (!res) {
		pool.logger().log(logmsg::error, fztranslate("Could not open '%s' for writing: %s"), name(), get_description(res));
		return {};
	}

	if (offset) {
		auto seek = static_cast<int64_t>(offset);
		auto new_pos = f.seek(seek, file::begin);
		if (new_pos != seek) {
			pool.logger().log(logmsg::error, fztranslate("Could not seek to offset %d within '%s'."), seek, name());
			return {};
		}
		if (!f.truncate()) {
			pool.logger().log(logmsg::error, fztranslate("Could not truncate '%s' to offset %d."), name(), offset);
			return {};
		}
	}

	return std::make_unique<file_writer>(name(), pool, std::move(f), thread_pool_, flags_ & file_writer_flags::fsync, std::move(progress_cb), max_buffers);
}

std::unique_ptr<writer_factory> file_writer_factory::clone() const
{
	return std::make_unique<file_writer_factory>(*this);
}

uint64_t file_writer_factory::size() const
{
	auto s = local_filesys::get_size(to_native(name()));
	if (s < 0) {
		return writer_base::nosize;
	}
	else {
		return static_cast<uint64_t>(s);
	}
}

datetime file_writer_factory::mtime() const
{
	return local_filesys::get_modification_time(to_native(name()));
}


bool file_writer_factory::set_mtime(datetime const& t)
{
	return local_filesys::set_modification_time(to_native(name()), t).operator bool();
}

buffer_writer::buffer_writer(buffer & buffer, std::wstring const& name, aio_buffer_pool & pool, size_t size_limit, progress_cb_t && progress_cb)
	: writer_base(name, pool, std::move(progress_cb), 1)
	, buffer_(buffer)
	, size_limit_(size_limit)
{
	buffer_.clear();
}

aio_result buffer_writer::preallocate(uint64_t size)
{
	if (size > size_limit_) {
		return aio_result::error;
	}

	buffer_.reserve(size);

	return aio_result::ok;
}

aio_result buffer_writer::do_add_buffer(scoped_lock &, buffer_lease && b)
{
	if (size_limit_ - buffer_.size() < b->size()) {
		error_ = true;
		return aio_result::error;
	}
	auto s = b->size();
	buffer_.append(b->get(), s);
	b.release();
	if (progress_cb_) {
		progress_cb_(this, static_cast<uint64_t>(s));
	}

	return aio_result::ok;
}

buffer_writer_factory::buffer_writer_factory(buffer & b, std::wstring const& name, size_t size_limit)
	: writer_factory(name)
	, buffer_(b)
	, size_limit_(size_limit)
{
}

std::unique_ptr<writer_base> buffer_writer_factory::open(aio_buffer_pool & pool, uint64_t offset, writer_base::progress_cb_t progress_cb, size_t)
{
	if (offset) {
		return {};
	}
	return std::make_unique<buffer_writer>(buffer_, name(), pool, size_limit_, std::move(progress_cb));
}

std::unique_ptr<writer_factory> buffer_writer_factory::clone() const
{
	return std::make_unique<buffer_writer_factory>(buffer_, name(), size_limit_);
}

}
