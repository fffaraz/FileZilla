#include "../libfilezilla/aio/reader.hpp"
#include "../libfilezilla/local_filesys.hpp"
#include "../libfilezilla/logger.hpp"
#include "../libfilezilla/translate.hpp"

namespace fz {

void reader_base::close()
{
	scoped_lock l(mtx_);
	do_close(l);
	buffer_pool_.remove_waiter(*this);
	waiting_ = false;
	remove_waiters();
	buffers_.clear();
}

bool reader_base::rewind()
{
	return seek(start_offset_, size_);
}

bool reader_base::seek(uint64_t offset, uint64_t size)
{
	// Step 1: Sanity checks, ignore seekable() for now

	if (offset == nosize) {
		offset = (start_offset_ == nosize) ? 0 : start_offset_;
		if (size == nosize) {
			size = size_;
		}
	}

	if (size != nosize && nosize - size <= offset) {
		// offset + size overflow or nosize
		return false;
	}
	if (size != nosize && offset + size > max_size_) {
		// Range unfulfillable
		return false;
	}

	scoped_lock l(mtx_);
	if (error_) {
		return false;
	}

	// Step 2: Check if anything is actually changing, so that we don't have to throw buffers away

	bool change{};
	if (get_buffer_called_) {
		change = true;
	}

	if (offset != start_offset_) {
		change = true;
	}

	if (size == nosize) {
		if (offset + size_ != max_size_) {
			// We had a size restriction, now we have none.
			change = true;
		}
	}
	else {
		if (size != size_) {
			change = true;
		}
	}

	if (!change) {
		// No need to throw away buffers
		return true;
	}

	if (!seekable()) {
		// Cannot start again if we already started once. Neither can we start from not the beginning.
		if (start_offset_ != nosize || offset != 0) {
			return false;
		}
	}

	buffer_pool_.remove_waiter(*this);
	waiting_ = false;
	remove_waiters();
	buffers_.clear();

	// Set the offset and sizes
	start_offset_ = offset;
	if (size != nosize) {
		size_ = size;
	}
	else {
		size_ = max_size_;
		if (size_ != nosize) {
			size_ -= start_offset_;
		}
	}
	remaining_ = size_;
	eof_ = remaining_ == 0;
	get_buffer_called_ = false;

	return do_seek(l);
}

bool reader_base::error() const
{
	scoped_lock l(mtx_);
	return error_;
}

std::pair<aio_result, buffer_lease> reader_base::get_buffer(event_handler & h)
{
	scoped_lock l(mtx_);
	auto ret = do_get_buffer(l);
	if (ret.first == aio_result::wait) {
		//fz::sleep(duration::from_milliseconds(1000));
		add_waiter(h);
	}
	return ret;
}

void reader_base::operator()(event_base const& ev)
{
	dispatch<aio_buffer_event>(ev, this, &reader_base::on_buffer_availability);
}

void reader_base::on_buffer_availability(aio_waitable const* w)
{
	fz::scoped_lock l(mtx_);
	if (waiting_) {
		waiting_ = false;
		do_on_buffer_availability(l, w);
	}
}

reader_factory_holder::reader_factory_holder(reader_factory_holder const& op)
{
	if (op.impl_) {
		impl_ = op.impl_->clone();
	}
}

reader_factory_holder& reader_factory_holder::operator=(reader_factory_holder const& op)
{
	if (this != &op && op.impl_) {
		impl_ = op.impl_->clone();
	}
	return *this;
}

reader_factory_holder::reader_factory_holder(reader_factory_holder && op) noexcept
{
	impl_ = std::move(op.impl_);
	op.impl_.reset();
}

reader_factory_holder& reader_factory_holder::operator=(reader_factory_holder && op) noexcept
{
	if (this != &op) {
		impl_ = std::move(op.impl_);
		op.impl_.reset();
	}

	return *this;
}

reader_factory_holder::reader_factory_holder(std::unique_ptr<reader_factory> && factory)
	: impl_(std::move(factory))
{
}

reader_factory_holder::reader_factory_holder(std::unique_ptr<reader_factory> const& factory)
	: impl_(factory ? factory->clone() : nullptr)
{
}

reader_factory_holder& reader_factory_holder::operator=(std::unique_ptr<reader_factory> && factory)
{
	if (impl_ != factory) {
		impl_ = std::move(factory);
	}

	return *this;
}

reader_factory_holder::reader_factory_holder(reader_factory const& factory)
	: impl_(factory.clone())
{
}

std::pair<aio_result, buffer_lease> threaded_reader::do_get_buffer(scoped_lock & l)
{
	if (buffers_.empty()) {
		if (error_) {
			return {aio_result::error, buffer_lease()};
		}
		else if (eof_) {
			return {aio_result::ok, buffer_lease()};
		}
		return {aio_result::wait, buffer_lease()};
	}
	else {
		bool const w = buffers_.size() == max_buffers_;
		buffer_lease b = std::move(buffers_.front());
		buffers_.pop_front();
		if (w) {
			wakeup(l);
		}
		get_buffer_called_ = true;
		return {aio_result::ok, std::move(b)};
	}
}


file_reader::file_reader(std::wstring && name, aio_buffer_pool & pool, file && f, thread_pool & tpool, uint64_t offset, uint64_t size, size_t max_buffers) noexcept
	: threaded_reader(name, pool, max_buffers)
    , file_(std::move(f))
    , thread_pool_(tpool)
{
	scoped_lock l(mtx_);
	if (file_) {
		auto s = file_.size();
		if (s >= 0) {
			max_size_ = static_cast<uint64_t>(s);
		}
		if (!seek(offset, size)) {
			error_ = true;
		}
	}
	else {
		error_ = true;
	}
}

file_reader::file_reader(std::wstring_view name, aio_buffer_pool & pool, file && f, thread_pool & tpool, uint64_t offset, uint64_t size, size_t max_buffers) noexcept
	: threaded_reader(name, pool, max_buffers)
    , file_(std::move(f))
    , thread_pool_(tpool)
{
	scoped_lock l(mtx_);
	if (file_) {
		auto s = file_.size();
		if (s >= 0) {
			max_size_ = static_cast<uint64_t>(s);
		}
		if (s >= 0) {
			max_size_ = static_cast<uint64_t>(s);
		}
		if (!seek(offset, size)) {
			error_ = true;
		}
	}
	if (!file_ || !task_) {
		error_ = true;
	}
}

file_reader::~file_reader() noexcept
{
	remove_handler();
	close();
}

bool file_reader::seekable() const
{
	return max_size_ != nosize;
}

void file_reader::do_close(scoped_lock & l)
{
	quit_ = true;
	cond_.signal(l);
	l.unlock();
	task_.join();
	l.lock();
	file_.close();
}

bool file_reader::do_seek(scoped_lock & l)
{
	// Step 1: Stop thread
	quit_ = true;
	cond_.signal(l);
	l.unlock();
	task_.join();
	l.lock();
	quit_ = false;

	// Step 2
	if (file_.seek(start_offset_, file::begin) != static_cast<int64_t>(start_offset_)) {
		return false;
	}

	// Re-start thread if needed
	if (!eof_) {
		task_ = thread_pool_.spawn([this]{ entry(); });
		return task_.operator bool();
	}
	else {
		return true;
	}
}

void file_reader::do_on_buffer_availability(fz::scoped_lock& l, aio_waitable const*)
{
	cond_.signal(l);
}

void file_reader::entry()
{
	scoped_lock l(mtx_);
	while (!quit_ && !error_ && !eof_) {
		if (buffers_.size() == max_buffers_) {
			cond_.wait(l);
			continue;
		}
		auto b = buffer_pool_.get_buffer(*this);
		if (!b) {
			waiting_ = true;
			cond_.wait(l);
			continue;
		}
		while (b->size() < b->capacity()) {
			l.unlock();
			size_t to_read = b->capacity() - b->size();
			if (remaining_ != nosize && to_read > remaining_) {
				to_read = remaining_;
			}
			rwresult r = to_read ? file_.read2(b->get(to_read), to_read) : rwresult{size_t(0)};
			l.lock();
			if (quit_ || error_) {
				return;
			}
			if (!r) {
				error_ = true;
				break;
			}
			else if (!r.value_) {
				if (remaining_ && remaining_ != nosize) {
					error_ = true;
				}
				else {
					eof_ = true;
				}
				break;
			}

			b->add(r.value_);
			if (remaining_ != nosize) {
				remaining_ -= r.value_;
			}
		}

		if (!b->empty()) {
			buffers_.emplace_back(std::move(b));
			if (buffers_.size() == 1) {
				signal_availibility();
			}
		}
		if ((eof_ || error_) && !quit_ && buffers_.empty()) {
			signal_availibility();
			break;
		}
	}
}


file_reader_factory::file_reader_factory(std::wstring const& file, thread_pool & tpool)
	: reader_factory(file)
	, thread_pool_(tpool)
{
}

namespace {
// Specific to opening for reading.
std::wstring get_description(fz::result const& res)
{
	switch (res.error_) {
	case result::noperm:
		return fztranslate("Permission denied.");
	case result::nofile:
		return fztranslate("File does not exist");
	case result::invalid:
		return fztranslate("Invalid filename");
	default:
		return sprintf(fztranslate("Unknown error %u (%u)"), res.error_, res.raw_);
	}
}
}

std::unique_ptr<reader_base> file_reader_factory::open(aio_buffer_pool & pool, uint64_t offset, uint64_t size, size_t max_buffers)
{
	if (!max_buffers) {
		max_buffers = preferred_buffer_count();
	}

	file f;
	auto res = f.open(to_native(name()), file::reading, file::existing);
	if (!res) {
		pool.logger().log(logmsg::error, fztranslate("Could not open '%s' for reading: %s"), name(), get_description(res));
		return {};
	}

	auto reader = std::make_unique<file_reader>(name(), pool, std::move(f), thread_pool_, offset, size, max_buffers);
	if (reader->error()) {
		return {};
	}
	return reader;
}

std::unique_ptr<reader_factory> file_reader_factory::clone() const
{
	return std::make_unique<file_reader_factory>(*this);
}

uint64_t file_reader_factory::size() const
{
	auto s = local_filesys::get_size(to_native(name()));
	if (s < 0) {
		return reader_base::nosize;
	}
	else {
		return static_cast<uint64_t>(s);
	}
}

datetime file_reader_factory::mtime() const
{
	return local_filesys::get_modification_time(to_native(name()));
}


view_reader::view_reader(std::wstring && name, aio_buffer_pool & pool, std::string_view data) noexcept
	: reader_base(name, pool, 1)
	, view_(data)
{
	start_offset_ = 0;
	size_ = max_size_ = remaining_ = view_.size();
	if (!remaining_) {
		eof_ = true;
	}
}

view_reader::~view_reader() noexcept
{
	remove_handler();
	close();
}

void view_reader::do_close(scoped_lock &)
{
}

std::pair<aio_result, buffer_lease> view_reader::do_get_buffer(scoped_lock &)
{
	if (error_) {
		return {aio_result::error, buffer_lease()};
	}
	else if (eof_) {
		return {aio_result::ok, buffer_lease()};
	}

	auto b = buffer_pool_.get_buffer(*this);
	if (!b) {
		waiting_ = true;
		return {aio_result::wait, buffer_lease()};
	}

	size_t to_read = b->capacity();
	if (remaining_ != nosize && remaining_ < to_read) {
		to_read = remaining_;
	}
	b->append(reinterpret_cast<uint8_t const*>(view_.data()) + start_offset_ + size_ - remaining_, to_read);
	remaining_ -= to_read;
	if (!remaining_) {
		eof_ = true;
	}
	get_buffer_called_ = true;

	return {aio_result::ok, std::move(b)};
}

void view_reader::do_on_buffer_availability(fz::scoped_lock&, aio_waitable const*)
{
	signal_availibility();
}

bool view_reader::do_seek(scoped_lock &)
{
	return true;
}

std::unique_ptr<reader_base> view_reader_factory::open(aio_buffer_pool & pool, uint64_t offset, uint64_t size, size_t)
{
	auto ret = std::make_unique<view_reader>(name(), pool, view_);
	if (offset || size != reader_base::nosize) {
		if (!ret->seek(offset, size)) {
			return {};
		}
	}

	return ret;
}

std::unique_ptr<reader_factory> view_reader_factory::clone() const
{
	return std::make_unique<view_reader_factory>(name_, view_);
}


string_reader::string_reader(std::wstring && name, aio_buffer_pool & pool, std::string const& data) noexcept
	: reader_base(name, pool, 1)
	, data_(data)
{
	start_offset_ = 0;
	size_ = max_size_ = remaining_ = data_.size();
	if (!remaining_) {
		eof_ = true;
	}
}

string_reader::string_reader(std::wstring && name, aio_buffer_pool & pool, std::string && data) noexcept
	: reader_base(name, pool, 1)
	, data_(std::move(data))
{
	start_offset_ = 0;
	size_ = max_size_ = remaining_ = data_.size();
	if (!remaining_) {
		eof_ = true;
	}
}

string_reader::~string_reader() noexcept
{
	remove_handler();
	close();
}

void string_reader::do_close(scoped_lock &)
{
}

std::pair<aio_result, buffer_lease> string_reader::do_get_buffer(scoped_lock &)
{
	if (error_) {
		return {aio_result::error, buffer_lease()};
	}
	else if (eof_) {
		return {aio_result::ok, buffer_lease()};
	}

	auto b = buffer_pool_.get_buffer(*this);
	if (!b) {
		waiting_ = true;
		return {aio_result::wait, buffer_lease()};
	}

	size_t to_read = b->capacity();
	if (remaining_ != nosize && remaining_ < to_read) {
		to_read = remaining_;
	}
	b->append(reinterpret_cast<uint8_t const*>(data_.data()) + start_offset_ + size_ - remaining_, to_read);
	remaining_ -= to_read;
	if (!remaining_) {
		eof_ = true;
	}
	get_buffer_called_ = true;

	return {aio_result::ok, std::move(b)};
}

void string_reader::do_on_buffer_availability(fz::scoped_lock&, aio_waitable const*)
{
	signal_availibility();
}

bool string_reader::do_seek(scoped_lock &)
{
	return true;
}

std::unique_ptr<reader_base> string_reader_factory::open(aio_buffer_pool & pool, uint64_t offset, uint64_t size, size_t)
{
	auto ret = std::make_unique<string_reader>(name(), pool, data_);
	if (offset || size != reader_base::nosize) {
		if (!ret->seek(offset, size)) {
			return {};
		}
	}

	return ret;
}

std::unique_ptr<reader_factory> string_reader_factory::clone() const
{
	return std::make_unique<string_reader_factory>(name_, data_);
}

}
