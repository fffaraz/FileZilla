#include <libfilezilla/aio/reader.hpp>
#include <libfilezilla/aio/writer.hpp>
#include <libfilezilla/logger.hpp>

#include <libfilezilla/encode.hpp>
#include <libfilezilla/event_handler.hpp>
#include <libfilezilla/event_loop.hpp>
#include <libfilezilla/hash.hpp>

#include <atomic>

class worker : public fz::event_handler
{
public:
	worker(fz::logger_interface & logger, fz::event_loop & loop, std::unique_ptr<fz::reader_factory> && in_factory, std::unique_ptr<fz::writer_factory> && out_factory)
		: fz::event_handler(loop)
		, logger_(logger)
		, reader_factory_(in_factory)
		, writer_factory_(out_factory)
	{
		if (!buffer_pool_) {
			logger_.log(fz::logmsg::error, "Could not init buffer pool");
			loop.stop();
			return;
		}

		reader_ = reader_factory_->open(buffer_pool_);
		if (!reader_) {
			logger_.log(fz::logmsg::error, "Could not open %s", reader_factory_->name());
			loop.stop();
			return;
		}

		auto cb = [this](fz::writer_base const*, uint64_t written) {
			written_ += written;
		};
		writer_ = writer_factory_->open(buffer_pool_, 0, cb);
		if (!writer_) {
			logger_.log(fz::logmsg::error, "Could not open %s", writer_factory_->name());
			loop.stop();
			return;
		}
	}

	virtual ~worker() {
		remove_handler();

		if (success_) {
			logger_.log(fz::logmsg::status, "File copied successfully, wrote %d bytes", written_.load());
			logger_.log(fz::logmsg::status, "Hash of data copied is %s", fz::hex_encode<std::string>(hash_.digest()));
		}
		else {
			logger_.log(fz::logmsg::error, "Copy failed.");
		}
	}

	virtual void operator()(fz::event_base const&) override
	{
		for (size_t i = 0; i < 10; ++i) {
			auto [res, b] = reader_->get_buffer(*this);
			if (res == fz::aio_result::error) {
				event_loop_.stop();
				return;
			}
			if (res != fz::aio_result::ok) {
				return;
			}
			if (!b) {
				auto res = writer_->finalize(*this);
				if (res == fz::aio_result::wait) {
					return;
				}
				else if (res == fz::aio_result::error) {
					event_loop_.stop();
					return;
				}

				success_ = true;
				event_loop_.stop();
				return;
			}

			hash_.update(b->get(), b->size());
			done_ += b->size();

			res = writer_->add_buffer(std::move(b), *this);
			if (res == fz::aio_result::wait) {
				return;
			}
			else if (res == fz::aio_result::error) {
				event_loop_.stop();
				return;
			}
		}
		send_event<fz::aio_buffer_event>(nullptr);
	}

	fz::logger_interface & logger_;

	fz::reader_factory_holder reader_factory_;
	fz::writer_factory_holder writer_factory_;

	uint64_t done_{};
	fz::hash_accumulator hash_{fz::hash_algorithm::sha1};
	fz::thread_pool tpool_;
	fz::aio_buffer_pool buffer_pool_{tpool_, logger_, 8};
	std::unique_ptr<fz::reader_base> reader_;
	std::unique_ptr<fz::writer_base> writer_;

	std::atomic<uint64_t> written_{};
	bool success_{};
};

int main(int argc, char* argv[])
{
	fz::stdout_logger logger;

	if (argc != 3) {
		logger.log(fz::logmsg::error, "Pass input and output filename");
		return 1;
	}

	fz::thread_pool pool;

	auto in = std::make_unique<fz::file_reader_factory>(fz::to_wstring(argv[1]), pool);
	auto out = std::make_unique<fz::file_writer_factory>(fz::to_wstring(argv[2]), pool);

	fz::event_loop loop(fz::event_loop::threadless);

	worker w(logger, loop, std::move(in), std::move(out));
	w.send_event<fz::aio_buffer_event>(nullptr);

	loop.run();

	return 0;
}
