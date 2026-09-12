#include "impersonation_desktop_impl.hpp"

#ifdef FZ_WINDOWS

#include "impersonation_desktop_helper.hpp"

#include "../libfilezilla/logger.hpp"

namespace fz {

impersonation_desktop::impl::~impl() = default;

class impersonation_desktop::impl::named final: public impersonation_desktop::impl
{
public:
	explicit named(std::wstring name)
		: name_(std::move(name))
	{
	}

	bool init(HANDLE, logger_interface &) override
	{
		return true;
	}

	std::wstring const *name() override
	{
		return &name_;
	}

private:
	std::wstring name_;
};

class impersonation_desktop::impl::isolated final: public impersonation_desktop::impl
{
public:
	explicit isolated(std::wstring desktop_name_prefix = {})
		: desktop_name_prefix_(std::move(desktop_name_prefix))
	{
	}

	bool init(HANDLE token, logger_interface &logger) override
	{
		if (initialized_) {
			return true;
		}

		auto resolved = windows::resolve_impersonation_desktop(token, desktop_name_prefix_, logger);
		if (!resolved) {
			return false;
		}

		if (resolved->name.empty()) {
			return false;
		}

		desktop_ = std::move(*resolved);
		initialized_ = true;
		return true;
	}

	std::wstring const *name() override
	{
		if (desktop_.name.empty()) {
			return nullptr;
		}

		return &desktop_.name;
	}

private:
	bool initialized_{};
	std::wstring desktop_name_prefix_;
	windows::resolved_impersonation_desktop desktop_;
};

std::unique_ptr<impersonation_desktop::impl> impersonation_desktop::impl::make(const mode &m)
{
	struct visitor {
		std::unique_ptr<impl> operator()(const impersonation_desktop::automatic &)
		{
			return nullptr;
		}

		std::unique_ptr<impl> operator()(const impersonation_desktop::named &m)
		{
			return std::make_unique<impl::named>(std::move(m.name));
		}

		std::unique_ptr<impl> operator()(const impersonation_desktop::isolated &m)
		{
			return std::make_unique<impl::isolated>(m.desktop_name_prefix);
		}
	};

	return std::visit(visitor(), m);
}

}

#endif
