#ifndef LIBFILEZILLA_BASIC_TLS_PARAMS_HEADER
#define LIBFILEZILLA_BASIC_TLS_PARAMS_HEADER

/** \cond PRIVATE
 *	\file
 *	\brief the implementation of the interface introduced by \ref tls_params.hpp
 */

#include "format.hpp"
#include "hash.hpp"
#include "string.hpp"
#include "forward_like.hpp"

#include <variant>

namespace fz {

template <typename T, typename Tag, typename Policy>
struct basic_tls_param;

template <typename T, typename Tag>
struct is_same_kind_of_basic_tls_param : std::false_type{};

template <typename T, typename Tag, typename Policy>
struct is_same_kind_of_basic_tls_param<basic_tls_param<T, Tag, Policy>, Tag> : std::true_type{};

template <typename T, typename Tag, typename Policy>
struct basic_tls_param final
{
	basic_tls_param(basic_tls_param const &) = default;
	basic_tls_param& operator=(basic_tls_param &&) = default;
	basic_tls_param& operator=(basic_tls_param const &) = default;

	template <typename U = T, std::enable_if_t<std::is_default_constructible_v<U>>* = nullptr>
	basic_tls_param()
		: value{}
	{}

	template <typename U, std::enable_if_t<std::is_constructible_v<T, U>>* = nullptr>
	explicit basic_tls_param(U && v)
		: value(std::forward<U>(v))
	{}

	template <typename U, typename V = std::remove_cv_t<std::remove_reference_t<U>>, std::enable_if_t<
		!std::is_same_v<V, basic_tls_param> &&
		is_same_kind_of_basic_tls_param<V, Tag>::value>* = nullptr>
	basic_tls_param(U && other)
		: value(forward_like<U>(other.value))
	{}

	explicit operator bool() const
	{
		return Policy::is_valid(value);
	}

	bool is_valid() const
	{
		return Policy::is_valid(value);
	}

	template <typename U, typename P>
	bool operator ==(basic_tls_param<U, Tag, P> const & rhs) const
	{
		return value == rhs.value;
	}

	template <typename U, typename P>
	bool operator !=(basic_tls_param<U, Tag, P> const & rhs) const
	{
		return value != rhs.value;
	}

	template <typename U, typename P>
	bool operator <(basic_tls_param<U, Tag, P> const & rhs) const
	{
		return value < rhs.value;
	}

	template <typename U, typename P>
	bool operator <=(basic_tls_param<U, Tag, P> const & rhs) const
	{
		return value <= rhs.value;
	}

	template <typename U, typename P>
	bool operator >(basic_tls_param<U, Tag, P> const & rhs) const
	{
		return value > rhs.value;
	}

	template <typename U, typename P>
	bool operator >=(basic_tls_param<U, Tag, P> const & rhs) const
	{
		return value >= rhs.value;
	}

	T value;
};

struct basic_tls_param_policy
{
	template <typename T>
	static bool is_valid(T const & v)
	{
		return !v.empty();
	}
};

struct tls_pkcs11url_policy
{
	static bool is_valid(std::string_view v)
	{
		static constexpr std::string_view pkcs11_scheme = "pkcs11:";

		return fz::starts_with(v, pkcs11_scheme);
	}
};

template <typename T>
using basic_tls_blob = basic_tls_param<T, struct tls_blob_tag, basic_tls_param_policy>;

template <typename T>
using basic_tls_filepath = basic_tls_param<T, struct tls_filepath_tag, basic_tls_param_policy>;

template <typename T>
using basic_tls_pkcs11url = basic_tls_param<T, struct tls_pkcs11url_tag, tls_pkcs11url_policy>;

template <typename B, typename F, typename P>
struct basic_tls_param_variant;

template <typename T>
struct is_basic_tls_param_variant : std::false_type{};

template <typename B, typename F, typename P>
struct is_basic_tls_param_variant<basic_tls_param_variant<B, F, P>> : std::true_type{};

template <typename B, typename F, typename P>
struct basic_tls_param_variant final
{
	using blob_type = basic_tls_blob<B>;
	using filepath_type = basic_tls_filepath<F>;
	using pkcs11url_type = basic_tls_pkcs11url<P>;

	using variant_type = std::variant<
		blob_type,
		filepath_type,
		pkcs11url_type
	>;

	blob_type const *blob() const
	{
		return std::get_if<blob_type>(&value);
	}

	filepath_type const *filepath() const
	{
		return std::get_if<filepath_type>(&value);
	}

	pkcs11url_type const *pkcs11url() const
	{
		return std::get_if<pkcs11url_type>(&value);
	}

	blob_type *blob()
	{
		return std::get_if<blob_type>(&value);
	}

	filepath_type *filepath()
	{
		return std::get_if<filepath_type>(&value);
	}

	pkcs11url_type *pkcs11url()
	{
		return std::get_if<pkcs11url_type>(&value);
	}

	native_string url() const
	{
		struct visitor
		{
			native_string operator()(filepath_type const &v)
			{
				return fz::sprintf(fzT("file:%s"), v ? v.value : fzT("<invalid>"));
			}

			native_string operator()(pkcs11url_type const &v)
			{
				if (v) {
					return to_native(v.value);
				}

				return fzT("pkcs11:<invalid>");
			}

			native_string operator()(blob_type const &v)
			{
				if (v) {
					return fz::sprintf(fzT("blob:md5:%s"), hex_encode<native_string>(md5(v.value)));
				}

				return fzT("blob:<invalid>");
			}
		};

		return std::visit(visitor(), value);
	}

	basic_tls_param_variant() = default;
	basic_tls_param_variant(basic_tls_param_variant &&) = default;
	basic_tls_param_variant(basic_tls_param_variant const &) = default;
	basic_tls_param_variant& operator=(basic_tls_param_variant &&) = default;
	basic_tls_param_variant& operator=(basic_tls_param_variant const &) = default;

	template <typename T, std::enable_if_t<std::is_constructible_v<variant_type, T>>* = nullptr>
	basic_tls_param_variant(T && v)
		: value(std::forward<T>(v))
	{}

	template <typename T, typename U = std::remove_cv_t<std::remove_reference_t<T>>, std::enable_if_t<
		!std::is_same_v<U, basic_tls_param_variant>
		&& is_basic_tls_param_variant<U>::value>* = nullptr>
	basic_tls_param_variant(T && other)
		: value(std::visit([](auto && v) {
			return variant_type(std::forward<decltype(v)>(v));
		}, forward_like<T>(other.value)))
	{
	}

	template <typename T, std::enable_if_t<!std::is_same_v<T, basic_tls_param_variant> && is_basic_tls_param_variant<T>::value>* = nullptr>
	basic_tls_param_variant& operator=(T && other)
	{
		*this = basic_tls_param_variant(std::forward<T>(other));
		return *this;
	}

	explicit operator bool() const
	{
		return std::visit([](auto && v) {
			return bool(v);
		}, value);
	}

	bool is_valid() const
	{
		return bool(*this);
	}

	template <typename F2, typename P2, typename B2>
	bool operator ==(basic_tls_param_variant<F2, P2, B2> const & rhs) const
	{
		return value == rhs.value;
	}

	template <typename F2, typename P2, typename B2>
	bool operator !=(basic_tls_param_variant<F2, P2, B2> const & rhs) const
	{
		return value != rhs.value;
	}

	template <typename F2, typename P2, typename B2>
	bool operator <(basic_tls_param_variant<F2, P2, B2> const & rhs) const
	{
		return value < rhs.value;
	}

	template <typename F2, typename P2, typename B2>
	bool operator <=(basic_tls_param_variant<F2, P2, B2> const & rhs) const
	{
		return value <= rhs.value;
	}

	template <typename F2, typename P2, typename B2>
	bool operator >(basic_tls_param_variant<F2, P2, B2> const & rhs) const
	{
		return value > rhs.value;
	}

	template <typename F2, typename P2, typename B2>
	bool operator >=(basic_tls_param_variant<F2, P2, B2> const & rhs) const
	{
		return value >= rhs.value;
	}

	variant_type value;
};

}

#endif

/** \endcond PRIVATE */
