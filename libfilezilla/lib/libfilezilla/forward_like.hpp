#ifndef LIBFILEZILLA_FORWARD_LIKE_HEADER
#define LIBFILEZILLA_FORWARD_LIKE_HEADER

#include <type_traits>

/** \file
 * \brief A function that acts like std::forward, but applies the value category of its first template parameter.
 *
 * It can be used, for instance, to perfect forward the member of a struct according to the value category
 * of the object that is the instance of that struct.
 *
 * Inspired by Vittorio Romeo's proposal: https://vittorioromeo.info/Misc/fwdlike.html
 */

namespace fz {

namespace detail {

    /// \private
    template <class T, class U>
    using apply_value_category_t = std::conditional_t<
        std::is_lvalue_reference_v<T>,
        std::remove_reference_t<U>&,
        std::remove_reference_t<U>&&
    >;

}

/// \brief applies the value category of T to u, so that u can be perfectly forwarded as-if it were of type T.
template <class T, class U>
constexpr detail::apply_value_category_t<T, U> forward_like(U && u) noexcept
{
	return static_cast<detail::apply_value_category_t<T, U>>(u);
}

}

#endif // LIBFILEZILLA_FORWARD_LIKE_HEADER
