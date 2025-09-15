#ifndef LIBFILEZILLA_TLS_PARAMS_HEADER
#define LIBFILEZILLA_TLS_PARAMS_HEADER

/** \file
 * \brief Functions and classes to abstract away the type of different parameters to tls-related functions
 *
 * Certain APIs require to be passed references to TLS certificates and/or cryptographic keys,
 * which shall be named "tls object" from now on.
 * These tls objects could reside on files, in memory or in PCKS#11 compliant security tokens (or compatible repositories).
 *
 * To express the full combination of possibilities, the APIs can take one of \ref fz::tls_param, \ref fz::tls_param_ref
 * and \ref fz::const_tls_param_ref as one of more of their parameters.
 *
 * Each of those types encapsulates, respectively, a tls object, a lvalue reference to that object, or a const lvalue reference
 * to that object.
 *
 * A tls object can be one of
 *
 *	- \ref fz::tls_blob - for a tls object in memory
 *	- \ref fz::tls_filepath - for a tls object on a file system
 *	- \ref fz::tls_pkcs11url - for a tls object referenced by a PKCS#11 URL.
 *
 * A \ref fz::const_tls_param_ref can be constructed from, or assigned by, one of:
 *	- \ref fz::tls_param
 *	- \ref fz::const_tls_param_ref
 *	- \ref fz::tls_param_ref
 *
 * The assignment rebinds.
 *
 * A \ref fz::tls_param_ref can be constructed from, or assigned by, one of:
 *	- \ref fz::tls_param
 *	- \ref fz::tls_param_ref
 *
 * The assignment rebinds.
 *
 * A \ref fz::tls_param can be constructed from, or assigned by, one of:
 *	- \ref fz::tls_param
 *	- \ref fz::const_tls_param_ref
 *	- \ref fz::tls_param_ref
 *
 * The assignment and the constructors copy (or move, if appropriate) the tls object contained in or referenced to by the right hand side.
 *
 * \par Example usage:
 * \code{.cpp}
 * int my_tls_funcion(fz::tls_param contains_the_tls_object, fz::const_tls_param contains_a_reference_to_the_object);
 *
 * int result = my_tls_function(fz::tls_blob("-----BEGIN PRIVATE KEY-----"), fz::tls_filepath(fzT("/path/to/the/file")));
 * \endcode
 */

#include "basic_tls_params.hpp"

namespace fz {

/** \brief Creates a tls_blob object.
 *  \param v (possibly a reference to) a \ref std::string containing, or a \ref std::string_view on, a blob of data
 */
template <typename T, std::enable_if_t<std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, std::string> || std::is_same_v<T, std::string_view>>* = nullptr>
basic_tls_blob<T> tls_blob(T && v)
{
	return basic_tls_blob<T>{ std::forward<T>(v) };
}

/** \brief Creates a tls_blob object.
 *
 *  This is an overload that takes as parameter an object convertible to a \ref std::string.
 *
 *  \param v an object convertible to a \ref std::string, containing a blob of data.
 */
template <typename T, std::enable_if_t<!(std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, std::string> || std::is_same_v<T, std::string_view>) && std::is_constructible_v<std::string, T>>* = nullptr>
basic_tls_blob<std::string> tls_blob(T && v)
{
	return basic_tls_blob<std::string>{ std::forward<T>(v) };
}

/** \brief Creates a tls_filepath object.
 *  \param v (possibly a rererence to) a \ref fz::native_string containing the path to a tls object on the filesystem.
 */
template <typename T, std::enable_if_t<std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, native_string>>* = nullptr>
basic_tls_filepath<T> tls_filepath(T && v)
{
	return basic_tls_filepath<T>{ std::forward<T>(v) };
}

/** \brief Creates a tls_filepath object.
 *
 *  This is an overload that takes as parameter an object convertible to a \ref fz::native_string.

 *  \param v an object convertible to a \ref fz::native_string, containing the path to a tls object on the filesystem.
 */
template <typename T, std::enable_if_t<!(std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, native_string>) && std::is_constructible_v<native_string, T>>* = nullptr>
basic_tls_filepath<native_string>
tls_filepath(T && v)
{
	return basic_tls_filepath<native_string>{ std::forward<T>(v) };
}

/** \brief Creates a tls_pkcs11url object.
 *  \param v (possibly a rererence to) a \ref std::string containing a URL representing a PKCS#11 object. The scheme must be <em>pkcs11:</em>.
 */
template <typename T, std::enable_if_t<std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, std::string>>* = nullptr>
basic_tls_pkcs11url<T> tls_pkcs11url(T && v)
{
	return basic_tls_pkcs11url<T>{ std::forward<T>(v) };
}

/** \brief Creates a tls_pkcs11url object.
 *
 *  This is an overload that takes as parameter an object convertible to a \ref std::string.

 *  \param v an object convertible to a \ref fz::native_string, containing a URL representing a PKCS#11 object. The scheme must be <em>pkcs11:</em>.
 */
template <typename T, std::enable_if_t<!std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>, std::string> && std::is_constructible_v<std::string, T>>* = nullptr>
basic_tls_pkcs11url<std::string> tls_pkcs11url(T && v)
{
	return basic_tls_pkcs11url<std::string>{ std::forward<T>(v) };
}

/// \brief Acts as a const lvalue reference to one of a \ref fz::tls_blob, \ref fz::tls_filepath or \ref fz::tls_pkcs11url
using const_tls_param_ref = basic_tls_param_variant<
	std::string_view const,
	native_string const &,
	std::string const &
>;

/// \brief Acts as a lvalue reference to one of a \ref fz::tls_blob, \ref fz::tls_filepath or \ref fz::tls_pkcs11url
using tls_param_ref = basic_tls_param_variant<
	std::string &,
	native_string const &,
	std::string const &
>;

/// \brief Acts as an instance of one of a \ref fz::tls_blob, \ref fz::tls_filepath or \ref fz::tls_pkcs11url
using tls_param = basic_tls_param_variant<
	std::string,
	native_string,
	std::string
>;

/// \brief The encoding type of a fz::tls_blob or the file pointed to by a fz::tls_filepath
enum class tls_data_format
{
	autodetect, ///< The type will be detected automatically using an heuristic
	pem,        ///< The provided data is in PEM format
	der         ///< The provided data is in DER format
};

/// \brief returns true if the blob is in PEM format. Uses a simple heuristic.
bool FZ_PUBLIC_SYMBOL is_pem(std::string_view blob);

}

#endif
