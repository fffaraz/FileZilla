#ifndef LIBFILEZILLA_VISIBILITY_HELPER_HEADER
#define LIBFILEZILLA_VISIBILITY_HELPER_HEADER

/** \file
 * \brief Helper macros for symbol visibility in shared libraries
 *
 * There are two main cases: Building a library and using it.
 * For building, symbols need to be marked as export, for using it they
 * need to be imported.
 *
 * Usage example:
 * \code
 * #include <libfilezilla/visibility_helper>
 * #ifdef BUILDING_LIBRARY // Provide this yourself
 *
 *   #define PUBLIC_SYMBOL FZ_EXPORT_PUBLIC
 *   #define PRIVATE_SYMBOL FZ_EXPORT_PRIVATE
 * #else
 *  #define PRIVATE_SYMBOL
 *  #define PUBLIC_SYMBOL FZ_IMPORT_SHARED
 * #endif
 *
 * struct PUBLIC_SYMBOL example {
 *   void do_stuff();
 *   void PRIVATE_SMBOL for_internal_use();
 * };
 * \endcode
 */

#ifdef DOXYGEN
/// Marks symbols as public to be exported
#define FZ_EXPORT_PUBLIC

/// Marks symbols as private, they won't be exported
#define FZ_EXPORT_PRIVATE

/// Import symbols from a shared library
#define FZ_IMPORT_SHARED

#else

#include "private/defs.hpp"

// Two cases when building: Windows, other platform
#ifdef FZ_WINDOWS

  // Under Windows we can either use Visual Studio or a proper compiler
  #ifdef _MSC_VER
    #define FZ_EXPORT_PUBLIC __declspec(dllexport)
    #define FZ_EXPORT_PRIVATE
  #else
    #define FZ_EXPORT_PUBLIC __declspec(dllexport)
    #define FZ_EXPORT_PRIVATE
  #endif

#else

  #define FZ_EXPORT_PUBLIC __attribute__((visibility("default")))
  #define FZ_EXPORT_PRIVATE __attribute__((visibility("hidden")))

#endif


#if defined(FZ_WINDOWS)
  #define FZ_IMPORT_SHARED __declspec(dllimport)
#else
  #define FZ_IMPORT_SHARED
#endif

#endif

#endif
