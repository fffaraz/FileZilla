#ifndef FZSSH_VISIBILITY_HEADER
#define FZSSH_VISIBILITY_HEADER

#include <libfilezilla/visibility_helper.hpp>

// Symbol visibility. There are two main cases: Building fzssh and using it
#ifdef BUILDING_FZSSH
  #define FZSSH_PUBLIC_SYMBOL FZ_EXPORT_PUBLIC
  #define FZSSH_PRIVATE_SYMBOL FZ_EXPORT_PRIVATE
#else
  #define FZSSH_PUBLIC_SYMBOL FZ_IMPORT_SHARED
  #define FZSSH_PRIVATE_SYMBOL
#endif

#endif
