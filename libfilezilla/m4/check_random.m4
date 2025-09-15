# Checks whether getrandom or getentropy are  is available.
# Defines HAVE_GERANDOM or HAVE_GETENTROPY if it is.
#
# CHECK_RANDOM([ACTION-SUCCESS], [ACTION-FAILURE])

AC_DEFUN([CHECK_RANDOM],
[
  AC_MSG_CHECKING([for getrandom])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
       #include <sys/random.h>
    ]], [[
     (void)getrandom;
     return 0;
    ]])
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_GETRANDOM], [1], [getrandom can be used])
    m4_default([$1], :)
  ], [
    AC_MSG_RESULT([no])

    AC_MSG_CHECKING([for getentropy])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        #include <sys/types.h>
        #ifdef __APPLE__
          #include <Availability.h>
          #include <sys/random.h>
        #endif
        #include <unistd.h>
      ]], [[
        (void)getentropy;
        return 0;
      ]])
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_GETENTROPY], [1], [getentropy can be used])
      m4_default([$1], :)
    ], [
      AC_MSG_RESULT([no])
      m4_default([$2], :)
    ])
  ])
])
