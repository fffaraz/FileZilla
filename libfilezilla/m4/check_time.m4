dnl We need the threadsafe variants of localtime
AC_DEFUN([CHECK_THREADSAFE_LOCALTIME],
[
  AC_CHECK_FUNCS(localtime_r, [], [
    AC_MSG_CHECKING([for localtime_s])
    dnl Checking for localtime_s is a bit more complex as it is a macro
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
       #include <time.h>
       ]], [[
         time_t t;
         struct tm m;
         localtime_s(&m, &t);
         return 0;
      ]])
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_LOCALTIME_S], [1], [localtime_s can be used])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([No threadsafe variant of localtime found])
    ])
  ])
])

dnl We need the threadsafe variants of gmtime
AC_DEFUN([CHECK_THREADSAFE_GMTIME], [
  AC_CHECK_FUNCS(gmtime_r, [], [
    AC_MSG_CHECKING([for gmtime_s])
    dnl Checking for gmtime_s is a bit more complex as it is a macro
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
       #include <time.h>
       ]], [[
         time_t t;
         struct tm m;
         gmtime_s(&m, &t);
         return 0;
      ]])
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_GMTIME_S], [1], [gmtime_s can be used])
    ], [
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([No threadsafe variant of gmtime found])
    ])
  ])
])

dnl We need an inverse for gmtime, either timegm or _mkgmtime
AC_DEFUN([CHECK_INVERSE_GMTIME], [
  # We need an inverse for gmtime, either timegm or _mkgmtime
  AC_CHECK_FUNCS(timegm, [], [
    if ! echo "${host_os}" | grep 'cygwin\|mingw\|^msys$' > /dev/null 2>&1; then
      AC_MSG_ERROR([No inverse function for gmtime was found])
    fi
  ])
])

dnl Check whether the struct stat::st_mtim exists and has the tv_nsec field
AC_DEFUN([CHECK_STRUCT_STAT_ST_MTIM],
[
  AC_MSG_CHECKING([for st_mtim member in stat struct])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
       #include <sys/stat.h>
    ]], [[
      struct stat st;
      (void)st.st_mtim.tv_sec;
      (void)st.st_mtim.tv_nsec;
      return 0;
    ]])
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_STRUCT_STAT_ST_MTIM], [1], [stat::st_mtim::tv_nsec can be used])
    m4_default([$1], :)
  ], [
    AC_MSG_RESULT([no])
  ])
])

