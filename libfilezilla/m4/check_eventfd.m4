AC_DEFUN([CHECK_EVENTFD],
[
  AC_MSG_CHECKING([for eventfd])
  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
     #include <sys/eventfd.h>
     ]], [[
       int fd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
       return (fd == -1) ? 1 : 0;
    ]])
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_EVENTFD], [1], [eventfd])
  ], [
    AC_MSG_RESULT([no])
  ])
])

