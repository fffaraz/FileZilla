dnl Checks for thread_local support

AC_DEFUN([CHECK_TCP_INFO], [

  AC_MSG_CHECKING([for TCP_INFO])

  AC_LANG_PUSH(C++)

  AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <sys/socket.h>
      #include <netinet/in.h>
      #include <netinet/tcp.h>
    ]], [[
      tcp_info info{};
      int fd{};
      socklen_t len = sizeof(tcp_info);
      int res = getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len);
      (void)res;
      (void)info.tcpi_rcv_wscale;
      return 0;
    ]])
  ], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_TCP_INFO], [1], [Define if TCP_INFO is supported])
  ], [
    AC_MSG_RESULT([no])
  ])

  AC_LANG_POP(C++)
])
