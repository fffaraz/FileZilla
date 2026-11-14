# Checks whether pipe2 is available.
# Defines HAVE_PIPE2 if it is.	
#
# CHECK_PIPE2([ACTION-SUCCESS], [ACTION-FAILURE])

AC_DEFUN([CHECK_PIPE2],
[
    AC_MSG_CHECKING([for pipe2])
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
         #include <unistd.h>
       ]], [[
	 (void)pipe2;
         return 0;
      ]])
    ], [
      AC_MSG_RESULT([yes])
      AC_DEFINE([HAVE_PIPE2], [1], [pipe2 can be used])
      m4_default([$1], :)
    ], [
      AC_MSG_RESULT([no])
      m4_default([$2], :)
    ])
  ])
])
