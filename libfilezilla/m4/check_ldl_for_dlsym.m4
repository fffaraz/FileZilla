dnl Checks whether dlsym needs linking with -ldl

AC_DEFUN([CHECK_LDL_FOR_DLSYM], [

  AC_MSG_CHECKING([whether dlsym needs -ldl])

  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #define _GNU_SOURCE
      #include <dlfcn.h>
    ]], [[
      (void)dlsym(RTLD_DEFAULT, "foo");
      return 0;
    ]])
  ], [
    AC_MSG_RESULT([no])
  ], [
    ldl_for_dlsym_oldlibs=$LIBS
    AX_APPEND_FLAG([-ldl], LIBS)

    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        #define _GNU_SOURCE
        #include <dlfcn.h>
      ]], [[
        (void)dlsym(RTLD_DEFAULT, "foo");
        return 0;
      ]])
    ], [
      AC_MSG_RESULT([yes])
    ], [
      LIBS=$ldl_for_dlsym_oldlibs
      AC_MSG_RESULT([no])
    ])
  ])
])
