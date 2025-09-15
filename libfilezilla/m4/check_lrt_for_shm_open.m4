dnl Checks whether shm_open needs linking with -lrt

AC_DEFUN([CHECK_LRT_FOR_SHM_OPEN], [

  AC_MSG_CHECKING([whether shm_open needs -lrt])

  AC_LINK_IFELSE([
    AC_LANG_PROGRAM([[
      #include <sys/mman.h>
      #include <sys/stat.h>
      #include <fcntl.h>
    ]], [[
      (void)shm_open("", 0, 0);
      return 0;
    ]])
  ], [
    AC_MSG_RESULT([no])
  ], [
    lrt_for_shm_open_oldlibs=$LIBS
    AX_APPEND_FLAG([-lrt], LIBS)

    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        #include <sys/mman.h>
        #include <sys/stat.h>
        #include <fcntl.h>
      ]], [[
        (void)shm_open("", 0, 0);
        return 0;
      ]])
    ], [
      AC_MSG_RESULT([yes])
    ], [
      LIBS=$lrt_for_shm_open_oldlibs
      AC_MSG_RESULT([no])
    ])
  ])
])
