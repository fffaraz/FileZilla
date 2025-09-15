AC_INIT([libfilezilla],[0.51.1],[tim.kosse@filezilla-project.org],[],[https://lib.filezilla-project.org/])

# Update the version information only immediately before a public release of your software
# If the library source code has changed at all since the last update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# If any interfaces have been added, removed, or changed since the last update, increment current, and set revision to 0.
# If any interfaces have been added since the last public release, then increment age.
# If any interfaces have been removed or changed since the last public release, then set age to 0.
# CURRENT:REVISION:AGE
LIBRARY_VERSION=49:0:1

AH_TOP([
#ifndef LIBFILEZILLA_CONFIG_HEADER
#define LIBFILEZILLA_CONFIG_HEADER
])
AH_BOTTOM([
#endif
])
AC_CONFIG_HEADERS([config/config.hpp])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([dist-xz no-dist-gzip subdir-objects nostdinc])

AC_CANONICAL_HOST

AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_INSTALL

LT_INIT([disable-static pic-only win32-dll])
LT_LANG([C++])
AC_SUBST(LIBRARY_VERSION)

AC_CACHE_SAVE


AC_ARG_ENABLE(locales, AS_HELP_STRING([--enable-locales],[Build message catalogs]), \
        [locales="$enableval"], [locales="yes"])

AC_ARG_ENABLE(localesonly, AS_HELP_STRING([--enable-localesonly],[Just build locales]), \
        [localesonly="$enableval"], [localesonly="no"])

if test "$locales" != "yes" -a "$localesonly" = "yes"; then
  AC_MSG_ERROR([invalid flags: --disable-locales cannot be used together with --enable-localesonly])
fi

if test "$enable_static" != "no"; then
  AC_MSG_ERROR([libfilezilla does not support --enable-static])
fi

if ! test "$localesonly" = "yes"; then

# Check if we're on Windows
if echo $host_os | grep 'cygwin\|mingw\|^msys$' > /dev/null 2>&1; then
  windows=1
else
  windows=0
fi

# Check if we're on Mac
if test "$host_vendor" = "apple"; then
  mac=1
else
  mac=0
fi

# If neither, we're Unix(-like)
if test "$mac" = "0" && test "$windows" = "0"; then
  unix=1
else
  unix=0
fi

if test "X$GCC" = Xyes; then
  AX_APPEND_FLAG(-Wall, CFLAGS)
  AX_APPEND_FLAG(-g, CFLAGS)
  AX_APPEND_FLAG(-Wall, CXXFLAGS)
  AX_APPEND_FLAG(-g, CXXFLAGS)
fi

# Do this early: Compiler and linker flags to work around a nasty bug in Xcode.
AX_CHECK_COMPILE_FLAG([-Werror=partial-availability], [
  # This warning should be on by default yet it's not even enabled by -Wall. Apple screwed up big time.
  AX_APPEND_FLAG(-Werror=partial-availability, CFLAGS)
  AX_APPEND_FLAG(-Werror=partial-availability, CXXFLAGS)
])

AX_CHECK_LINK_FLAG([-Wl,-no_weak_imports], [
  # If the programmer wants weak symbols he would just used dlopen/dlsym
  # But not so on Apple systems where even basic functions like clock_gettime can
  # be randomly missing at runtime.
  AX_APPEND_FLAG([-Wl,-no_weak_imports], LFDLAGS)
])

# Check for C++14 support
AX_CXX_COMPILE_STDCXX_17([noext],[mandatory])
CHECK_LIBCXX

# To make sure stat.st_size is a 64bit (or larger) value
AC_SYS_LARGEFILE

# libstdc++ as shipped with GCC 4.7 has a steady clock that isn't steady (who implements such crap?)
CHECK_STEADY_CLOCK

# No thread_local in GCC 4.7 and it for some reason isn't supported on OS X either
CHECK_THREAD_LOCAL

AC_CHECK_DECLS([CLOCK_MONOTONIC], [], [], [[#include <time.h>]])

if test "$windows" = "0"; then
  AC_CHECK_FUNC(poll, [], [
    AC_MSG_ERROR([Please update to an operating system supporitng poll().])
  ])
  AC_CHECK_FUNCS(posix_fadvise pipe2 accept4)

  # eventfd is preferred over selfpipe, half the descriptors after all.
  CHECK_EVENTFD
fi

# Some platforms have no d_type entry in their dirent structure
gl_CHECK_TYPE_STRUCT_DIRENT_D_TYPE

CHECK_THREADSAFE_LOCALTIME
CHECK_THREADSAFE_GMTIME
CHECK_INVERSE_GMTIME

CHECK_CLOCK_GETTIME

CHECK_STRUCT_STAT_ST_MTIM

AC_CHECK_DECLS([pthread_condattr_setclock], [], [], [[#include <pthread.h>]])

if test "$windows" = "1"; then
  libdeps="-lws2_32 -liphlpapi"
else
  libdeps=-lpthread
  CHECK_ICONV([libdeps="$libdeps -liconv"])

  CHECK_MEMFD_CREATE
  if test "$have_memfd_create" != "yes"; then
    CHECK_LRT_FOR_SHM_OPEN
  fi

  CHECK_RANDOM
  CHECK_LDL_FOR_DLSYM
fi

if test "$windows" = "0" && test "$mac" = "0"; then
  CHECK_TCP_INFO
fi


AC_SUBST([libdeps])


# Add build information to config.hpp
# -----------------------------------

# Add host to config.hpp
AC_DEFINE_UNQUOTED(USED_HOST, ["$host"], [Host system under which the program will run.])
AC_DEFINE_UNQUOTED(USED_BUILD, ["$build"], [Build system under which the program was compiled on.])

# Add used CXXFLAGS to config.hpp
AC_DEFINE_UNQUOTED(USED_CXXFLAGS, ["$CXXFLAGS"], [Define to the used CXXFLAGS to compile this package.])

# Get compiler (version)
AH_TEMPLATE(USED_COMPILER, [Define to name and version of used compiler])
if COMPILER=`$CC --version | head -n 1`; then
  AC_DEFINE_UNQUOTED(USED_COMPILER, ["$COMPILER"])
fi


# Require pkg-config
# ------------------
PKG_PROG_PKG_CONFIG

if test -z "$PKG_CONFIG"; then
  AC_MSG_ERROR([pkg-config not found. pkg-config is required to check for some dependencies.])
fi

# GMP
# ---

PKG_CHECK_MODULES([GMP], [gmp >= 6.2],, [
  AC_MSG_ERROR([gmplib 6.2 or greater was not found. You can get it from https://gmplib.org/])
])

AC_SUBST(GMP_LIBS)
AC_SUBST(GMP_CFLAGS)

# Nettle
# ------

PKG_CHECK_MODULES([NETTLE], [nettle >= 3.3],, [
  AC_MSG_ERROR([nettle 3.3 greater was not found. You can get it from https://www.lysator.liu.se/~nisse/nettle/])
])

AC_SUBST(NETTLE_LIBS)
AC_SUBST(NETTLE_CFLAGS)

PKG_CHECK_MODULES([HOGWEED], [hogweed >= 3.3],, [
  AC_MSG_ERROR([hogweed 3.3 greater was not found. You can get it from https://www.lysator.liu.se/~nisse/nettle/])
])

AC_SUBST(HOGWEED_LIBS)
AC_SUBST(HOGWEED_CFLAGS)


# GnuTLS
# ------

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.7.0],, [
  AC_MSG_ERROR([GnuTLS 3.7.0 or greater was not found. You can get it from https://gnutls.org/])
])

AC_SUBST(GNUTLS_LIBS)
AC_SUBST(GNUTLS_CFLAGS)

AC_ARG_ENABLE(gnutlssystemciphers, AS_HELP_STRING([--enable-gnutlssystemciphers],[Enables the use of gnutls system ciphers.]),
  [gnutlssystemciphers="$enableval"], [gnutlssystemciphers="no"])

if test "$gnutlssystemciphers" = "yes"; then
  AC_DEFINE(FZ_USE_GNUTLS_SYSTEM_CIPHERS, 1, [Set to 1 to use ciphers defined in system policy.])
fi


# Check for windres on MinGW builds
# ---------------------------------

AC_MSG_CHECKING([whether to use windres])
if test "$windows" = "1"; then
  AC_MSG_RESULT([yes])
  AC_CHECK_TOOL([WINDRES], [windres])
  if test "x$WINDRES" = "x"; then
	AC_MSG_ERROR([windres could not be found, please make sure this program is within your path.])
  fi
else
  AC_MSG_RESULT([no])
fi
AC_SUBST(WINDRES)



# Set version macros
# ------------------

# version.rc.in needs a major, minor and micro version number
PACKAGE_VERSION_SUFFIX=${PACKAGE_VERSION##*-}
vnumber=${PACKAGE_VERSION%-*}
PACKAGE_VERSION_MAJOR=${vnumber%%.*}
vnumber=${vnumber#$PACKAGE_VERSION_MAJOR}
vnumber=${vnumber#.}
PACKAGE_VERSION_MINOR=${vnumber%%.*}
vnumber=${vnumber#$PACKAGE_VERSION_MINOR}
vnumber=${vnumber#.}
PACKAGE_VERSION_MICRO=${vnumber%%.*}
vnumber=${vnumber#$PACKAGE_VERSION_MICRO}
vnumber=${vnumber#.}
PACKAGE_VERSION_NANO=${vnumber%%.*}

if test -z "$PACKAGE_VERSION_MAJOR"; then
  PACKAGE_VERSION_MAJOR=0
fi
if test -z "$PACKAGE_VERSION_MINOR"; then
  PACKAGE_VERSION_MINOR=0
fi
if test -z "$PACKAGE_VERSION_MICRO"; then
  PACKAGE_VERSION_MICRO=0
fi
if test -z "$PACKAGE_VERSION_NANO"; then
  PACKAGE_VERSION_NANO=0
fi

AC_SUBST(PACKAGE_VERSION_MAJOR)
AC_SUBST(PACKAGE_VERSION_MINOR)
AC_SUBST(PACKAGE_VERSION_MICRO)
AC_SUBST(PACKAGE_VERSION_NANO)
AC_SUBST(PACKAGE_VERSION_SUFFIX)

# Enable DEP and ASLR linker flags
# --------------------------------

AX_CHECK_LINK_FLAG([-Wl,--dynamicbase], [AX_APPEND_FLAG([-Wl,--dynamicbase], LDFLAGS)])
AX_CHECK_LINK_FLAG([-Wl,--nxcompat], [AX_APPEND_FLAG([-Wl,--nxcompat], LDFLAGS)])

# Set Windows-specific linker flags
# ---------------------------------
if test "$windows" = 1 > /dev/null 2>&1; then
  # We currently require Vista minimum.
  AX_CHECK_LINK_FLAG([-Wl,--major-subsystem-version -Wl,6], [AX_APPEND_FLAG([-Wl,--major-subsystem-version -Wl,6], LDFLAGS)])
  AX_CHECK_LINK_FLAG([-Wl,--minor-subsystem-version -Wl,0], [AX_APPEND_FLAG([-Wl,--minor-subsystem-version -Wl,0], LDFLAGS)])
  AX_CHECK_LINK_FLAG([-Wl,--major-os-version -Wl,6], [AX_APPEND_FLAG([-Wl,--major-os-version -Wl,6], LDFLAGS)])
  AX_CHECK_LINK_FLAG([-Wl,--minor-os-version -Wl,0], [AX_APPEND_FLAG([-Wl,--minor-os-version -Wl,0], LDFLAGS)])

  # Set the Large Address Aware flag on 32bit Windows
  if ! echo $host_cpu | grep "x86_64" > /dev/null 2>&1; then
    AX_CHECK_LINK_FLAG([-Wl,--large-address-aware], [AX_APPEND_FLAG([-Wl,--large-address-aware], LDFLAGS)])
  else
     # Base address >4GB to some compatibility mode the kernel uses for old programs
    AX_CHECK_LINK_FLAG([-Wl,--image-base -Wl,0x120000000], [AX_APPEND_FLAG([-Wl,--image-base -Wl,0x120000000], LDFLAGS)])
  fi
fi

# CppUnit tests
# -------------

PKG_CHECK_MODULES(CPPUNIT, [cppunit >= 1.13.0], [have_cppunit=yes],[:])

# Debugging flags
# ---------------

AC_ARG_ENABLE(socketdebug, AS_HELP_STRING([--enable-socketdebug],[Enables debug code to check socket(_layer) invariantes for read/write calls and event sequencing.]), \
        [socketdebug="$enableval"], [dsocketdebug="no"])
if test "$socketdebug" = "yes"; then
  AC_DEFINE(DEBUG_SOCKETEVENTS, 1, [Set to 1 to ensure socket invariants.])
fi


fi

# Doxygen
# -------

DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(libfilezilla, Doxyfile)


# Everything translation related
# ------------------------------

LIBFILEZILLA_LINGUAS=
LIBFILEZILLA_LINGUAS_PO=
LIBFILEZILLA_LINGUAS_MO=
LIBFILEZILLA_LINGUAS_PO_NEW=

if test "$locales" = "yes"; then
  AC_PATH_PROG(xgettext, xgettext)
  if test -z "$xgettext"; then
    AC_MSG_ERROR([xgettext not found, please install the GNU gettext package and make sure xgettext is in the path.])
  fi

  AC_PATH_PROG(msgfmt, msgfmt)
  if test -z "$msgfmt"; then
    AC_MSG_ERROR([ msgfmt not found, please install the GNU gettext package and make sure  msgfmt is in the path.])
  fi

  FZ_PATH_PROG_VER(msgmerge, msgmerge, 0.11.0)
  if test -z "$msgmerge"; then
    AC_MSG_ERROR([msgmerge not found or too old, please install a current version of the GNU gettext package and make sure msgmerge is in the path.])
  fi

  AC_MSG_CHECKING([available libfilezilla message catalogs])

  if /bin/ls > /dev/null; then
    LSPROG='/bin/ls'
  else
    LSPROG='ls'
  fi

  if test x$srcdir = x; then
    path="locales"
  else
    path="$srcdir/locales"
  fi
  for i in `$LSPROG $path/*.po`; do
    i=${i%.*}
    i=${i##*/}
    LIBFILEZILLA_LINGUAS_PO=$LIBFILEZILLA_LINGUAS_PO${LIBFILEZILLA_LINGUAS_PO:+ }\$\(srcdir\)/$i.po
    LIBFILEZILLA_LINGUAS_PO_NEW=$LIBFILEZILLA_LINGUAS_PO_NEW${LIBFILEZILLA_LINGUAS_PO_NEW:+ }$i.po.new
    LIBFILEZILLA_LINGUAS=$LIBFILEZILLA_LINGUAS${LIBFILEZILLA_LINGUAS:+ }$i
    LIBFILEZILLA_LINGUAS_MO=$LIBFILEZILLA_LINGUAS_MO${LIBFILEZILLA_LINGUAS_MO:+ }$i.mo
  done

  AC_MSG_RESULT([$LIBFILEZILLA_LINGUAS])
fi

AC_SUBST(LIBFILEZILLA_LINGUAS)
AC_SUBST(LIBFILEZILLA_LINGUAS_PO)
AC_SUBST(LIBFILEZILLA_LINGUAS_PO_NEW)
AC_SUBST(LIBFILEZILLA_LINGUAS_MO)

# Output automake conditionals
# ----------------------------

AM_CONDITIONAL(FZ_WINDOWS, test "$windows" = "1")
AM_CONDITIONAL(FZ_MAC, test "$mac" = "1")
AM_CONDITIONAL(FZ_UNIX, test "$unix" = "1")
AM_CONDITIONAL(HAVE_CPPUNIT, [test "$have_cppunit" = "yes"])
AM_CONDITIONAL([LOCALES_ONLY], [test "$localesonly" = "yes"])
AM_CONDITIONAL([LOCALES], [test "$locales" = "yes"])

AC_CONFIG_FILES(
  Makefile
  lib/Makefile
  lib/libfilezilla.pc
  lib/libfilezilla/version.hpp
  lib/windows/version.rc
  demos/Makefile
  doc/Doxyfile
  doc/Makefile
  locales/Makefile
  tests/Makefile
)

AC_OUTPUT
