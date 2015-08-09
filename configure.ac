m4_define([VERSION_INFO_CURRENT],[0])
m4_define([VERSION_INFO_REVISION],[0])
m4_define([VERSION_INFO_AGE],[0])

AC_INIT([libtorrent-reputation], [0.0.0], [ssiloti@gmail.com])
AC_CONFIG_SRCDIR([src/reputation_manager.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

INTERFACE_VERSION_INFO=VERSION_INFO_CURRENT:VERSION_INFO_REVISION:VERSION_INFO_AGE
AC_SUBST(INTERFACE_VERSION_INFO)

dnl Pass some build options to .pc file
COMPILETIME_OPTIONS=""

AC_PROG_CXX

AX_BOOST_BASE([1.47])
AX_BOOST_THREAD()
AS_IF([test -z "$BOOST_THREAD_LIB"],
    [AC_MSG_ERROR(Boost.Thread library not found. Try using --with-boost-thread=lib)])

CPPFLAGS="$BOOST_CPPFLAGS $CPPFLAGS"
LDFLAGS="$BOOST_LDFLAGS $LDFLAGS"
LIBS="$BOOST_THREAD_LIB $LIBS"

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES([DEPS], [sqlite3 libtorrent-rasterbar >= 1.1])
AC_SUBST(DEPS_CFLAGS)
AC_SUBST(DEPS_LIBS)

LT_INIT

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_FILES([Makefile] [libtorrent-reputation.pc])

AC_OUTPUT
