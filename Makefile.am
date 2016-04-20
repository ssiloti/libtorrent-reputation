ACLOCAL_AMFLAGS = -I m4 --install

AM_CXXFLAGS = $(DEPS_CFLAGS) -I$(top_srcdir)/include

lib_LTLIBRARIES = libtorrent-reputation.la

libtorrent_reputation_la_SOURCES = \
    src/sha256.cpp \
    src/lt_identify.cpp \
    src/reputation_manager.cpp \
    src/chacha20poly1305/chacha.cpp \
    src/chacha20poly1305/poly1305.cpp \
    src/chacha20poly1305/chacha20poly1305.cpp

libtorrent_reputation_la_LIBADD = @BOOST_THREAD_LIB@
libtorrent_reputation_la_LDFLAGS = -version-info $(INTERFACE_VERSION_INFO)

includedir = @includedir@/libtorrent/extensions

include_HEADERS = \
    include/libtorrent/extensions/lt_identify.hpp \
    include/libtorrent/extensions/reputation_export.hpp \
    include/libtorrent/extensions/reputation_manager.hpp

noinst_HEADERS = \
    src/chacha20poly1305/chacha.hpp \
    src/chacha20poly1305/poly1305.hpp \
    src/chacha20poly1305/chacha20poly1305.hpp \
    src/sha256.hpp

EXTRA_DIST = \
    Jamroot.jam \
    test/Jamfile \
    test/main.cpp \
    test/test.cpp \
    test/test.hpp \
    test/test_reputation_extension.cpp

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtorrent-reputation.pc
