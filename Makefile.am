ACLOCAL_AMFLAGS = -I m4 --install

AM_CXXFLAGS = $(DEPS_CFLAGS) -I./include

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

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtorrent-reputation.pc
