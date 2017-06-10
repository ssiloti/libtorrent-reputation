/* $OpenBSD: poly1305.h,v 1.1 2013/11/21 00:45:44 djm Exp $ */

/*
 * Public Domain poly1305 from Andrew M.
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <libtorrent/span.hpp>

#define POLY1305_KEYLEN 32
#define POLY1305_TAGLEN 16

void poly1305_auth(unsigned char out[POLY1305_TAGLEN]
	, libtorrent::span<libtorrent::span<char>> m
	, const unsigned char key[POLY1305_KEYLEN]);

#endif /* POLY1305_H */
