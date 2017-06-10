#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include "chacha.hpp"
#include "poly1305.hpp"

#define crypto_secretbox_KEYBYTES 32
#define crypto_secretbox_NONCEBYTES 8

int crypto_secretbox(libtorrent::span<libtorrent::span<char>> m
	, unsigned char tag[POLY1305_TAGLEN]
	, const unsigned char *n
	, const unsigned char *k);

int crypto_secretbox_open(libtorrent::span<libtorrent::span<char>> c
	, unsigned char tag[POLY1305_TAGLEN]
	, const unsigned char *n
	, const unsigned char *k);

#endif
