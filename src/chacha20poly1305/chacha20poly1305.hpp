#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include "chacha.hpp"
#include "poly1305.hpp"

#define crypto_secretbox_KEYBYTES 32
#define crypto_secretbox_NONCEBYTES 8

int crypto_secretbox(std::vector<boost::asio::mutable_buffer> const& m
	, unsigned char tag[POLY1305_TAGLEN]
	, const unsigned char *n
	, const unsigned char *k);

int crypto_secretbox_open(std::vector<boost::asio::mutable_buffer> const& c
	, unsigned char tag[POLY1305_TAGLEN]
	, const unsigned char *n
	, const unsigned char *k);

#endif
