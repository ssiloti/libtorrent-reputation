/*
 * Copyright (c) 2013
 * Frank Denis <j at pureftpd dot org>, Steven Siloti
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "chacha20poly1305.hpp"
#include <cassert>

int crypto_secretbox(libtorrent::span<libtorrent::span<char>> m
	, unsigned char tag[POLY1305_TAGLEN]
	, const unsigned char *n
	, const unsigned char *k)
{
	int i;
	std::array<char, POLY1305_KEYLEN> subkey;
	chacha_ctx ctx;
	for (i = 0;i < POLY1305_KEYLEN;++i) subkey[i] = 0;
	chacha_keysetup(&ctx,k,crypto_secretbox_KEYBYTES*8);
	chacha_ivsetup(&ctx,n,0);
	libtorrent::span<char> subkey_span(subkey);
	chacha_encrypt_bytes(&ctx, { &subkey_span, 1 });
	chacha_ivsetup(&ctx,n,1);
	int encrypted_bytes = chacha_encrypt_bytes(&ctx,m);
	poly1305_auth(tag,m,(unsigned char*)subkey.data());
	return encrypted_bytes;
}

int crypto_verify_16(const unsigned char *x,const unsigned char *y)
{
  unsigned int differentbits = 0;
#define F(i) differentbits |= x[i] ^ y[i];
  F(0)
  F(1)
  F(2)
  F(3)
  F(4)
  F(5)
  F(6)
  F(7)
  F(8)
  F(9)
  F(10)
  F(11)
  F(12)
  F(13)
  F(14)
  F(15)
  return (1 & ((differentbits - 1) >> 8)) - 1;
}

int crypto_secretbox_open(libtorrent::span<libtorrent::span<char>> c
	, unsigned char tag[POLY1305_TAGLEN]
	, const unsigned char *n
	, const unsigned char *k)
{
	int i;
	std::array<char, POLY1305_KEYLEN> subkey;
	unsigned char polytag[POLY1305_TAGLEN];
	chacha_ctx ctx;
	for (i = 0;i < POLY1305_KEYLEN;++i) subkey[i] = 0;
	chacha_keysetup(&ctx,k,crypto_secretbox_KEYBYTES*8);
	chacha_ivsetup(&ctx,n,0);
	libtorrent::span<char> subkey_span(subkey);
	chacha_encrypt_bytes(&ctx, { &subkey_span, 1 });
	poly1305_auth(polytag,c,(unsigned char*)subkey.data());
	if (crypto_verify_16(polytag,tag) != 0) return -1;
	chacha_ivsetup(&ctx,n,1);
	return chacha_encrypt_bytes(&ctx,c);
}
