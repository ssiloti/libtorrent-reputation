/* $OpenBSD: chacha.h,v 1.1 2013/11/21 00:45:44 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_HPP
#define CHACHA_HPP

#include <vector>
#include <boost/asio/buffer.hpp>

struct chacha_ctx {
	unsigned int input[16];
};

#define CHACHA_MINKEYLEN    16
#define CHACHA_NONCELEN     8
#define CHACHA_CTRLEN       8
#define CHACHA_STATELEN     (CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN     64

void chacha_keysetup(struct chacha_ctx *x, const unsigned char *k, unsigned int kbits);
void chacha_ivsetup(struct chacha_ctx *x, const unsigned char *iv, unsigned int blkcnt);
int chacha_encrypt_bytes(struct chacha_ctx *x, std::vector<boost::asio::mutable_buffer> const& m);

#endif	/* CHACHA_H */

