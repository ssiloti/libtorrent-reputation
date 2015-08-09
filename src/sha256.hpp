/* Sha256.h -- SHA-256 Hash
2010-06-11 : Igor Pavlov : Public domain */

#ifndef TORRENT_SHA256_HPP_INCLUDED
#define TORRENT_SHA256_HPP_INCLUDED

#include <boost/cstdint.hpp>

#define SHA256_DIGEST_SIZE 32

namespace libtorrent
{

typedef struct
{
	boost::uint32_t state[8];
	boost::uint64_t count;
	boost::uint8_t buffer[64];
} CSha256;

void Sha256_Init(CSha256 *p);
void Sha256_Update(CSha256 *p, const boost::uint8_t *data, size_t size);
void Sha256_Final(CSha256 *p, boost::uint8_t *digest);

}

#endif
