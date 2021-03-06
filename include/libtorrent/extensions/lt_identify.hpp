/*

Copyright (c) 2014, Steven Siloti
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef TORRENT_LT_IDENTIFY_HPP_INCLUDED
#define TORRENT_LT_IDENTIFY_HPP_INCLUDED

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <memory>
#include <functional>
#include <array>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <libtorrent/extensions.hpp>
#include <libtorrent/peer_connection_handle.hpp>
#include <libtorrent/kademlia/types.hpp>

#include "libtorrent/extensions/reputation_export.hpp"

namespace libtorrent
{

struct bdecode_node;
class entry;

struct lt_identify_crypto_plugin;
struct bt_peer_connection_handle;

// represents an ed25519 key pair
struct lt_identify_keypair
{
	dht::secret_key sk;
	dht::public_key pk;
};

struct lt_identify_peer_plugin : peer_plugin
{
	// internal
	lt_identify_peer_plugin(lt_identify_keypair const& key, bt_peer_connection_handle const& pc);

	string_view type() const override { return "lt_identify"; }

	// internal
	void add_handshake(entry& h) override;

	// internal
	bool on_extension_handshake(bdecode_node const& h) override;
	void maybe_send_identify();
	bool on_extended(int length, int msg_id, span<char const> body) override;

	// returns the peer's public key
	// returns NULL if the peer's key is not yet known
	dht::public_key const* peer_key() const
	{
		if (m_got_identify)
			return &m_peer_pk;
		else
			return NULL;
	}

	// takes a BEP10 extension handshake and returns true if it indicates
	// that this extension is supported
	static bool supports_extension(bdecode_node const& h)
	{
		return get_message_index(h) != 0;
	}

	// register a callback to be invoked when the peer's identity is known
	// the callback may be invoked within this function if the peer's identity
	// is already known
	void notify_on_identified(std::function<void(lt_identify_peer_plugin const&)> cb) const
	{
		if (m_got_identify)
			cb(*this);
		else
			m_got_id_notifiers.push_back(cb);
	}

private:
	static const int nonce_size = 24;

	static int get_message_index(bdecode_node const& h);

	lt_identify_keypair const& m_kp;
	bt_peer_connection_handle m_pc;
	std::shared_ptr<lt_identify_crypto_plugin> m_cp;
	dht::public_key m_peer_pk;
	std::array<char, nonce_size> m_nonce;
	int m_message_index;
	bool m_sent_identify:1;
	bool m_got_identify:1;
	mutable std::vector<std::function<void(lt_identify_peer_plugin const&)> > m_got_id_notifiers;
};

struct TORRENT_REPUTATION_EXPORT lt_identify_plugin : plugin
{
	// populate key with a random key pair
	void create_keypair();
	// populate key using the given prng seed
	void create_keypair(std::array<char, 32> const& seed);
	// internal
	std::shared_ptr<torrent_plugin> new_torrent(torrent_handle const&, void*) override;
	// the key pair to use as the client's identity
	lt_identify_keypair key;
};

}

#endif // TORRENT_LT_IDENTIFY_HPP_INCLUDED
