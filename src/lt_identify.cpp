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

#include <random>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/shared_ptr.hpp>
#include <boost/bind.hpp>
#include <boost/detail/endian.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/io.hpp"
#include "sha256.hpp"
#include "libtorrent/extensions/lt_identify.hpp"
#include "libtorrent/ed25519.hpp"

#include "chacha20poly1305/chacha20poly1305.hpp"

namespace libtorrent { namespace identify_errors
{
	// libtorrent uses boost.system's ``error_code`` class to represent
	// errors. libtorrent has its own error category get_identify_category()
	// whith the error codes defined by error_code_enum.
	enum error_code_enum
	{
		invalid_identify_message
	};

	// hidden
	boost::system::error_code make_error_code(error_code_enum e);
} } // namespace libtorrent

namespace boost { namespace system
{
	template<> struct is_error_code_enum<libtorrent::identify_errors::error_code_enum>
	{ static const bool value = true; };

	template<> struct is_error_condition_enum<libtorrent::identify_errors::error_code_enum>
	{ static const bool value = true; };
} }

namespace libtorrent
{
	struct identify_error_category : boost::system::error_category
	{
		virtual const char* name() const BOOST_SYSTEM_NOEXCEPT;
		virtual std::string message(int ev) const BOOST_SYSTEM_NOEXCEPT;
		virtual boost::system::error_condition default_error_condition(
			int ev) const BOOST_SYSTEM_NOEXCEPT
		{ return boost::system::error_condition(ev, *this); }
	};

	const char* identify_error_category::name() const BOOST_SYSTEM_NOEXCEPT
	{
		return "identify error";
	}

	std::string identify_error_category::message(int ev) const BOOST_SYSTEM_NOEXCEPT
	{
		static char const* msgs[] =
		{
			"peer sent an invalid identify message",
		};
		if (ev < 0 || ev >= int(sizeof(msgs)/sizeof(msgs[0])))
			return "Unknown error";
		return msgs[ev];
	}

	boost::system::error_category& get_identify_category()
	{
		static identify_error_category bdecode_category;
		return bdecode_category;
	}

namespace identify_errors
{
	boost::system::error_code make_error_code(error_code_enum e)
	{
		return boost::system::error_code(e, get_identify_category());
	}
}

namespace
{
	inline void htol(boost::uint64_t v, unsigned char p[crypto_secretbox_NONCEBYTES])
	{
		for (unsigned i = 0; i < sizeof(boost::uint64_t); ++i)
			p[i] = (unsigned char)((v >> (i*8)) & 0xFF);
	}
}

struct lt_identify_crypto_plugin : crypto_plugin
{
	lt_identify_crypto_plugin(bool is_outgoing)
	: local_nonce(is_outgoing ? 1 : 2)
	, remote_nonce(is_outgoing ? 2 : 1)
	, can_encrypt(false)
	{}

	virtual void set_incoming_key(unsigned char const* key, int len)
	{
		TORRENT_ASSERT(len == crypto_secretbox_KEYBYTES);
		memcpy(this->key, key, crypto_secretbox_KEYBYTES);
		can_encrypt = true;
	}

	virtual void set_outgoing_key(unsigned char const* key, int len)
	{ set_incoming_key(key, len); }

	virtual int encrypt(std::vector<boost::asio::mutable_buffer>& vec)
	{
		if (!can_encrypt) { vec.clear(); return 0; }

		unsigned char nonce[crypto_secretbox_NONCEBYTES];
		htol(local_nonce, nonce);
		int produce = crypto_secretbox(vec, header.tag, nonce, key);
		unsigned char* psize = header.length;
		detail::write_uint32(produce + sizeof(header.tag), psize);
		vec.resize(1);
		vec[0] = boost::asio::mutable_buffer(header.all, sizeof(header));
		local_nonce += 2;
		return produce + sizeof(header);
	}

	// the header must not be split across buffers
	// TODO: how does the caller know the size of the header?
	virtual void decrypt(std::vector<boost::asio::mutable_buffer>& vec
		, int& consume, int& produce, int& packet_size)
	{
		namespace asio = boost::asio;

		TORRENT_ASSERT(can_encrypt);
		produce = 0;
		packet_size = sizeof(header);
		if (vec.empty())
			return;
		TORRENT_ASSERT(asio::buffer_size(vec[0]) >= sizeof(header));
		unsigned char* recv_buffer = asio::buffer_cast<unsigned char*>(vec[0]);
		packet_size = detail::read_int32(recv_buffer) + sizeof(header.length);
		if (asio::buffer_size(vec[0]) == sizeof(header) && vec.size() == 1)
			return;
		unsigned char* tag = recv_buffer;
		vec[0] = vec[0] + sizeof(header);
		if (asio::buffer_size(vec[0]) == 0)
			vec.erase(vec.begin());
		unsigned char nonce[crypto_secretbox_NONCEBYTES];
		htol(remote_nonce, nonce);
		produce = crypto_secretbox_open(vec, tag, nonce, key);
		consume = sizeof(header);
		packet_size = sizeof(header);
		remote_nonce += 2;
	}

	unsigned char key[crypto_secretbox_KEYBYTES];
	boost::uint64_t local_nonce, remote_nonce;
	union
	{
		unsigned char all[sizeof(uint32_t)+POLY1305_TAGLEN];
		struct
		{
			unsigned char length[sizeof(uint32_t)];
			unsigned char tag[POLY1305_TAGLEN];
		};
	} header;
	bool can_encrypt;
};

namespace
{
	struct lt_identify_torrent_plugin : torrent_plugin
	{
		lt_identify_torrent_plugin(lt_identify_keypair const& sp)
		: m_kp(sp)
		{}

		virtual boost::shared_ptr<peer_plugin> new_connection(
			peer_connection_handle const& pc)
		{
			if (pc.type() != peer_connection::bittorrent_connection)
				return boost::shared_ptr<peer_plugin>();

			bt_peer_connection_handle c(pc);
			return boost::shared_ptr<peer_plugin>(new lt_identify_peer_plugin(m_kp, c));
		}

	private:
		lt_identify_keypair const& m_kp;
	};
}

lt_identify_peer_plugin::lt_identify_peer_plugin(lt_identify_keypair const& sp
	, bt_peer_connection_handle const& pc)
	: m_kp(sp)
	, m_pc(pc)
	, m_message_index(0)
	, m_sent_identify(false)
	, m_got_identify(false)
{
	static std::random_device dev;
	static std::uniform_int_distribution<short> dist(
		std::numeric_limits<char>::min()
		, std::numeric_limits<char>::max());
	for (int i=0; i < nonce_size; ++i)
		m_nonce[i] = char(dist(dev));
}

void lt_identify_peer_plugin::add_handshake(entry& h)
{
	entry& messages = h["m"];
	messages["lt_identify"] = 9;
}

bool lt_identify_peer_plugin::on_extension_handshake(bdecode_node const& h)
{
	m_message_index = get_message_index(h);
	if (m_message_index == 0)
		return false;

	m_cp = boost::make_shared<lt_identify_crypto_plugin>(m_pc.is_outgoing());

	maybe_send_identify();
	return true;
}

void lt_identify_peer_plugin::maybe_send_identify()
{
	if (m_pc.is_disconnecting()) return;

	if (m_message_index == 0 || m_sent_identify)
		return;

#ifndef TORRENT_DISABLE_LOGGING
	m_pc.peer_log(peer_log_alert::outgoing_message, "LT_IDENTIFY");
#endif

	entry e;
	e["pk"] = std::string(m_kp.pk.data(), m_kp.pk.size());
	e["nonce"] = std::string(m_nonce, nonce_size);

	char msg[128];
	char* header = msg;
	char* p = &msg[6];
	int len = bencode(p, e);
	int total_size = 2 + len;
	namespace io = detail;
	io::write_uint32(total_size, header);
	io::write_uint8(bt_peer_connection::msg_extended, header);
	io::write_uint8(m_message_index, header);
	m_pc.send_buffer(msg, len + 6);
	m_pc.switch_send_crypto(m_cp);
	m_sent_identify = true;
}

bool lt_identify_peer_plugin::on_extended(int length, int msg_id
	, buffer::const_interval body)
{
	if (msg_id != 9) return false;
	if (m_cp->can_encrypt) return true;
	if (!m_pc.packet_finished()) return true;

	int len;
	entry msg = bdecode(body.begin, body.end, len);
	if (msg.type() != entry::dictionary_t)
	{
#ifndef TORRENT_DISABLE_LOGGING
		m_pc.peer_log(peer_log_alert::incoming_message, "LT_IDENTIFY [ not a dictionary ]");
#endif
		m_pc.disconnect(identify_errors::invalid_identify_message, op_bittorrent, 2);
		return true;
	}

	entry const* pk_ent = msg.find_key("pk");
	entry const* nonce_ent = msg.find_key("nonce");
	if (pk_ent == 0
		|| pk_ent->type() != entry::string_t
		|| pk_ent->string().size() != m_peer_pk.size()
		|| nonce_ent == 0
		|| nonce_ent->type() != entry::string_t
		|| nonce_ent->string().size() != nonce_size)
	{
#ifndef TORRENT_DISABLE_LOGGING
		m_pc.peer_log(peer_log_alert::incoming_message, "LT_IDENTIFY [ missing or invalid keys ]");
#endif
		m_pc.disconnect(identify_errors::invalid_identify_message, op_bittorrent, 2);
		return true;
	}

#ifndef TORRENT_DISABLE_LOGGING
	m_pc.peer_log(peer_log_alert::incoming_message, "LT_IDENTIFY");
#endif

	memcpy(m_peer_pk.data(), pk_ent->string().data(), m_peer_pk.size());
	struct
	{
		unsigned char shared_secret[ed25519_shared_secret_size];
		unsigned char outgoing_nonce[nonce_size];
		unsigned char incoming_nonce[nonce_size];
	} key_iv;
	ed25519_key_exchange(key_iv.shared_secret
		, (unsigned char*)m_peer_pk.data()
		, (unsigned char*)m_kp.sk.data());

	if (m_pc.is_outgoing())
	{
		memcpy(key_iv.outgoing_nonce, m_nonce, nonce_size);
		memcpy(key_iv.incoming_nonce, nonce_ent->string().data(), nonce_size);
	}
	else
	{
		memcpy(key_iv.outgoing_nonce, nonce_ent->string().data(), nonce_size);
		memcpy(key_iv.incoming_nonce, m_nonce, nonce_size);
	}

	unsigned char key[crypto_secretbox_KEYBYTES];
	CSha256 p;
	Sha256_Init(&p);
	Sha256_Update(&p, (unsigned char*)&key_iv, sizeof(key_iv));
	Sha256_Final(&p, key);
	m_cp->set_incoming_key(key, crypto_secretbox_KEYBYTES);
	m_pc.switch_recv_crypto(m_cp);
	m_got_identify = true;

	for (std::vector<boost::function<void(lt_identify_peer_plugin const&)> >::iterator
		i = m_got_id_notifiers.begin();
		i != m_got_id_notifiers.end(); ++i)
		(*i)(*this);
	m_got_id_notifiers.clear();

	return true;
}

int lt_identify_peer_plugin::get_message_index(bdecode_node const& h)
{
	if (h.type() != bdecode_node::dict_t) return 0;
	bdecode_node messages = h.dict_find_dict("m");
	if (!messages) return 0;

	int index = messages.dict_find_int_value("lt_identify", -1);
	if (index == -1) return 0;
	return index;
}

void lt_identify_plugin::create_keypair()
{
	boost::array<unsigned char, ed25519_seed_size> seed;
	ed25519_create_seed(seed.data());
	create_keypair(seed);
}

void lt_identify_plugin::create_keypair(boost::array<unsigned char, ed25519_seed_size> const& seed)
{
	ed25519_create_keypair((unsigned char*)key.pk.data(), (unsigned char*)key.sk.data(), seed.data());
}

boost::shared_ptr<torrent_plugin> lt_identify_plugin::new_torrent(torrent_handle const&, void*)
{
	return boost::make_shared<lt_identify_torrent_plugin>(this->key);
}

} // namespace libtorrent
