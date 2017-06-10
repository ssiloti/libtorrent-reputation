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

//#define TORRENT_SESSION_HPP_INCLUDED
//#define TORRENT_PEER_CONNECTION_HANDLE_HPP_INCLUDED
//#define TORRENT_BT_PEER_CONNECTION_HPP_INCLUDED
//#define TORRENT_LT_IDENTIFY_HPP_INCLUDED
//#define TORRENT_EXTENSIONS_HPP_INCLUDED
//#include "libtorrent/session.hpp"
#include "test.hpp"

// any headers which reference peer_connection must be included before the
// mockups to avoid ambiguous references
#include <map>
#include <vector>
#include <limits>
#include <queue>
#include <sqlite3.h>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/thread/condition_variable.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <libtorrent/extensions/lt_identify.hpp>
#include <libtorrent/session_handle.hpp>
#include <libtorrent/kademlia/msg.hpp>
#include <libtorrent/kademlia/item.hpp>
#include <libtorrent/peer_connection_handle.hpp>
#include <libtorrent/bt_peer_connection.hpp> // for bt_peer_connection::msg_extended
#include <libtorrent/sha1_hash.hpp>
#include <libtorrent/io.hpp>
#include <libtorrent/bdecode.hpp>
#include <libtorrent/bencode.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/session_status.hpp>
#include <libtorrent/kademlia/ed25519.hpp>

#include <libtorrent/alert_manager.hpp>

namespace libtorrent {

	namespace { class reputation_peer_plugin; }

namespace mocks
{
	struct torrent_handle;
	struct session_handle;
	struct bt_peer_connection_handle;
	typedef bt_peer_connection_handle peer_connection_handle;

	struct torrent_plugin;

	struct plugin
	{
		// hidden
		virtual ~plugin() {}

		// these are flags that can be returned by implemented_features()
		// indicating which callbacks this plugin is interested in
		enum feature_flags_t
		{
			// include this bit if your plugin needs to alter the order of the
			// optimistic unchoke of peers. i.e. have the on_optimistic_unchoke()
			// callback be called.
			optimistic_unchoke_feature = 1,

			// include this bit if your plugin needs to have on_tick() called
			tick_feature = 2,

			// include this bit if your plugin needs to have on_dht_request()
			// called
			dht_request_feature = 4,

			// include this bit if your plugin needs to have on_alert()
			// called
			alert_feature = 8,
		};

		// This function is expected to return a bitmask indicating which features
		// this plugin implements. Some callbacks on this object may not be called
		// unless the corresponding feature flag is returned here. Note that
		// callbacks may still be called even if the corresponding feature is not
		// specified in the return value here. See feature_flags_t for possible
		// flags to return.
		virtual std::uint32_t implemented_features() { return 0; }

		// this is called by the session every time a new torrent is added.
		// The ``torrent*`` points to the internal torrent object created
		// for the new torrent. The ``void*`` is the userdata pointer as
		// passed in via add_torrent_params.
		//
		// If the plugin returns a torrent_plugin instance, it will be added
		// to the new torrent. Otherwise, return an empty shared_ptr to a
		// torrent_plugin (the default).
		virtual std::shared_ptr<torrent_plugin> new_torrent(torrent_handle const&, void*)
		{
			return std::shared_ptr<torrent_plugin>();
		}

		// called when plugin is added to a session
		virtual void added(session_handle const&) {}

		// called when a dht request is received.
		// If your plugin expects this to be called, make sure to include the flag
		// ``dht_request_feature`` in the return value from implemented_features().
		virtual bool on_dht_request(string_view /* query */
			, udp::endpoint const& /* source */, bdecode_node const& /* message */
			, entry& /* response */)
		{
			return false;
		}

		// called when an alert is posted alerts that are filtered are not posted.
		// If your plugin expects this to be called, make sure to include the flag
		// ``alert_feature`` in the return value from implemented_features().
		virtual void on_alert(alert const*) {}

		// return true if the add_torrent_params should be added
		virtual bool on_unknown_torrent(sha1_hash const& /* info_hash */
			, peer_connection_handle const& /* pc */, add_torrent_params& /* p */)
		{
			return false;
		}

		// called once per second.
		// If your plugin expects this to be called, make sure to include the flag
		// ``tick_feature`` in the return value from implemented_features().
		virtual void on_tick() {}

		// called when choosing peers to optimistically unchoke. The return value
		// indicates the peer's priority for unchoking. Lower return values
		// correspond to higher priority. Priorities above 2^63-1 are reserved.
		// If your plugin has no priority to assign a peer it should return 2^64-1.
		// If your plugin expects this to be called, make sure to include the flag
		// ``optimistic_unchoke_feature`` in the return value from implemented_features().
		// If multiple plugins implement this function the lowest return value
		// (i.e. the highest priority) is used.
		virtual uint64_t get_unchoke_priority(peer_connection_handle const& /* peer */)
		{
			return std::numeric_limits<uint64_t>::max();
		}

		// called when saving settings state
		virtual void save_state(entry&) {}

		// called when loading settings state
		virtual void load_state(bdecode_node const&) {}
	};

	// Torrent plugins are associated with a single torrent and have a number
	// of functions called at certain events. Many of its functions have the
	// ability to change or override the default libtorrent behavior.
	struct torrent_plugin
	{
		// hidden
		virtual ~torrent_plugin() {}

		// This function is called each time a new peer is connected to the torrent. You
		// may choose to ignore this by just returning a default constructed
		// ``shared_ptr`` (in which case you don't need to override this member
		// function).
		//
		// If you need an extension to the peer connection (which most plugins do) you
		// are supposed to return an instance of your peer_plugin class. Which in
		// turn will have its hook functions called on event specific to that peer.
		//
		// The ``peer_connection_handle`` will be valid as long as the ``shared_ptr``
		// is being held by the torrent object. So, it is generally a good idea to not
		// keep a ``shared_ptr`` to your own peer_plugin. If you want to keep references
		// to it, use ``weak_ptr``.
		//
		// If this function throws an exception, the connection will be closed.
		virtual std::shared_ptr<peer_plugin> new_connection(peer_connection_handle const&)
		{
			return std::shared_ptr<peer_plugin>();
		}

		// These hooks are called when a piece passes the hash check or fails the hash
		// check, respectively. The ``index`` is the piece index that was downloaded.
		// It is possible to access the list of peers that participated in sending the
		// piece through the ``torrent`` and the ``piece_picker``.
		virtual void on_piece_pass(piece_index_t /*index*/) {}
		virtual void on_piece_failed(piece_index_t /*index*/) {}

		// This hook is called approximately once per second. It is a way of making it
		// easy for plugins to do timed events, for sending messages or whatever.
		virtual void tick() {}

		// These hooks are called when the torrent is paused and unpaused respectively.
		// The return value indicates if the event was handled. A return value of
		// ``true`` indicates that it was handled, and no other plugin after this one
		// will have this hook function called, and the standard handler will also not be
		// invoked. So, returning true effectively overrides the standard behavior of
		// pause or unpause.
		//
		// Note that if you call ``pause()`` or ``resume()`` on the torrent from your
		// handler it will recurse back into your handler, so in order to invoke the
		// standard handler, you have to keep your own state on whether you want standard
		// behavior or overridden behavior.
		virtual bool on_pause() { return false; }
		virtual bool on_resume() { return false; }

		// This function is called when the initial files of the torrent have been
		// checked. If there are no files to check, this function is called immediately.
		//
		// i.e. This function is always called when the torrent is in a state where it
		// can start downloading.
		virtual void on_files_checked() {}

		// called when the torrent changes state
		// the state is one of torrent_status::state_t
		// enum members
		virtual void on_state(int /*s*/) {}

		// called every time policy::add_peer is called
		// src is a bitmask of which sources this peer
		// has been seen from. flags is a bitmask of:

		enum flags_t {
			// this is the first time we see this peer
			first_time = 1,
			// this peer was not added because it was
			// filtered by the IP filter
			filtered = 2
		};

		// called every time a new peer is added to the peer list.
		// This is before the peer is connected to. For ``flags``, see
		// torrent_plugin::flags_t. The ``source`` argument refers to
		// the source where we learned about this peer from. It's a
		// bitmask, because many sources may have told us about the same
		// peer. For peer source flags, see peer_info::peer_source_flags.
		virtual void on_add_peer(tcp::endpoint const&,
			int /*src*/, int /*flags*/) {}
	};

	struct lt_identify_keypair
	{
		dht::secret_key sk;
		dht::public_key pk;
	};

	struct lt_identify_peer_plugin : peer_plugin
	{
		lt_identify_peer_plugin(dht::public_key const& k)
			: pk(k)
		{}

		static bool supports_extension(bdecode_node const&)
		{
			return true;
		}

		dht::public_key const* peer_key() const
		{
			return &pk;
		}

		void notify_on_identified(std::function<void(lt_identify_peer_plugin const&)> cb) const
		{
			cb(*this);
		}

		dht::public_key const& pk;
	};

	struct lt_identify_plugin : plugin
	{
		// populate key with a random key pair
		void create_keypair()
		{
			create_keypair(dht::ed25519_create_seed());
		}

		// populate key using the given prng seed
		void create_keypair(std::array<char, 32> const& seed)
		{
			std::tie(key.pk, key.sk) = dht::ed25519_create_keypair(seed);
		}

		// the key pair to use as the client's identity
		lt_identify_keypair key;
	};

	namespace asio = boost::asio;

	time_point current_time = ::libtorrent::clock_type::now();

	struct clock_type
	{
		static time_point now() { return current_time; }
	};

	struct torrent_handle
	{
		static const boost::uint32_t query_accurate_download_counters = 1;

		torrent_handle(boost::int64_t size, boost::int64_t done, torrent_status::state_t state)
			: m_down_limit(0)
		{
			m_status.total_wanted_done = done;
			m_status.total_wanted = size;
			m_status.state = state;
		}

		bool is_valid() const { return true; }
		torrent_status status(boost::uint32_t flags = 0xffffffff) const
		{
			return m_status;
		}
		int download_limit() const { return m_down_limit; }

		torrent_status m_status;
		int m_down_limit;
	};

	struct bt_peer_connection
	{
		enum { msg_extended = 20 };
	};

	struct bt_peer_connection_mock_impl
	{
		bt_peer_connection_mock_impl(dht::public_key const& k);

		lt_identify_peer_plugin identity;
		tcp::endpoint m_remote;
		std::vector<std::pair<std::vector<char>, int> > sent_buffers;
		std::shared_ptr<reputation_peer_plugin> rep;
		torrent_handle m_torrent;
		int sent_chokes;

		bool choked : 1;
		bool interesting : 1;
		bool peer_choked : 1;
		bool peer_interested : 1;
		bool pckt_finished : 1;
		bool disconnected : 1;
	};

	struct bt_peer_connection_handle
	{
		bt_peer_connection_handle(bt_peer_connection_mock_impl* impl)
			: m_impl(impl)
		{}

		peer_plugin const* find_plugin(char const* type) const;

		bool ignore_unchoke_slots() const { return false; }
		void choke_this_peer() { m_impl->sent_chokes++; }

		connection_type type() const { return connection_type::bittorrent; }

		bool is_choked() { return m_impl->choked; }
		bool is_interesting() { return m_impl->interesting; }
		bool has_peer_choked() { return m_impl->peer_choked; }
		bool is_peer_interested() { return m_impl->peer_interested; }
		bool packet_finished() { return m_impl->pckt_finished; }
		bool is_disconnecting() { return false; }

		void disconnect(error_code const&, operation_t, int)
		{
			m_impl->disconnected = true;
		}

		tcp::endpoint const& remote() const { return m_impl->m_remote; }

		torrent_handle associated_torrent() const
		{
			return m_impl->m_torrent;
		}

		void send_buffer(char const* buf, int size, int flags = 0)
		{
			m_impl->sent_buffers.push_back(std::make_pair(std::vector<char>(buf, buf + size), flags));
		}

		bool operator<(bt_peer_connection_handle const& o) const
		{ return m_impl < o.m_impl; }

		bt_peer_connection_mock_impl* m_impl;
	};

	struct dht_direct_request_t
	{
		boost::asio::ip::udp::endpoint ep;
		entry e;
		void* userdata;
	};

	bt_peer_connection_mock_impl::bt_peer_connection_mock_impl(dht::public_key const& k)
		: identity(k)
		, m_torrent(boost::int64_t(0), boost::int64_t(0), torrent_status::downloading)
		, sent_chokes(0)
		, choked(true)
		, interesting(false)
		, peer_choked(true)
		, peer_interested(false)
		, pckt_finished(true)
		, disconnected(false)
	{}

	struct session_mock_impl
	{
		session_mock_impl(std::vector<dht::item>& store)
			: m_dht_store(store)
			, m_pending_dht_alerts(8, 0xFFFFFFFF)
		{}

		void post_alerts()
		{
			std::vector<alert*> alerts;
			m_pending_dht_alerts.get_all(alerts);
			for (std::vector<alert*>::iterator i = alerts.begin();
			i != alerts.end(); ++i)
			{
				post_alert(*i);
			}
		}

		void post_alert(alert const* a);

		std::vector<dht_direct_request_t> m_dht_direct_requests;
		std::vector<dht::item>& m_dht_store;
		alert_manager m_pending_dht_alerts;
		unsigned short m_listen_port;
		std::vector<torrent_handle> m_torrents;
		settings_pack m_settings;
		session_status m_status;
		plugin* m_rep_plugin;
	};

	struct session_handle
	{
		session_handle() : m_impl(NULL) {}

		// mocks
		bool is_valid() const { return true; }
		bool is_dht_running() const { return true; }

		void dht_direct_request(udp::endpoint ep, entry const& e, void* userdata = 0)
		{
			dht_direct_request_t r;
			r.ep = ep;
			r.e = e;
			r.userdata = userdata;
			m_impl->m_dht_direct_requests.push_back(r);
		}

		void dht_get_item(std::array<char, 32> key
			, std::string salt = std::string())
		{
			for (std::vector<dht::item>::iterator i = m_impl->m_dht_store.begin();
			i != m_impl->m_dht_store.end(); ++i)
			{
				if (i->pk().bytes == key && i->salt() == salt)
				{
					m_impl->m_pending_dht_alerts.emplace_alert<dht_mutable_item_alert>(
						i->pk().bytes, i->sig().bytes, i->seq().value, i->salt(), i->value(), true);
					return;
				}
			}
			m_impl->m_pending_dht_alerts.emplace_alert<dht_mutable_item_alert>(
				key, std::array<char, 64>(), 0, salt, entry(), true);
		}

		void dht_put_item(std::array<char, 32> key
			, std::function<void(entry&, std::array<char, 64>&
			, boost::int64_t&, std::string const&)> cb
			, std::string salt = std::string())
		{
			for (std::vector<dht::item>::iterator i = m_impl->m_dht_store.begin();
			i != m_impl->m_dht_store.end(); ++i)
			{
				if (i->pk().bytes == key && i->salt() == salt)
				{
					entry value = i->value();
					auto sig = i->sig();
					auto seq = i->seq();
					cb(value, sig.bytes, seq.value, salt);
					i->assign(value, salt, seq, i->pk(), sig);
					return;
				}
			}
			entry value;
			dht::signature sig;
			dht::sequence_number seq;
			cb(value, sig.bytes, seq.value, salt);
			dht::item i;
			i.assign(value, salt, seq, dht::public_key(key.data()), sig);
			m_impl->m_dht_store.push_back(i);
		}

		unsigned short listen_port() const { return m_impl->m_listen_port; }

		std::vector<torrent_handle> get_torrents() const
		{ return m_impl->m_torrents; }

		settings_pack get_settings() const
		{ return m_impl->m_settings; }

		session_status status() const
		{ return m_impl->m_status; }

		struct mock_io_service
		{
			template <typename Func>
			void dispatch(Func f)
			{
				f();
			}
		};

		mock_io_service get_io_service() { return mock_io_service(); }

		// internal
		session_handle(session_mock_impl* impl)
			: m_impl(impl)
		{}

		session_mock_impl* m_impl;
	};

	time_t test_time;

	time_t time(void*)
	{
		return test_time;
	}

} // namespace mocks

} // namespace libtorrent

#define TORRENT_DISABLE_LOGGING
#define TORRENT_REPUTATION_MANAGER_TEST

#define plugin mocks::plugin
#define torrent_plugin mocks::torrent_plugin
#define lt_identify_keypair mocks::lt_identify_keypair
#define lt_identify_peer_plugin mocks::lt_identify_peer_plugin
#define lt_identify_plugin mocks::lt_identify_plugin
#define torrent_handle mocks::torrent_handle
#define session_handle mocks::session_handle
#define bt_peer_connection_handle mocks::bt_peer_connection_handle
#define peer_connection_handle mocks::peer_connection_handle
#define bt_peer_connection mocks::bt_peer_connection
#define dht_direct_request_t mocks::dht_direct_request_t
#define clock_type mocks::clock_type
#define current_time mocks::current_time
#define time mocks::time

#include "../src/reputation_manager.cpp"

#undef plugin
#undef torrent_plugin
#undef lt_identify_keypair
#undef lt_identify_peer_plugin
#undef lt_identify_plugin
#undef torrent_handle
#undef session_handle
#undef bt_peer_connection_handle
#undef peer_connection_handle
#undef bt_peer_connection
#undef dht_direct_request_t
#undef clock_type
#undef current_time
#undef time

namespace libtorrent
{
namespace mocks
{
	peer_plugin const* bt_peer_connection_handle::find_plugin(char const* type) const
	{
		if (strcmp(type, "lt_identify") == 0)
			return &m_impl->identity;
		else if (strcmp(type, "reputation") == 0)
			return m_impl->rep.get();
		else
			return NULL;
	}

	void session_mock_impl::post_alert(alert const* a)
	{
		static_cast<reputation_manager*>(m_rep_plugin)->on_alert(a);
	}

	struct test_identity
	{
		test_identity()
			: connection(key.pk)
			, sequence(0)
		{
			std::tie(key.pk, key.sk) = dht::ed25519_create_keypair(
				dht::ed25519_create_seed());
			rid = hasher(key.pk.bytes).final();
		}

		lt_identify_keypair key;
		bt_peer_connection_mock_impl connection;
		reputation_key rkey;
		reputation_id rid;
		contact_info ci;
		boost::int64_t sequence;
	};

	struct test_client
	{
		test_client()
			: identity(std::make_shared<lt_identify_plugin>())
			, repman_hnd(create_reputation_plugin(*identity, ".", ""))
			, ses(std::make_shared<session_mock_impl>(std::ref(dht_store)))
		{
			ses->m_listen_port = 1;
			ses->m_rep_plugin = repman_hnd.reputation_plugin.get();
			repman().added(session_handle(ses.get()));
		}

		reputation_manager& repman()
		{ return *static_cast<reputation_manager*>(repman_hnd.reputation_plugin.get()); }

		std::shared_ptr<lt_identify_plugin> identity;
		reputation_handle repman_hnd;
		std::vector<dht::item> dht_store;
		std::shared_ptr<session_mock_impl> ses;
	};

	std::pair<stored_standing_update, signed_state> generate_forward_standing(
		reputation_manager& repman
		, test_identity& recipient
		, reputation_key intermediary
		, reputation_id const& intermediary_rid)
	{
		entry e;
		e["seq"] = recipient.sequence++;
		e["sender"] = repman.client_rid().to_string();
		e["recipient"] = recipient.rid.to_string();
		e["intermediary"] = intermediary_rid.to_string();
		e["volume"] = 1;
		{
			std::vector<char> sig_buf;
			bencode(std::back_inserter(sig_buf), e);
			dht::signature sig;
			sig = dht::ed25519_sign(sig_buf
				, recipient.key.pk
				, recipient.key.sk);
			e["sig"] = sig.bytes;
		}

		standing_update update(e, repman.client_rid(), recipient.rid, recipient.key.pk);
		stored_standing_update stored_update(update, intermediary, recipient.rkey);

		signed_state peer_state;
		peer_state.subject = intermediary_rid;
		peer_state.download_referred = 1;
		repman.update_state_for(intermediary, peer_state);

		return std::make_pair(stored_update, peer_state);
	}

	int reply_to_update_standing(bool success
		, dht_direct_request_t& req
		, reputation_manager& repman
		, asio::ip::udp::endpoint const& ep
		, stored_standing_update const& u
		, reputation_key test_peer
		, reputation_id const& rid
		, reputation_id const& client_rid
		, lt_identify_keypair const& kp)
	{
		TEST_EQUAL(req.ep, ep);
		TEST_EQUAL(req.e["q"].string(), std::string("update_standing"));
		entry const& a = req.e["a"];
		TEST_EQUAL(a["receipt"]["seq"].integer(), u.update.sequence);
		TEST_EQUAL(a["receipt"]["sender"], repman.client_rid().to_string());
		TEST_EQUAL(a["receipt"]["recipient"], u.update.recipient.to_string());
		TEST_CHECK(a["receipt"].find_key("intermediary") == NULL);
		TEST_EQUAL(a["receipt"]["volume"].integer(), u.update.volume);

		if (success)
		{
			entry reply;
//			reply["t"] = req.e["t"];
			reply["y"] = "q";
			reply["r"]["id"] = std::string("12345678901234567890");
			signed_state current_state;
			current_state.subject = client_rid;
			repman.state_at(test_peer, client_reputation_key, current_state);
			{
				reply["r"]["state"] = current_state.reputation_state::to_entry();
				reply["r"]["state"]["rr"].integer() += a["receipt"]["volume"].integer();
				reply["r"]["state"].dict().erase("sig");

				std::vector<char> sig_buf;
				bencode(std::back_inserter(sig_buf), reply["r"]["state"]);
				dht::signature sig;
				sig = dht::ed25519_sign(sig_buf, kp.pk, kp.sk);
				reply["r"]["state"]["sig"] = sig.bytes;
			}
			std::vector<char> lazy_buf;
			bencode(std::back_inserter(lazy_buf), reply);
			bdecode_node lazy_reply;
			error_code ec;
			bdecode(lazy_buf.data(), (&lazy_buf.back())+1, lazy_reply, ec);
			{
				aux::stack_allocator alloc;
				dht_direct_response_alert a(alloc, req.userdata, ep, lazy_reply);
				repman.on_alert(&a);
			}

			{
				signed_state state;
				TEST_CHECK(repman.state_at(test_peer, client_reputation_key, state));
				TEST_EQUAL(state.upload_direct, current_state.upload_direct);
				TEST_EQUAL(state.download_direct, current_state.download_direct);
				TEST_EQUAL(state.upload_recommended, current_state.upload_recommended);
				TEST_EQUAL(state.download_recommended, current_state.download_recommended);
				TEST_EQUAL(state.upload_referred, current_state.upload_referred);
				TEST_EQUAL(state.download_referred, current_state.download_referred + a["receipt"]["volume"].integer());
			}
		}
		else
		{
			aux::stack_allocator alloc;
			dht_direct_response_alert a(alloc, req.userdata, ep);
			repman.on_alert(&a);
		}

		return 0;
	}

	typedef std::array<test_identity, 3> peer_ids_t;
	void create_test_peers(reputation_manager& repman, peer_ids_t& peers)
	{
		for (peer_ids_t::iterator i = peers.begin();
			i != peers.end(); ++i)
		{
			i->connection.rep = std::make_shared<reputation_peer_plugin>(
				std::ref(repman)
				, bt_peer_connection_handle(&i->connection));
			i->ci.addr_v4 = asio::ip::address_v4::from_string("1.2.3.4");
			i->ci.port = std::distance(peers.begin(), i);
			i->connection.m_remote.address(i->ci.addr_v4);
			i->connection.m_remote.port(i->ci.port);

			{
				entry e;
				e["m"]["lt_known_peers"] = 1;
				e["m"]["lt_my_standing"] = 2;
				e["m"]["lt_your_standing"] = 3;
				e["m"]["lt_attribution"] = 4;
				e["m"]["lt_receipt"] = 5;
				std::vector<char> handshake_buf;
				bencode(std::back_inserter(handshake_buf), e);
				bdecode_node handshake;
				error_code ec;
				bdecode(handshake_buf.data(), handshake_buf.data() + handshake_buf.size(), handshake, ec);
				TEST_CHECK(i->connection.rep->on_extension_handshake(handshake));
			}

			i->connection.rep->establish_rkey();
			i->rkey = i->connection.rep->rkey();
			TEST_CHECK(i->rkey > 0);
			for (int b = 0; b <= i->ci.port + 1; ++b)
				repman.observed(i->rkey);

			reputation_id temp_rid;
			repman.rid(i->rkey, temp_rid);
			TEST_EQUAL(i->rid, temp_rid);

			TEST_EQUAL(i->rkey, repman.rkey(i->rid));

			dht::public_key temp_pkey;
			repman.pkey(i->rkey, temp_pkey);
			TEST_CHECK(temp_pkey == i->key.pk);
		}
	}

	void create_test_standings(reputation_manager& repman, peer_ids_t& peer_ids)
	{
		// pre-load the database with standings both at and for the client for and
		// at the test peers
		for (peer_ids_t::iterator i = peer_ids.begin();
			i != peer_ids.end(); ++i)
		{
			reputation_state client_state;
			client_state.upload_direct = std::distance(peer_ids.begin(), i) + 1;
			client_state.download_direct = std::distance(peer_ids.begin(), i) + 10;
			repman.update_state_for(i->rkey, client_state);

			signed_state peer_state;
			peer_state.subject = repman.client_rid();
			peer_state.upload_direct = std::distance(peer_ids.begin(), i) + 1;
			peer_state.download_direct = std::distance(peer_ids.begin(), i) + 10;
			entry e = peer_state.reputation_state::to_entry();
			std::vector<char> state_buf;
			bencode(std::back_inserter(state_buf), e);
			peer_state.sig = dht::ed25519_sign(state_buf, i->key.pk, i->key.sk);
			repman.store_state(i->rkey, client_reputation_key, peer_state);
		}
	}

	int test_known_peers()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		std::vector<reputation_id> peers;
		tc.repman().known_peers(peers);
		TEST_EQUAL(peers.size(), peer_ids.size());
		peer_ids_t::reverse_iterator pid = peer_ids.rbegin();
		for (std::vector<reputation_id>::iterator i = peers.begin();
			i != peers.end(); ++i, ++pid)
		{
			TEST_EQUAL(*i, pid->rid);
		}

		return 0;
	}

	int test_update_state()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		test_identity& i = peer_ids[0];

		reputation_state new_state;
		new_state.upload_direct = 3;
		new_state.download_direct = 1;
		new_state.upload_recommended = 3;
		new_state.download_recommended = 4;
		new_state.upload_referred = 5;
		new_state.download_referred = 6;
		tc.repman().update_state_for(i.rkey, new_state);
		TEST_EQUAL(new_state.upload_direct, 3);
		TEST_EQUAL(new_state.download_direct, 1);
		TEST_EQUAL(new_state.upload_recommended, 3);
		TEST_EQUAL(new_state.download_recommended, 4);
		TEST_EQUAL(new_state.upload_referred, 5);
		TEST_EQUAL(new_state.download_referred, 6);

		tc.repman().update_state_for(i.rkey, new_state);
		TEST_EQUAL(new_state.upload_direct, 6);
		TEST_EQUAL(new_state.download_direct, 2);
		TEST_EQUAL(new_state.upload_recommended, 6);
		TEST_EQUAL(new_state.download_recommended, 8);
		TEST_EQUAL(new_state.upload_referred, 10);
		TEST_EQUAL(new_state.download_referred, 12);

		signed_state sstate;
		memset(&sstate, 0, sizeof(signed_state));
		sstate.subject = i.rid;
		tc.repman().update_state_for(i.rkey, sstate);
		TEST_EQUAL(sstate.upload_direct, 6);
		TEST_EQUAL(sstate.download_direct, 2);
		TEST_EQUAL(sstate.upload_recommended, 6);
		TEST_EQUAL(sstate.download_recommended, 8);
		TEST_EQUAL(sstate.upload_referred, 10);
		TEST_EQUAL(sstate.download_referred, 12);
		std::vector<char> state_buf;
		bencode(std::back_inserter(state_buf), sstate.reputation_state::to_entry());
		bool valid = dht::ed25519_verify(sstate.sig
			, state_buf
			, tc.identity->key.pk);
		TEST_CHECK(valid);

		TEST_EQUAL(tc.repman().direct_value(i.rkey)
			, double(sstate.download_direct - sstate.upload_direct + sstate.download_referred - sstate.upload_referred)
				* (2.0 / (peer_ids.size() + 1.0)));

		return 0;
	}

	int test_download_multiplier()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		test_identity& i = peer_ids[0];

		{
			reputation_state new_state;
			new_state.upload_direct = 402;
			new_state.download_direct = 2;
			new_state.upload_recommended = 6;
			new_state.download_recommended = 8;
			new_state.upload_referred = 10;
			new_state.download_referred = 12;
			tc.repman().update_state_for(i.rkey, new_state);
		}

		tc.ses->m_torrents.push_back(torrent_handle(108, 8, torrent_status::downloading));
		boost::int64_t adjusted = tc.repman().adjust_download_direct(100);
		boost::int64_t expected_adj = (double(402 - 2) / double(108 - 8 + 100)) * 100;
		TEST_EQUAL(adjusted, expected_adj);

		return 0;
	}

	int test_single_attribution()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		test_identity& intermediary = peer_ids[0];

		{
			reputation_state state;
			state.upload_direct = 2;
			state.download_direct = 4;
			state.upload_recommended = 6;
			state.download_recommended = 8;
			state.upload_referred = 10;
			state.download_referred = 12;
			tc.repman().update_state_for(intermediary.rkey, state);
		}

		test_identity& i = peer_ids[1];

		{
			signed_state state;
			state.subject = i.rid;
			state.upload_direct = 1;
			state.download_direct = 2;
			state.upload_recommended = 3;
			state.download_recommended = 4;
			state.upload_referred = 5;
			state.download_referred = 6;
			std::vector<char> state_buf;
			bencode(std::back_inserter(state_buf), state.reputation_state::to_entry());
			state.sig = dht::ed25519_sign(state_buf
				, intermediary.key.pk
				, intermediary.key.sk);
			tc.repman().store_state(intermediary.rkey, i.rkey, state);
		}

		peer_reputation rep;
		rep.attributions.push_back(attribution(intermediary.rkey, 0));
		tc.repman().consider_attributions(i.rkey, rep);
		TEST_EQUAL(rep.attributions.size(), 1);
		if (rep.attributions.size() == 1)
		{
			TEST_EQUAL(rep.attributions[0].contribution, 100);
			TEST_EQUAL(rep.attributions[0].intermediary, intermediary.rkey);
		}

		return 0;
	}

	int test_state_at()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		test_identity& i = peer_ids[0];
		signed_state state;
		state.subject = hasher(tc.identity->key.pk.bytes).final();
		state.upload_direct = 10;
		state.download_direct = 20;
		state.upload_recommended = 30;
		state.download_recommended = 40;
		state.upload_referred = 50;
		state.download_referred = 60;
		std::vector<char> state_buf;
		bencode(std::back_inserter(state_buf), state.reputation_state::to_entry());
		state.sig = dht::ed25519_sign(state_buf
			, i.key.pk
			, i.key.sk);
		tc.repman().store_state(i.rkey, client_reputation_key, state);
		memset(&state, 0, sizeof(signed_state));
		state.subject = hasher(tc.identity->key.pk.bytes).final();
		tc.repman().state_at(i.rkey, client_reputation_key, state);
		TEST_EQUAL(state.upload_direct, 10);
		TEST_EQUAL(state.download_direct, 20);
		TEST_EQUAL(state.upload_recommended, 30);
		TEST_EQUAL(state.download_recommended, 40);
		TEST_EQUAL(state.upload_referred, 50);
		TEST_EQUAL(state.download_referred, 60);
		int valid = dht::ed25519_verify(state.sig, state_buf, i.key.pk);
		TEST_EQUAL(valid, 1);

		return 0;
	}

	int test_optimistic_unchoke()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		reputation_state new_state;
		new_state.upload_direct = 1;
		new_state.download_direct = 3;
		tc.repman().update_state_for(peer_ids[0].rkey, new_state);
		new_state.download_direct = 5;
		tc.repman().update_state_for(peer_ids[1].rkey, new_state);

		std::array<peer_connection_handle, 2> peers
			= {&peer_ids[0].connection, &peer_ids[1].connection};
		std::vector<peer_connection_handle> ppeers;
		for (std::array<peer_connection_handle, 2>::iterator i = peers.begin();
			i != peers.end(); ++i)
		{
			i->m_impl->choked = true;
			i->m_impl->rep->on_interested();
			ppeers.push_back(*i);
		}

		std::array<std::uint64_t, 2> prios;
		std::transform(peers.begin(), peers.end(), prios.begin()
			, [&](peer_connection_handle const& e)
				{ return tc.repman().get_unchoke_priority(e); });

		TEST_CHECK(prios[0] > prios[1]);

		return 0;
	}

	int test_put_ci()
	{
		test_client tc;

		{
			aux::stack_allocator alloc;
			{
				external_ip_alert a(alloc, address::from_string("1.2.3.4"));
				tc.repman().on_alert(&a);
			}
			{
				external_ip_alert a(alloc, address::from_string("::102:304"));
				tc.repman().on_alert(&a);
			}
		}

		TEST_EQUAL(tc.dht_store.size(), 1);
		if (tc.dht_store.size() == 1)
		{
			dht::item const& ci = tc.dht_store.front();
			TEST_EQUAL(ci.value().type(), entry::string_t);
			TEST_EQUAL(ci.salt(), std::string());
			TEST_CHECK(ci.pk() == tc.identity->key.pk);
			std::string const& value = ci.value().string();
			char client_ci[contact_info::v46_size]
				= {1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 0, 1};
			TEST_EQUAL(value, std::string(client_ci, contact_info::v46_size));
		}

		return 0;
	}

	int test_update_standing_rx()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		{
			reputation_state new_state;
			new_state.upload_direct = 1;
			new_state.download_direct = 10;
			new_state.upload_recommended = 3;
			new_state.download_recommended = 4;
			new_state.upload_referred = 1;
			new_state.download_referred = 1;
			tc.repman().update_state_for(peer_ids[2].rkey, new_state);
		}

		signed_state old_state;
		old_state.subject = peer_ids[1].rid;
		tc.repman().state_at(client_reputation_key, peer_ids[1].rkey, old_state);

		reputation_id intermediary = hasher(tc.identity->key.pk.bytes).final();
		entry request;
		{
			request["q"] = std::string("update_standing");
			request["a"]["id"] = std::string("12345678901234567890");
			request["a"]["receipt"]["seq"] = 1;
			request["a"]["receipt"]["sender"] = peer_ids[1].rid.to_string();
			request["a"]["receipt"]["recipient"] = peer_ids[2].rid.to_string();
			request["a"]["receipt"]["intermediary"]
				= intermediary.to_string();
			request["a"]["receipt"]["volume"] = 3;
			std::vector<char> standing_buf;
			bencode(std::back_inserter(standing_buf), request["a"]["receipt"]);
			dht::signature sig;
			sig = dht::ed25519_sign(standing_buf
				, peer_ids[2].key.pk
				, peer_ids[2].key.sk);
			request["a"]["receipt"]["sig"] = sig.bytes;
			request["a"]["receipt"].dict().erase("intermediary");
		}

		{
			signed_state peer_state;
			peer_state.subject = intermediary;
			peer_state.download_referred = 1;
			request["a"]["state"] = peer_state.reputation_state::to_entry();
			std::vector<char> state_buf;
			bencode(std::back_inserter(state_buf), request["a"]["state"]);
			peer_state.sig = dht::ed25519_sign(state_buf
				, peer_ids[1].key.pk
				, peer_ids[1].key.sk);
			request["a"]["state"] = peer_state.to_entry();
		}

		std::vector<char> request_buf;
		bencode(std::back_inserter(request_buf), request);
		bdecode_node le;
		error_code ec;
		bdecode(&*request_buf.begin(), (&request_buf.back())+1, le, ec);

		entry response;
		bool result = tc.repman().on_update_standing(
			asio::ip::udp::endpoint(peer_ids[1].ci.addr_v4, peer_ids[1].ci.port)
			, le, response);

		TEST_CHECK(result);
		{
			entry& new_state = response["r"]["state"];
			TEST_EQUAL(old_state.upload_direct, new_state["ds"].integer());
			TEST_EQUAL(old_state.download_direct, new_state["dr"].integer());
			TEST_EQUAL(old_state.upload_recommended, new_state["is"].integer());
			TEST_EQUAL(old_state.download_recommended, new_state["ir"].integer());
			TEST_EQUAL(old_state.upload_referred, new_state["rs"].integer());
			TEST_EQUAL(old_state.download_referred + 3, new_state["rr"].integer());
		}

		// send a second update
		request["a"]["receipt"].dict().erase("sig");
		request["a"]["receipt"]["intermediary"]
			= intermediary.to_string();
		request["a"]["receipt"]["seq"] = 2;
		request["a"]["receipt"]["volume"] = 5;
		request_buf.clear();
		dht::signature sig;
		bencode(std::back_inserter(request_buf), request["a"]["receipt"]);
		sig = dht::ed25519_sign(request_buf
			, peer_ids[2].key.pk
			, peer_ids[2].key.sk);
		request["a"]["receipt"]["sig"] = sig.bytes;
		request["a"]["receipt"].dict().erase("intermediary");

		request_buf.clear();
		bencode(std::back_inserter(request_buf), request);
		bdecode(&*request_buf.begin(), (&request_buf.back())+1, le, ec);

		result = tc.repman().on_update_standing(
			asio::ip::udp::endpoint(peer_ids[1].ci.addr_v4, peer_ids[1].ci.port)
			, le, response);

		TEST_CHECK(result);
		{
			entry& new_state = response["r"]["state"];
			TEST_EQUAL(old_state.upload_direct, new_state["ds"].integer());
			TEST_EQUAL(old_state.download_direct, new_state["dr"].integer());
			TEST_EQUAL(old_state.upload_recommended, new_state["is"].integer());
			TEST_EQUAL(old_state.download_recommended, new_state["ir"].integer());
			TEST_EQUAL(old_state.upload_referred, new_state["rs"].integer());
			TEST_EQUAL(old_state.download_referred + 8, new_state["rr"].integer());
		}

		return 0;
	}

	int test_update_standing_tx()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		{
			// Forward standing case 1: IPv6 only, all working
			contact_info ci;
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, std::weak_ptr<reputation_session>());
			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
			if (!tc.ses->m_dht_direct_requests.empty())
			{
				asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
				reply_to_update_standing(true
					, tc.ses->m_dht_direct_requests.front()
					, tc.repman()
					, ep
					, u.first
					, test_peer
					, rid
					, tc.repman().client_rid()
					, kp);
				tc.ses->m_dht_direct_requests.clear();
			}
		}

		{
			// Forward standing case 2: IPv4 only, all working
			contact_info ci;
			ci.addr_v4 = asio::ip::address_v4::from_string("1.2.3.4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, std::weak_ptr<reputation_session>());
			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
			if (!tc.ses->m_dht_direct_requests.empty())
			{
				asio::ip::udp::endpoint ep(ci.addr_v4, ci.port);
				reply_to_update_standing(true
					, tc.ses->m_dht_direct_requests.front()
					, tc.repman()
					, ep
					, u.first
					, test_peer
					, rid
					, tc.repman().client_rid()
					, kp);
				tc.ses->m_dht_direct_requests.clear();
			}
		}

		{
			// Forward standing case 3: IPv6 and IPv4, v6 fails, v4 works
			contact_info ci;
			ci.addr_v4 = asio::ip::address_v4::from_string("1.2.3.4");
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, std::weak_ptr<reputation_session>());
			for (int i = 0; i < 2; i++)
			{
				TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
				if (!tc.ses->m_dht_direct_requests.empty())
				{
					asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
					reply_to_update_standing(false
						, tc.ses->m_dht_direct_requests.front()
						, tc.repman()
						, ep
						, u.first
						, test_peer
						, rid
						, tc.repman().client_rid()
						, kp);
					tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());
				}
			}
			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
			if (!tc.ses->m_dht_direct_requests.empty())
			{
				asio::ip::udp::endpoint ep(ci.addr_v4, ci.port);
				reply_to_update_standing(true
					, tc.ses->m_dht_direct_requests.front()
					, tc.repman()
					, ep
					, u.first
					, test_peer
					, rid
					, tc.repman().client_rid()
					, kp);
				tc.ses->m_dht_direct_requests.clear();
			}
		}

		{
			// Forward standing case 4: IPv6 and IPv4, v6 fails, v4 fails, new v6 works
			contact_info ci;
			ci.addr_v4 = asio::ip::address_v4::from_string("1.2.3.4");
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, std::weak_ptr<reputation_session>());
			for (int i = 0; i < 2; i++)
			{
				TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
				if (!tc.ses->m_dht_direct_requests.empty())
				{
					asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
					reply_to_update_standing(false
						, tc.ses->m_dht_direct_requests.front()
						, tc.repman()
						, ep
						, u.first
						, test_peer
						, rid
						, tc.repman().client_rid()
						, kp);
					tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());
				}
			}

			char ep_compact[22] = {4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6, 7, 0, 2};
			tc.ses->m_dht_store.push_back(
				dht::item(entry(std::string(ep_compact, 22))
					, {}
					, dht::sequence_number(1)
					, kp.pk
					, kp.sk));
			test_time += 60*60*25;

			for (int i = 0; i < 2; i++)
			{
				TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
				if (!tc.ses->m_dht_direct_requests.empty())
				{
					asio::ip::udp::endpoint ep(ci.addr_v4, ci.port);
					reply_to_update_standing(false
						, tc.ses->m_dht_direct_requests.front()
						, tc.repman()
						, ep
						, u.first
						, test_peer
						, rid
						, tc.repman().client_rid()
						, kp);
					tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());
				}
			}

			tc.ses->post_alerts();

			ci.addr_v4 = asio::ip::address_v4::from_string("4.5.6.7");
			ci.addr_v6 = asio::ip::address_v6::from_string("::405:607");
			ci.port = 2;

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
			if (!tc.ses->m_dht_direct_requests.empty())
			{
				asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
				reply_to_update_standing(true
					, tc.ses->m_dht_direct_requests.front()
					, tc.repman()
					, ep
					, u.first
					, test_peer
					, rid
					, tc.repman().client_rid()
					, kp);
				tc.ses->m_dht_direct_requests.clear();
			}
		}

		return 0;
	}

	int test_update_standing_tx_multiple()
	{
		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		{
			// Forward standing case 1: Three outstanding updates, IPv6 only, all working
			contact_info ci;
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::vector<std::pair<stored_standing_update, signed_state> > updates;
			for (int i = 0; i < 3; ++i)
			{
				updates.push_back(generate_forward_standing(tc.repman(), peer_ids[i], test_peer, rid));
				tc.repman().forward_standing(updates.back().first
					, updates.back().second
					, std::weak_ptr<reputation_session>());
			}
			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 3);
			for (std::vector<dht_direct_request_t>::iterator i = tc.ses->m_dht_direct_requests.begin()
				; i != tc.ses->m_dht_direct_requests.end(); ++i)
			{
				asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
				reply_to_update_standing(true
					, *i
					, tc.repman()
					, ep
					, updates[std::distance(tc.ses->m_dht_direct_requests.begin(), i)].first
					, test_peer
					, rid
					, tc.repman().client_rid()
					, kp);
			}

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 3);
			tc.ses->m_dht_direct_requests.clear();
		}

		{
			// Forward standing case 3: IPv6 and IPv4, v6 fails, v4 works
			contact_info ci;
			ci.addr_v4 = asio::ip::address_v4::from_string("1.2.3.4");
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::vector<std::pair<stored_standing_update, signed_state> > updates;
			for (int req = 0; req < 2; ++req)
			{
				updates.push_back(generate_forward_standing(tc.repman(), peer_ids[req], test_peer, rid));
				tc.repman().forward_standing(updates.back().first
					, updates.back().second
					, std::weak_ptr<reputation_session>());
			}

			// fail each request once to cause the IPV6 address to be failed
			// then fail the second request again to get it to roll over to the
			// IPV4 address
			for (int req = 0; req < 3; req++)
			{
				TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 2);
				if (!tc.ses->m_dht_direct_requests.empty())
				{
					asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
					reply_to_update_standing(false
						, tc.ses->m_dht_direct_requests.front()
						, tc.repman()
						, ep
						, updates[req % 2].first
						, test_peer
						, rid
						, tc.repman().client_rid()
						, kp);
					tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());
				}
			}

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 2);
			if (tc.ses->m_dht_direct_requests.size() == 2)
			{
				// the failing operation above reverses the order of the requests
				// swap them back so they're in their original order
				std::swap(tc.ses->m_dht_direct_requests[0], tc.ses->m_dht_direct_requests[1]);
			}
			else
				// losing a request is going to completely hose the rest of the test
				// so just bail out
				return 0;

			updates.push_back(generate_forward_standing(tc.repman(), peer_ids[2], test_peer, rid));
			tc.repman().forward_standing(updates.back().first
				, updates.back().second
				, std::weak_ptr<reputation_session>());

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 3);

			for (std::vector<dht_direct_request_t>::iterator req = tc.ses->m_dht_direct_requests.begin();
				req != tc.ses->m_dht_direct_requests.end(); ++req)
			{
				asio::ip::udp::endpoint ep(ci.addr_v4, ci.port);
				reply_to_update_standing(true
					, *req
					, tc.repman()
					, ep
					, updates[std::distance(tc.ses->m_dht_direct_requests.begin(), req)].first
					, test_peer
					, rid,
					tc.repman().client_rid()
					, kp);
			}

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 3);
			tc.ses->m_dht_direct_requests.clear();
		}

		{
			// Forward standing case 4: IPv6 and IPv4, v6 fails, v4 fails, new v6 works
			contact_info ci;
			ci.addr_v4 = asio::ip::address_v4::from_string("1.2.3.4");
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			auto seed = dht::ed25519_create_seed();
			std::tie(kp.pk, kp.sk) = dht::ed25519_create_keypair(seed);
			reputation_id rid = hasher(kp.pk.bytes).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::vector<std::pair<stored_standing_update, signed_state> > updates;

			for (int req = 0; req < 2; ++req)
			{
				updates.push_back(generate_forward_standing(tc.repman(), peer_ids[req], test_peer, rid));
				tc.repman().forward_standing(updates.back().first
					, updates.back().second
					, std::weak_ptr<reputation_session>());
			}

			// fail each request once to cause the IPV6 address to be failed
			// then fail the second request again to get it to roll over to the
			// IPV4 address
			for (int req = 0; req < 3; req++)
			{
				TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 2);
				if (!tc.ses->m_dht_direct_requests.empty())
				{
					asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
					reply_to_update_standing(false
						, tc.ses->m_dht_direct_requests.front()
						, tc.repman()
						, ep
						, updates[req % 2].first
						, test_peer
						, rid
						, tc.repman().client_rid()
						, kp);
					tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());
				}
			}

			char ep_compact[22] = {4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6, 7, 0, 2};
			tc.ses->m_dht_store.push_back(
				dht::item(entry(std::string(ep_compact, 22))
					, {}
					, dht::sequence_number(1)
					, kp.pk
					, kp.sk));
			test_time += 60*60*25;

			// the failing operation above reverses the order of the requests
			// so start with the second test peer when failing IPV4
			for (int req = 1; req < 4; req++)
			{
				if (!tc.ses->m_dht_direct_requests.empty())
				{
					asio::ip::udp::endpoint ep(ci.addr_v4, ci.port);
					reply_to_update_standing(false
						, tc.ses->m_dht_direct_requests.front()
						, tc.repman()
						, ep
						, updates[req % 2].first
						, test_peer
						, rid
						, tc.repman().client_rid()
						, kp);
					tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());
				}
			}

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 0);

			updates.push_back(generate_forward_standing(tc.repman(), peer_ids[2], test_peer, rid));
			tc.repman().forward_standing(updates.back().first
				, updates.back().second
				, std::weak_ptr<reputation_session>());

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 0);
			TEST_CHECK(tc.ses->m_pending_dht_alerts.pending());

			tc.ses->post_alerts();

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 3);

			ci.addr_v4 = asio::ip::address_v4::from_string("4.5.6.7");
			ci.addr_v6 = asio::ip::address_v6::from_string("::405:607");
			ci.port = 2;

			for (std::vector<dht_direct_request_t>::iterator req = tc.ses->m_dht_direct_requests.begin();
				req != tc.ses->m_dht_direct_requests.end(); ++req)
			{
				asio::ip::udp::endpoint ep(ci.addr_v6, ci.port);
				reply_to_update_standing(true
					, *req
					, tc.repman()
					, ep
					, updates[std::distance(tc.ses->m_dht_direct_requests.begin(), req)].first
					, test_peer
					, rid,
					tc.repman().client_rid()
					, kp);
			}

			TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 3);
			tc.ses->m_dht_direct_requests.clear();
		}

		return 0;
	}

	void validate_standing(test_identity& peer_id
		, reputation_manager& repman
		, bt_peer_connection_mock_impl& connection
		, boost::int64_t upload_direct
		, boost::int64_t download_direct)
	{
		std::vector<char> const& buffer = connection.sent_buffers.front().first;
		std::vector<char>::const_iterator pos = buffer.begin();
		detail::read_uint32(pos);
		TEST_EQUAL(detail::read_uint8(pos), 20);
		TEST_EQUAL(detail::read_uint8(pos), 2);
		bdecode_node e;
		error_code ec;
		bdecode(&*pos, &(*--buffer.end()) + 1, e, ec);
		for (int i = 0; i < e.dict_size(); ++i)
		{
			TEST_EQUAL(e.dict_at(i).first.size(), reputation_id::size());
			if (e.dict_at(i).first.size() != reputation_id::size())
				continue;
			reputation_id irid(e.dict_at(i).first.data());
			TEST_EQUAL(irid, peer_id.rid);
			signed_state istate(e.dict_at(i).second, repman.client_rid(), peer_id.key.pk);
			TEST_EQUAL(istate.upload_direct, upload_direct);
			TEST_EQUAL(istate.download_direct, download_direct);
		}
	}

	struct test_peer_plugin
	{
		test_peer_plugin(reputation_manager& repman)
			: con(key.pk)
		{
			auto seed = dht::ed25519_create_seed();
			std::tie(key.pk, key.sk) = dht::ed25519_create_keypair(seed);
			peer = std::make_shared<reputation_peer_plugin>(std::ref(repman)
				, bt_peer_connection_handle(&con));
//			con.m_remote.address(asio::ip::address_v4::from_string("1.0.0.1"));
//			con.m_remote.port(123);
			send_handshake();
		}

		test_peer_plugin(reputation_manager& repman
			, std::array<char, 32> const& seed)
			: con(key.pk)
		{
			std::tie(key.pk, key.sk) = dht::ed25519_create_keypair(seed);
			peer = std::make_shared<reputation_peer_plugin>(std::ref(repman)
				, bt_peer_connection_handle(&con));
			send_handshake();
		}

		void send_handshake()
		{
			entry e;
			e["m"]["lt_known_peers"] = 1;
			e["m"]["lt_my_standing"] = 2;
			e["m"]["lt_your_standing"] = 3;
			e["m"]["lt_attribution"] = 4;
			e["m"]["lt_receipt"] = 5;
			std::vector<char> handshake_buf;
			bencode(std::back_inserter(handshake_buf), e);
			bdecode_node handshake;
			error_code ec;
			bdecode(handshake_buf.data(), handshake_buf.data() + handshake_buf.size(), handshake, ec);
			peer->on_extension_handshake(handshake);
			// discard the extension handshake
			con.sent_buffers.clear();
		}

		lt_identify_keypair key;
		bt_peer_connection_mock_impl con;
		std::shared_ptr<reputation_peer_plugin> peer;
	};

	int test_known_peers_tx()
	{
		test_client tc;
		test_peer_plugin tp(tc.repman());

		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		tp.con.choked = true;
		tp.peer->on_interested();
		TEST_EQUAL(tp.con.sent_buffers.size(), 1);
		if (!tp.con.sent_buffers.empty())
		{
			std::vector<char> const& buffer = tp.con.sent_buffers.front().first;
			TEST_EQUAL(buffer.size(), 3 * reputation_id::size() + 6);
			if (buffer.size() == 3 * reputation_id::size() + 6)
			{
				std::vector<char>::const_iterator pos
					= buffer.begin();
				TEST_EQUAL(detail::read_uint32(pos), 3 * reputation_id::size() + 2);
				TEST_EQUAL(detail::read_uint8(pos), 20);
				TEST_EQUAL(detail::read_uint8(pos), 1);
				for (peer_ids_t::reverse_iterator i = peer_ids.rbegin();
					i != peer_ids.rend(); ++i)
				{
					for (reputation_id::iterator ri = i->rid.begin();
						ri != i->rid.end(); ++ri)
						TEST_EQUAL(*ri, (unsigned char)(*pos++));
				}
			}
			tp.con.sent_buffers.clear();
		}

		return 0;
	}

	int test_standing_tx()
	{
		test_client tc;
		test_peer_plugin tp(tc.repman());

		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);
		create_test_standings(tc.repman(), peer_ids);

		//double expected_indirect_ratio = (10.0 * 10 + 11 * 11 + 12 * 12) / (1.0 * 1 + 2 * 2 + 3 * 3);
		//TEST_EQUAL(tc.repman().indirect_ratio(), expected_indirect_ratio);

		tp.con.interesting = true;
		tp.con.peer_choked = true;
		tc.ses->m_settings.set_int(settings_pack::download_rate_limit, 0);

		{
			// send known_peers to the test client
			std::vector<char> body;
			std::back_insert_iterator<std::vector<char> > bi(body);
			for (peer_ids_t::const_iterator i = peer_ids.begin();
				i != peer_ids.end(); ++i)
				bi = std::copy(i->rid.begin(), i->rid.end(), bi);
			tp.peer->on_extended(3 * reputation_id::size(), 10, body);
		}

		// induce the peer to send standing at all three test peers
		TEST_EQUAL(tp.con.sent_buffers.size(), 1);
		if (!tp.con.sent_buffers.empty())
		{
			validate_standing(peer_ids[0], tc.repman(), tp.con, 1, 10);
			tp.con.sent_buffers.clear();
		}

		tp.peer->on_choke();

		TEST_EQUAL(tp.con.sent_buffers.size(), 1);
		if (!tp.con.sent_buffers.empty())
		{
			validate_standing(peer_ids[1], tc.repman(), tp.con, 1 + 1, 10 + 1);
			tp.con.sent_buffers.clear();
		}

		current_time += minutes(2);
		tc.repman().on_tick();

		TEST_EQUAL(tp.con.sent_buffers.size(), 1);
		if (!tp.con.sent_buffers.empty())
		{
			validate_standing(peer_ids[2], tc.repman(), tp.con, 1 + 2, 10 + 2);
			tp.con.sent_buffers.clear();
		}

		// make sure ithe client doesn't send more standings then it has
		current_time += minutes(2);
		tc.repman().on_tick();

		TEST_CHECK(tp.con.sent_buffers.empty());

		return 0;
	}

	// test the process of receiving standing at intermediaries, sending attribution,
	// recieving credit at intermediaries, and forwarding standing to the intermediaries
	int test_indirect_credit_rx()
	{
		test_client tc;
		test_peer_plugin tp(tc.repman());

		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);
		create_test_standings(tc.repman(), peer_ids);

		// test_standing_rx
		for (peer_ids_t::iterator i = peer_ids.begin();
			i != peer_ids.end(); ++i)
		{
			signed_state peer_state;
			peer_state.subject = tp.peer->rid();
			peer_state.download_direct = std::distance(peer_ids.begin(), i) + 10;
			peer_state.upload_direct = std::distance(peer_ids.begin(), i) + 1;
			{
				entry state = peer_state.reputation_state::to_entry();
				std::vector<char> state_buf;
				bencode(std::back_inserter(state_buf), state);
				peer_state.sig = dht::ed25519_sign(state_buf, i->key.pk, i->key.sk);
			}
			{
				entry standing;
				standing[i->rid.to_string()] = peer_state.to_entry();
				standing[i->rid.to_string()].dict().erase("subject");
				std::vector<char> body;
				bencode(std::back_inserter(body), standing);
				tp.peer->on_extended(body.size(), 11, body);
			}
		}

		int value_sum[3];
		value_sum[0] = std::max(10 - 1 + 10 - 1, 1);
		value_sum[1] = std::max(11 - 2 + 11 - 2, 1);
		value_sum[2] = std::max(12 - 3 + 12 - 3, 1);

		// 2.25
		// 3.375
		// 4.5

		double expected_rep =
			(12.0 - 3.0) * (4.0 / 4.0) * ((12.0 - 3) / value_sum[2]);

		TEST_EQUAL(tp.peer->reputation(), expected_rep);

		// test_attribution_tx
		{
			tp.peer->sent_unchoke();

			TEST_EQUAL(tp.con.sent_buffers.size(), 1);
			if (!tp.con.sent_buffers.empty())
			{
				std::vector<char> const& buffer = tp.con.sent_buffers.front().first;
				std::vector<char>::const_iterator pos = buffer.begin();
				detail::read_uint32(pos);
				TEST_EQUAL(detail::read_uint8(pos), 20);
				TEST_EQUAL(detail::read_uint8(pos), 4);
				bdecode_node e;
				error_code ec;
				TEST_EQUAL(bdecode(&*pos, &(*--buffer.end()) + 1, e, ec), 0);
				TEST_EQUAL(e.dict_size(), 1);
				int total_contributions = 0;
				for (int i = 0; i < e.dict_size(); i++)
				{
					TEST_CHECK(std::any_of(peer_ids.begin(), peer_ids.end()
						, [&](test_identity const& tid)
							{ return tid.rid == reputation_id(e.dict_at(i).first.data()); }));
					total_contributions += e.dict_at(i).second.int_value();
				}
				TEST_EQUAL(total_contributions, 100);
			}

			tp.con.sent_buffers.clear();

			// check for and respond to get_standing queries
			TEST_CHECK(!tc.ses->m_dht_direct_requests.empty());
			peer_ids_t::iterator pid;
			for (std::vector<dht_direct_request_t>::iterator i = tc.ses->m_dht_direct_requests.begin()
				; i != tc.ses->m_dht_direct_requests.end(); ++i)
			{
				entry const& a = i->e["a"];
				for (pid = peer_ids.begin(); pid != peer_ids.end(); ++pid)
					if (pid->ci.port == i->ep.port()) break;
				TEST_CHECK(pid != peer_ids.end());
				TEST_EQUAL(a["for"].string(), tp.peer->rid().to_string());

				entry reply;
	//			reply["t"] = req.e["t"];
				reply["y"] = "q";
				reply["r"]["id"] = std::string("12345678901234567890");
				reply["r"]["sender"] = pid->rid.to_string();
				signed_state current_state;
				current_state.subject = tp.peer->rid();
				// be lazy and just pull the state we inserted with the my_standing messages above
				// from the client's db
				TEST_CHECK(tc.repman().state_at(pid->rkey, tp.peer->rkey(), current_state));
				reply["r"]["state"] = current_state.to_entry();
				std::vector<char> lazy_buf;
				bencode(std::back_inserter(lazy_buf), reply);
				bdecode_node lazy_reply;
				error_code ec;
				bdecode(lazy_buf.data(), (&lazy_buf.back())+1, lazy_reply, ec);
				aux::stack_allocator alloc;
				dht_direct_response_alert alert(alloc, i->userdata, i->ep, lazy_reply);
				tc.repman().on_alert(&alert);
			}

			tc.ses->m_dht_direct_requests.clear();

			TEST_CHECK(!tp.con.sent_buffers.empty());
			if (!tp.con.sent_buffers.empty())
			{
				std::vector<char> const& buffer = tp.con.sent_buffers.front().first;
				std::vector<char>::const_iterator pos = buffer.begin();
				detail::read_uint32(pos);
				TEST_EQUAL(detail::read_uint8(pos), 20);
				TEST_EQUAL(detail::read_uint8(pos), 3);
				bdecode_node e;
				error_code ec;
				TEST_EQUAL(bdecode(&*pos, &(*--buffer.end()) + 1, e, ec), 0);

				TEST_EQUAL(e.dict_size(), 1);
				TEST_EQUAL(e.dict_at(0).first.size(), reputation_id::size());
				reputation_id irid(e.dict_at(0).first.data());
				TEST_EQUAL(irid, pid->rid);
				signed_state istate(e.dict_at(0).second, tp.peer->rid(), pid->key.pk);
			}

			tp.con.sent_buffers.clear();
		}

		// update_standing_rx
		tp.peer->sent_payload(1024*1024*11);

		{
			entry receipt;
			receipt["state"]["subject"] = tc.repman().client_rid().to_string();
			receipt["state"]["ds"] = 1024*1024*11;
			receipt["state"]["dr"] = 1024*1024*11;
			receipt["state"]["is"] = 0;
			receipt["state"]["ir"] = 0;
			receipt["state"]["rs"] = 0;
			receipt["state"]["rr"] = 0;
			std::vector<char> receipt_buf;
			bencode(std::back_inserter(receipt_buf), receipt["state"]);
			dht::signature sig;
			sig = dht::ed25519_sign(receipt_buf, tp.key.pk, tp.key.sk);
			receipt["state"].dict().erase("subject");
			receipt["state"]["sig"] = sig.bytes;

			{
				peer_ids_t::iterator i = peer_ids.end(); --i;
				entry::dictionary_type attribution;
				attribution["seq"] = 1;
				attribution["sender"] = tc.repman().client_rid().to_string();
				attribution["recipient"] = tp.peer->rid().to_string();
				attribution["intermediary"] = i->rid.to_string();
				attribution["volume"] = 1024*1024*11;
				std::vector<char> attrib_buf;
				bencode(std::back_inserter(attrib_buf), attribution);
				dht::signature sig;
				sig = ed25519_sign(attrib_buf
					, tp.key.pk
					, tp.key.sk);
				attribution.erase("sender");
				attribution.erase("recipient");
				attribution["sig"] = sig.bytes;
				receipt["receipts"].list().push_back(attribution);
			}

			std::vector<char> body;
			bencode(std::back_inserter(body), receipt);
			tp.peer->on_extended(body.size(), 14, body);
		}

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);

		{
			std::vector<dht_direct_request_t>::iterator i = tc.ses->m_dht_direct_requests.begin();
			entry& args = i->e["a"];
			test_identity const& intermediary = peer_ids[i->ep.port()];
			TEST_EQUAL(i->ep.address().to_v4(), intermediary.ci.addr_v4);
			TEST_EQUAL(args["receipt"]["volume"].integer(), 1024*1024*11);
			TEST_EQUAL(args["receipt"]["sender"].string(), tc.repman().client_rid().to_string());
			TEST_EQUAL(args["receipt"]["recipient"].string(), tp.peer->rid().to_string());
			std::string sig = args["receipt"]["sig"].string();
			args["receipt"].dict().erase("sig");
			TEST_CHECK(args["receipt"].dict().find("intermediary") == args["receipt"].dict().end());
			args["receipt"]["intermediary"] = intermediary.rid.to_string();

			std::vector<char> verify_buf;
			bencode(std::back_inserter(verify_buf), args["receipt"]);
			TEST_CHECK(dht::ed25519_verify(dht::signature(sig.data())
				, verify_buf, tp.key.pk));
		}

		return 0;
	}

	int test_attribution_rx()
	{
		test_client tc;
		test_peer_plugin tp(tc.repman());

		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		{
			entry attribution;
			attribution[peer_ids[0].rid.to_string()] = 34;
			attribution[peer_ids[1].rid.to_string()] = 33;
			attribution[peer_ids[2].rid.to_string()] = 33;
			std::vector<char> body;
			bencode(std::back_inserter(body), attribution);
			tp.peer->on_extended(body.size(), 13, body);
		}

		{
			peer_request req;
			req.length = 1024 * 1024 * 11;
			tp.peer->on_piece(req, span<char>());
		}

		TEST_EQUAL(tp.con.sent_buffers.size(), 1);

		if (!tp.con.sent_buffers.empty())
		{
			std::vector<char> const& buffer = tp.con.sent_buffers.front().first;
			std::vector<char>::const_iterator pos = buffer.begin();
			detail::read_uint32(pos);
			TEST_EQUAL(detail::read_uint8(pos), 20);
			TEST_EQUAL(detail::read_uint8(pos), 5);
			bdecode_node e;
			error_code ec;
			TEST_EQUAL(bdecode(&*pos, &(*--buffer.end()) + 1, e, ec), 0);
			TEST_EQUAL(e.type(), bdecode_node::dict_t);
			bdecode_node state = e.dict_find_dict("state");
			TEST_EQUAL(state.dict_find_int_value("ds", -1), 0);
			TEST_EQUAL(state.dict_find_int_value("dr", -1), 1024*1024*11);
			TEST_EQUAL(state.dict_find_int_value("is", -1), 0);
			TEST_EQUAL(state.dict_find_int_value("ir", -1), 0);
			TEST_EQUAL(state.dict_find_int_value("rs", -1), 0);
			TEST_EQUAL(state.dict_find_int_value("rr", -1), 0);
			TEST_EQUAL(state.dict_find_string("subject").type(), bdecode_node::none_t);

			{
				entry state_verify;
				state_verify = state;
				state_verify["subject"] = tp.peer->rid().to_string();
				state_verify.dict().erase("sig");

				std::vector<char> verify_buf;
				bencode(std::back_inserter(verify_buf), state_verify);
				TEST_CHECK(dht::ed25519_verify(dht::signature(state.dict_find_string_value("sig").data())
					, verify_buf
					, tc.identity->key.pk));
			}

			boost::int64_t total_attributed = 0;
			bdecode_node receipts = e.dict_find_list("receipts");
			for (int i = 0; i < receipts.list_size(); i++)
			{
				bdecode_node receipt = receipts.list_at(i);
				peer_ids_t::iterator intermediary = std::find_if(peer_ids.begin(), peer_ids.end()
					, [&](test_identity const& tid) { return tid.rid
						== reputation_id(receipt.dict_find_string_value("intermediary").data()); });
				TEST_CHECK(intermediary != peer_ids.end());
				int contribution = intermediary == peer_ids.begin() ? 34 : 33;
				boost::int64_t expected_volume = i < receipts.list_size() - 1
					? (1024*1024*11 * contribution) / 100
					: 1024*1024*11 - total_attributed;
				TEST_EQUAL(receipt.dict_find_int_value("volume", -1), expected_volume);
				total_attributed += receipt.dict_find_int_value("volume", -1);
				entry receipt_verify;
				receipt_verify = receipt;
				receipt_verify.dict().erase("sig");
				TEST_CHECK(receipt_verify.dict().find("sender") == receipt_verify.dict().end());
				TEST_CHECK(receipt_verify.dict().find("recipient") == receipt_verify.dict().end());
				receipt_verify["sender"] = tp.peer->rid().to_string();
				receipt_verify["recipient"] = tc.repman().client_rid().to_string();

				std::vector<char> verify_buf;
				bencode(std::back_inserter(verify_buf), receipt_verify);
				TEST_CHECK(dht::ed25519_verify(dht::signature(receipt.dict_find_string_value("sig").data())
					, verify_buf
					, tc.identity->key.pk));
			}
		}

		tp.con.sent_buffers.clear();

		return 0;
	}

	int test_standing_persistence()
	{
		auto seed = dht::ed25519_create_seed();

		peer_ids_t peer_ids;

		{
			test_client tc;
			test_peer_plugin tp(tc.repman(), seed);

			tp.peer->sent_payload(1024*1024*11);
			peer_request req;
			req.length = 1024*1024*11;
			tp.peer->on_piece(req, span<char>());
		}

		test_client tc;
		test_peer_plugin tp(tc.repman(), seed);

		tp.peer->sent_payload(1024*1024*11);
		peer_request req;
		req.length = 1024*1024*11;
		tp.peer->on_piece(req, span<char>());

		signed_state state;
		state.subject = peer_ids[0].rid;
		tc.repman().state_at(0, 1, state);
		TEST_EQUAL(state.upload_direct, 1024*1024*22);
		TEST_EQUAL(state.download_direct, 1024*1024*22);

		return 0;
	}

	int test_get_standing_failure()
	{
		test_client tc;
		test_peer_plugin tp(tc.repman());

		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		char ep_compact[6] = {1, 0, 0, 1, 0, 12};
		tc.ses->m_dht_store.push_back(
			dht::item(entry(std::string(ep_compact, 6))
				, span<char const>()
				, dht::sequence_number(1)
				, peer_ids[0].key.pk
				, peer_ids[0].key.sk));

		tp.peer->establish_rkey();
		tc.repman().get_standing(peer_ids[0].rkey, tp.peer->rkey(), tc.repman().peer_session(tp.peer->rid()));

		TEST_CHECK(tc.ses->m_pending_dht_alerts.pending());
		tc.ses->post_alerts();

		udp::endpoint ep;
		ep.address(address_v4::from_string("1.0.0.1"));
		ep.port(12);

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
		{
			aux::stack_allocator alloc;
			dht_direct_request_t& req = tc.ses->m_dht_direct_requests.front();
			dht_direct_response_alert alert(alloc, req.userdata, ep);
			tc.repman().on_alert(&alert);
		}
		tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
		{
			aux::stack_allocator alloc;
			dht_direct_request_t& req = tc.ses->m_dht_direct_requests.front();
			dht_direct_response_alert alert(alloc, req.userdata, ep);
			tc.repman().on_alert(&alert);
		}
		tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 0);
		TEST_EQUAL(tp.con.choked, true);

		return 0;
	}

} // namespace
} // namespace libtorrent

using namespace libtorrent;

TORRENT_TEST(reputation_manager)
{
	int (*tests[])(void) =
		{ mocks::test_known_peers
		, mocks::test_update_state
		, mocks::test_download_multiplier
		, mocks::test_single_attribution
		, mocks::test_state_at
		, mocks::test_optimistic_unchoke
		, mocks::test_put_ci
		, mocks::test_update_standing_rx
		, mocks::test_update_standing_tx
		, mocks::test_update_standing_tx_multiple
		, mocks::test_known_peers_tx
		, mocks::test_standing_tx
		, mocks::test_indirect_credit_rx
		, mocks::test_attribution_rx
		, mocks::test_standing_persistence
		, mocks::test_get_standing_failure
		, NULL};

	for (int i = 0; tests[i] != NULL; ++i)
	{
		mocks::current_time = ::libtorrent::clock_type::now();
		mocks::test_time = ::time(NULL);
		std::remove("reputation.sqlite");
		if ((*tests[i])())
			return;
	}
}
