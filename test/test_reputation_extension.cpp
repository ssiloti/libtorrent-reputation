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

#include "libtorrent/session.hpp"
#include "test.hpp"

#include "libtorrent/extensions/lt_identify.hpp"
#include "libtorrent/extensions/reputation_manager.hpp"
#include "libtorrent/peer_connection_interface.hpp"

// any headers which reference peer_connection must be included before the
// mockups to avoid ambiguous references
#include "libtorrent/extensions/reputation_manager.hpp"
#include "libtorrent/extensions/lt_identify.hpp"
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/aux_/session_call.hpp"
#include "libtorrent/kademlia/dht_tracker.hpp"
#include "libtorrent/kademlia/node.hpp"
#include "libtorrent/bt_peer_connection.hpp"
#include "libtorrent/sha1_hash.hpp"
#include "libtorrent/io.hpp"
#include "libtorrent/extensions.hpp"
#include "libtorrent/bdecode.hpp"
#include "libtorrent/bencode.hpp"
#include "libtorrent/alert_types.hpp"

namespace libtorrent
{

namespace
{
	namespace asio = boost::asio;

	time_point current_time = clock_type::now();

	time_point const& time_now() { return current_time; }

	struct lt_identify_peer_plugin : peer_plugin
	{
		lt_identify_peer_plugin(boost::array<char, 32> const& k)
			: pk(k)
		{}

		static bool supports_extension(bdecode_node const&)
		{ return true; }

		boost::array<char, 32> const* peer_key() const
		{ return &pk; }

		void notify_on_identified(boost::function<void(lt_identify_peer_plugin const&)> cb) const
		{
			cb(*this);
		}

		boost::array<char, 32> const& pk;
	};

	class reputation_peer_plugin;
	struct torrent;

	// Define a mock connection class so that the extension can be tested
	// without having to do real transfers between two sessions.
	// This makes things much easier.
	struct bt_peer_connection
	{
		enum message_type
		{
			// standard messages
			msg_choke = 0,
			msg_unchoke,
			msg_interested,
			msg_not_interested,
			msg_have,
			msg_bitfield,
			msg_request,
			msg_piece,
			msg_cancel,
			// DHT extension
			msg_dht_port,
			// FAST extension
			msg_suggest_piece = 0xd,
			msg_have_all,
			msg_have_none,
			msg_reject_request,
			msg_allowed_fast,

			// extension protocol message
			msg_extended = 20,

			num_supported_messages
		};

		enum connection_type
		{
			bittorrent_connection = 0,
			url_seed_connection = 1,
			http_seed_connection = 2
		};

		bt_peer_connection(boost::array<char, 32> const& k);

		bool is_choked() { return choked; }
		bool is_interesting() { return interesting; }
		bool packet_finished() { return pckt_finished; }
		bool has_peer_choked() { return peer_choked; }
		bool is_peer_interested() { return peer_interested; }
		bool is_disconnecting() { return false; }

		int type() const { return bittorrent_connection; }

		void disconnect(error_code const&, operation_t, int)
		{ disconnected = true; }

		void send_buffer(char const* buf, int size, int flags = 0)
		{
			sent_buffers.push_back(std::make_pair(std::vector<char>(buf, buf + size), flags));
		}

		peer_plugin const* find_plugin(char const* type);

		tcp::endpoint const& remote() const { return m_remote; }

		void send_choke() { sent_chokes++; }

		bool ignore_unchoke_slots() const { return false; }

		boost::weak_ptr<torrent> associated_torrent() const
		{ return m_torrent; }

		bool choked:1;
		bool interesting:1;
		bool pckt_finished:1;
		bool peer_choked:1;
		bool peer_interested:1;
		bool disconnected:1;

		std::vector<std::pair<std::vector<char>, int> > sent_buffers;
		lt_identify_peer_plugin identity;
		boost::shared_ptr<reputation_peer_plugin> rep;
		tcp::endpoint m_remote;
		int sent_chokes;
		boost::shared_ptr<torrent> m_torrent;
	};

	typedef bt_peer_connection peer_connection;

	struct torrent_peer
	{
		torrent_peer(peer_connection* c) : connection(c) {}
		peer_connection* connection;
	};

	struct disk_buffer_holder {};

	struct dht_direct_request_t
	{
		boost::asio::ip::udp::endpoint ep;
		entry e;
		boost::function<void(dht::msg const&)> f;
	};

	struct stat
	{
		int download_rate() { return 0; }
	};

	struct torrent
	{
		torrent(boost::int64_t size, boost::int64_t done, torrent_status::state_t state)
			: m_total_wanted(size), m_total_done(done), m_state(state)
		{}

		void status(torrent_status* st, boost::uint32_t flags)
		{
			st->total_wanted_done = m_total_done;
			st->total_wanted = m_total_wanted;
			st->state = m_state;
		}

		void choke_peer(peer_connection& c)
		{
			m_choked_peers.push_back(&c);
		}

		int peer_class() const { return 0; }
		stat statistics() const { return stat(); }

		boost::int64_t m_total_done, m_total_wanted;
		torrent_status::state_t m_state;
		std::vector<peer_connection*> m_choked_peers;
	};

	struct torrent_handle
	{
		static const boost::uint32_t query_accurate_download_counters = 1;

		torrent_handle(boost::int64_t size, boost::int64_t done, torrent_status::state_t state)
			: m_torrent(boost::make_shared<torrent>(size, done, state))
		{}

		boost::shared_ptr<torrent> native_handle() { return m_torrent; }

		boost::shared_ptr<torrent> m_torrent;
	};

	bt_peer_connection::bt_peer_connection(boost::array<char, 32> const& k)
		: choked(true)
		, interesting(false)
		, pckt_finished(true)
		, peer_choked(true)
		, peer_interested(false)
		, disconnected(false)
		, identity(k)
		, sent_chokes(0)
		, m_torrent(boost::make_shared<torrent>(boost::int64_t(0), boost::int64_t(0), torrent_status::downloading))
	{}

	namespace aux
	{
		struct session_settings
		{
			int get_int(int) const { return 100; }
		};

		struct session_impl
		{
			session_impl(std::vector<dht::item>& store)
				: m_dht_store(store)
				, m_pending_dht_alerts(8, 0xFFFFFFFF)
			{}

			external_ip const& external_address() const
			{ return m_external_ip; }

			boost::uint16_t listen_port() const
			{ return m_listen_port; }

			bool dht() { return true; }

			void dht_get_mutable_item(boost::array<char, 32> key
				, std::string salt = std::string())
			{
				for (std::vector<dht::item>::iterator i = m_dht_store.begin();
					i != m_dht_store.end(); ++i)
				{
					if (i->pk() == key && i->salt() == salt)
					{
						m_pending_dht_alerts.emplace_alert<dht_mutable_item_alert>(
							i->pk(), i->sig(), i->seq(), i->salt(), i->value());
						return;
					}
				}
				m_pending_dht_alerts.emplace_alert<dht_mutable_item_alert>(
					key, boost::array<char, 64>(), 0, salt, entry());
			}

			void dht_put_mutable_item(boost::array<char, 32> key
				, boost::function<void(entry&, boost::array<char,64>&
					, boost::uint64_t&, std::string const&)> cb
				, std::string salt = std::string())
			{
				for (std::vector<dht::item>::iterator i = m_dht_store.begin();
					i != m_dht_store.end(); ++i)
				{
					if (i->pk() == key && i->salt() == salt)
					{
						entry value = i->value();
						boost::array<char, 64> sig = i->sig();
						boost::uint64_t seq = i->seq();
						cb(value, sig, seq, salt);
						i->assign(value, salt, seq, key.data(), sig.data());
						return;
					}
				}
				entry value;
				boost::array<char, 64> sig;
				boost::uint64_t seq = 0;
				cb(value, sig, seq, salt);
				dht::item i;
				i.assign(value, salt, seq, key.data(), sig.data());
				m_dht_store.push_back(i);
			}

			void add_extension_dht_query(std::string const& query, ::libtorrent::aux::session_impl::dht_extension_handler_t handler)
			{}

			void dht_direct_request(boost::asio::ip::udp::endpoint ep, entry& e
				, boost::function<void(dht::msg const&)> f)
			{
				dht_direct_request_t r;
				r.ep = ep;
				r.e = e;
				r.f = f;
				m_dht_direct_requests.push_back(r);
			}

			std::vector<torrent_handle> get_torrents() const
			{
				return m_torrents;
			}

			void post_alerts()
			{
				std::vector<alert*> alerts;
				int num_resume;
				m_pending_dht_alerts.get_all(alerts, num_resume);
				for (std::vector<alert*>::iterator i = alerts.begin();
					i != alerts.end(); ++i)
				{
					post_alert(*i);
				}
			}

			void post_alert(alert const* a);

			int peak_down_rate() const { return 100; }
			int download_rate_limit(int) { return 100; }
			session_settings settings() const { return session_settings(); }

			session_status status() const
			{
				session_status status;
				status.download_rate = 0;
				return status;
			}

			external_ip m_external_ip;
			boost::uint16_t m_listen_port;
			std::vector<torrent_handle> m_torrents;
			std::vector<dht::item>& m_dht_store;
			alert_manager m_pending_dht_alerts;
			std::vector<dht_direct_request_t> m_dht_direct_requests;

			typedef std::vector<boost::shared_ptr<plugin> > ses_extension_list_t;
			ses_extension_list_t m_ses_extensions;
		};

		typedef session_impl session_interface;
	} // namespace aux

	time_t test_time;

	time_t time(void*)
	{
		return test_time;
	}

} // namespace
} // namespace libtorrent

#define TORRENT_DISABLE_LOGGING
#define TORRENT_REPUTATION_MANAGER_TEST
#include "../src/reputation_manager.cpp"

namespace libtorrent
{
namespace
{
	peer_plugin const* bt_peer_connection::find_plugin(char const* type)
	{
		if (strcmp(type, "lt_identify") == 0)
			return &identity;
		else if (strcmp(type, "reputation") == 0)
			return rep.get();
		else
			return NULL;
	}

	void aux::session_impl::post_alert(alert const* a)
	{
		for (ses_extension_list_t::iterator i = m_ses_extensions.begin();
			i != m_ses_extensions.end(); ++i)
		{
			static_cast<reputation_manager*>(i->get())->on_alert(a);
		}
	}

	struct test_identity
	{
		test_identity()
			: connection(key.pk)
			, sequence(0)
		{
			boost::array<unsigned char, ed25519_seed_size> seed;
			ed25519_create_seed(seed.data());
			ed25519_create_keypair((unsigned char*)key.pk.data()
				, (unsigned char*)key.sk.data()
				, seed.data());
			rid = hasher(key.pk.data(), key.pk.size()).final();
		}

		lt_identify_keypair key;
		bt_peer_connection connection;
		reputation_key rkey;
		reputation_id rid;
		contact_info ci;
		boost::int64_t sequence;
	};

	struct test_client
	{
		test_client()
			: identity(boost::make_shared<lt_identify_plugin>())
			, repman_hnd(create_reputation_plugin(*identity, ".", ""))
			, ses(boost::make_shared<aux::session_impl>(boost::ref(dht_store)))
		{
			ses->m_external_ip.cast_vote(address::from_string("1.2.3.4"), 0, address::from_string("1.0.0.0"));
			ses->m_external_ip.cast_vote(address::from_string("::102:304"), 0, address::from_string("1::"));
			ses->m_listen_port = 1;
			ses->m_ses_extensions.push_back(repman_hnd.reputation_plugin);
			repman().added(ses.get());
		}

		reputation_manager& repman()
		{ return *static_cast<reputation_manager*>(repman_hnd.reputation_plugin.get()); }

		boost::shared_ptr<lt_identify_plugin> identity;
		reputation_handle repman_hnd;
		std::vector<dht::item> dht_store;
		boost::shared_ptr<aux::session_impl> ses;
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
			char sig[ed25519_signature_size];
			ed25519_sign((unsigned char*)sig
				, (unsigned char*)sig_buf.data()
				, sig_buf.size()
				, (unsigned char*)recipient.key.pk.data()
				, (unsigned char*)recipient.key.sk.data());
			e["sig"] = std::string(sig, ed25519_signature_size);
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
				char sig[ed25519_signature_size];
				ed25519_sign((unsigned char*)sig
					, (unsigned char*)sig_buf.data()
					, sig_buf.size()
					, (unsigned char*)kp.pk.data()
					, (unsigned char*)kp.sk.data());
				reply["r"]["state"]["sig"] = std::string(sig, ed25519_signature_size);
			}
			std::vector<char> lazy_buf;
			bencode(std::back_inserter(lazy_buf), reply);
			bdecode_node lazy_reply;
			error_code ec;
			bdecode(lazy_buf.data(), (&lazy_buf.back())+1, lazy_reply, ec);
			req.f(dht::msg(lazy_reply, ep));

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
			req.f(dht::msg(bdecode_node(), ep));
		}

		return 0;
	}

	typedef boost::array<test_identity, 3> peer_ids_t;
	void create_test_peers(reputation_manager& repman, peer_ids_t& peers)
	{
		for (peer_ids_t::iterator i = peers.begin();
			i != peers.end(); ++i)
		{
			i->connection.rep = boost::make_shared<reputation_peer_plugin>(boost::ref(repman)
				, boost::ref(i->connection));
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

			pubkey_type temp_pkey;
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
			ed25519_sign((unsigned char*)peer_state.sig.data(),
				(unsigned char const*)state_buf.data(),
				state_buf.size(),
				(unsigned char const*)i->key.pk.data(),
				(unsigned char const*)i->key.sk.data());
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
		int valid = ed25519_verify((unsigned char*)sstate.sig.data()
			, (unsigned char*)state_buf.data()
			, state_buf.size()
			, (unsigned char*)tc.identity->key.pk.data());
		TEST_EQUAL(valid, 1);

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
			ed25519_sign((unsigned char*)state.sig.data(),
				(unsigned char const*)state_buf.data(),
				state_buf.size(),
				(unsigned char const*)intermediary.key.pk.data(),
				(unsigned char const*)intermediary.key.sk.data());
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
		state.subject = hasher(tc.identity->key.pk.data(), tc.identity->key.pk.size()).final();
		state.upload_direct = 10;
		state.download_direct = 20;
		state.upload_recommended = 30;
		state.download_recommended = 40;
		state.upload_referred = 50;
		state.download_referred = 60;
		std::vector<char> state_buf;
		bencode(std::back_inserter(state_buf), state.reputation_state::to_entry());
		ed25519_sign((unsigned char*)state.sig.data(),
			(unsigned char const*)state_buf.data(),
			state_buf.size(),
			(unsigned char const*)i.key.pk.data(),
			(unsigned char const*)i.key.sk.data());
		tc.repman().store_state(i.rkey, client_reputation_key, state);
		memset(&state, 0, sizeof(signed_state));
		state.subject = hasher(tc.identity->key.pk.data(), tc.identity->key.pk.size()).final();
		tc.repman().state_at(i.rkey, client_reputation_key, state);
		TEST_EQUAL(state.upload_direct, 10);
		TEST_EQUAL(state.download_direct, 20);
		TEST_EQUAL(state.upload_recommended, 30);
		TEST_EQUAL(state.download_recommended, 40);
		TEST_EQUAL(state.upload_referred, 50);
		TEST_EQUAL(state.download_referred, 60);
		int valid = ed25519_verify((unsigned char*)state.sig.data()
			, (unsigned char*)state_buf.data()
			, state_buf.size()
			, (unsigned char*)i.key.pk.data());
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

		boost::array<torrent_peer, 2> peers
			= {&peer_ids[0].connection, &peer_ids[1].connection};
		std::vector<torrent_peer*> ppeers;
		for (boost::array<torrent_peer, 2>::iterator i = peers.begin();
			i != peers.end(); ++i)
		{
			i->connection->choked = true;
			i->connection->rep->on_interested();
			ppeers.push_back(&*i);
		}
		tc.repman().on_optimistic_unchoke(ppeers);
		TEST_EQUAL(ppeers.size(), 2);
		TEST_EQUAL(ppeers[0], &peers[1]);
		TEST_EQUAL(ppeers[1], &peers[0]);

		return 0;
	}

	int test_put_ci()
	{
		test_client tc;

		tc.repman().on_tick();

		TEST_CHECK(!tc.dht_store.empty());
		if (!tc.dht_store.empty())
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

		reputation_id intermediary = hasher(tc.identity->key.pk.data(), tc.identity->key.pk.size()).final();
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
			char sig_buf[64];
			ed25519_sign((unsigned char*)sig_buf,
				(unsigned char const*)standing_buf.data(),
				standing_buf.size(),
				(unsigned char const*)peer_ids[2].key.pk.data(),
				(unsigned char const*)peer_ids[2].key.sk.data());
			request["a"]["receipt"]["sig"] = std::string(sig_buf, 64);
			request["a"]["receipt"].dict().erase("intermediary");
		}

		{
			signed_state peer_state;
			peer_state.subject = intermediary;
			peer_state.download_referred = 1;
			request["a"]["state"] = peer_state.reputation_state::to_entry();
			std::vector<char> state_buf;
			bencode(std::back_inserter(state_buf), request["a"]["state"]);
			ed25519_sign((unsigned char*)peer_state.sig.data(),
				(unsigned char const*)state_buf.data(),
				state_buf.size(),
				(unsigned char const*)peer_ids[1].key.pk.data(),
				(unsigned char const*)peer_ids[1].key.sk.data());
			request["a"]["state"] = peer_state.to_entry();
		}

		std::vector<char> request_buf;
		bencode(std::back_inserter(request_buf), request);
		bdecode_node le;
		error_code ec;
		bdecode(&*request_buf.begin(), (&request_buf.back())+1, le, ec);

		entry response;
		bool result = tc.repman().on_update_standing(
			dht::msg(le, asio::ip::udp::endpoint(peer_ids[1].ci.addr_v4, peer_ids[1].ci.port))
			, response);

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
		char sig_buf[64];
		bencode(std::back_inserter(request_buf), request["a"]["receipt"]);
		ed25519_sign((unsigned char*)sig_buf,
			(unsigned char const*)request_buf.data(),
			request_buf.size(),
			(unsigned char const*)peer_ids[2].key.pk.data(),
			(unsigned char const*)peer_ids[2].key.sk.data());
		request["a"]["receipt"]["sig"] = std::string(sig_buf, 64);
		request["a"]["receipt"].dict().erase("intermediary");

		request_buf.clear();
		bencode(std::back_inserter(request_buf), request);
		bdecode(&*request_buf.begin(), (&request_buf.back())+1, le, ec);

		result = tc.repman().on_update_standing(
			dht::msg(le, asio::ip::udp::endpoint(peer_ids[1].ci.addr_v4, peer_ids[1].ci.port))
			, response);

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
		unsigned char seed[ed25519_seed_size];

		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		{
			// Forward standing case 1: IPv6 only, all working
			contact_info ci;
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, boost::weak_ptr<reputation_session>());
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
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, boost::weak_ptr<reputation_session>());
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
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, boost::weak_ptr<reputation_session>());
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
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::pair<stored_standing_update, signed_state> u = generate_forward_standing(tc.repman(), peer_ids[1], test_peer, rid);
			tc.repman().forward_standing(u.first, u.second, boost::weak_ptr<reputation_session>());
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
				dht::item(entry(std::string(ep_compact, 22)), std::make_pair((char*)NULL, 0), 1, kp.pk.data(), kp.sk.data()));
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
		unsigned char seed[ed25519_seed_size];

		test_client tc;
		peer_ids_t peer_ids;
		create_test_peers(tc.repman(), peer_ids);

		{
			// Forward standing case 1: Three outstanding updates, IPv6 only, all working
			contact_info ci;
			ci.addr_v6 = asio::ip::address_v6::from_string("::1:2:3:4");
			ci.port = 1;
			lt_identify_keypair kp;
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::vector<std::pair<stored_standing_update, signed_state> > updates;
			for (int i = 0; i < 3; ++i)
			{
				updates.push_back(generate_forward_standing(tc.repman(), peer_ids[i], test_peer, rid));
				tc.repman().forward_standing(updates.back().first, updates.back().second, boost::weak_ptr<reputation_session>());
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
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::vector<std::pair<stored_standing_update, signed_state> > updates;
			for (int req = 0; req < 2; ++req)
			{
				updates.push_back(generate_forward_standing(tc.repman(), peer_ids[req], test_peer, rid));
				tc.repman().forward_standing(updates.back().first, updates.back().second, boost::weak_ptr<reputation_session>());
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
			tc.repman().forward_standing(updates.back().first, updates.back().second, boost::weak_ptr<reputation_session>());

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
			ed25519_create_seed(seed);
			ed25519_create_keypair((unsigned char*)kp.pk.data(), (unsigned char*)kp.sk.data(), seed);
			reputation_id rid = hasher(kp.pk.data(), kp.pk.size()).final();
			reputation_key test_peer = tc.repman().establish_peer(kp.pk, rid, ci);
			std::vector<std::pair<stored_standing_update, signed_state> > updates;

			for (int req = 0; req < 2; ++req)
			{
				updates.push_back(generate_forward_standing(tc.repman(), peer_ids[req], test_peer, rid));
				tc.repman().forward_standing(updates.back().first, updates.back().second, boost::weak_ptr<reputation_session>());
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
				dht::item(entry(std::string(ep_compact, 22)), std::make_pair((char*)NULL, 0), 1, kp.pk.data(), kp.sk.data()));
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
			tc.repman().forward_standing(updates.back().first, updates.back().second, boost::weak_ptr<reputation_session>());

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
		, peer_connection& connection
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
			TEST_EQUAL(e.dict_at(i).first.size(), reputation_id::size);
			if (e.dict_at(i).first.size() != reputation_id::size)
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
			boost::array<unsigned char, ed25519_seed_size> seed;
			ed25519_create_seed(seed.data());
			ed25519_create_keypair((unsigned char*)key.pk.data()
				, (unsigned char*)key.sk.data()
				, seed.data());
			peer = boost::make_shared<reputation_peer_plugin>(boost::ref(repman), boost::ref(con));
//			con.m_remote.address(asio::ip::address_v4::from_string("1.0.0.1"));
//			con.m_remote.port(123);
			send_handshake();
		}

		test_peer_plugin(reputation_manager& repman
			, boost::array<unsigned char, ed25519_seed_size> const& seed)
			: con(key.pk)
		{
			ed25519_create_keypair((unsigned char*)key.pk.data()
				, (unsigned char*)key.sk.data()
				, seed.data());
			peer = boost::make_shared<reputation_peer_plugin>(boost::ref(repman), boost::ref(con));
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
		bt_peer_connection con;
		boost::shared_ptr<reputation_peer_plugin> peer;
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
			TEST_EQUAL(buffer.size(), 3 * reputation_id::size + 6);
			if (buffer.size() == 3 * reputation_id::size + 6)
			{
				std::vector<char>::const_iterator pos
					= buffer.begin();
				TEST_EQUAL(detail::read_uint32(pos), 3 * reputation_id::size + 2);
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

		double expected_indirect_ratio = (10.0 * 10 + 11 * 11 + 12 * 12) / (1.0 * 1 + 2 * 2 + 3 * 3);

		TEST_EQUAL(tc.repman().indirect_ratio(), expected_indirect_ratio);

		tp.con.interesting = true;
		tp.con.peer_choked = true;

		{
			// send known_peers to the test client
			std::vector<char> body;
			std::back_insert_iterator<std::vector<char> > bi(body);
			for (peer_ids_t::const_iterator i = peer_ids.begin();
				i != peer_ids.end(); ++i)
				bi = std::copy(i->rid.begin(), i->rid.end(), bi);
			tp.peer->on_extended(3 * reputation_id::size
				, 10
				, buffer::const_interval(body.data(), body.data() + body.size()));
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
				ed25519_sign((unsigned char*)peer_state.sig.data(),
					(unsigned char const*)state_buf.data(),
					state_buf.size(),
					(unsigned char const*)i->key.pk.data(),
					(unsigned char const*)i->key.sk.data());
			}
			{
				entry standing;
				standing[i->rid.to_string()] = peer_state.to_entry();
				standing[i->rid.to_string()].dict().erase("subject");
				std::vector<char> body;
				bencode(std::back_inserter(body), standing);
				tp.peer->on_extended(body.size()
					, 11
					, buffer::const_interval(body.data(), body.data() + body.size()));
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
					TEST_CHECK(std::find_if(peer_ids.begin(), peer_ids.end()
						, boost::bind(&test_identity::rid, _1) == reputation_id(e.dict_at(i).first.data())) != peer_ids.end());
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
				i->f(dht::msg(lazy_reply, i->ep));
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
				TEST_EQUAL(e.dict_at(0).first.size(), reputation_id::size);
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
			signature_type sig;
			ed25519_sign((unsigned char*)sig.data()
				, (unsigned char*)receipt_buf.data()
				, receipt_buf.size()
				, (unsigned char*)tp.key.pk.data()
				, (unsigned char*)tp.key.sk.data());
			receipt["state"].dict().erase("subject");
			receipt["state"]["sig"] = std::string(sig.begin(), sig.end());

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
				signature_type sig;
				ed25519_sign((unsigned char*)sig.data()
					, (unsigned char*)attrib_buf.data()
					, attrib_buf.size()
					, (unsigned char*)tp.key.pk.data()
					, (unsigned char*)tp.key.sk.data());
				attribution.erase("sender");
				attribution.erase("recipient");
				attribution["sig"] = std::string(sig.begin(), sig.end());
				receipt["receipts"].list().push_back(attribution);
			}

			std::vector<char> body;
			bencode(std::back_inserter(body), receipt);
			tp.peer->on_extended(body.size()
				, 14
				, buffer::const_interval(body.data(), body.data() + body.size()));
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
			TEST_EQUAL(ed25519_verify(
				(unsigned char*)sig.data()
				, (unsigned char*)verify_buf.data()
				, verify_buf.size()
				, (unsigned char*)tp.key.pk.data()), 1);
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
			tp.peer->on_extended(body.size()
				, 13
				, buffer::const_interval(body.data(), body.data() + body.size()));
		}

		{
			peer_request req;
			req.length = 1024 * 1024 * 11;
			disk_buffer_holder buf_holder;
			tp.peer->on_piece(req, buf_holder);
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
			TEST_EQUAL(state.dict_find_string("subject"), NULL);

			{
				entry state_verify;
				state_verify = state;
				state_verify["subject"] = tp.peer->rid().to_string();
				state_verify.dict().erase("sig");

				std::vector<char> verify_buf;
				bencode(std::back_inserter(verify_buf), state_verify);
				TEST_EQUAL(ed25519_verify(
					(unsigned char*)state.dict_find_string_value("sig").data()
					, (unsigned char*)verify_buf.data()
					, verify_buf.size()
					, (unsigned char*)tc.identity->key.pk.data()), 1);
			}

			boost::int64_t total_attributed = 0;
			bdecode_node receipts = e.dict_find_list("receipts");
			for (int i = 0; i < receipts.list_size(); i++)
			{
				bdecode_node receipt = receipts.list_at(i);
				peer_ids_t::iterator intermediary = std::find_if(peer_ids.begin(), peer_ids.end()
					, boost::bind(&test_identity::rid, _1)
						== reputation_id(receipt.dict_find_string_value("intermediary").data()));
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
				TEST_EQUAL(ed25519_verify(
					(unsigned char*)receipt.dict_find_string_value("sig").data()
					, (unsigned char*)verify_buf.data()
					, verify_buf.size()
					, (unsigned char*)tc.identity->key.pk.data()), 1);
			}
		}

		tp.con.sent_buffers.clear();

		return 0;
	}

	int test_standing_persistence()
	{
		boost::array<unsigned char, ed25519_seed_size> seed;
		ed25519_create_seed(seed.data());

		peer_ids_t peer_ids;

		{
			test_client tc;
			test_peer_plugin tp(tc.repman(), seed);

			tp.peer->sent_payload(1024*1024*11);
			peer_request req;
			req.length = 1024*1024*11;
			disk_buffer_holder buf_holder;
			tp.peer->on_piece(req, buf_holder);
		}

		test_client tc;
		test_peer_plugin tp(tc.repman(), seed);

		tp.peer->sent_payload(1024*1024*11);
		peer_request req;
		req.length = 1024*1024*11;
		disk_buffer_holder buf_holder;
		tp.peer->on_piece(req, buf_holder);

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
				, std::make_pair((char*)NULL, 0)
				, 1, peer_ids[0].key.pk.data(), peer_ids[0].key.sk.data()));

		tp.peer->establish_rkey();
		tc.repman().get_standing(peer_ids[0].rkey, tp.peer->rkey(), tc.repman().peer_session(tp.peer->rid()));

		TEST_CHECK(tc.ses->m_pending_dht_alerts.pending());
		tc.ses->post_alerts();

		udp::endpoint ep;
		ep.address(address_v4::from_string("1.0.0.1"));
		ep.port(12);

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
		tc.ses->m_dht_direct_requests.front().f(dht::msg(bdecode_node(), ep));
		tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 1);
		tc.ses->m_dht_direct_requests.front().f(dht::msg(bdecode_node(), ep));
		tc.ses->m_dht_direct_requests.erase(tc.ses->m_dht_direct_requests.begin());

		TEST_EQUAL(tc.ses->m_dht_direct_requests.size(), 0);
		TEST_EQUAL(tp.con.m_torrent->m_choked_peers.size(), 1);

		return 0;
	}

} // namespace
} // namespace libtorrent

using namespace libtorrent;

TORRENT_TEST(reputation_manager)
{
	int (*tests[])(void) =
		{test_known_peers
		, test_update_state
		, test_download_multiplier
		, test_single_attribution
		, test_state_at
		, test_optimistic_unchoke
		, test_put_ci
		, test_update_standing_rx
		, test_update_standing_tx
		, test_update_standing_tx_multiple
		, test_known_peers_tx
		, test_standing_tx
		, test_indirect_credit_rx
		, test_attribution_rx
		, test_standing_persistence
		, test_get_standing_failure
		, NULL};

	for (int i = 0; tests[i] != NULL; ++i)
	{
		current_time = clock_type::now();
		test_time = ::time(NULL);
		std::remove("reputation.sqlite");
		if (int result = (*tests[i])())
			return;
	}
}
