/*

Copyright (c) 2014-2015, Steven Siloti
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

#include <map>
#include <vector>
#include <limits>
#include <queue>
#include <sqlite3.h>

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <boost/tuple/tuple.hpp>
#include <boost/make_shared.hpp>
#include <boost/bind.hpp>
#include <boost/thread/condition_variable.hpp>

#ifdef _MSC_VER
#pragma warning(pop)
#endif


#include <libtorrent/extensions/reputation_manager.hpp>
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
#include <libtorrent/alert_types.hpp>
#include <libtorrent/session_status.hpp>
#include <libtorrent/ed25519.hpp>

#include "sha256.hpp"
#include "chacha20poly1305/chacha.hpp"

/*
 * The reputation extension has four main classes:
 *
 * reputation_store - Provides a convenience wrapper around the sqlite database
 * used to store peer and state data.
 *
 * reputation_manager - Implements the session plugin and provides a high level
 * interface to the peer plugin.
.*
 * reputation_session - Represents an active session with a peer. Multiple
 * connections to the same peer share the same session.
 *
 * reputation_peer_plugin - Implements the peer plugin and connection
 * specific state.
 *
 * TODO: Don't send peers with stored outstanding updates as known or use
 * them as intermediaries.
 *
 */

namespace libtorrent { namespace reputation_errors
{
	// libtorrent uses boost.system's ``error_code`` class to represent
	// errors. libtorrent has its own error category get_reputation_category()
	// whith the error codes defined by error_code_enum.
	enum error_code_enum
	{
		// peer failed to send a receipt for data sent to it in a timely manner
		failed_to_send_receipt,
		// the peer sent an invalid standing
		invalid_standing_message,
		// the peer sent an invalid attribution
		invalid_attribution_message,
		// the peer sent a contribution outside of the range (0, 100]
		// or total contributions did not add up to 100
		invalid_contribution,
		// the peer sent an invalid receipt
		invalid_receipt_message,
		// the peer sent a receipt at an intermediary the client does not know about
		unknown_intermediary_receipt,
		// the peer sent a receipt which was either not at an intermediery included in the
		// attribution message sent to it or the volume was not greater than that sent in
		// the previous receipt
		irrelevant_receipt,
		// the peer sent a state for the client which was invalid or outdated
		invalid_reputation_state,
		// the total credit issued by the peer fell too far behind the actual amount
		// of payload sent
		insufficient_credit,
		// intermediary receipts were expected but not included
		missing_receipts,
	};

	// hidden
	boost::system::error_code make_error_code(error_code_enum e);
} } // namespace libtorrent

namespace boost { namespace system
{
	template<> struct is_error_code_enum<libtorrent::reputation_errors::error_code_enum>
	{ static const bool value = true; };

	template<> struct is_error_condition_enum<libtorrent::reputation_errors::error_code_enum>
	{ static const bool value = true; };
} }

namespace libtorrent
{
	struct reputation_error_category : boost::system::error_category
	{
		virtual const char* name() const BOOST_SYSTEM_NOEXCEPT;
		virtual std::string message(int ev) const BOOST_SYSTEM_NOEXCEPT;
		virtual boost::system::error_condition default_error_condition(
			int ev) const BOOST_SYSTEM_NOEXCEPT
		{ return boost::system::error_condition(ev, *this); }
	};

	const char* reputation_error_category::name() const BOOST_SYSTEM_NOEXCEPT
	{
		return "reputation error";
	}

	std::string reputation_error_category::message(int ev) const BOOST_SYSTEM_NOEXCEPT
	{
		static char const* msgs[] =
		{
			"peer failed to send a receipt for data sent to it in a timely manner",
			"the peer sent an invalid standing",
			"the peer sent an invalid attribution",
			"the peer sent a contribution outside of the range (0, 100], or total contributions did not add up to 100",
			"the peer sent an invalid receipt",
			"the peer sent a receipt at an intermediary the client does not know about",
			"the peer sent a receipt at an irrelevent intermediery",
			"the peer sent a state for the client which was invalid or outdated",
			"the total credit issued by the peer fell too far behind the actual amount of payload sent",
			"intermediary receipts were expected but not included",
		};
		if (ev < 0 || ev >= int(sizeof(msgs)/sizeof(msgs[0])))
			return "Unknown error";
		return msgs[ev];
	}

	boost::system::error_category& get_reputation_category()
	{
		static reputation_error_category bdecode_category;
		return bdecode_category;
	}

namespace reputation_errors
{
	boost::system::error_code make_error_code(error_code_enum e)
	{
		return boost::system::error_code(e, get_reputation_category());
	}
}

namespace
{
	enum { max_attributions = 1 };
	enum
	{
		invalid_reputation_key = -1,
		client_reputation_key = 0
	};
	enum { receipt_interval_bytes = 1024*1024*10 };

	/*
	 * Some common shorthand for various peer identifiers:
	 * pkey, pk - an ed25519 public key
	 * rid      - reputation id, SHA1 hash of a public key
	 * rkey     - reputation key, primary key index from the peers table in the database
	*/

	typedef sha1_hash reputation_id;
	typedef sqlite_int64 reputation_key;
	typedef boost::array<char, ed25519_signature_size> signature_type;
	typedef boost::array<char, ed25519_public_key_size> pubkey_type;

	struct reputation_exception : std::exception
	{
		reputation_exception(std::string const& w) : m_what(w) {}
		virtual char const* what() const throw() { return m_what.c_str(); }
		virtual ~reputation_exception() throw() {}
	private:
		std::string m_what;
	};

	inline bool valid(reputation_key k) { return k > 0; }

	bool rid_from_entry(reputation_id& dest, bdecode_node const& e, char const* name)
	{
		bdecode_node elm = e.dict_find_string(name);
		if (!elm || elm.string_length() != reputation_id::size)
			return false;
		dest.assign(elm.string_ptr());
		return true;
	}

	bool rid_from_entry(reputation_id& dest, entry::dictionary_type const& e, char const* name)
	{
		entry::dictionary_type::const_iterator elm = e.find(name);
		if (elm == e.end()
			|| elm->second.type() != entry::string_t
			|| elm->second.string().length() != reputation_id::size)
			return false;
		dest.assign(elm->second.string().data());
		return true;
	}

	struct reputation_state
	{
		entry to_entry() const
		{
			TORRENT_ASSERT(!subject.is_all_zeros());

			entry e;
			e["subject"] = subject.to_string();
			e["ds"] = upload_direct;
			e["dr"] = download_direct;
			e["is"] = upload_recommended;
			e["ir"] = download_recommended;
			e["rs"] = upload_referred;
			e["rr"] = download_referred;
			return e;
		}

		reputation_state()
		{
			zero();
		}

		void zero()
		{
			upload_direct = 0;
			download_direct = 0;
			upload_recommended = 0;
			download_recommended = 0;
			upload_referred = 0;
			download_referred = 0;
		}

		reputation_id subject;
		// bytes of piece data sent directly from the client to the peer
		boost::int64_t upload_direct;
		// bytes of piece data sent directly from the peer to the client
		boost::int64_t download_direct;
		// bytes of piece data sent to other peers due to this peer's
		// recommendation as the intermediary
		boost::int64_t upload_recommended;
		// bytes of piece data received by the client from other peers due to
		// this peer recommendation as the intermediary
		boost::int64_t download_recommended;
		// bytes of piece data sent by any peer to this peer due to the client's referrals
		boost::int64_t upload_referred;
		// bytes of piece data sent by this peer to each of the client's referrals
		boost::int64_t download_referred;
	};

	struct signed_state : reputation_state
	{
		// TODO: disallow default construction. It's easy to forget to
		// initialize the subject when it's needed
		signed_state()
		{
			clear_signature();
		}

		signed_state(bdecode_node const& e
			, reputation_id const& expected_subject
			, pubkey_type const& pk
			, bool extra_fields_allowed = false)
		{
			if (e.type() != bdecode_node::dict_t)
				throw reputation_exception("entry is not a dict");

			if (e.data_section().second > 200)
				throw reputation_exception("entry is too big");

			entry state_entry;
			state_entry = e;
			from_entry(state_entry, expected_subject, pk, extra_fields_allowed);
		}

		signed_state(entry const& e
			, reputation_id const& expected_subject
			, pubkey_type const& pk
			, bool extra_fields_allowed = false)
		{
			if (e.type() != entry::dictionary_t)
				throw reputation_exception("entry is not a dict");

			entry state_entry;
			state_entry = e;
			from_entry(state_entry, expected_subject, pk, extra_fields_allowed);
		}

		entry to_entry() const
		{
			entry e = reputation_state::to_entry();
			e.dict().erase("subject");
			e["sig"] = std::string(sig.data(), sig.size());
			return e;
		}

		void clear_signature()
		{
			std::fill(sig.begin(), sig.end(), 0);
		}

		bool signature_valid()
		{
			return signature_type::size_type(std::count(sig.begin(), sig.end(), 0)) != sig.size();
		}

		signature_type sig;

	private:
		void from_entry(entry& state_entry
			, reputation_id const& expected_subject
			, pubkey_type const& pk
			, bool extra_fields_allowed)
		{
			entry::dictionary_type& dict = state_entry.dict();

			if (rid_from_entry(subject, dict, "subject") && subject != expected_subject)
				throw reputation_exception("invalid subject");

			subject = expected_subject;
			dict["subject"] = expected_subject.to_string();

			entry::dictionary_type::const_iterator sig_entry = dict.find("sig");
			if (sig_entry == dict.end() || sig_entry->second.type() != entry::string_t)
				throw reputation_exception("invalid signature");
			entry::string_type const& sig_string = sig_entry->second.string();
			if (sig_string.size() != sig.size())
				throw reputation_exception("invalid signature");
			std::copy(sig_string.begin(), sig_string.end(), sig.begin());

			dict.erase("sig");
			boost::array<char, 256> verify_str;
			int bsize = bencode(verify_str.begin(), state_entry);
			TORRENT_ASSERT(bsize < 256);
			if (ed25519_verify((unsigned char*)sig.data()
				, (unsigned char*)verify_str.data()
				, bsize
				, (unsigned char*)pk.data()) != 1)
			{
				throw reputation_exception("invalid signature");
			}

			try
			{
				assign_entry(upload_direct, dict, "ds");
				assign_entry(download_direct, dict, "dr");
				assign_entry(upload_recommended, dict, "is");
				assign_entry(download_recommended, dict, "ir");
				assign_entry(upload_referred, dict, "rs");
				assign_entry(download_referred, dict, "rr");
			}
			catch (libtorrent_exception)
			{
				throw reputation_exception("invalid state counter");
			}

			if (dict.size() != 7)
			{
				if (extra_fields_allowed)
					// If there are unknown fields they will be discarded.
					// Zero out the signature because it will not validate
					// if we reconstitute the state from the fields we know.
					clear_signature();
				else
					throw reputation_exception("unknown fields");
			}
		}

		void assign_entry(boost::int64_t& dest, entry::dictionary_type const& e, char const* name)
		{
			entry::dictionary_type::const_iterator elm = e.find(name);
			if (elm == e.end())
				throw reputation_exception(std::string("key not found: ") + name);
			dest = elm->second.integer();
			if (dest < 0)
				throw reputation_exception("invalid state counter");
		}
	};

	struct attribution
	{
		attribution()
			: sequence(-1), intermediary(invalid_reputation_key), contribution(0) {}
		attribution(reputation_key i, int c)
			: sequence(-1), intermediary(i), contribution(c) {}
		boost::int64_t sequence;
		reputation_key intermediary;
		boost::uint8_t contribution;
		bool credited;
	};

	typedef std::vector<attribution> attributions_type;

	struct peer_reputation
	{
		peer_reputation()
			: reputation(std::numeric_limits<double>::min())
		{}

		bool direct() const
		{
			for (attributions_type::const_iterator i = attributions.begin();
				i != attributions.end(); ++i)
				if (i->contribution > 0)
					return false;
			return valid();
		}

		bool valid() const
		{
			return reputation != std::numeric_limits<double>::min();
		}

		void assign_direct(double value)
		{
			reputation = value;
			attributions.clear();
		}

		void invalidate()
		{
			assign_direct(std::numeric_limits<double>::min());
		}

		double reputation;
		attributions_type attributions;
	};

	struct standing_update
	{
		standing_update(entry& e
			, reputation_id const& expected_sender
			, reputation_id const& expected_recipient
			, pubkey_type recipient_pk)
			: recipient(expected_recipient)
		{
			if (e.type() != entry::dictionary_t)
				throw reputation_exception("receipt is not a dictionary");

			entry::dictionary_type& edict = e.dict();
			entry::dictionary_type::iterator seq_entry = edict.find("seq");
			if (seq_entry == edict.end()
				|| seq_entry->second.type() != entry::int_t
				|| seq_entry->second.integer() < 0)
				throw reputation_exception("invalid sequence number");
			sequence = seq_entry->second.integer();

			reputation_id sender;
			if (rid_from_entry(sender, edict, "sender") && sender != expected_sender)
				throw reputation_exception("invalid sender");
			if (rid_from_entry(recipient, edict, "recipient") && recipient != expected_recipient)
				throw reputation_exception("invalid recipient");
			if (!rid_from_entry(intermediary, edict, "intermediary"))
				throw reputation_exception("invalid intermediary");

			entry::dictionary_type::iterator volume_entry = edict.find("volume");
			if (volume_entry == edict.end()
				|| volume_entry->second.type() != entry::int_t
				|| volume_entry->second.integer() < 0)
				throw reputation_exception("invalid volume");
			volume = volume_entry->second.integer();

			entry::dictionary_type::iterator sig_entry = edict.find("sig");
			if (sig_entry == edict.end()
				|| sig_entry->second.type() != entry::string_t
				|| sig_entry->second.string().length() != signature_type::static_size)
				throw reputation_exception("invalid signature");
			std::copy(sig_entry->second.string().begin()
				, sig_entry->second.string().end()
				, sig.begin());

			edict["sender"] = expected_sender.to_string();
			edict["recipient"] = expected_recipient.to_string();
			edict.erase("sig");

			boost::array<char, 256> verify_str;
			int bsize = bencode(verify_str.begin(), e);
			TORRENT_ASSERT(bsize < 256);
			edict["sig"] = std::string(sig.data(), sig.size());
			if (ed25519_verify((unsigned char*)sig.data()
				, (unsigned char*)verify_str.data()
				, bsize
				, (unsigned char*)recipient_pk.data()) != 1)
			{
				throw reputation_exception("invalid signature");
			}
		}

		standing_update(
			boost::int64_t sequence
			, reputation_id recipient
			, reputation_id intermediary
			, boost::int64_t volume
			, signature_type sig)
				: sequence(sequence)
				, recipient(recipient)
				, intermediary(intermediary)
				, volume(volume)
				, sig(sig)
			{}

		entry to_entry(reputation_id const& sender)
		{
			// this data is going to be sent to the intermediary
			// so that field is ommitted here
			entry e;
			e["seq"] = sequence;
			e["sender"] = sender.to_string();
			e["recipient"] = recipient.to_string();
			e["volume"] = volume;
			e["sig"] = std::string(sig.data(), sig.size());
			return e;
		}

		boost::int64_t sequence;
		// currently this struct is only used for forwarding updates so the sender is always the client
		//reputation_id sender;
		reputation_id recipient;
		reputation_id intermediary;
		boost::int64_t volume;
		signature_type sig;
	};

	struct stored_standing_update
	{
		stored_standing_update(standing_update const& update
			, reputation_key intermediary, reputation_key recipient)
			: update(update), intermediary(intermediary), recipient(recipient)
		{}

		standing_update update;
		reputation_key intermediary;
		reputation_key recipient;
	};

	struct reputation_value
	{
		reputation_value(double v, reputation_key i)
			: value(v), rkey(i) {}
		double value;
		reputation_key rkey;
	};

	class reputation_manager;
	class reputation_session;
	class reputation_peer_plugin;

	struct reputation_torrent_plugin : torrent_plugin
	{
		reputation_torrent_plugin(reputation_manager& repman)
			: m_repman(repman)
		{}

		virtual boost::shared_ptr<peer_plugin> new_connection(
			peer_connection_handle const& pc);

	private:
		reputation_manager& m_repman;
	};

	struct contact_info
	{
		enum
		{
			v4_size = sizeof(boost::asio::ip::address_v4::bytes_type) + sizeof(uint16_t),
			v6_size = sizeof(boost::asio::ip::address_v6::bytes_type) + sizeof(uint16_t),
			v46_size = sizeof(boost::asio::ip::address_v4::bytes_type)
				+ sizeof(boost::asio::ip::address_v6::bytes_type) + sizeof(uint16_t),
		};

		typedef boost::array<boost::uint8_t, v46_size> bytes_type;

		template <typename OutIterator>
		OutIterator to_bytes(OutIterator out) const
		{
			using namespace boost::asio::ip;

			if (addr_v4 != address_v4())
			{
				address_v4::bytes_type adr_bytes = addr_v4.to_bytes();
				out = std::copy(adr_bytes.begin(), adr_bytes.end(), out);
			}
			if (addr_v6 != address_v6())
			{
				address_v6::bytes_type adr_bytes = addr_v6.to_bytes();
				out = std::copy(adr_bytes.begin(), adr_bytes.end(), out);
			}

			detail::write_uint16(port, out);
			return out;
		}

		contact_info() : port(0) {}

		template <typename Iterator>
		contact_info(Iterator begin, Iterator end)
		{
			using namespace boost::asio::ip;

			int size = std::distance(begin, end);

			if (size == v4_size || size >= v46_size)
			{
				address_v4::bytes_type adr_bytes;
				std::copy(begin, begin + adr_bytes.size(), adr_bytes.begin());
				addr_v4 = address_v4(adr_bytes);
				begin += adr_bytes.size();
			}
			if (size == v6_size || size >= v46_size)
			{
				address_v6::bytes_type adr_bytes;
				std::copy(begin, begin + adr_bytes.size(), adr_bytes.begin());
				addr_v6 = address_v6(adr_bytes);
				begin += adr_bytes.size();
			}

			if (begin == end)
				throw reputation_exception("invalid contact info");

			if (addr_v4 == address_v4() && addr_v6 == address_v6())
				throw reputation_exception("invalid IP addresses");

			port = detail::read_uint16(begin);
			if (port == 0)
				throw reputation_exception("invalid port");
		}

		address_v4 addr_v4;
		address_v6 addr_v6;
		uint16_t port;
	};

	void pbkdf2_hmac_sha256(std::string const& pw
		, std::vector<boost::uint8_t> const& salt
		, boost::array<boost::uint8_t, 32>& key)
	{
		boost::array<boost::uint8_t, 4> const i = {0,0,0,1};
		boost::array<boost::uint8_t, 512> mac_key = {0};

		if (pw.size() > mac_key.size())
		{
			CSha256 pw_digest;
			Sha256_Init(&pw_digest);
			Sha256_Update(&pw_digest, (boost::uint8_t*)pw.data(), pw.size());
			Sha256_Final(&pw_digest, mac_key.data());
		}
		else
			std::copy(pw.begin(), pw.end(), mac_key.begin());

		boost::array<boost::uint8_t, 512> ikey, okey;
		std::transform(mac_key.begin(), mac_key.end(), ikey.begin()
			, boost::bind(std::bit_xor<boost::uint8_t>(), 0x36, _1));
		std::transform(mac_key.begin(), mac_key.end(), okey.begin()
			, boost::bind(std::bit_xor<boost::uint8_t>(), 0x5c, _1));

		CSha256 digest;
		Sha256_Init(&digest);
		Sha256_Update(&digest, ikey.data(), ikey.size());
		Sha256_Update(&digest, salt.data(), salt.size());
		Sha256_Update(&digest, i.data(), i.size());
		Sha256_Final(&digest, key.data());

		Sha256_Init(&digest);
		Sha256_Update(&digest, okey.data(), okey.size());
		Sha256_Update(&digest, key.data(), key.size());
		Sha256_Final(&digest, key.data());

		for (int i = 0; i < 4096; ++i)
		{
			boost::array<boost::uint8_t, 32> u;

			Sha256_Init(&digest);
			Sha256_Update(&digest, ikey.data(), ikey.size());
			Sha256_Update(&digest, key.data(), key.size());
			Sha256_Final(&digest, u.data());

			Sha256_Init(&digest);
			Sha256_Update(&digest, okey.data(), okey.size());
			Sha256_Update(&digest, u.data(), u.size());
			Sha256_Final(&digest, u.data());

			std::transform(key.begin(), key.end(), u.begin(), key.begin()
				, std::bit_xor<boost::uint8_t>());
		}
	}

	void encrypt_seed(std::string const& sk_password
		, pubkey_type const& client_pk
		, boost::array<unsigned char, ed25519_seed_size>& seed)
	{
		boost::array<boost::uint8_t, 32> private_enc_key;
		pbkdf2_hmac_sha256(sk_password
			, std::vector<uint8_t>(client_pk.begin(), client_pk.end())
			, private_enc_key);

		chacha_ctx seed_encrypt;
		chacha_keysetup(&seed_encrypt, private_enc_key.data(), 256);
		unsigned char iv[CHACHA_NONCELEN] = {0,0,0,0,0,0,0,0};
		chacha_ivsetup(&seed_encrypt, iv, 0);
		std::vector<boost::asio::mutable_buffer> m;
		m.push_back(boost::asio::mutable_buffer(seed.data(), seed.size()));
		chacha_encrypt_bytes(&seed_encrypt, m);
	}

	struct db_init_error : std::exception
	{
		db_init_error() : m_what("error initializing reputation database") {}
		db_init_error(std::string const& w) : m_what(w) {}
		virtual char const* what() const throw() { return m_what.c_str(); }
		virtual ~db_init_error() throw() {}
		std::string m_what;
	};

	class reputation_store
	{
		void prepare(char const* sql, sqlite3_stmt*& stmt)
		{
			if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, NULL) != SQLITE_OK)
				throw db_init_error();
		}

	public:
		reputation_store(std::string db_path)
		{
			sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);

			if (sqlite3_open((db_path + "/reputation.sqlite").c_str(), &m_db) != SQLITE_OK)
				throw db_init_error();
			if (sqlite3_exec(m_db, schema, NULL, NULL, NULL) != SQLITE_OK)
				throw db_init_error();
			if (sqlite3_exec(m_db, "PRAGMA foreign_keys = TRUE", NULL, NULL, NULL) != SQLITE_OK)
				throw db_init_error();
			prepare(establish_peer_stmt, m_establish_peer);
			prepare(get_rid_stmt, m_get_rid);
			prepare(get_key_stmt, m_get_key);
			prepare(get_pkey_stmt, m_get_pkey);
			prepare(known_peers_stmt, m_known_peers);
			prepare(indirect_value_stmt, m_indirect_value);
			prepare(direct_value_stmt, m_direct_value);
			prepare(self_value_stmt, m_self_value);
			prepare(state_at_stmt, m_state_at_for);
			prepare(observed_stmt, m_observed);
			prepare(observation_count_stmt, m_observation_count);
			prepare(store_state_stmt, m_store_state);
			prepare(get_peer_ep_stmt, m_get_peer_ep);
			prepare(set_peer_ep_stmt, m_set_peer_ep);
			prepare(drop_observations_stmt, m_drop_observations);
			prepare(last_sequence_stmt, m_last_sequence);
			prepare(received_sequence_stmt, m_received_sequence);
			prepare(upload_referred_stmt, m_upload_referred);
			prepare(download_referred_stmt, m_download_referred);
			prepare(touch_peer_stmt, m_touch_peer);
			prepare(touch_peer_state_stmt, m_touch_peer_state);
			prepare(purge_state_stmt, m_purge_state);
			prepare(purge_peers_stmt, m_purge_peers);
			prepare(global_direct_balance_stmt, m_global_direct_balance);
			prepare(get_value_stmt, m_get_value);
			prepare(set_value_stmt, m_set_value);
			prepare(outstanding_updates_to_intermediary_stmt, m_outstanding_updates_to_intermediary);
			prepare(get_outstanding_update_stmt, m_get_outstanding_update);
			prepare(save_update_stmt, m_save_update);
			prepare(retried_update_stmt, m_retried_update);
			prepare(delete_update_stmt, m_delete_update);
			prepare(retryable_updates_stmt, m_retryable_updates);
		}

		~reputation_store()
		{
			sqlite3_finalize(m_retryable_updates);
			sqlite3_finalize(m_delete_update);
			sqlite3_finalize(m_retried_update);
			sqlite3_finalize(m_save_update);
			sqlite3_finalize(m_get_outstanding_update);
			sqlite3_finalize(m_outstanding_updates_to_intermediary);
			sqlite3_finalize(m_set_value);
			sqlite3_finalize(m_get_value);
			sqlite3_finalize(m_global_direct_balance);
			sqlite3_finalize(m_purge_peers);
			sqlite3_finalize(m_purge_state);
			sqlite3_finalize(m_touch_peer_state);
			sqlite3_finalize(m_touch_peer);
			sqlite3_finalize(m_download_referred);
			sqlite3_finalize(m_upload_referred);
			sqlite3_finalize(m_received_sequence);
			sqlite3_finalize(m_last_sequence);
			sqlite3_finalize(m_drop_observations);
			sqlite3_finalize(m_set_peer_ep);
			sqlite3_finalize(m_get_peer_ep);
			sqlite3_finalize(m_store_state);
			sqlite3_finalize(m_observation_count);
			sqlite3_finalize(m_observed);
			sqlite3_finalize(m_state_at_for);
			sqlite3_finalize(m_self_value);
			sqlite3_finalize(m_direct_value);
			sqlite3_finalize(m_indirect_value);
			sqlite3_finalize(m_known_peers);
			sqlite3_finalize(m_get_pkey);
			sqlite3_finalize(m_get_key);
			sqlite3_finalize(m_get_rid);
			sqlite3_finalize(m_establish_peer);
			int result = sqlite3_close(m_db);
			TORRENT_ASSERT(result == SQLITE_OK);
		}

		friend class transaction;
		class transaction : boost::noncopyable
		{
		public:
			transaction(reputation_store& s)
				: m_db(s.m_db)
			{
				int result = sqlite3_exec(m_db, "BEGIN", NULL, NULL, NULL);
				TORRENT_ASSERT(result == SQLITE_OK);
			}

			~transaction()
			{
				int result = sqlite3_exec(m_db, "COMMIT", NULL, NULL, NULL);
				TORRENT_ASSERT(result == SQLITE_OK);
			}

		private:
			sqlite3* m_db;
		};

		bool establish_client(pubkey_type const& client_pk)
		{
			pubkey_type db_client_pk;
			if (get_pkey(client_reputation_key, db_client_pk))
			{
				if (db_client_pk != client_pk)
					return false;
			}
			else
			{
				reputation_id client_rid = hasher(client_pk.data(), client_pk.size()).final();
				sqlite3_stmt* establish_client;
				int result = sqlite3_prepare_v2(m_db
					, "INSERT OR IGNORE INTO peers (reputation_key, public_key, reputation_id) \
						VALUES (?1, ?2, ?3)"
					, -1, &establish_client, NULL);
				TORRENT_ASSERT(result == SQLITE_OK);
				sqlite3_bind_int64(establish_client, 1, client_reputation_key);
				sqlite3_bind_blob(establish_client, 2, client_pk.data(), client_pk.size(), SQLITE_STATIC);
				sqlite3_bind_blob(establish_client, 3, &client_rid[0], reputation_id::size, SQLITE_STATIC);
				result = sqlite3_step(establish_client);
				TORRENT_ASSERT(result == SQLITE_DONE);
				sqlite3_reset(establish_client);
				sqlite3_finalize(establish_client);
			}
			return true;
		}

		reputation_key establish_peer(pubkey_type const& pk
			, reputation_id const& rid
			, contact_info const& ci)
		{
			reputation_key rkey = get_rkey(rid);
			if (!valid(rkey))
			{
				sqlite3_bind_blob(m_establish_peer, 1, pk.data(), pk.size(), SQLITE_STATIC);
				sqlite3_bind_blob(m_establish_peer, 2, &rid[0], reputation_id::size, SQLITE_STATIC);
				sqlite_bind_ci(m_establish_peer, 3, ci);
				int result = sqlite3_step(m_establish_peer);
				TORRENT_ASSERT(result == SQLITE_DONE);
				int rows_changed = sqlite3_changes(m_db);
				TORRENT_ASSERT(rows_changed == 1);
				if (rows_changed == 1)
					rkey = sqlite3_last_insert_rowid(m_db);
				sqlite3_reset(m_establish_peer);
			}
			return rkey;
		}

		bool get_rid(reputation_key rkey, reputation_id& rid)
		{
			bool ret = false;
			sqlite3_bind_int64(m_get_rid, 1, rkey);
			int result = sqlite3_step(m_get_rid);
			if (result == SQLITE_ROW)
			{
				int rid_size = sqlite3_column_bytes(m_get_rid, 0);
				TORRENT_ASSERT(rid_size == reputation_id::size);
				if (rid_size == reputation_id::size)
				{
					rid.assign((char*)sqlite3_column_blob(m_get_rid, 0));
					ret = true;
				}
			}
			else
				TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_get_rid);
			return ret;
		}

		reputation_key get_rkey(reputation_id const& rid)
		{
			reputation_key rkey = invalid_reputation_key;
			sqlite3_bind_blob(m_get_key, 1, &rid[0], reputation_id::size, SQLITE_STATIC);
			int result = sqlite3_step(m_get_key);
			if (result == SQLITE_ROW)
			{
				rkey = sqlite3_column_int64(m_get_key, 0);
			}
			else
				TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_get_key);
			return rkey;
		}

		bool get_pkey(reputation_key rkey, pubkey_type& pk)
		{
			bool ret = false;
			sqlite3_bind_int64(m_get_pkey, 1, rkey);
			int result = sqlite3_step(m_get_pkey);
			if (result == SQLITE_ROW)
			{
				if (sqlite3_column_bytes(m_get_pkey, 0) == int(pk.size()))
				{
					memcpy(pk.data(), sqlite3_column_blob(m_get_pkey, 0), pk.size());
					ret = true;
				}
			}
			sqlite3_reset(m_get_pkey);
			return ret;
		}

		void known_peers(std::vector<reputation_id>& peers)
		{
			int result;
			transaction t(*this);
			while ((result = sqlite3_step(m_known_peers)) == SQLITE_ROW )
			{
				int rid_size = sqlite3_column_bytes(m_known_peers, 0);
				TORRENT_ASSERT(rid_size == reputation_id::size);
				if (rid_size == reputation_id::size)
				{
					peers.push_back(reputation_id((char const*)sqlite3_column_blob(m_known_peers, 0)));
				}
			}
			sqlite3_reset(m_known_peers);
		}

		bool state_at_for(reputation_key at, reputation_key for_, signed_state& state)
		{
			bool ret = false;
			sqlite3_bind_int64(m_state_at_for, 1, at);
			sqlite3_bind_int64(m_state_at_for, 2, for_);
			int result = sqlite3_step(m_state_at_for);
			if (result == SQLITE_ROW)
			{
				ret = sqlite_copy_state(at, for_, state);
			}
			else
			{
				state.zero();
			}
			sqlite3_reset(m_state_at_for);
			return ret;
		}

		void observed(reputation_key peer, double credited = 1.0)
		{
			sqlite3_bind_int64(m_observed, 1, peer);
			sqlite3_bind_double(m_observed, 2, credited);
			int result = sqlite3_step(m_observed);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_observed);
		}

		std::pair<double, reputation_key> observation_count(reputation_id const& peer)
		{
			double count = 0;
			reputation_key rep_key = -1;

			sqlite3_bind_blob(m_observation_count, 1, peer.begin(), peer.size, SQLITE_STATIC);
			int result = sqlite3_step(m_observation_count);
			if (result == SQLITE_ROW)
			{
				rep_key = sqlite3_column_int64(m_observation_count, 0);
				count = sqlite3_column_double(m_observation_count, 1);
			}
			sqlite3_reset(m_observation_count);

			return std::make_pair(count, rep_key);
		}

		enum store_state_result
		{
			state_success,  // state was successfully stored
			state_outdated, // state was equal or older than what was already stored
			state_invalid,  // at least one of the state counters has gone backwards
			                // this should never happen and indicates a seriously malfunctioning peer
		};

		// if the result is state_success the referred states will be modified to reflect the difference
		// from the stored state, if any
		// if the result is not state_success state will be modified to reflect the current stored state
		store_state_result store_state(reputation_key at, reputation_key for_, signed_state& state)
		{
			// should not be storing state at ourselves
			TORRENT_ASSERT(valid(at));
			if (!valid(at))
				throw reputation_exception("Invalid attempt to store state at client");

			bool greater = false;
			bool less = false;

			boost::int64_t upload_referred_increase = 0;
			boost::int64_t download_referred_increase = 0;

			sqlite3_bind_int64(m_state_at_for, 1, at);
			sqlite3_bind_int64(m_state_at_for, 2, for_);
			int result = sqlite3_step(m_state_at_for);
			if (result == SQLITE_ROW)
			{
				greater |= state.upload_direct > sqlite3_column_int64(m_state_at_for, 0);
				less |= state.upload_direct < sqlite3_column_int64(m_state_at_for, 0);
				greater |= state.download_direct > sqlite3_column_int64(m_state_at_for, 1);
				less |= state.download_direct < sqlite3_column_int64(m_state_at_for, 1);
				greater |= state.upload_recommended > sqlite3_column_int64(m_state_at_for, 2);
				less |= state.upload_recommended < sqlite3_column_int64(m_state_at_for, 2);
				greater |= state.download_recommended > sqlite3_column_int64(m_state_at_for, 3);
				less |= state.download_recommended < sqlite3_column_int64(m_state_at_for, 3);
				greater |= state.upload_referred > sqlite3_column_int64(m_state_at_for, 4);
				less |= state.upload_referred < sqlite3_column_int64(m_state_at_for, 4);
				greater |= state.download_referred > sqlite3_column_int64(m_state_at_for, 5);
				less |= state.download_referred < sqlite3_column_int64(m_state_at_for, 5);
			}
			else
				greater = true;

			store_state_result store_result;
			if (greater && !less)
			{
				store_result = state_success;
				upload_referred_increase = state.upload_referred - sqlite3_column_int64(m_state_at_for, 4);
				download_referred_increase = state.download_referred - sqlite3_column_int64(m_state_at_for, 5);
			}
			else if (!greater)
				store_result = state_outdated;
			else
				store_result = state_invalid;

			if (store_result == state_success || !sqlite_copy_state(at, for_, state))
			{
				// the given state was newer or the stored state is invalid
				sqlite3_reset(m_state_at_for);
				store_result = state_success;
				sqlite3_bind_int64(m_store_state, 1, at);
				sqlite3_bind_int64(m_store_state, 2, for_);
				sqlite_bind_state(m_store_state, 3, state);
				if (state.signature_valid())
					sqlite3_bind_blob(m_store_state, 9, state.sig.data(), state.sig.size(), SQLITE_STATIC);
				else
					sqlite3_bind_null(m_store_state, 9);
				result = sqlite3_step(m_store_state);
				TORRENT_ASSERT(result == SQLITE_DONE);
				sqlite3_reset(m_store_state);
			}
			else
				sqlite3_reset(m_state_at_for);

			state.upload_referred = upload_referred_increase;
			state.download_referred = download_referred_increase;

			return store_result;
		}

		double direct_value(reputation_key peer)
		{
			double ret(0.0);
			sqlite3_bind_int64(m_direct_value, 1, peer);
			int result = sqlite3_step(m_direct_value);
			if (result == SQLITE_ROW)
			{
				ret = sqlite3_column_double(m_direct_value, 0);
			}
			sqlite3_reset(m_direct_value);
			return ret;
		}

		double indirect_value(reputation_key peer, reputation_key intermediary)
		{
			double ret(0.0);
			sqlite3_bind_int64(m_indirect_value, 1, peer);
			sqlite3_bind_int64(m_indirect_value, 2, intermediary);
			int result = sqlite3_step(m_indirect_value);
			if (result == SQLITE_ROW)
			{
				ret = sqlite3_column_double(m_indirect_value, 0);
			}
			sqlite3_reset(m_indirect_value);
			return ret;
		}

		double self_value()
		{
			double ret(0.0);
			if (sqlite3_step(m_self_value) == SQLITE_ROW)
			{
				ret = sqlite3_column_double(m_self_value, 0);
			}
			sqlite3_reset(m_self_value);
			return ret;
		}

		void update_state_for(reputation_key peer, reputation_state& state)
		{
			sqlite3_bind_int64(m_state_at_for, 1, client_reputation_key);
			sqlite3_bind_int64(m_state_at_for, 2, peer);
			int result = sqlite3_step(m_state_at_for);
			if (result == SQLITE_ROW)
			{
				state.upload_direct += sqlite3_column_int64(m_state_at_for, 0);
				state.download_direct += sqlite3_column_int64(m_state_at_for, 1);
				state.upload_recommended += sqlite3_column_int64(m_state_at_for, 2);
				state.download_recommended += sqlite3_column_int64(m_state_at_for, 3);
				state.upload_referred += sqlite3_column_int64(m_state_at_for, 4);
				state.download_referred += sqlite3_column_int64(m_state_at_for, 5);
			}
			sqlite3_reset(m_state_at_for);

			sqlite3_bind_int64(m_store_state, 1, client_reputation_key);
			sqlite3_bind_int64(m_store_state, 2, peer);
			sqlite_bind_state(m_store_state, 3, state);
			sqlite3_bind_null(m_store_state, 9);
			result = sqlite3_step(m_store_state);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_store_state);
		}

		std::pair<contact_info, time_t> get_peer_ep(reputation_key peer)
		{
			std::pair<contact_info, time_t> ret;
			ret.second = -1;
			sqlite3_bind_int64(m_get_peer_ep, 1, peer);
			int result = sqlite3_step(m_get_peer_ep);
			if (result == SQLITE_ROW)
			{
				int address_size = sqlite3_column_bytes(m_get_peer_ep, 0);
				uint8_t* address_ptr = (uint8_t*)sqlite3_column_blob(m_get_peer_ep, 0);
				try
				{
					ret.first = contact_info(address_ptr, address_ptr + address_size);
					ret.second = sqlite3_column_int64(m_get_peer_ep, 1);
				}
				catch (reputation_exception) {}
			}
			sqlite3_reset(m_get_peer_ep);
			return ret;
		}

		bool set_peer_ep(reputation_key peer, contact_info const& ci)
		{
			sqlite3_bind_int64(m_set_peer_ep, 1, peer);
			sqlite_bind_ci(m_set_peer_ep, 2, ci);
			int result = sqlite3_step(m_set_peer_ep);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_set_peer_ep);
			return sqlite3_changes(m_db) == 1;
		}

		// there was a failure to contact the peer
		void contact_failure(reputation_key peer)
		{
			sqlite3_bind_int64(m_drop_observations, 1, peer);
			int result = sqlite3_step(m_drop_observations);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_drop_observations);
		}

		void on_receipt(reputation_key recipient
			, reputation_key sender
			, boost::int64_t sequence
			, boost::int64_t volume)
		{
			transaction t(*this);

			boost::int64_t last_sequence = -1;

			sqlite3_bind_int64(m_last_sequence, 1, recipient);
			sqlite3_bind_int64(m_last_sequence, 2, sender);
			int result = sqlite3_step(m_last_sequence);
			TORRENT_ASSERT(result == SQLITE_ROW || result == SQLITE_DONE);
			if (result == SQLITE_ROW)
			{
				last_sequence = sqlite3_column_int64(m_last_sequence, 0);
			}
			sqlite3_reset(m_last_sequence);

			if (sequence <= last_sequence)
				return;

			sqlite3_bind_int64(m_received_sequence, 1, recipient);
			sqlite3_bind_int64(m_received_sequence, 2, sender);
			sqlite3_bind_int64(m_received_sequence, 3, sequence);
			result = sqlite3_step(m_received_sequence);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_received_sequence);

			signed_state recipient_state;
			if (!state_at_for(client_reputation_key, recipient, recipient_state))
				return;

			boost::int64_t const max_upload_referred
				= recipient_state.download_referred
				+ recipient_state.download_direct
				- recipient_state.upload_direct;

			// cap volume to enforce no negative ballance
			if (recipient_state.upload_referred + volume > max_upload_referred)
				volume = std::max(max_upload_referred - recipient_state.upload_referred
					, boost::int64_t(0));

			if (volume > 0)
			{
				sqlite3_bind_int64(m_upload_referred, 1, recipient);
				sqlite3_bind_int64(m_upload_referred, 2, volume);
				result = sqlite3_step(m_upload_referred);
				TORRENT_ASSERT(result == SQLITE_DONE);
				sqlite3_reset(m_upload_referred);

				sqlite3_bind_int64(m_download_referred, 1, sender);
				sqlite3_bind_int64(m_download_referred, 2, volume);
				result = sqlite3_step(m_download_referred);
				TORRENT_ASSERT(result == SQLITE_DONE);
				sqlite3_reset(m_download_referred);

				if (sqlite3_changes(m_db) == 0)
				{
					reputation_state state;
					state.download_referred = volume;
					update_state_for(sender, state);
				}
			}
		}

		void touch(reputation_key peer)
		{
			sqlite3_bind_int64(m_touch_peer, 1, peer);
			int result = sqlite3_step(m_touch_peer);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_touch_peer);
			sqlite3_bind_int64(m_touch_peer_state, 1, peer);
			result = sqlite3_step(m_touch_peer_state);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_touch_peer_state);
		}

		boost::int64_t global_direct_transfer_balance()
		{
			boost::int64_t balance = 0;
			int result = sqlite3_step(m_global_direct_balance);
			TORRENT_ASSERT(result == SQLITE_ROW);
			if (result == SQLITE_ROW)
				balance = sqlite3_column_int64(m_global_direct_balance, 0);
			sqlite3_reset(m_global_direct_balance);
			return balance;
		}

		void purge_state()
		{
			int result = sqlite3_step(m_purge_state);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_purge_state);
		}

		void purge_peers()
		{
			int result = sqlite3_step(m_purge_peers);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_purge_peers);
		}

		int get_int_value(int key, int default_)
		{
			sqlite3_bind_int(m_get_value, 1, key);
			int result = sqlite3_step(m_get_value);
			if (result == SQLITE_ROW)
			{
				default_ = sqlite3_column_int(m_get_value, 0);
			}
			sqlite3_reset(m_get_value);
			return default_;
		}

		sqlite_int64 get_int64_value(int key, sqlite_int64 default_)
		{
			sqlite3_bind_int(m_get_value, 1, key);
			int result = sqlite3_step(m_get_value);
			if (result == SQLITE_ROW)
			{
				default_ = sqlite3_column_int64(m_get_value, 0);
			}
			sqlite3_reset(m_get_value);
			return default_;
		}

		std::vector<char> get_blob_value(int key)
		{
			std::vector<char> ret;
			sqlite3_bind_int(m_get_value, 1, key);
			int result = sqlite3_step(m_get_value);
			if (result == SQLITE_ROW)
			{
				ret.assign((char*)sqlite3_column_blob(m_get_value, 0)
					, (char*)sqlite3_column_blob(m_get_value, 0) + sqlite3_column_bytes(m_get_value, 0));
			}
			sqlite3_reset(m_get_value);
			return ret;
		}

		void set_int_value(int key, int value)
		{
			sqlite3_bind_int(m_set_value, 1, key);
			sqlite3_bind_int(m_set_value, 2, value);
			int result = sqlite3_step(m_set_value);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_set_value);
		}

		void set_int64_value(int key, sqlite3_int64 value)
		{
			sqlite3_bind_int(m_set_value, 1, key);
			sqlite3_bind_int64(m_set_value, 2, value);
			int result = sqlite3_step(m_set_value);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_set_value);
		}

		void set_blob_value(int key, std::vector<char> const& value)
		{
			sqlite3_bind_int(m_set_value, 1, key);
			sqlite3_bind_blob(m_set_value, 2, value.data(), value.size(), SQLITE_STATIC);
			int result = sqlite3_step(m_set_value);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_set_value);
		}

		bool has_pending_updates(reputation_key intermediary)
		{
			sqlite3_bind_int64(m_outstanding_updates_to_intermediary, 1, intermediary);
			int result = sqlite3_step(m_outstanding_updates_to_intermediary);
			TORRENT_ASSERT(result == SQLITE_DONE || result == SQLITE_ROW);
			sqlite3_reset(m_outstanding_updates_to_intermediary);
			return result == SQLITE_ROW;
		}

		void pending_updates_for(reputation_key intermediary
			, std::vector<stored_standing_update>& updates)
		{
			sqlite3_bind_int64(m_outstanding_updates_to_intermediary, 1, intermediary);
			while (sqlite3_step(m_outstanding_updates_to_intermediary) == SQLITE_ROW) try
			{
				updates.push_back(load_standing_update(m_outstanding_updates_to_intermediary));
			}
			catch (reputation_exception) {}
			sqlite3_reset(m_outstanding_updates_to_intermediary);
		}

		void save_pending_update(stored_standing_update const& update)
		{
			boost::int64_t volume = 0;
			int retries = 0;
			time_t last_attempt = time(NULL);

			sqlite3_bind_int64(m_get_outstanding_update, 1, update.intermediary);
			sqlite3_bind_int64(m_get_outstanding_update, 2, update.recipient);
			sqlite3_bind_int64(m_get_outstanding_update, 3, update.update.sequence);
			int result = sqlite3_step(m_get_outstanding_update);
			TORRENT_ASSERT(result == SQLITE_DONE || result == SQLITE_ROW);
			if (result == SQLITE_ROW)
			{
				volume = sqlite3_column_int64(m_get_outstanding_update, update_volume);
				retries = sqlite3_column_int(m_get_outstanding_update, update_retries);
				last_attempt = time_t(sqlite3_column_int64(m_get_outstanding_update, update_last_attempt));
			}
			sqlite3_reset(m_get_outstanding_update);

			if (retries > 5) return;

			if (update.update.volume < volume)
				// This update has been superseded by the one in storage.
				// This probably shouldn't happen, but if it does just drop the update.
				return;
			else if (update.update.volume == volume)
			{
				// We're re-saving the same update as is on disk, just bump the retry count and reset
				// the last attempt timestamp.
				sqlite3_bind_int64(m_retried_update, 1, update.intermediary);
				sqlite3_bind_int64(m_retried_update, 2, update.recipient);
				sqlite3_bind_int64(m_retried_update, 3, update.update.sequence);
				result = sqlite3_step(m_retried_update);
				TORRENT_ASSERT(result == SQLITE_DONE);
				sqlite3_reset(m_retried_update);
			}
			else
			{
				// This is a new update which is either unstored or supersedes the stored update.
				// Preserve the retry count and last attempt from the superseded update, if any, and insert the new
				// update, possibly replacing the existing row.
				sqlite3_bind_int64(m_save_update, 1, update.intermediary);
				sqlite3_bind_int64(m_save_update, 2, update.recipient);
				sqlite3_bind_int64(m_save_update, 3, update.update.sequence);
				sqlite3_bind_int64(m_save_update, 4, update.update.volume);
				sqlite3_bind_blob(m_save_update, 5, update.update.sig.data(), update.update.sig.size(), SQLITE_STATIC);
				sqlite3_bind_int64(m_save_update, 6, last_attempt);
				sqlite3_bind_int(m_save_update, 7, retries);
				result = sqlite3_step(m_save_update);
				TORRENT_ASSERT(result == SQLITE_DONE);
				sqlite3_reset(m_save_update);
			}
		}

		void delete_pending_update(reputation_key intermediary, reputation_key recipient
			, boost::int64_t sequence, boost::int64_t volume)
		{
			sqlite3_bind_int64(m_delete_update, 1, intermediary);
			sqlite3_bind_int64(m_delete_update, 2, recipient);
			sqlite3_bind_int64(m_delete_update, 3, sequence);
			sqlite3_bind_int64(m_delete_update, 4, volume);
			int result = sqlite3_step(m_delete_update);
			TORRENT_ASSERT(result == SQLITE_DONE);
			sqlite3_reset(m_delete_update);
		}

		void get_retryable_updates(std::vector<stored_standing_update>& updates)
		{
			while (sqlite3_step(m_retryable_updates) == SQLITE_ROW) try
			{
				updates.push_back(load_standing_update(m_retryable_updates));
			}
			catch (reputation_exception) {}
			sqlite3_reset(m_retryable_updates);
		}

	private:
		enum
		{
			update_intermediary,
			update_recipient,
			update_sequence,
			update_volume,
			update_sig,
			update_last_attempt,
			update_retries,
		};

		// state must not be modified if false is returned
		bool sqlite_copy_state(reputation_key at, reputation_key for_, signed_state& state)
		{
			if (at != client_reputation_key)
			{
				void const* sig = sqlite3_column_blob(m_state_at_for, 6);
				if (sig != NULL)
				{
					unsigned sig_size = unsigned(sqlite3_column_bytes(m_state_at_for, 6));
					TORRENT_ASSERT(sig_size == state.sig.size());
					if (sig_size == state.sig.size())
						memcpy(state.sig.data(), sig, state.sig.size());
					else
						return false;
				}
				else
				{
					TORRENT_ASSERT(for_ != client_reputation_key);
					if (for_ == client_reputation_key)
						return false;
					state.clear_signature();
				}
			}

			state.upload_direct = sqlite3_column_int64(m_state_at_for, 0);
			state.download_direct = sqlite3_column_int64(m_state_at_for, 1);
			state.upload_recommended = sqlite3_column_int64(m_state_at_for, 2);
			state.download_recommended = sqlite3_column_int64(m_state_at_for, 3);
			state.upload_referred = sqlite3_column_int64(m_state_at_for, 4);
			state.download_referred = sqlite3_column_int64(m_state_at_for, 5);

			return true;
		}

		void sqlite_bind_state(sqlite3_stmt* stmt, int param, reputation_state const& state)
		{
			sqlite3_bind_int64(stmt, param    , state.upload_direct);
			sqlite3_bind_int64(stmt, param + 1, state.download_direct);
			sqlite3_bind_int64(stmt, param + 2, state.upload_recommended);
			sqlite3_bind_int64(stmt, param + 3, state.download_recommended);
			sqlite3_bind_int64(stmt, param + 4, state.upload_referred);
			sqlite3_bind_int64(stmt, param + 5, state.download_referred);
		}

		void sqlite_bind_ci(sqlite3_stmt* stmt, int param, contact_info const& ci)
		{
			contact_info::bytes_type bytes;
			contact_info::bytes_type::iterator bytes_end
				= ci.to_bytes(bytes.begin());

			sqlite3_bind_blob(stmt
				, param
				, bytes.data()
				, std::distance(bytes.begin(), bytes_end)
				, SQLITE_TRANSIENT);
		}

		stored_standing_update load_standing_update(sqlite3_stmt* query)
		{
			reputation_id recipient,intermediary;
			signature_type sig;
			get_rid(sqlite3_column_int64(query, update_intermediary), intermediary);
			get_rid(sqlite3_column_int64(query, update_recipient), recipient);
			TORRENT_ASSERT(sqlite3_column_bytes(query, update_sig) == int(sig.size()));
			if (sqlite3_column_bytes(query, update_sig) != int(sig.size()))
				throw reputation_exception("wrong size for signature");
			std::memcpy(sig.data(), sqlite3_column_blob(query, update_sig), sig.size());
			return stored_standing_update(standing_update(
					sqlite3_column_int64(query, update_sequence)
					, recipient
					, intermediary
					, sqlite3_column_int64(query, update_volume)
					, sig)
				, sqlite3_column_int64(query, update_intermediary)
				, sqlite3_column_int64(query, update_recipient));
		}

		sqlite3* m_db;

		static char const*const schema;
		static char const*const establish_peer_stmt;
		sqlite3_stmt* m_establish_peer;
		static char const*const get_rid_stmt;
		sqlite3_stmt* m_get_rid;
		static char const*const get_key_stmt;
		sqlite3_stmt* m_get_key;
		static char const*const get_pkey_stmt;
		sqlite3_stmt* m_get_pkey;
		static char const*const known_peers_stmt;
		sqlite3_stmt* m_known_peers;
		static char const*const indirect_value_stmt;
		sqlite3_stmt* m_indirect_value;
		static char const*const direct_value_stmt;
		sqlite3_stmt* m_direct_value;
		static char const*const self_value_stmt;
		sqlite3_stmt* m_self_value;
		static char const*const state_at_stmt;
		sqlite3_stmt* m_state_at_for;
		static char const*const observed_stmt;
		sqlite3_stmt* m_observed;
		static char const*const observation_count_stmt;
		sqlite3_stmt* m_observation_count;
		static char const*const store_state_stmt;
		sqlite3_stmt* m_store_state;
		static char const*const get_peer_ep_stmt;
		sqlite3_stmt* m_get_peer_ep;
		static char const*const set_peer_ep_stmt;
		sqlite3_stmt* m_set_peer_ep;
		static char const*const drop_observations_stmt;
		sqlite3_stmt* m_drop_observations;
		static char const*const last_sequence_stmt;
		sqlite3_stmt* m_last_sequence;
		static char const*const received_sequence_stmt;
		sqlite3_stmt* m_received_sequence;
		static char const*const upload_referred_stmt;
		sqlite3_stmt* m_upload_referred;
		static char const*const download_referred_stmt;
		sqlite3_stmt* m_download_referred;
		static char const*const touch_peer_stmt;
		sqlite3_stmt* m_touch_peer;
		static char const*const touch_peer_state_stmt;
		sqlite3_stmt* m_touch_peer_state;
		static char const*const purge_state_stmt;
		sqlite3_stmt* m_purge_state;
		static char const*const purge_peers_stmt;
		sqlite3_stmt* m_purge_peers;
		static char const*const global_direct_balance_stmt;
		sqlite3_stmt* m_global_direct_balance;
		static char const*const get_value_stmt;
		sqlite3_stmt* m_get_value;
		static char const*const set_value_stmt;
		sqlite3_stmt* m_set_value;
		static char const*const outstanding_updates_to_intermediary_stmt;
		sqlite3_stmt* m_outstanding_updates_to_intermediary;
		static char const*const get_outstanding_update_stmt;
		sqlite3_stmt* m_get_outstanding_update;
		static char const*const save_update_stmt;
		sqlite3_stmt* m_save_update;
		static char const*const retried_update_stmt;
		sqlite3_stmt* m_retried_update;
		static char const*const delete_update_stmt;
		sqlite3_stmt* m_delete_update;
		static char const*const retryable_updates_stmt;
		sqlite3_stmt* m_retryable_updates;
	};

	char const*const reputation_store::schema =
		"CREATE TABLE IF NOT EXISTS peers ("
		"reputation_key       INTEGER  PRIMARY KEY, "
		"reputation_id        BLOB     NOT NULL UNIQUE, "
		"public_key           BLOB     NOT NULL, "
		"observations         REAL     NOT NULL DEFAULT 0, "
		"last_active          INTEGER  NOT NULL DEFAULT (strftime('%s','now')), "
		"contact_info         BLOB, "
		"ci_updated           INTEGER  NOT NULL DEFAULT (strftime('%s','now')) "
		");"
		"CREATE TABLE IF NOT EXISTS state ("
		"at                   INTEGER  NOT NULL REFERENCES peers, "
		"for                  INTEGER  NOT NULL REFERENCES peers, "
		"upload_direct        INTEGER  NOT NULL DEFAULT 0, "
		"download_direct      INTEGER  NOT NULL DEFAULT 0, "
		"upload_recommended   INTEGER  NOT NULL DEFAULT 0, "
		"download_recommended INTEGER  NOT NULL DEFAULT 0, "
		"upload_referred      INTEGER  NOT NULL DEFAULT 0, "
		"download_referred    INTEGER  NOT NULL DEFAULT 0, "
		"sig                  BLOB     DEFAULT NULL, "
		"last_active          INTEGER  NOT NULL DEFAULT (strftime('%s','now')), "
		"PRIMARY KEY (at, for) "
		");"
		// The sequence number of the last receipt received from the sender
		// issued by the recipient
		"CREATE TABLE IF NOT EXISTS update_sequence ("
		"recipient            INTEGER  NOT NULL REFERENCES peers ON DELETE CASCADE, "
		"sender               INTEGER  NOT NULL REFERENCES peers ON DELETE CASCADE, "
		"sequence             INTEGER  NOT NULL, "
		"PRIMARY KEY(recipient, sender) "
		");"
		"CREATE TABLE IF NOT EXISTS outgoing_updates ( "
		"intermediary         INTEGER  NOT NULL REFERENCES peers, "
		"recipient            INTEGER  NOT NULL REFERENCES peers, "
		"sequence             INTEGER  NOT NULL, "
		"volume               INTEGER  NOT NULL, "
		"sig                  BLOB     NOT NULL, "
		"last_attempt         INTEGER  NOT NULL DEFAULT (strftime('%s','now')), "
		"retries              INTEGER  NOT NULL DEFAULT 0, "
		"PRIMARY KEY (intermediary, recipient, sequence) "
		");"
		"CREATE TABLE IF NOT EXISTS client_store ("
		"key                  INTEGER PRIMARY KEY, "
		"value "
		");";

	char const*const reputation_store::establish_peer_stmt =
		"INSERT OR IGNORE INTO peers (public_key, reputation_id, contact_info) "
		"VALUES (?1, ?2, ?3)";

	char const*const reputation_store::get_rid_stmt =
		"SELECT reputation_id FROM peers WHERE reputation_key = ?";

	char const*const reputation_store::get_key_stmt =
		"SELECT reputation_key FROM peers WHERE reputation_id = ?";

	char const*const reputation_store::get_pkey_stmt =
		"SELECT public_key FROM peers WHERE reputation_key = ?";

	char const*const reputation_store::known_peers_stmt =
		"SELECT reputation_id, reputation_key FROM peers "
			"WHERE reputation_key != 0 ORDER BY observations DESC LIMIT 2000";

	char const*const reputation_store::direct_value_stmt =
		"SELECT CAST(download_direct - upload_direct + download_referred - upload_referred AS REAL) "
				"* (observations / max((SELECT max(observations) FROM peers), 1.0)) "
			"FROM state, peers WHERE at = 0 AND for = ?1 AND reputation_key = ?1";

	char const*const reputation_store::indirect_value_stmt =
		"SELECT (CAST(max(c.download_direct - c.upload_direct + c.download_recommended - c.upload_recommended, 0) AS REAL) "
				"* (observations / max((SELECT max(observations) FROM peers), 1.0))) "
			"* (CAST(max(i.download_direct - i.upload_direct + i.download_referred - i.upload_referred, 0) AS REAL) "
				"/ CAST((SELECT sum(max(download_direct - upload_direct + download_referred - upload_referred, 0)) FROM state WHERE at = ?2) AS REAL)) "
			"FROM state c, state i, peers "
			"WHERE c.at = 0 AND c.for = ?2 "
				"AND i.for = ?1 AND i.at = ?2 "
				"AND reputation_key = ?2";

	char const*const reputation_store::self_value_stmt =
		"SELECT CAST(sum(upload_direct) AS REAL) / CAST(sum(download_direct) AS REAL) "
			"FROM state WHERE at = 0";

	char const*const reputation_store::state_at_stmt =
		"SELECT upload_direct, download_direct, "
			"upload_recommended, download_recommended, "
			"upload_referred, download_referred, sig "
			"FROM state WHERE at = ?1 AND for = ?2";

	char const*const reputation_store::observed_stmt =
		"UPDATE peers SET observations = observations + ?2, "
			"last_active = strftime('%s','now') "
			"WHERE reputation_key = ?1";

	char const*const reputation_store::observation_count_stmt =
		"SELECT reputation_key, observations FROM peers WHERE reputation_id = ?";

	char const*const reputation_store::store_state_stmt =
		"INSERT OR REPLACE INTO state "
			"VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, strftime('%s','now'))";

	char const*const reputation_store::get_peer_ep_stmt =
		"SELECT contact_info, ci_updated FROM peers WHERE reputation_key = ?";

	char const*const reputation_store::set_peer_ep_stmt =
		"UPDATE peers SET contact_info = ?2 "
			", ci_updated = strftime('%s','now') "
			", last_active = strftime('%s','now') "
			"WHERE reputation_key = ?1";

	char const*const reputation_store::drop_observations_stmt =
		"UPDATE peers SET observations = max(observations - max(observations * 20 / 100, 2), 0) "
			"WHERE reputation_key = ?";

	char const*const reputation_store::last_sequence_stmt =
		"SELECT sequence FROM update_sequence WHERE recipient = ?1 AND sender = ?2";

	char const*const reputation_store::received_sequence_stmt =
		"INSERT OR REPLACE INTO update_sequence (recipient, sender, sequence) VALUES (?1, ?2, ?3)";

	char const*const reputation_store::upload_referred_stmt =
		"UPDATE state SET upload_referred = upload_referred + ?2, last_active = strftime('%s','now') "
			"WHERE at = 0 AND for = ?1";

	char const*const reputation_store::download_referred_stmt =
		"UPDATE state SET download_referred = download_referred + ?2, last_active = strftime('%s','now') "
			"WHERE at = 0 AND for = ?1";

	char const*const reputation_store::touch_peer_stmt =
		"UPDATE peers SET last_active = strftime('%s','now') WHERE reputation_key = ?";

	char const*const reputation_store::touch_peer_state_stmt =
		"UPDATE state SET last_active = strftime('%s','now') "
			"WHERE (at = 0 AND for = ?) OR (at = ? AND for = 0)";

	// state and peers get purged after 10 weeks of inactivity
	char const*const reputation_store::purge_state_stmt =
		"DELETE FROM state WHERE strftime('%s','now') - last_active > 60*60*24*70";

	// only purge peers without any stored state or sessions to avoid foreign key contraint violations
	// (it sure would be nice if sqlite provided a way to ignore rows which cannot be deleted due to constraints)
	char const*const reputation_store::purge_peers_stmt =
		"DELETE FROM peers WHERE reputation_key != 0 "
			"AND strftime('%s','now') - last_active > 60*60*24*70 "
			"AND (SELECT count(*) FROM state WHERE at = reputation_key OR for = reputation_key) == 0 ";

	char const*const reputation_store::global_direct_balance_stmt =
		"SELECT sum(upload_direct - download_direct) FROM state WHERE at = 0";

	char const*const reputation_store::get_value_stmt =
		"SELECT value FROM client_store WHERE key = ?";

	char const*const reputation_store::set_value_stmt =
		"INSERT OR REPLACE INTO client_store VALUES (?1, ?2)";

	char const*const reputation_store::outstanding_updates_to_intermediary_stmt =
		"SELECT * FROM outgoing_updates WHERE intermediary = ?";

	char const*const reputation_store::get_outstanding_update_stmt =
		"SELECT * FROM outgoing_updates WHERE intermediary = ?1 AND recipient = ?2 AND sequence = ?3";

	char const*const reputation_store::save_update_stmt =
		"INSERT OR REPLACE INTO outgoing_updates "
			"(intermediary, recipient, sequence, volume, sig, last_attempt, retries) "
			"VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";

	char const*const reputation_store::retried_update_stmt =
		"UPDATE outgoing_updates SET retries = retries + 1, last_attempt = strftime('%s','now') "
			"WHERE intermediary = ?1 AND recipient = ?2 AND sequence = ?3";

	char const*const reputation_store::delete_update_stmt =
		"DELETE FROM outgoing_updates WHERE intermediary = ?1 AND recipient = ?2 AND sequence = ?3 and volume = ?4";

	char const*const reputation_store::retryable_updates_stmt =
		"SELECT * FROM outgoing_updates WHERE strftime('%s','now') - last_attempt > retries * retries * 60*60 + 60*60";

	class reputation_manager : public plugin
	{
		struct attribution_candidate : reputation_value
		{
			attribution_candidate(attribution a, double v)
				: reputation_value(v, a.intermediary)
				, sequence(a.sequence)
			{}
			boost::int64_t sequence;
		};

		enum store_values
		{
			store_ip_seq,
			store_next_receipt_sequence,
			store_private_seed,
			store_xfer_history_current_hour,
			store_xfer_history_hour_0,
			store_xfer_history_hour_23 = store_xfer_history_hour_0 + 24,
		};

	public:
		reputation_manager(lt_identify_plugin& identity
			, std::string const& storage_path
			, std::string const& sk_password)
			: m_store(storage_path)
			, m_last_xfer_history_rollover(clock_type::now())
			, m_global_balance(m_store.global_direct_transfer_balance())
			, m_identity(identity)
		{
			pubkey_type db_client_pk;
			if (pkey(client_reputation_key, db_client_pk))
			{
				if (db_client_pk != identity.key.pk)
				{
					std::vector<char> chipher_seed = m_store.get_blob_value(store_private_seed);
					if (chipher_seed.size() != ed25519_seed_size)
						throw reputation_exception("supplied key does not match database");

					boost::array<unsigned char, ed25519_seed_size> seed;
					std::copy(chipher_seed.begin(), chipher_seed.end(), seed.begin());

					encrypt_seed(sk_password, db_client_pk, seed);
					identity.create_keypair(seed);

					if (db_client_pk != identity.key.pk)
						throw bad_reputation_password();
				}
			}
			else
			{
				boost::array<unsigned char, ed25519_seed_size> seed;
				ed25519_create_seed(seed.data());
				identity.create_keypair(seed);

				encrypt_seed(sk_password, identity.key.pk, seed);

				transaction t(*this);

				std::vector<char> db_private_seed(seed.begin(), seed.end());
				m_store.set_blob_value(store_private_seed, db_private_seed);
				m_store.establish_client(identity.key.pk);
			}

			m_client_rid = hasher(identity.key.pk.data(), identity.key.pk.size()).final();
		}

		virtual boost::shared_ptr<torrent_plugin> new_torrent(torrent_handle const&, void*)
		{
			return boost::make_shared<reputation_torrent_plugin>(boost::ref(*this));
		}

		virtual void added(session_handle ses)
		{
			m_ses = ses;
		}

		virtual void register_dht_extensions(dht_extensions_t& exts)
		{
			exts.push_back(std::make_pair("update_standing"
				, boost::bind(&reputation_manager::on_update_standing, this, _1, _2, _3)));
			exts.push_back(std::make_pair("get_standing"
				, boost::bind(&reputation_manager::on_get_standing, this, _1, _2, _3)));
		}

		virtual void on_alert(alert const* a)
		{
			if (a->type() == dht_mutable_item_alert::alert_type)
				incoming_mutable_item(*static_cast<dht_mutable_item_alert const*>(a));
			else if (a->type() == external_ip_alert::alert_type)
			{
				external_ip_alert const* ip = static_cast<external_ip_alert const*>(a);
				if (ip->external_address.is_v4())
					m_external_address_v4 = ip->external_address.to_v4();
				else if (ip->external_address.is_v6())
					m_external_address_v6 = ip->external_address.to_v6();
				put_client_ep();
			}
			else if (a->type() == dht_direct_response_alert::alert_type)
			{
				dht_direct_response_alert const* r = static_cast<dht_direct_response_alert const*>(a);

				{
					forward_standing_request_ctx* c = reinterpret_cast<forward_standing_request_ctx*>(r->userdata);
					std::vector<forward_standing_request_ctx*>::iterator new_end
						= std::remove(m_outstanding_forward_queries.begin(), m_outstanding_forward_queries.end(), c);
					if (new_end != m_outstanding_forward_queries.end())
					{
						m_outstanding_forward_queries.erase(new_end, m_outstanding_forward_queries.end());
						bdecode_node msg = r->response();
						standing_update_ack(c->intermediary, c->recipient, msg, r->addr);
						delete c;
					}
				}

				{
					get_standing_request_ctx* c = reinterpret_cast<get_standing_request_ctx*>(r->userdata);
					std::vector<get_standing_request_ctx*>::iterator new_end
						= std::remove(m_outstanding_get_queries.begin(), m_outstanding_get_queries.end(), c);
					if (new_end != m_outstanding_get_queries.end())
					{
						m_outstanding_get_queries.erase(new_end, m_outstanding_get_queries.end());
						bdecode_node msg = r->response();
						get_standing_ack(c->intermediary, c->recipient, msg, r->addr);
						delete c;
					}
				}
			}
		}

		virtual void on_tick()
		{
			time_point now = clock_type::now();

			if (m_last_contact_info_put == time_point()
				|| now - m_last_contact_info_put > hours(1))
				put_client_ep();

			if (m_last_state_peers_purge == time_point()
				|| now - m_last_state_peers_purge > hours(24*7))
			{
				m_store.purge_state();
				m_store.purge_peers();
				m_last_state_peers_purge = now;
			}

			if (now - m_last_xfer_history_rollover > hours(1))
			{
				transaction t(*this);
				int current_hour = m_store.get_int_value(store_xfer_history_current_hour, 0);
				if (++current_hour > 23)
					current_hour = 0;
				m_store.set_int_value(store_xfer_history_current_hour, current_hour);
				m_store.set_int_value(store_xfer_history_hour_0 + current_hour, 0);
				m_last_xfer_history_rollover = now;
			}

			if (now - m_last_standing_update_retry > hours(1))
			{
				std::vector<stored_standing_update> updates;
				m_store.get_retryable_updates(updates);
				for (std::vector<stored_standing_update>::iterator u = updates.begin();
					u != updates.end(); ++u)
				{
					signed_state state;
					state.subject = u->update.intermediary;
					m_store.state_at_for(client_reputation_key, u->intermediary, state);
					forward_standing(*u, state, boost::weak_ptr<reputation_session>());
				}
			}

			send_next_standing();
		}

		virtual bool on_optimistic_unchoke(std::vector<peer_connection_handle>& peers);

		bool on_get_standing(udp::endpoint const&
			, bdecode_node const& request, entry& response)
		{
			using namespace dht;

#if defined TORRENT_DEBUG
			bdecode_node q = request.dict_find_string("q");
			char const* query = q.string_ptr();
			int const qlen = q.string_length();

			TORRENT_ASSERT(qlen == strlen("get_standing"));
			TORRENT_ASSERT(memcmp(query, "get_standing", qlen) == 0);
#endif

			bdecode_node arg_ent = request.dict_find_dict("a");
			if (!arg_ent) return true;

			char error_string[200];

			key_desc_t msg_desc[] = {
				{"for", bdecode_node::string_t, reputation_id::size, 0},
				{"sender", bdecode_node::string_t, reputation_id::size, 0},
				{"state", bdecode_node::dict_t, 0, 0},
			};

			bdecode_node msg_keys[3];
			if (!verify_message(arg_ent, msg_desc, msg_keys, error_string, sizeof(error_string)))
			{
				incoming_error(response, error_string);
				return true;
			}

			reputation_id requester_id(msg_keys[1].string_ptr());
			reputation_key requester = rkey(requester_id);

			if (!valid(requester))
			{
				incoming_error(response, "unknown requester");
				return true;
			}

			reputation_id requested_id(msg_keys[0].string_ptr());
			reputation_key requested = rkey(requested_id);

			if (!valid(requested))
			{
				incoming_error(response, "unknown peer");
				return true;
			}

			pubkey_type requester_pk;
			if (pkey(requester, requester_pk))
			{
				try
				{
					signed_state sender_state(msg_keys[2], m_client_rid, requester_pk);
					if (store_state(requester, client_reputation_key, sender_state)
						== reputation_store::state_invalid)
					{
						incoming_error(response, "invalid state");
						return true;
					}
				}
				catch (reputation_exception e)
				{
					incoming_error(response, e.what());
					return true;
				}
			}
			else
			{
				TORRENT_ASSERT(false);
			}

			signed_state state;
			state.subject = requested_id;
			state_at(client_reputation_key, requested, state);
			response["r"]["state"] = state.to_entry();
			return true;
		}

		bool on_update_standing(udp::endpoint const&
			, bdecode_node const& request, entry& response)
		{
			using namespace dht;

#if defined TORRENT_DEBUG
			bdecode_node q = request.dict_find_string("q");
			char const* query = q.string_ptr();
			int const qlen = q.string_length();

			TORRENT_ASSERT(qlen == strlen("update_standing"));
			TORRENT_ASSERT(memcmp(query, "update_standing", qlen) == 0);
#endif

			bdecode_node arg_ent = request.dict_find_dict("a");
			if (!arg_ent) return true;

			char error_string[200];

			enum
			{
				key_id,
				key_receipt,
				key_seq,
				key_sender,
				key_receipient,
				key_intermediary,
				key_volume,
				key_sig,
				key_state,
			};
			key_desc_t msg_desc[] = {
				{"id", bdecode_node::string_t, reputation_id::size, 0},
				{"receipt", bdecode_node::dict_t, 0, key_desc_t::parse_children},
					{"seq", bdecode_node::int_t, 0, 0},
					{"sender", bdecode_node::string_t, reputation_id::size, 0},
					{"recipient", bdecode_node::string_t, reputation_id::size, 0},
					{"intermediary", bdecode_node::string_t, reputation_id::size, key_desc_t::optional},
					{"volume", bdecode_node::int_t, 0, 0},
					{"sig", bdecode_node::string_t, signature_type::static_size, key_desc_t::last_child},
				{"state", bdecode_node::dict_t, 0, 0},
			};

			bdecode_node msg_keys[9];
			if (!verify_message(arg_ent, msg_desc, msg_keys, error_string, sizeof(error_string)))
			{
				incoming_error(response, error_string);
				return true;
			}

			if (msg_keys[key_seq].int_value() < 0)
			{
				incoming_error(response, "invalid sequence number");
				return true;
			}

			if (msg_keys[key_intermediary]
				&& m_client_rid != reputation_id(msg_keys[key_intermediary].string_ptr()))
			{
				incoming_error(response, "invalid intermediary");
				return true;
			}

			reputation_id sender_id(msg_keys[key_sender].string_ptr());
			reputation_key sender = rkey(sender_id);

			if (!valid(sender))
			{
				incoming_error(response, "unknown sender");
				return true;
			}

			reputation_key recipient = rkey(reputation_id(msg_keys[key_receipient].string_ptr()));

			if (!valid(recipient))
			{
				incoming_error(response, "unknown recipient");
				return true;
			}

			if (msg_keys[key_volume].int_value() <= 0)
			{
				incoming_error(response, "invalid volume");
				return true;
			}

			pubkey_type recipient_pk;
			if (!pkey(recipient, recipient_pk))
			{
				TORRENT_ASSERT(false);
				incoming_error(response, "failed to get receipient key");
				return true;
			}

			if (arg_ent.data_section().second > 1000)
			{
				incoming_error(response, "standing update too big");
				return true;
			}

			{
				entry validation_entry;
				validation_entry = msg_keys[key_receipt];
				validation_entry.dict().erase("sig");
				validation_entry["intermediary"] = m_client_rid.to_string();
				boost::array<char, 1024> validation_buf;
				int bsize = bencode(validation_buf.begin(), validation_entry);
				TORRENT_ASSERT(bsize < 1024);
				if (ed25519_verify((unsigned char*)msg_keys[key_sig].string_ptr()
					, (unsigned char*)validation_buf.data()
					, bsize
					, (unsigned char const*)recipient_pk.data()) != 1)
				{
					incoming_error(response, "invalid signature");
					return true;
				}
			}

			pubkey_type sender_pk;
			if (pkey(sender, sender_pk))
			{
				try
				{
					signed_state sender_state(msg_keys[key_state], m_client_rid, sender_pk);
					if (store_state(sender, client_reputation_key, sender_state)
						== reputation_store::state_invalid)
					{
						incoming_error(response, "invalid state");
						return true;
					}
				}
				catch (reputation_exception e)
				{
					incoming_error(response, e.what());
					return true;
				}
			}
			else
			{
				TORRENT_ASSERT(false);
			}

			m_store.on_receipt(recipient
				, sender
				, msg_keys[key_seq].int_value()
				, msg_keys[key_volume].int_value());

			signed_state state;
			state.subject = sender_id;
			state_at(client_reputation_key, sender, state);
			response["r"]["state"] = state.to_entry();
			return true;
		}

		double global_ratio()
		{
			return m_store.self_value();
		}

		reputation_id const& client_rid()
		{
			return m_client_rid;
		}

		void sign(char const* m, int mlen, char* sig)
		{
			ed25519_sign((unsigned char*)sig
				, (unsigned char const*)m
				, mlen
				, (unsigned char const*)m_identity.key.pk.data()
				, (unsigned char const*)m_identity.key.sk.data());
		}

		friend class transaction;
		class transaction : public reputation_store::transaction
		{
		public:
			transaction(reputation_manager& m)
				: reputation_store::transaction(m.m_store)
			{}
		};

		reputation_key establish_peer(pubkey_type const& pk
			, reputation_id const& rid
			, contact_info const& ci)
		{
			return m_store.establish_peer(pk, rid, ci);
		}

		reputation_store::store_state_result store_state(
			reputation_key at
			, reputation_key for_
			, signed_state& state)
		{
			return m_store.store_state(at, for_, state);
		}

		bool rid(reputation_key peer, reputation_id& rid)
		{
			return m_store.get_rid(peer, rid);
		}

		reputation_key rkey(reputation_id const& rid)
		{
			return m_store.get_rkey(rid);
		}

		bool pkey(reputation_key rkey, pubkey_type& pk)
		{
			return m_store.get_pkey(rkey, pk);
		}

		void known_peers(std::vector<reputation_id>& peers)
		{
			m_store.known_peers(peers);
		}

		void touch(reputation_key rkey)
		{
			m_store.touch(rkey);
		}

		void consider_attributions(reputation_key peer, peer_reputation& rep)
		{
			if (rep.direct()) return;

			std::vector<attribution_candidate> candidates;
			candidates.reserve(rep.attributions.size());

			for (attributions_type::iterator i = rep.attributions.begin();
				i != rep.attributions.end(); ++i)
			{
				double ivalue = m_store.indirect_value(peer, i->intermediary);
				if (ivalue > 0)
				{
					candidates.push_back(attribution_candidate(*i, ivalue));
				}
			}

			std::sort(candidates.begin(), candidates.end(), candidate_intermediary_cmp);

			double total_value = 0.0;
			for (std::vector<attribution_candidate>::iterator i = candidates.begin();
				i != candidates.end(); ++i)
			{
				if (std::distance(candidates.begin(), i) < max_attributions)
					total_value += i->value;
				else
					i->value = 0;
			}

			int rounding_error = 100;
			int contributors = 0;
			rep.invalidate();

			for (std::vector<attribution_candidate>::iterator i = candidates.begin();
				i != candidates.end(); ++i)
			{
				if (i->value <= 0)
					continue;

				int contribution = 0;
				if (total_value > 0.0)
					contribution = int(i->value / total_value * 100);
				TORRENT_ASSERT(contribution >= 0);
				TORRENT_ASSERT(contribution <= 100);

				if (contribution > 0)
					contributors++;

				rep.attributions.push_back(attribution(
					i->rkey
					, boost::uint8_t(contribution)));

				rounding_error -= contribution;
				touch(i->rkey);
			}

			if (contributors > 0)
			{
				// correct for rounding error so the contributions add up to exactly 100
				rep.attributions[0].contribution += rounding_error;
				rep.reputation = total_value / contributors;
			}
		}

		bool state_at(reputation_key at, reputation_key for_, signed_state& state)
		{
			// if request is for state at the client then it's ok if we don't have
			// any stored. we'll happily sign a zero'd out state for whoever wants it
			if (!m_store.state_at_for(at, for_, state) && at != client_reputation_key)
				return false;

			if (at == client_reputation_key)
			{
				boost::array<char, 256> state_buf;
				int bsize = bencode(state_buf.begin(), state.reputation_state::to_entry());
				TORRENT_ASSERT(bsize < 256);
				sign(state_buf.data(), bsize, state.sig.data());
			}
			return true;
		}

		void update_state_for(reputation_key peer, reputation_state& state)
		{
			m_global_balance += state.upload_direct - state.download_direct;
			m_store.update_state_for(peer, state);
		}

		void update_state_for(reputation_key peer, signed_state& state)
		{
			m_global_balance += state.upload_direct - state.download_direct;
			m_store.update_state_for(peer, state);
			boost::array<char, 256> state_buf;
			int bsize = bencode(state_buf.begin(), state.reputation_state::to_entry());
			TORRENT_ASSERT(bsize < 256);
			sign(state_buf.data(), bsize, state.sig.data());
		}

		// take known peers received from a peer and sort them by acending preference
		// that they be used as an intermediary
		void consider_known_peers(buffer::const_interval known_peers
			, std::vector<reputation_key>& sorted_peers)
		{
			std::vector<std::pair<double, reputation_key> > candidates;
			candidates.reserve(known_peers.left() / reputation_id::size);

			transaction t(*this);

			while (known_peers.left() >= reputation_id::size)
			{
				reputation_id known_rid(known_peers.begin);
				std::pair<double, reputation_key> known_obs = m_store.observation_count(known_rid);
				if (valid(known_obs.second))
				{
					// don't try to send our standing at an intermediary we
					// don't have a positive ballance with
					signed_state state;
					m_store.state_at_for(known_obs.second, client_reputation_key, state);
					if (state.download_direct + state.download_referred
						> state.upload_direct + state.upload_referred)
					{
						candidates.push_back(known_obs);
						touch(known_obs.second);
					}
				}
				known_peers.begin += reputation_id::size;
			}

			std::sort(candidates.begin(), candidates.end());
			std::vector<std::pair<double, reputation_key> >::iterator unique_end =
				std::unique(candidates.begin(), candidates.end());

			sorted_peers.resize(std::distance(candidates.begin(), unique_end));
			std::transform(candidates.begin(), unique_end, sorted_peers.begin()
				, boost::bind(&std::pair<double, reputation_key>::second, _1));
		}

		double direct_value(reputation_key peer)
		{
			return m_store.direct_value(peer);
		}

		void forward_standing(stored_standing_update const& update
			, signed_state const& intermediary_state
			, boost::weak_ptr<reputation_session> session)
		{
			// recipient SHOULD be valid unless the update was loaded from storage
			if (!session.expired() && m_store.has_pending_updates(update.intermediary))
			{
				m_store.save_pending_update(update);
				// Not sure if this is necessary or safe
				// the intermediary should already have been signaled as exhausted
				//peer_exhausted_at(session, update.intermediary);
				return;
			}

			bool new_intermediary;
			query_destinations::iterator intermediary_queue;
			boost::tie(intermediary_queue, new_intermediary) = m_datagram_queries.insert(
				std::make_pair(update.intermediary, datagram_query_destination(intermediary_state)));

			if (intermediary_queue->second.ci_status == ci_failed)
			{
				peer_exhausted_at(session, intermediary_queue->first);
				m_store.save_pending_update(update);
				return;
			}

			bool new_recipient;
			outstanding_updates::iterator recipient_queue;
			boost::tie(recipient_queue, new_recipient) = intermediary_queue->second.updates.insert(
				std::make_pair(update.recipient, update_standing_recipient(update.update, session)));
			if (new_recipient)
			{
				if (intermediary_queue->second.ci_status == ci_aquired)
				{
					if (new_intermediary)
						intermediary_queue->second.ci = m_store.get_peer_ep(update.intermediary).first;
					forward_standing(intermediary_queue, recipient_queue);
				}
				else
				{
					TORRENT_ASSERT(intermediary_queue->second.ci_status == ci_pending);
					recipient_queue->second.pending_ci = true;
				}
			}
			else
			{
				std::deque<standing_update>& q = recipient_queue->second.updates;
				if (!q.empty())
					TORRENT_ASSERT(update.update.sequence > q.back().sequence);
				q.push_back(update.update);
			}
		}

		void get_standing(reputation_key at, reputation_key for_
			, boost::weak_ptr<reputation_session> session)
		{
			signed_state at_state;
			reputation_id at_rid;
			if (!rid(at, at_rid)) return;
			at_state.subject = at_rid;
			state_at(client_reputation_key, at, at_state);
			bool new_intermediary;
			query_destinations::iterator intermediary_queue;
			boost::tie(intermediary_queue, new_intermediary) = m_datagram_queries.insert(
				std::make_pair(at, datagram_query_destination(at_state)));

			if (intermediary_queue->second.ci_status == ci_failed)
			{
				peer_exhausted_at(session, intermediary_queue->first);
				return;
			}

			bool new_recipient;
			outstanding_gets::iterator recipient_queue;
			boost::tie(recipient_queue, new_recipient) = intermediary_queue->second.gets.insert(
				std::make_pair(for_, get_standing_subject(session)));
			if (new_recipient)
			{
				if (intermediary_queue->second.ci_status == ci_aquired)
				{
					if (new_intermediary)
						intermediary_queue->second.ci = m_store.get_peer_ep(at).first;
					get_standing(intermediary_queue, recipient_queue);
				}
				else
				{
					TORRENT_ASSERT(intermediary_queue->second.ci_status == ci_pending);
					recipient_queue->second.pending_ci = true;
				}
			}
		}

		void observed(reputation_key peer)
		{
			m_store.observed(peer);
		}

		boost::int64_t next_receipt_sequence()
		{
			boost::int64_t sequence = m_store.get_int64_value(store_next_receipt_sequence, 0);
			m_store.set_int64_value(store_next_receipt_sequence, sequence + 1);
			return sequence;
		}

		boost::int64_t adjust_download_direct(boost::int64_t credit)
		{
			if (m_global_balance <= 0 || credit <= 0)
				return credit;
			boost::int64_t global_bytes_remaining = bytes_pending_download() + credit;
			TORRENT_ASSERT(global_bytes_remaining > 0);
			double multiplier = double(m_global_balance) / double(global_bytes_remaining);
			if (multiplier <= 1.0)
				return credit;
			return boost::int64_t(credit * multiplier);
		}

		void schedule_next_standing(boost::weak_ptr<reputation_session> peer)
		{
			standing_queue_type::iterator existing = std::find_if(
				m_standing_queue.begin(), m_standing_queue.end()
				, pending_standing_cmp(peer));
			if (existing != m_standing_queue.end())
				m_standing_queue.erase(existing);
			m_standing_queue.push_back(
				std::make_pair(clock_type::now() + minutes(1), peer));
		}

		void choke_peer(peer_connection_handle c)
		{
			if (!c.ignore_unchoke_slots())
				c.choke_this_peer();
		}

		session_handle session() const { return m_ses; }

		boost::shared_ptr<reputation_session> peer_session(reputation_id const& rid)
		{
			boost::shared_ptr<reputation_session> ses;
			std::map<reputation_id, boost::weak_ptr<reputation_session> >::iterator ses_itr
				= m_sessions.find(rid);

			if (ses_itr != m_sessions.end())
			{
				ses = ses_itr->second.lock();
				if (!ses)
				{
					ses = boost::make_shared<reputation_session>(boost::ref(*this), rid);
					ses_itr->second = ses;
				}
			}
			else
			{
				ses = boost::make_shared<reputation_session>(boost::ref(*this), rid);
				m_sessions.insert(std::make_pair(rid, ses));
			}

			TORRENT_ASSERT(ses);
			return ses;
		}

		void remove_session(reputation_id const& rid)
		{
#if defined TORRENT_DEBUG
			std::map<reputation_id, boost::weak_ptr<reputation_session> >::iterator i
				= m_sessions.find(rid);
			TORRENT_ASSERT(i != m_sessions.end());
			TORRENT_ASSERT(!i->second.lock());
#endif
			m_sessions.erase(rid);
		}

		void payload_received(boost::int64_t bytes)
		{
			int current_hour = m_store.get_int_value(store_xfer_history_current_hour, 0);
			boost::int64_t current_payload_received
				= m_store.get_int64_value(store_xfer_history_hour_0 + current_hour, 0);
			m_store.set_int64_value(store_xfer_history_hour_0 + current_hour
				, current_payload_received + bytes);
		}

		void observe_peers(boost::int64_t session_bytes_downloaded
			, std::vector<reputation_key> const& known_peers)
		{
			if (session_bytes_downloaded == 0)
				return;

			boost::int64_t bytes_downloaded_today = 0;
			for (int hour = 0; hour < 23; ++hour)
				bytes_downloaded_today += m_store.get_int64_value(store_xfer_history_hour_0 + hour, 0);

			TORRENT_ASSERT(bytes_downloaded_today != 0);
			if (bytes_downloaded_today == 0)
				return;

			double download_share = double(session_bytes_downloaded) / double(bytes_downloaded_today);
			TORRENT_ASSERT(download_share <= 1.0);
			TORRENT_ASSERT(download_share >= 0.0);

			for (std::vector<reputation_key>::const_iterator peer = known_peers.begin();
				peer != known_peers.end(); ++peer)
				m_store.observed(*peer, download_share);
		}

	private:
		enum contact_info_status
		{
			ci_aquired,
			ci_pending,
			ci_failed,
		};

		struct update_standing_recipient
		{
			update_standing_recipient(standing_update const& u
				, boost::weak_ptr<reputation_session> s)
				: updates(1, u), session(s), pending_ci(false)
			{}

			std::deque<standing_update> updates;
			boost::weak_ptr<reputation_session> session;
			bool pending_ci;
		};

		struct get_standing_subject
		{
			get_standing_subject(boost::weak_ptr<reputation_session> s)
				: session(s), pending_ci(false)
			{}

			boost::weak_ptr<reputation_session> session;
			bool pending_ci;
		};

		// key is recipient
		typedef std::map<reputation_key, update_standing_recipient> outstanding_updates;
		// key is for
		typedef std::map<reputation_key, get_standing_subject> outstanding_gets;

		struct datagram_query_destination
		{
			datagram_query_destination(signed_state const& state)
				: consecutive_failures_v4(0)
				, consecutive_failures_v6(0)
				, ci_status(ci_aquired)
				, state(state)
			{}

			void ack_received(udp::endpoint const& addr)
			{
				if (ci.port == addr.port())
				{
					if (addr.address().is_v6()
						&& ci.addr_v6 == addr.address().to_v6())
					{
						consecutive_failures_v6 = 0;
					}
					else if (addr.address().is_v4()
						&& ci.addr_v4 == addr.address().to_v4())
					{
						consecutive_failures_v4 = 0;
					}
				}
			}

			void failure_to_contact(udp::endpoint const& addr)
			{
				if (ci.port == addr.port())
				{
					// give up on an address after 2 consecutive failures
					if (addr.address().is_v6()
						&& ci.addr_v6 == addr.address().to_v6()
						&& ++consecutive_failures_v6 == 2)
					{
						ci.addr_v6 = address_v6();
					}
					else if (addr.address().is_v4()
						&& ci.addr_v4 == addr.address().to_v4()
						&& ++consecutive_failures_v4 == 2)
					{
						ci.addr_v4 = address_v4();
					}
				}
			}

			contact_info ci;
			char consecutive_failures_v4, consecutive_failures_v6;
			// set to true when there is an outstanding request for new contact information
			contact_info_status ci_status;
			outstanding_updates updates;
			// value is true if get is pending for new contact info
			outstanding_gets gets;
			signed_state state;
		};

		// map key is intermediary
		typedef std::map<reputation_key, datagram_query_destination> query_destinations;

		// queue for sending "my_standing" BT messages at regular intervals
		// not to be confused with the queue for "standing_update" DHT messages defined above
		typedef std::deque<std::pair<time_point, boost::weak_ptr<reputation_session> > > standing_queue_type;

		struct forward_standing_request_ctx
		{
			forward_standing_request_ctx(reputation_manager& self
				, query_destinations::iterator intermediary
				, outstanding_updates::iterator recipient)
				: self(self), intermediary(intermediary), recipient(recipient)
			{}

			reputation_manager& self;
			query_destinations::iterator intermediary;
			outstanding_updates::iterator recipient;
		};

		struct get_standing_request_ctx
		{
			get_standing_request_ctx(reputation_manager& self
				, query_destinations::iterator intermediary
				, outstanding_gets::iterator recipient)
				: self(self), intermediary(intermediary), recipient(recipient)
			{}

			reputation_manager& self;
			query_destinations::iterator intermediary;
			outstanding_gets::iterator recipient;
		};

		// sort in decending order
		static bool candidate_intermediary_cmp(attribution_candidate const& l
			, attribution_candidate const& r)
		{
			return l.value > r.value;
		}

		struct pending_standing_cmp
		{
			pending_standing_cmp(boost::weak_ptr<reputation_session> p)
				: peer(p)
			{}

			bool operator()(reputation_manager::standing_queue_type::value_type const& o)
			{
				return !(o.second < peer || peer < o.second);
			}

			boost::weak_ptr<reputation_session> peer;
		};

		void erase_recipient(query_destinations::iterator intermediary
			, outstanding_updates::iterator recipient)
		{
			intermediary->second.updates.erase(recipient);
			if (intermediary->second.updates.empty()
				&& intermediary->second.gets.empty())
				m_datagram_queries.erase(intermediary);
		}

		void erase_get_standing(query_destinations::iterator intermediary
			, outstanding_gets::iterator recipient)
		{
			intermediary->second.gets.erase(recipient);
			if (intermediary->second.updates.empty()
				&& intermediary->second.gets.empty())
				m_datagram_queries.erase(intermediary);
		}

		void save_standing_updates(query_destinations::iterator intermediary
			, outstanding_updates::iterator recipient)
		{
			std::deque<standing_update>& q = recipient->second.updates;
			transaction t(*this);
			for (std::deque<standing_update>::iterator u = q.begin(); u != q.end(); ++u)
			{
				m_store.save_pending_update(
					stored_standing_update(*u, intermediary->first, recipient->first));
			}
			erase_recipient(intermediary, recipient);
		}

		void forward_standing(query_destinations::iterator intermediary
			, outstanding_updates::iterator recipient)
		{
			using boost::asio::ip::udp;
			TORRENT_ASSERT(!recipient->second.updates.empty());

			if (!m_ses.is_valid() || !m_ses.is_dht_running())
			{
				save_standing_updates(intermediary, recipient);
				return;
			}

			datagram_query_destination& i = intermediary->second;
			standing_update& r = recipient->second.updates.front();
			entry e;
			e["q"] = "update_standing";
			e["a"]["receipt"] = r.to_entry(client_rid());
			e["a"]["state"] = i.state.to_entry();
			if (i.ci.addr_v6 != address_v6())
			{
				udp::endpoint ep;
				ep.address(i.ci.addr_v6);
				ep.port(i.ci.port);
				forward_standing_request_ctx* ctx = new forward_standing_request_ctx(
					*this, intermediary, recipient);
				m_outstanding_forward_queries.push_back(ctx);
				m_ses.dht_direct_request(ep, e, ctx);
					//, boost::bind(&reputation_manager::standing_update_ack, this, intermediary, recipient, _1));
			}
			else if (i.ci.addr_v4 != address_v4())
			{
				udp::endpoint ep;
				ep.address(i.ci.addr_v4);
				ep.port(i.ci.port);
				forward_standing_request_ctx* ctx = new forward_standing_request_ctx(
					*this, intermediary, recipient);
				m_outstanding_forward_queries.push_back(ctx);
				m_ses.dht_direct_request(ep, e, ctx);
					//, boost::bind(&reputation_manager::standing_update_ack, this, intermediary, recipient, _1));
			}
			else
				standing_update_failure(intermediary, recipient, udp::endpoint());
		}

		void get_standing(query_destinations::iterator intermediary
			, outstanding_gets::iterator recipient)
		{
			using boost::asio::ip::udp;
			datagram_query_destination& i = intermediary->second;
			reputation_id for_;
			if (!rid(recipient->first, for_) || !m_ses.is_valid() || !m_ses.is_dht_running())
			{
				erase_get_standing(intermediary, recipient);
				return;
			}

			entry e;
			e["q"] = "get_standing";
			e["a"]["for"] = for_.to_string();
			e["a"]["sender"] = client_rid().to_string();
			e["a"]["state"] = i.state.to_entry();
			if (i.ci.addr_v6 != address_v6())
			{
				udp::endpoint ep;
				ep.address(i.ci.addr_v6);
				ep.port(i.ci.port);
				get_standing_request_ctx* ctx = new get_standing_request_ctx(
					*this, intermediary, recipient);
				m_outstanding_get_queries.push_back(ctx);
				m_ses.dht_direct_request(ep, e, ctx);
					//, boost::bind(&reputation_manager::get_standing_ack, this, intermediary, recipient, _1));
			}
			else if (i.ci.addr_v4 != address_v4())
			{
				udp::endpoint ep;
				ep.address(i.ci.addr_v4);
				ep.port(i.ci.port);
				get_standing_request_ctx* ctx = new get_standing_request_ctx(
					*this, intermediary, recipient);
				m_outstanding_get_queries.push_back(ctx);
				m_ses.dht_direct_request(ep, e, ctx);
					//, boost::bind(&reputation_manager::get_standing_ack, this, intermediary, recipient, _1));
			}
			else
				get_standing_failure(intermediary, recipient, udp::endpoint());
		}

		enum get_contact_info_result
		{
			get_ci_sent,
			get_ci_internal_error,
			get_ci_failed,
		};
		get_contact_info_result get_ci(query_destinations::iterator intermediary)
		{
			time_t last_update;
			last_update = m_store.get_peer_ep(intermediary->first).second;
			// give up if its IP changed less than 4 hours ago
			if (time(NULL) - last_update > 60*60*4)
			{
				pubkey_type peer_key;
				if (pkey(intermediary->first, peer_key)
					&& m_ses.is_valid() && m_ses.is_dht_running())
				{
					m_ses.dht_get_item(peer_key);
					intermediary->second.ci_status = ci_pending;
					return get_ci_sent;
				}
				else
					return get_ci_internal_error;
			}
			else
			{
				m_store.contact_failure(intermediary->first);
				return get_ci_failed;
			}
		}

		void standing_update_failure(query_destinations::iterator intermediary
			, outstanding_updates::iterator recipient
			, udp::endpoint const& addr)
		{
			if (intermediary->second.ci_status == ci_pending)
			{
				// we're already waiting for new contact info, just need to
				// wait for the DHT query to finish
				recipient->second.pending_ci = true;
				return;
			}
			else if (intermediary->second.ci_status == ci_failed)
			{
				peer_exhausted_at(recipient->second.session, intermediary->first);
				save_standing_updates(intermediary, recipient);
				return;
			}

			intermediary->second.failure_to_contact(addr);

			contact_info& ci = intermediary->second.ci;
			if (ci.addr_v6 != address_v6()
				|| ci.addr_v4 != address_v4())
			{
				forward_standing(intermediary, recipient);
			}
			else
			{
				// no more addresses to try, query the DHT for new contact info
				switch (get_ci(intermediary))
				{
				case get_ci_failed:
					peer_exhausted_at(recipient->second.session, intermediary->first);
				case get_ci_internal_error:
					intermediary->second.ci_status = ci_failed;
					save_standing_updates(intermediary, recipient);
					break;
				case get_ci_sent:
					recipient->second.pending_ci = true;
					break;
				default:
					break;
				}
			}
		}

		void get_standing_failure(query_destinations::iterator intermediary
			, outstanding_gets::iterator recipient
			, udp::endpoint const& addr)
		{
#ifndef TORRENT_DISABLE_LOGGING
			reputation_log("Get standing failure");
#endif
			if (intermediary->second.ci_status == ci_pending)
			{
				// we're already waiting for new contact info, just need to
				// wait for the DHT query to finish
				recipient->second.pending_ci = true;
				return;
			}
			else if (intermediary->second.ci_status == ci_failed)
			{
				peer_exhausted_at(recipient->second.session, intermediary->first);
				erase_get_standing(intermediary, recipient);
				return;
			}

			intermediary->second.failure_to_contact(addr);

			contact_info& ci = intermediary->second.ci;
			if (ci.addr_v6 != address_v6()
				|| ci.addr_v4 != address_v4())
			{
				get_standing(intermediary, recipient);
			}
			else
			{
				// no more addresses to try, query the DHT for new contact info
				if (get_ci(intermediary) != get_ci_sent)
				{
					intermediary->second.ci_status = ci_failed;
					peer_exhausted_at(recipient->second.session, intermediary->first);
					erase_get_standing(intermediary, recipient);
				}
				else
				{
					recipient->second.pending_ci = true;
				}
			}
		}

		void on_valid_standing_update_ack(query_destinations::iterator intermediary
			, outstanding_updates::iterator recipient
			, udp::endpoint const& addr)
		{
			m_store.delete_pending_update(intermediary->first, recipient->first
				, recipient->second.updates.front().sequence, recipient->second.updates.front().volume);
			intermediary->second.ack_received(addr);
			recipient->second.updates.pop_front();

			if (!recipient->second.updates.empty())
				forward_standing(intermediary, recipient);

			// Now that we've gotten a valid ack, load up any stored updates
			// for this intermediary and send them
			std::vector<stored_standing_update> updates;
			m_store.pending_updates_for(intermediary->first, updates);
			if (!updates.empty())
			{
				signed_state istate;
				istate.subject = updates.front().update.intermediary;
				state_at(client_reputation_key, intermediary->first, istate);
				for (std::vector<stored_standing_update>::iterator i = updates.begin();
					i != updates.end(); ++i)
				{
					forward_standing(*i, istate, boost::weak_ptr<reputation_session>());
				}
			}

			if (recipient->second.updates.empty())
				erase_recipient(intermediary, recipient);
		}

		bdecode_node state_from_response(bdecode_node const& m)
		{
			using namespace dht;

			key_desc_t msg_desc[] = {
				{"r", bdecode_node::dict_t, 0, key_desc_t::parse_children},
					{"id", bdecode_node::string_t, reputation_id::size, 0},
					{"state", bdecode_node::dict_t, 0, key_desc_t::last_child},
			};

			bdecode_node msg_keys[3];
			char error_string[200];
			if (!verify_message(m, msg_desc, msg_keys, error_string, sizeof(error_string)))
			{
				return bdecode_node();
			}

			return msg_keys[2];
		}

		void standing_update_ack(query_destinations::iterator intermediary
			, outstanding_updates::iterator recipient
			, bdecode_node const& m
			, boost::asio::ip::udp::endpoint const& addr)
		{
			bdecode_node state_entry = state_from_response(m);
			if (state_entry.type() != bdecode_node::dict_t)
			{
				standing_update_failure(intermediary, recipient, addr);
				return;
			}

			pubkey_type pk;
			if (!pkey(intermediary->first, pk))
			{
				save_standing_updates(intermediary, recipient);
				return;
			}

			try
			{
				signed_state state(state_entry, client_rid(), pk);
				reputation_store::store_state_result result
					= store_state(intermediary->first, client_reputation_key, state);
				if (result == reputation_store::state_invalid)
				{
					// something's not right with the intermediary so fail it
					standing_update_failure(intermediary, recipient, addr);
				}
				else if (state.download_referred < recipient->second.updates.front().volume)
				{
					// the peer has run out of ballance at the intermediary
					// cull the intermediary and choke the peer so it has to
					// prove itself worthy over again
					peer_exhausted_at(recipient->second.session, intermediary->first);
					on_valid_standing_update_ack(intermediary, recipient, addr);
				}
				else
					on_valid_standing_update_ack(intermediary, recipient, addr);
			}
			catch (reputation_exception)
			{
				standing_update_failure(intermediary, recipient, addr);
			}
		}

		void get_standing_ack(query_destinations::iterator intermediary
			, outstanding_gets::iterator recipient
			, bdecode_node const& m
			, boost::asio::ip::udp::endpoint const& addr)
		{
#ifndef TORRENT_DISABLE_LOGGING
			{
				reputation_id intermediary_rid; rid(intermediary->first, intermediary_rid);
				reputation_log("Get standing ack for peer %s", to_hex(intermediary_rid.to_string()));
			}
#endif
			bdecode_node state_entry = state_from_response(m);
			if (state_entry != bdecode_node::dict_t)
			{
				get_standing_failure(intermediary, recipient, addr);
				return;
			}

			pubkey_type pk;
			if (!pkey(intermediary->first, pk))
			{
				erase_get_standing(intermediary, recipient);
				return;
			}

			try
			{
				reputation_id for_rid;
				rid(recipient->first, for_rid);
				signed_state state(state_entry, for_rid, pk);
				reputation_store::store_state_result result
					= store_state(intermediary->first, recipient->first, state);
				if (result == reputation_store::state_invalid)
				{
					// something's not right with the intermediary so fail it
					get_standing_failure(intermediary, recipient, addr);
				}
				else
				{
					// we need to re-read the state because store_state puts the difference in the
					// referred states
					state_at(intermediary->first, recipient->first, state);
					send_their_standing(recipient->second.session, intermediary->second.state.subject, state);
					if (state.download_direct + state.download_referred
						<= state.upload_direct + state.upload_referred)
						peer_exhausted_at(recipient->second.session, intermediary->first);
					intermediary->second.ack_received(addr);
					erase_get_standing(intermediary, recipient);
				}
			}
			catch (reputation_exception)
			{
				get_standing_failure(intermediary, recipient, addr);
			}
		}

		// The peer has no more credit to give at the intermediary
		void peer_exhausted_at(boost::weak_ptr<reputation_session> peer, reputation_key intermediary);
		void send_their_standing(boost::weak_ptr<reputation_session> peer
			, reputation_id at, signed_state const& state);

		void contact_info_failure(query_destinations::iterator intermediary)
		{
#ifndef TORRENT_DISABLE_LOGGING
			{
				reputation_id intermediary_rid; rid(intermediary->first, intermediary_rid);
				reputation_log("Failed to get contact info for peer %s", to_hex(intermediary_rid.to_string()).c_str());
			}
#endif
			m_store.contact_failure(intermediary->first);
			intermediary->second.ci_status = ci_failed;
			for (outstanding_updates::iterator recipient = intermediary->second.updates.begin();
				recipient != intermediary->second.updates.end();)
			{
				if (!recipient->second.pending_ci)
				{
					if (++recipient == intermediary->second.updates.end())
						break;
					continue;
				}

				peer_exhausted_at(recipient->second.session, intermediary->first);
				// Lots of annoying boilerplate is required here because the call to save_standing_updates
				// will remove the recipient thus invalidating its iterator. It also might remove the
				// intermediary so we have to check the exit condition before the call.
				outstanding_updates::iterator temp = recipient;
				bool intermediary_maybe_invalidated = ++recipient == intermediary->second.updates.end();
				save_standing_updates(intermediary, temp);
				if (intermediary_maybe_invalidated) break;
			}
			for (outstanding_gets::iterator recipient = intermediary->second.gets.begin();
				recipient != intermediary->second.gets.end();)
			{
				if (!recipient->second.pending_ci)
				{
					if (++recipient == intermediary->second.gets.end())
						break;
					continue;
				}

				peer_exhausted_at(recipient->second.session, intermediary->first);
				outstanding_gets::iterator temp = recipient;
				bool intermediary_maybe_invalidated = ++recipient == intermediary->second.gets.end();
				erase_get_standing(intermediary, temp);
				if (intermediary_maybe_invalidated) break;
			}
		}

		reputation_key handle_purged_intermediary(dht_mutable_item_alert const& alert
			, reputation_id const& peer_rid)
		{
			reputation_key peer_rkey = invalid_reputation_key;

			if (alert.item.type() != entry::string_t)
				return peer_rkey;

			// Although it shouldn't happen, check to see if there are updates waiting for
			// contact info for this peer even though we purged it from the db
			// Something must be done to prevent leaking the updates, happily the alert
			// has all the info we need to resurect the peer in the db
			for (query_destinations::iterator i = m_datagram_queries.begin();
				i != m_datagram_queries.end(); ++i)
			{
				if (i->second.updates.empty())
					continue;

				reputation_id intermediary = i->second.updates.begin()->second.updates.front().intermediary;
				if (intermediary != peer_rid)
					continue;

				// Got it! create a new reputation_key and re-insert the
				// standing updates under it
				peer_rkey = establish_peer(alert.key, peer_rid, contact_info());
				query_destinations::iterator new_intermediary =
					m_datagram_queries.insert(std::make_pair(peer_rkey, i->second)).first;

				// Since we've just created a copy of all the outstanding queries set them all to
				// pending contact info so that they will get retried
				for (outstanding_updates::iterator recipient = new_intermediary->second.updates.begin();
					recipient != new_intermediary->second.updates.end(); ++recipient)
				{
					recipient->second.pending_ci = true;
				}
				for (outstanding_gets::iterator recipient = new_intermediary->second.gets.begin();
					recipient != new_intermediary->second.gets.end(); ++recipient)
				{
					recipient->second.pending_ci = true;
				}
				update_state_for(peer_rkey, i->second.state);

				// There may still be outstanding queries to the old entry, in that case we need to leave
				// the descriptors in place so that the iterators will still be valid when the callback
				// is invoked
				i->second.ci_status = ci_failed;
				for (outstanding_updates::iterator recipient = i->second.updates.begin();
					recipient != i->second.updates.end();)
				{
					if (recipient->second.pending_ci)
					{
						outstanding_updates::iterator temp = recipient;
						++recipient;
						i->second.updates.erase(temp);
					}
					else
					{
						++recipient;
					}
				}
				for (outstanding_gets::iterator recipient = i->second.gets.begin();
					recipient != i->second.gets.end();)
				{
					if (recipient->second.pending_ci)
					{
						outstanding_gets::iterator temp = recipient;
						++recipient;
						i->second.gets.erase(temp);
					}
					else
					{
						++recipient;
					}
				}
				if (i->second.updates.empty() && i->second.gets.empty())
					m_datagram_queries.erase(i);
				break;
			}

			return peer_rkey;
		}

		void incoming_mutable_item(dht_mutable_item_alert const& alert)
		{
			if (!alert.salt.empty())
				return;

			if (!m_ses.is_valid() || !m_ses.is_dht_running())
				return;

			reputation_id peer_rid = hasher(alert.key.data(), alert.key.size()).final();
			reputation_key peer_rkey = rkey(peer_rid);

			if (!valid(peer_rkey))
			{
				TORRENT_ASSERT(false);
				peer_rkey = handle_purged_intermediary(alert, peer_rid);
				if (!valid(peer_rkey))
					return;
			}

			query_destinations::iterator intermediary = m_datagram_queries.find(peer_rkey);

			if (intermediary == m_datagram_queries.end())
			{
#ifndef TORRENT_DISABLE_LOGGING
				reputation_log("Couldn't find any queries for peer %s", to_hex(peer_rid.to_string()).c_str());
#endif
				return;
			}

			if (intermediary->second.ci_status != ci_pending)
			{
#ifndef TORRENT_DISABLE_LOGGING
				reputation_log("Got duplicate item for peer %s", to_hex(peer_rid.to_string()).c_str());
#endif
				return;
			}

			if (alert.item.type() != entry::string_t)
			{
				contact_info_failure(intermediary);
				return;
			}

			std::string const& ci_bytes = alert.item.string();
			try
			{
				intermediary->second.ci = contact_info(ci_bytes.begin(), ci_bytes.end());
			}
			catch (reputation_exception)
			{
				contact_info_failure(intermediary);
				return;
			}

			m_store.set_peer_ep(peer_rkey, intermediary->second.ci);

			intermediary->second.ci_status = ci_aquired;
			intermediary->second.consecutive_failures_v6 = 0;
			intermediary->second.consecutive_failures_v4 = 0;
			for (outstanding_updates::iterator recipient = intermediary->second.updates.begin();
				recipient != intermediary->second.updates.end(); ++recipient)
			{
				if (recipient->second.pending_ci)
				{
					recipient->second.pending_ci = false;
					forward_standing(intermediary, recipient);
				}
			}

			for (outstanding_gets::iterator recipient = intermediary->second.gets.begin();
				recipient != intermediary->second.gets.end(); ++recipient)
			{
				if (recipient->second.pending_ci)
				{
					recipient->second.pending_ci = false;
					get_standing(intermediary, recipient);
				}
			}
		}

		void put_client_ep()
		{
			if (m_ses.is_valid())
			{
				m_ses.dht_put_item(m_identity.key.pk
					, boost::bind(&reputation_manager::put_client_ep, this, _1, _2, _3, _4));
			}
			m_last_contact_info_put = clock_type::now();
		}

		void put_client_ep(entry& value
			, boost::array<char,ed25519_signature_size>& sig
			, boost::uint64_t& seq, std::string const& salt)
		{
			if (m_ses.is_valid())
			{
				contact_info ci;
				ci.addr_v4 = m_external_address_v4;
				ci.addr_v6 = m_external_address_v6;
				ci.port = m_ses.listen_port();

				value = std::string();
				value.string().reserve(contact_info::v46_size);
				ci.to_bytes(std::back_inserter(value.string()));

				seq = std::max(boost::uint64_t(m_store.get_int64_value(store_ip_seq, 0))+1, seq+1);
				m_store.set_int64_value(store_ip_seq, seq);

				std::vector<char> buf;
				bencode(std::back_inserter(buf), value);
				dht::sign_mutable_item(
					std::make_pair(buf.data(), buf.size())
					, std::make_pair(salt.data(), salt.size())
					, seq
					, m_identity.key.pk.data()
					, m_identity.key.sk.data()
					, sig.data());
			}
		}

		boost::int64_t bytes_pending_download()
		{
			boost::int64_t global_bytes_remaining = 0;

			if (m_ses.is_valid())
			{
				std::vector<torrent_handle> torrents = m_ses.get_torrents();
				for (std::vector<torrent_handle>::iterator t = torrents.begin();
					t != torrents.end(); ++t)
				{
					if (!t->is_valid()) continue;
					torrent_status tstatus = t->status(0);
					if (tstatus.state == torrent_status::finished
						|| tstatus.state == torrent_status::seeding)
						continue;
					// TODO: Is this really necessary? Just how inaccurate are the regular
					// counters?
					tstatus = t->status(torrent_handle::query_accurate_download_counters);
					global_bytes_remaining +=
						tstatus.total_wanted - tstatus.total_wanted_done;
				}
			}

			return global_bytes_remaining;
		}

#ifndef TORRENT_DISABLE_LOGGING
		void reputation_log(char const* fmt, ...)
		{
			//TORRENT_ASSERT(is_single_thread());
#if 0
			if (!session().alerts().should_post<log_alert>()) return;

			va_list v;
			va_start(v, fmt);

			char buf[512];
			vsnprintf(buf, sizeof(buf), fmt, v);
			va_end(v);

			session().alerts().emplace_alert<log_alert>(buf);
#endif
		}
#endif

		void send_next_standing();

		reputation_store m_store;
		reputation_id m_client_rid;
		time_point m_last_contact_info_put;
		time_point m_last_state_peers_purge;
		time_point m_last_xfer_history_rollover;
		time_point m_last_standing_update_retry;
		std::map<reputation_id, boost::weak_ptr<reputation_session> > m_sessions;
		session_handle m_ses;
		boost::int64_t m_global_balance;
		standing_queue_type m_standing_queue;
		query_destinations m_datagram_queries;
		lt_identify_plugin const& m_identity;
		address_v4 m_external_address_v4;
		address_v6 m_external_address_v6;
		std::vector<forward_standing_request_ctx*> m_outstanding_forward_queries;
		std::vector<get_standing_request_ctx*> m_outstanding_get_queries;
	};

	class reputation_session : public boost::enable_shared_from_this<reputation_session>
	{
	public:
		reputation_session(reputation_manager& repman, reputation_id rid)
			: m_repman(repman)
			, m_rid(rid)
			, m_rkey(repman.rkey(rid))
			, m_sent_known_peers(false)
			, m_observed(false)
			, m_last_receipt_sent(clock_type::now())
			, m_payload_received_since_receipt(0)
			, m_payload_received_this_session(0)
			, m_payload_sent_since_db_update(0)
			, m_payload_sent_since_receipt(0)
			, m_payload_sent_this_session(0)
			, m_payload_attributed_this_session(0)
			, m_payload_direct_credited_this_session(0)
			, m_last_direct_download_state(0)
			, m_next_mutual_intermediary(m_mutual_intermediaries.begin())
		{
			if (has_rkey())
			{
				m_repman.touch(m_rkey);
				signed_state state;
				if (m_repman.state_at(m_rkey, client_reputation_key, state))
				{
					m_last_direct_download_state = state.download_direct;
				}
			}
		}

		~reputation_session()
		{
			// We can't send a receipt since we don't have any open connections
			// with the peer anymore, but call the function anyways just to update
			// our database for any residule credit
			if (has_rkey())
			{
				receipt();
				m_repman.observe_peers(m_payload_received_this_session, m_mutual_intermediaries);
			}
			m_repman.remove_session(m_rid);
		}

		bool sent_known_peers() const { return m_sent_known_peers; }
		bool has_rkey() const { return valid(m_rkey); }

		reputation_id const& rid() const
		{
			return m_rid;
		}

		reputation_key rkey() const
		{
			TORRENT_ASSERT(has_rkey());
			return m_rkey;
		}

		peer_reputation const& reputation() const { return m_rep; }

		void add_connection(boost::weak_ptr<reputation_peer_plugin> con)
		{
			m_connections.push_back(con);
		}

		void remove_connection(reputation_peer_plugin const* con)
		{
			peer_connections::iterator valid_end = m_connections.end();
			for (peer_connections::iterator i = m_connections.begin();
				i != valid_end;)
			{
				boost::shared_ptr<reputation_peer_plugin> peer = i->lock();
				if (peer && peer.get() != con)
					++i;
				else
					std::swap(*i, *--valid_end);
			}
			TORRENT_ASSERT(std::distance(valid_end, m_connections.end()) == 1);
			prune_connections(valid_end);
		}

		void establish_rkey(pubkey_type const& peer_key, contact_info ci)
		{
			TORRENT_ASSERT(!has_rkey());
			m_rkey = m_repman.establish_peer(peer_key, m_rid, ci);
		}

		void known_peers(std::vector<reputation_id>& peers)
		{
			m_repman.known_peers(peers);
			m_sent_known_peers = true;
		}

		void observed()
		{
			TORRENT_ASSERT(has_rkey());
			if (!m_observed)
			{
				m_repman.observed(m_rkey);
				m_observed = true;
			}
		}

		void check_for_direct_reputation()
		{
			if (has_rkey())
			{
				double dvalue = m_repman.direct_value(rkey());
				if (dvalue > 0.0)
					m_rep.assign_direct(dvalue);
			}
		}

		bool on_piece(int length)
		{
			m_payload_received_since_receipt += length;
			m_payload_received_this_session += length;
			if (m_payload_received_since_receipt > receipt_interval_bytes
				|| clock_type::now() - m_last_receipt_sent > minutes(10))
			{
				return true;
			}
			return false;
		}

		entry attributions()
		{
			entry e;
			for (attributions_type::iterator i = m_rep.attributions.begin();
				i != m_rep.attributions.end(); ++i)
			{
				if (i->contribution == 0)
					continue;
				reputation_id rid;
				if (!m_repman.rid(i->intermediary, rid))
					continue;
				e[rid.to_string()] = i->contribution;
			}
			return e;
		}

		boost::int64_t direct_credit_deficit() const
		{
			return m_payload_sent_this_session - m_payload_direct_credited_this_session;
		}

		boost::int64_t attributed_credit_deficit() const
		{
			return m_payload_sent_this_session - m_payload_attributed_this_session;
		}

		error_code sent_payload(int bytes)
		{
			m_payload_sent_since_db_update += bytes;
			m_payload_sent_since_receipt += bytes;
			m_payload_sent_this_session += bytes;
			if (m_payload_sent_since_db_update > receipt_interval_bytes)
			{
				establish_rkey();
				reputation_state state;
				state.upload_direct = m_payload_sent_since_db_update;
				m_repman.update_state_for(m_rkey, state);
				m_payload_sent_since_db_update = 0;
			}

			if (m_payload_sent_since_receipt > receipt_interval_bytes * 2)
			{
				return reputation_errors::failed_to_send_receipt;
			}
			return error_code();
		}

		void on_known_peers(buffer::const_interval body)
		{
			m_repman.consider_known_peers(body, m_mutual_intermediaries);
			m_next_mutual_intermediary = m_mutual_intermediaries.begin();
		}

		error_code on_my_standing(bdecode_node const& msg)
		{
			if (msg.type() != bdecode_node::dict_t)
			{
				return reputation_errors::invalid_standing_message;
			}

			reputation_manager::transaction t(m_repman);
			establish_rkey();

			for (int i = 0; i < msg.dict_size(); ++i)
			{
				std::pair<std::string, bdecode_node> standing = msg.dict_at(i);
				if (standing.first.size() != reputation_id::size)
				{
					return reputation_errors::invalid_standing_message;
				}

				reputation_key intermediary = m_repman.rkey(reputation_id(standing.first.data()));
				if (!valid(intermediary))
					continue;
				pubkey_type pk;
				if (!m_repman.pkey(intermediary, pk))
					continue;

				try
				{
					signed_state state(standing.second, m_rid, pk, true);
					m_repman.store_state(intermediary, rkey(), state);

					attributions_type::iterator existing_entry = std::find_if(
						m_rep.attributions.begin()
						, m_rep.attributions.end()
						, boost::bind(&attribution::intermediary, _1) == intermediary);

					if (existing_entry == m_rep.attributions.end())
						m_rep.attributions.push_back(attribution(intermediary, 0));
				}
				catch (reputation_exception)
				{
					return reputation_errors::invalid_standing_message;
				}
			}
			m_repman.consider_attributions(rkey(), m_rep);
			return error_code();
		}

		error_code on_your_standing(bdecode_node const& msg)
		{
			if (msg.type() != bdecode_node::dict_t)
			{
				return reputation_errors::invalid_standing_message;
			}

			reputation_manager::transaction t(m_repman);

			for (int i = 0; i < msg.dict_size(); ++i)
			{
				std::pair<std::string, bdecode_node> standing = msg.dict_at(i);
				if (standing.first.size() != reputation_id::size)
				{
					return reputation_errors::invalid_standing_message;
				}

				reputation_key intermediary = m_repman.rkey(reputation_id(standing.first.data()));
				if (!valid(intermediary))
					continue;
				pubkey_type pk;
				if (!m_repman.pkey(intermediary, pk))
					continue;

				try
				{
					signed_state state(standing.second, m_repman.client_rid(), pk);
					m_repman.store_state(intermediary, client_reputation_key, state);
				}
				catch (reputation_exception)
				{
					return reputation_errors::invalid_standing_message;
				}
			}
			return error_code();
		}

		error_code on_attribution(bdecode_node const& msg)
		{
			if (msg.type() != bdecode_node::dict_t)
			{
				return reputation_errors::invalid_attribution_message;
			}

			m_remote_attributions.clear();

			int total_contribution = 0;
			for (int i = 0; i < msg.dict_size(); ++i)
			{
				std::pair<std::string, bdecode_node> attrib = msg.dict_at(i);
				if (attrib.first.size() != reputation_id::size
					|| attrib.second.type() != bdecode_node::int_t)
				{
					return reputation_errors::invalid_attribution_message;
				}

				int contribution = int(attrib.second.int_value());
				if (contribution <= 0 || contribution > 100)
				{
					return reputation_errors::invalid_contribution;
				}

				total_contribution += contribution;
				reputation_key intermediary = m_repman.rkey(reputation_id(attrib.first.data()));
				if (valid(intermediary))
				{
					attributions_type::iterator existing_entry
						= std::find_if(m_remote_attributions.begin()
							, m_remote_attributions.end()
							, boost::bind(&attribution::intermediary, _1) == intermediary);

					if (existing_entry != m_remote_attributions.end())
					{
						m_remote_attributions.clear();
						return reputation_errors::invalid_attribution_message;
					}

					m_remote_attributions.push_back(attribution(intermediary, contribution));
				}
			}

			if (total_contribution != 100)
			{
				return reputation_errors::invalid_contribution;
			}

			return error_code();
		}

		error_code on_receipt(bdecode_node const& msg)
		{
			bdecode_node state_entry = msg.dict_find_dict("state");
			if (!state_entry)
			{
				return reputation_errors::invalid_receipt_message;
			}

			reputation_manager::transaction t(m_repman);
			establish_rkey();

			pubkey_type pk;
			if (!m_repman.pkey(rkey(), pk))
			{
				TORRENT_ASSERT(false);
				return error_code();
			}

			try
			{
				signed_state state_at_peer(state_entry, m_repman.client_rid(), pk);

				if (m_repman.store_state(rkey(), client_reputation_key, state_at_peer)
					!= reputation_store::state_success)
				{
					return reputation_errors::invalid_reputation_state;
				}

				on_download_credit(state_at_peer.download_direct);

				if (direct_credit_deficit() > receipt_interval_bytes)
				{
					return reputation_errors::insufficient_credit;
				}
			}
			catch (reputation_exception)
			{
				return reputation_errors::invalid_receipt_message;
			}

			observed();

			bdecode_node receipts_entry = msg.dict_find_list("receipts");

			// if the client has received any piece data from the peer it cannot expect to get
			// intermediary receipts since the client now has direct standing with the peer
			// if the peer is feeling generous we'll still take it of course
			// use our state because there's nothing stopping the peer from lying about direct states
			signed_state state_for_peer;
			state_for_peer.subject = rid();
			m_repman.state_at(client_reputation_key, rkey(), state_for_peer);

			if (state_for_peer.download_direct == 0 &&
				((!receipts_entry && !reputation().attributions.empty())
				|| (receipts_entry && receipts_entry.list_size() != int(reputation().attributions.size()))))
			{
				return reputation_errors::missing_receipts;
			}

			if (receipts_entry)
			{
				for (std::vector<attribution>::iterator i = m_rep.attributions.begin();
					i != m_rep.attributions.end(); ++i)
					i->credited = false;

				for (int i = 0; i < receipts_entry.list_size(); ++i)
				{
					error_code ec = process_receipt(receipts_entry.list_at(i), pk);
					if (ec)
						return ec;
				}

				if (attributed_credit_deficit() > receipt_interval_bytes
					&& state_for_peer.download_direct == 0)
				{
					return reputation_errors::insufficient_credit;
				}
			}
			else
			{
				m_payload_attributed_this_session += m_payload_sent_since_receipt;
			}

			m_payload_sent_since_receipt = 0;

			return error_code();
		}

		entry receipt()
		{
			reputation_manager::transaction t(m_repman);
			establish_rkey();
			observed();

			signed_state peer_state;
			peer_state.subject = m_rid;
			peer_state.upload_direct = m_payload_sent_since_db_update;
			peer_state.download_direct = m_repman.adjust_download_direct(m_payload_received_since_receipt);
			m_repman.update_state_for(m_rkey, peer_state);
			// if the peer now has a positive direct ballance that overrides the indirect reputation
			if (peer_state.upload_direct > peer_state.download_direct)
				m_rep.assign_direct(m_repman.direct_value(m_rkey));

			entry e;
			e["state"] = peer_state.to_entry();

			if (!m_remote_attributions.empty())
			{
				entry::list_type& receipts = e["receipts"].list();
				boost::int64_t payload_unattributed = m_payload_received_since_receipt;
				boost::int64_t sequence = m_repman.next_receipt_sequence();
				for (attributions_type::iterator i = m_remote_attributions.begin();
					i != m_remote_attributions.end(); ++i)
				{
					boost::int64_t volume;
					reputation_state intermediary_state;
					if (i == --m_remote_attributions.end())
						volume = payload_unattributed;
					else
						volume = (m_payload_received_since_receipt * i->contribution) / 100;

					intermediary_state.download_recommended = volume;
					payload_unattributed -= intermediary_state.download_recommended;
					m_repman.update_state_for(i->intermediary, intermediary_state);

					entry e;
					entry::dictionary_type& r = e.dict();

					r["seq"] = sequence;
					r["sender"] = m_rid.to_string();
					r["recipient"] = m_repman.client_rid().to_string();

					reputation_id intermediary;
					if (!m_repman.rid(i->intermediary, intermediary))
					{
						TORRENT_ASSERT(false);
						continue;
					}
					r["intermediary"] = intermediary.to_string();

					r["volume"] = volume;

					boost::array<char, 256> verify_str;
					int bsize = bencode(verify_str.begin(), e);
					TORRENT_ASSERT(bsize < 256);
					signature_type sig;
					m_repman.sign(verify_str.data(), bsize, sig.data());
					r.erase("sender");
					r.erase("recipient");
					r["sig"] = std::string(sig.data(), signature_type::static_size);

					// TODO: Optimization opportunity once the codebase moves to C++11
					// use emplace_back and std::move to move e into the list
					receipts.push_back(e);
				}
				TORRENT_ASSERT(payload_unattributed == 0);
			}

			m_repman.payload_received(m_payload_received_since_receipt);
			m_payload_sent_since_db_update = m_payload_received_since_receipt = 0;
			m_last_receipt_sent = clock_type::now();

			return e;
		}

		void send_next_intermediary();
		void send_their_standing(reputation_id const& at, signed_state const& standing);
		bool wants_receipt();

		entry get_next_intermediary()
		{
			signed_state client_state;
			reputation_id rid;
			while (m_next_mutual_intermediary != m_mutual_intermediaries.end()
				&& (!m_repman.state_at(*m_next_mutual_intermediary, client_reputation_key, client_state)
					|| !m_repman.rid(*m_next_mutual_intermediary, rid)))
				++m_next_mutual_intermediary;

			if (m_next_mutual_intermediary == m_mutual_intermediaries.end())
			{
				return entry();
			}

			// don't bother with sending receipts if the client is already at 90% or more
			// of it's download capacity.
			if (!wants_receipt())
			{
				m_repman.schedule_next_standing(shared_from_this());
				return entry();
			}

			client_state.subject = rid;
			entry e;
			e[rid.to_string()] = client_state.to_entry();

			++m_next_mutual_intermediary;

			if (m_next_mutual_intermediary != m_mutual_intermediaries.end())
				m_repman.schedule_next_standing(shared_from_this());

			return e;
		}

		void get_standing_at_attributions()
		{
			for (attributions_type::iterator i = m_rep.attributions.begin();
				i != m_rep.attributions.end(); ++i)
			{
				if (i->contribution == 0)
					continue;
				m_repman.get_standing(i->intermediary, rkey(), shared_from_this());
			}
		}

		// The peer has no more credit to give at the intermediary
		void exhausted_intermediary(reputation_key intermediary);

	private:
		typedef std::vector<boost::weak_ptr<reputation_peer_plugin> > peer_connections;

		void establish_rkey();

#ifndef TORRENT_DISABLE_LOGGING
		void session_log(char const* fmt, ...) const
		{
			//TORRENT_ASSERT(is_single_thread());

#if 0
			if (!m_repman.session().alerts().should_post<log_alert>()) return;

			va_list v;
			va_start(v, fmt);

			char buf[512];
			vsnprintf(buf, sizeof(buf), fmt, v);
			va_end(v);

			m_repman.session().alerts().emplace_alert<log_alert>(buf);
#endif
		}
#endif

		void on_download_credit(boost::int64_t download_direct)
		{
			if (m_last_direct_download_state)
			{
				m_payload_direct_credited_this_session
					+= download_direct - m_last_direct_download_state;
				TORRENT_ASSERT(m_payload_direct_credited_this_session >= 0);
			}
			else
			{
				m_payload_direct_credited_this_session += m_payload_sent_since_receipt;
			}
			m_last_direct_download_state = download_direct;
		}

		// process an intermediary receipt
		error_code process_receipt(bdecode_node const& receipt, pubkey_type pk)
		{
			if (receipt.data_section().second > 200)
			{
				return reputation_errors::invalid_receipt_message;
			}

			try
			{
				entry e; e = receipt;
				standing_update standing(e, m_repman.client_rid(), rid(), pk);
				stored_standing_update stored_standing(standing, m_repman.rkey(standing.intermediary), rkey());

				std::vector<attribution>::iterator attrib
					= std::find_if(m_rep.attributions.begin()
						, m_rep.attributions.end()
						, boost::bind(&attribution::intermediary, _1) == stored_standing.intermediary);

				if (attrib == m_rep.attributions.end()
					|| attrib->credited
					|| std::distance(m_rep.attributions.begin(), attrib) >= max_attributions
					|| standing.sequence <= attrib->sequence)
				{
					return reputation_errors::irrelevant_receipt;
				}

				signed_state state_update;
				state_update.subject = standing.intermediary;
				state_update.upload_recommended = standing.volume;
				m_payload_attributed_this_session += state_update.upload_recommended;
				m_repman.update_state_for(stored_standing.intermediary, state_update);

				attrib->credited = true;
				attrib->sequence = standing.sequence;
				m_repman.forward_standing(stored_standing, state_update, shared_from_this());
			}
			catch (reputation_exception)
			{
				return reputation_errors::invalid_receipt_message;
			}

			return error_code();
		}

		void prune_connections(peer_connections::iterator valid_end)
		{
			m_connections.erase(valid_end, m_connections.end());
		}

		reputation_manager& m_repman;
		reputation_id m_rid;
		reputation_key m_rkey;
		peer_reputation m_rep;
		bool m_sent_known_peers:1;
		bool m_observed:1;
		time_point m_last_receipt_sent;
		boost::int64_t m_payload_received_since_receipt;
		boost::int64_t m_payload_received_this_session;
		boost::int64_t m_payload_sent_since_db_update;
		boost::int64_t m_payload_sent_since_receipt;
		boost::int64_t m_payload_sent_this_session;
		boost::int64_t m_payload_attributed_this_session;
		boost::int64_t m_payload_direct_credited_this_session;
		boost::int64_t m_last_direct_download_state;

		// the top max_attributions intermediaries known by both of us
		// sorted in acending order by our observation count
		std::vector<reputation_key> m_mutual_intermediaries;
		// the next intermediary to send our standing at to the peer
		std::vector<reputation_key>::iterator m_next_mutual_intermediary;
		// attributions received from the peer
		attributions_type m_remote_attributions;

		peer_connections m_connections;
	};

	class reputation_peer_plugin
		: public peer_plugin
		, public boost::enable_shared_from_this<reputation_peer_plugin>
	{
	public:
		reputation_peer_plugin(reputation_manager& repman, bt_peer_connection_handle pc)
			: m_repman(repman)
			, m_pc(pc)
			, m_known_peers_msg_id(0)
			, m_my_standing_msg_id(0)
			, m_your_standing_msg_id(0)
			, m_attribution_msg_id(0)
			, m_receipt_msg_id(0)
		{}

		~reputation_peer_plugin()
		{
			if (m_ses)
				m_ses->remove_connection(this);
		}

		virtual char const* type() const { return "reputation"; }

		virtual void add_handshake(entry& h)
		{
			entry& messages = h["m"];
			messages["lt_known_peers"] = 10;
			messages["lt_my_standing"] = 11;
			messages["lt_your_standing"] = 12;
			messages["lt_attribution"] = 13;
			messages["lt_receipt"] = 14;
		}

		virtual bool on_extension_handshake(bdecode_node const& h)
		{
			bdecode_node messages = h.dict_find_dict("m");
			if (!messages) return false;

			if (!lt_identify_peer_plugin::supports_extension(h))
				return false;

			lt_identify_peer_plugin const* ident_plugin =
					static_cast<lt_identify_peer_plugin const*>(m_pc.find_plugin("lt_identify"));

			if (!ident_plugin)
				return false;

			m_known_peers_msg_id = int(messages.dict_find_int_value("lt_known_peers", 0));
			m_my_standing_msg_id = int(messages.dict_find_int_value("lt_my_standing", 0));
			m_your_standing_msg_id = int(messages.dict_find_int_value("lt_your_standing", 0));
			m_attribution_msg_id = int(messages.dict_find_int_value("lt_attribution", 0));
			m_receipt_msg_id = int(messages.dict_find_int_value("lt_receipt", 0));

			if (!(m_known_peers_msg_id && m_my_standing_msg_id
				&& m_your_standing_msg_id && m_attribution_msg_id
				&& m_receipt_msg_id))
				return false;

			ident_plugin->notify_on_identified(boost::bind(&reputation_peer_plugin::get_rid, this, _1));

			return true;;
		}

		virtual bool on_interested()
		{
			if (m_pc.is_choked() && m_ses && !m_ses->reputation().valid())
			{
				m_ses->check_for_direct_reputation();
				if (!m_ses->reputation().direct() || reputation() < 0.0)
					send_known_peers();
			}
			return false;
		}

		virtual bool on_choke()
		{
			if (m_pc.is_interesting() && m_ses)
				m_ses->send_next_intermediary();
			return false;
		}

		virtual bool on_extended(int length, int msg_id
			, buffer::const_interval body)
		{
			switch (msg_id)
			{
			case 10:on_known_peers(length, body); return true;
			case 11:on_my_standing(length, body); return true;
			case 12:on_your_standing(length, body); return true;
			case 13:on_attribution(length, body); return true;
			case 14:on_receipt(length, body); return true;
			default:return false;
			}
		}

		virtual bool on_piece(peer_request const& piece
			, disk_buffer_holder& /*data*/)
		{
			if (m_ses && m_ses->on_piece(piece.length))
				send_receipt();
			return false;
		}

		virtual void sent_unchoke()
		{
			// we might be sending an unchoke before receiving the extension handshake
			// or the identify message
			// so we must bail out if a session has not yet been established
			if (!m_ses) return;
			send_attribution();
			m_ses->get_standing_at_attributions();
		}

		virtual void sent_payload(int bytes)
		{
			if (!m_ses)
				return;

			error_code ec = m_ses->sent_payload(bytes);
			if (ec)
			{
				m_pc.disconnect(ec, op_bittorrent, 2);
				return;
			}
		}

		reputation_key rkey() const { return m_ses->rkey(); }
		reputation_id const& rid() const { return m_ses->rid(); }
		double reputation() const { return m_ses->reputation().reputation; }

		bool send_next_intermediary(entry const& e)
		{
			TORRENT_ASSERT(m_ses);
			TORRENT_ASSERT(m_my_standing_msg_id);
			TORRENT_ASSERT(m_receipt_msg_id);
			if (m_pc.is_disconnecting() || !m_pc.has_peer_choked())
				return false;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::outgoing_message, "LT_MY_STANDING");
#endif

			send_bencoded_extended_msg(e, m_my_standing_msg_id);
			return true;
		}

		void send_their_standing(reputation_id const& at, signed_state const& standing)
		{
			TORRENT_ASSERT(m_your_standing_msg_id);
			if (m_pc.is_disconnecting() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::outgoing_message, "LT_YOUR_STANDING");
#endif

			entry e;
			e[at.to_string()] = standing.to_entry();
			send_bencoded_extended_msg(e, m_your_standing_msg_id);
		}

		void choke()
		{
			m_repman.choke_peer(m_pc);
		}

		void establish_rkey()
		{
			TORRENT_ASSERT(m_ses);
			if (!m_ses->has_rkey())
			{
				lt_identify_peer_plugin const* ident_plugin =
					static_cast<lt_identify_peer_plugin const*>(m_pc.find_plugin("lt_identify"));
				TORRENT_ASSERT(ident_plugin != NULL);
				pubkey_type const* peer_key = ident_plugin->peer_key();
				TORRENT_ASSERT(peer_key != NULL);
				contact_info ci;
				// Take a guess that the peer is listening for DHT requests on the same
				// port as BT connections. If we're wrong we'll query the DHT for that
				// info when we need it.
				if (m_pc.remote().address().is_v4())
					ci.addr_v4 = m_pc.remote().address().to_v4();
				else if (m_pc.remote().address().is_v6())
					ci.addr_v6 = m_pc.remote().address().to_v6();
				ci.port = m_pc.remote().port();
				m_ses->establish_rkey(*peer_key, ci);
			}
		}

		torrent_handle associated_torrent()
		{ return m_pc.associated_torrent(); }

	private:
		void on_known_peers(int /*length*/, buffer::const_interval body)
		{
			TORRENT_ASSERT(m_my_standing_msg_id);
			if (!m_pc.packet_finished() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::incoming_message, "LT_KNOWN_PEERS");
#endif

			m_ses->on_known_peers(body);

			if (m_pc.is_interesting() && m_pc.has_peer_choked())
				m_ses->send_next_intermediary();
			else
			{
#ifndef TORRENT_DISABLE_LOGGING
				m_pc.peer_log(peer_log_alert::info, "ON_KNOWN_PEERS"
					, "ignoring known peers, interesting = %hhu, choked = %hhu"
					, m_pc.is_interesting(), m_pc.has_peer_choked());
#endif
			}
		}

		void on_my_standing(int /*length*/, buffer::const_interval body)
		{
			TORRENT_ASSERT(m_receipt_msg_id);
			if (!m_pc.packet_finished() || !m_ses)
				return;

			bdecode_node msg;
			error_code ec;
			if (bdecode(body.begin, body.end, msg, ec) != 0)
			{
				m_pc.disconnect(reputation_errors::invalid_standing_message, op_bittorrent, 2);
				return;
			}

			ec = m_ses->on_my_standing(msg);
			if (ec)
			{
				m_pc.disconnect(ec, op_bittorrent, 2);
				return;
			}

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::info, "ON_MY_STANDING"
				, "REPUTATION [ %lf | attributions: %d ]"
				, m_ses->reputation().reputation, int(m_ses->reputation().attributions.size()));
#endif
		}

		void on_your_standing(int /*length*/, buffer::const_interval body)
		{
			if (!m_pc.packet_finished() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::incoming_message, "LT_YOUR_STANDING");
#endif

			bdecode_node msg;
			error_code ec;
			if (bdecode(body.begin, body.end, msg, ec) != 0)
			{
				m_pc.disconnect(reputation_errors::invalid_standing_message, op_bittorrent, 2);
				return;
			}

			ec = m_ses->on_your_standing(msg);
			if (ec)
			{
				m_pc.disconnect(ec, op_bittorrent, 2);
				return;
			}
		}

		void on_attribution(int /*length*/, buffer::const_interval body)
		{
			TORRENT_ASSERT(m_receipt_msg_id);
			if (!m_pc.packet_finished() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::incoming_message, "LT_ATTRIBUTION");
#endif

			bdecode_node msg;
			error_code ec;
			if (bdecode(body.begin, body.end, msg, ec) != 0)
			{
				m_pc.disconnect(reputation_errors::invalid_attribution_message, op_bittorrent, 2);
				return;
			}

			ec = m_ses->on_attribution(msg);
			if (ec)
			{
				m_pc.disconnect(ec, op_bittorrent, 2);
				return;
			}
		}

		void on_receipt(int /*length*/, buffer::const_interval body)
		{
			if (!m_pc.packet_finished() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::incoming_message, "LT_RECEIPT");
#endif

			bdecode_node msg;
			error_code ec;
			if (bdecode(body.begin, body.end, msg, ec) != 0)
			{
				m_pc.disconnect(reputation_errors::invalid_receipt_message, op_bittorrent, 2);
				return;
			}

			ec = m_ses->on_receipt(msg);
			if (ec)
			{
				m_pc.disconnect(ec, op_bittorrent, 2);
				return;
			}
		}

		void send_known_peers()
		{
			TORRENT_ASSERT(m_known_peers_msg_id);
			TORRENT_ASSERT(m_my_standing_msg_id);
			if (m_pc.is_disconnecting() || m_ses->sent_known_peers() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::outgoing_message, "LT_KNOWN_PEERS");
#endif

			std::vector<reputation_id> peers;
			peers.reserve(2000);
			m_ses->known_peers(peers);
			std::vector<char> body;
			body.reserve(peers.size() * reputation_id::size + 6);
			std::back_insert_iterator<std::vector<char> > bi(body);
			detail::write_uint32(peers.size() * reputation_id::size + 2, bi);
			detail::write_uint8(bt_peer_connection::msg_extended, bi);
			detail::write_uint8(m_known_peers_msg_id, bi);
			for (std::vector<reputation_id>::const_iterator i = peers.begin();
				i != peers.end(); ++i)
				bi = std::copy(i->begin(), i->end(), bi);
			m_pc.send_buffer(body.data(), body.size());
		}

		void send_attribution()
		{
			TORRENT_ASSERT(m_attribution_msg_id);
			TORRENT_ASSERT(m_receipt_msg_id);
			if (m_pc.is_disconnecting() || !m_ses
				|| !m_ses->reputation().valid() || m_ses->reputation().direct()
				|| m_ses->reputation().attributions.empty())
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::outgoing_message, "LT_ATTRIBUTION");
#endif
			entry const& e = m_ses->attributions();
			if (!e.dict().empty())
				send_bencoded_extended_msg(e, m_attribution_msg_id);
		}

		void send_receipt()
		{
			TORRENT_ASSERT(m_receipt_msg_id);
			if (m_pc.is_disconnecting() || !m_ses)
				return;

#ifndef TORRENT_DISABLE_LOGGING
			m_pc.peer_log(peer_log_alert::outgoing_message, "LT_RECEIPT");
#endif

			send_bencoded_extended_msg(m_ses->receipt(), m_receipt_msg_id);
		}

		void get_rid(lt_identify_peer_plugin const& identity)
		{
			boost::array<char, ed25519_public_key_size> const* peer_key
				= identity.peer_key();
			if (peer_key)
			{
				reputation_id rid = hasher(peer_key->data(), peer_key->size()).final();
				m_ses = m_repman.peer_session(rid);
				m_ses->add_connection(shared_from_this());

				if (m_pc.has_peer_choked())
					on_choke();
				if (m_pc.is_peer_interested())
					on_interested();
			}
		}

		void send_bencoded_extended_msg(entry const& e, int msg_id)
		{
			char msg[4096];
			char* header = msg;
			char* p = &msg[6];
			int len = bencode(p, e);
			int total_size = 2 + len;
			namespace io = detail;
			io::write_uint32(total_size, header);
			io::write_uint8(bt_peer_connection::msg_extended, header);
			io::write_uint8(msg_id, header);
			m_pc.send_buffer(msg, len + 6);
		}

		reputation_manager& m_repman;
		bt_peer_connection_handle m_pc;
		boost::shared_ptr<reputation_session> m_ses;
		int m_known_peers_msg_id;
		int m_my_standing_msg_id;
		int m_your_standing_msg_id;
		int m_attribution_msg_id;
		int m_receipt_msg_id;
	};

	bool reputation_manager::on_optimistic_unchoke(std::vector<peer_connection_handle>& peers)
	{
		std::vector<std::pair<double, peer_connection_handle> > peer_reps;
		peer_reps.reserve(peers.size());

		for (std::vector<peer_connection_handle>::iterator p = peers.begin();
			p != peers.end(); ++p)
		{
			double rep = 0.0;
			reputation_peer_plugin const* peer_rep
				= static_cast<reputation_peer_plugin const*>(p->find_plugin("reputation"));
			if (peer_rep)
			{
				rep = peer_rep->reputation();
			}
			peer_reps.push_back(std::make_pair(rep, *p));
		}

		std::stable_sort(peer_reps.begin(), peer_reps.end());
		// reverse the vector so the result is sorted in decending order
		std::transform(peer_reps.rbegin()
			, peer_reps.rend()
			, peers.begin()
			, boost::bind(&std::pair<double, peer_connection_handle>::second, _1));
		return false;
	}

	void reputation_manager::peer_exhausted_at(
		boost::weak_ptr<reputation_session> weak_peer
		, reputation_key intermediary)
	{
		boost::shared_ptr<reputation_session> peer = weak_peer.lock();
		if (peer)
			peer->exhausted_intermediary(intermediary);
	}

	void reputation_manager::send_their_standing(
		boost::weak_ptr<reputation_session> weak_peer
		, reputation_id at
		, signed_state const& state)
	{
		boost::shared_ptr<reputation_session> peer = weak_peer.lock();
		if (peer)
			peer->send_their_standing(at, state);
	}

	void reputation_manager::send_next_standing()
	{
		time_point now = clock_type::now();
		while (!m_standing_queue.empty()
			&& m_standing_queue.front().first <= now)
		{
			boost::shared_ptr<reputation_session> session
				= m_standing_queue.front().second.lock();
			if (session)
				session->send_next_intermediary();
			m_standing_queue.pop_front();
		}
	}

	void reputation_session::send_next_intermediary()
	{
		entry const& e = get_next_intermediary();
		if (e.type() == entry::undefined_t)
			return;

		peer_connections::iterator valid_end = m_connections.end();
		peer_connections::iterator i = m_connections.begin();
		while (i != valid_end)
		{
			boost::shared_ptr<reputation_peer_plugin> peer = i->lock();
			TORRENT_ASSERT(peer);
			if (peer)
			{
				if (peer->send_next_intermediary(e))
					break;
				++i;
			}
			else
				std::swap(*i, *--valid_end);
		}

		if (i == valid_end)
		{
			// none of the connections needed the receipt
			// put it back at the head of the queue
			--m_next_mutual_intermediary;
			// no need to schedule sending it again. when a peer connection
			// enters a state where a receipt needs to be sent it will trigger
			// a call to this function
		}
		prune_connections(valid_end);
	}

	void reputation_session::send_their_standing(reputation_id const& at, signed_state const& standing)
	{
		peer_connections::iterator valid_end = m_connections.end();
		while (valid_end != m_connections.begin())
		{
			boost::shared_ptr<reputation_peer_plugin> peer = m_connections.front().lock();
			TORRENT_ASSERT(peer);
			if (peer)
			{
				peer->send_their_standing(at, standing);
				break;
			}
			else
				std::swap(m_connections.front(), *--valid_end);
		}
		prune_connections(valid_end);
	}

	void reputation_session::exhausted_intermediary(reputation_key intermediary)
	{
#ifndef TORRENT_DISABLE_LOGGING
		{
			reputation_id intermediary_rid; m_repman.rid(intermediary, intermediary_rid);
			session_log("Exhausted credit at %s", to_hex(intermediary_rid.to_string()).c_str());
		}
#endif

		check_for_direct_reputation();
		if (m_rep.direct())
			return;

		{
			reputation_manager::transaction t(m_repman);
			m_repman.consider_attributions(m_rkey, m_rep);
		}

		if (!m_rep.attributions.empty()
			&& m_rep.attributions.front().intermediary == intermediary)
			return;

		peer_connections::iterator valid_end = m_connections.end();
		for (peer_connections::iterator i = m_connections.begin();
			i != valid_end;)
		{
			boost::shared_ptr<reputation_peer_plugin> peer = i->lock();
			TORRENT_ASSERT(peer);
			if (peer)
			{
				peer->choke();
				++i;
			}
			else
				std::swap(*i, *--valid_end);
		}
		prune_connections(valid_end);
	}

	void reputation_session::establish_rkey()
	{
		if (!has_rkey())
		{
			peer_connections::iterator valid_end = m_connections.end();
			while (valid_end != m_connections.begin())
			{
				boost::shared_ptr<reputation_peer_plugin> peer = m_connections.front().lock();
				TORRENT_ASSERT(peer);
				if (peer)
				{
					peer->establish_rkey();
					break;
				}
				else
					std::swap(m_connections.front(), *--valid_end);
			}
			prune_connections(valid_end);
		}
	}

	bool reputation_session::wants_receipt()
	{
		bool wanted = false;

		session_handle session = m_repman.session();
		int global_capacity = session.get_settings().get_int(settings_pack::download_rate_limit);
		bool const global_bandwidth_available = global_capacity <= 0
			|| session.status().download_rate < global_capacity * 90 / 100;

		peer_connections::iterator valid_end = m_connections.end();
		for (peer_connections::iterator i = m_connections.begin();
			i != valid_end;)
		{
			boost::shared_ptr<reputation_peer_plugin> peer = i->lock();
			TORRENT_ASSERT(peer);
			if (peer)
			{
				torrent_handle t = peer->associated_torrent();
				if (t.is_valid())
				{
					int rate_limit = t.download_limit();

					if (rate_limit <= 0)
						wanted = global_bandwidth_available;
					else if (t.status().download_rate < rate_limit * 90 / 100)
						wanted = true;
				}

				if (wanted) break;
				++i;
			}
			else
				std::swap(*i, *--valid_end);
		}
		prune_connections(valid_end);
		return wanted;
	}

	boost::shared_ptr<peer_plugin> reputation_torrent_plugin::new_connection(
		peer_connection_handle const& pc)
	{
		if (pc.type() != peer_connection::bittorrent_connection)
			return boost::shared_ptr<peer_plugin>();

		bt_peer_connection_handle c(pc);
		return boost::shared_ptr<peer_plugin>(new reputation_peer_plugin(m_repman, c));
	}
} // namespace

void torrent_wait(bool& done, boost::mutex& mut, boost::condition_variable& cond)
{
	boost::unique_lock<boost::mutex> l(mut);
	while (!done) { cond.wait(l); };
}

template <class R>
void fun_ret(R& ret, bool& done, boost::condition_variable& e, boost::mutex& m, boost::function<R(void)> f)
{
	ret = f();
	boost::unique_lock<boost::mutex> l(m);
	done = true;
	e.notify_all();
}

template <typename Ret>
Ret sync_call_ret(libtorrent::session_handle ses, boost::function<Ret(void)> f)
{
	bool done = false;
	boost::mutex mut;
	boost::condition_variable cond;
	Ret r;
	ses.get_io_service().dispatch(boost::bind(&fun_ret<Ret>
		, boost::ref(r)
		, boost::ref(done)
		, boost::ref(cond)
		, boost::ref(mut)
		, f));
	torrent_wait(done, mut, cond);
	return r;
}

double reputation_handle::global_ratio()
{
	reputation_manager* repman = static_cast<reputation_manager*>(reputation_plugin.get());
	return sync_call_ret<double>(repman->session()
		, boost::bind(&reputation_manager::global_ratio, repman));
}

reputation_handle create_reputation_plugin(lt_identify_plugin& identity
	, std::string const& storage_path
	, std::string const& sk_password)
{
	try
	{
		return reputation_handle(
			boost::make_shared<reputation_manager>(boost::ref(identity), storage_path, sk_password));
	}
	catch (reputation_exception)
	{
		return reputation_handle(boost::shared_ptr<reputation_manager>());
	}
	catch (db_init_error)
	{
		return reputation_handle(boost::shared_ptr<reputation_manager>());
	}
}

} // namespace libtorrent

