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

#ifndef REPUTATION_MANAGER_HPP_INCLUDED
#define REPUTATION_MANAGER_HPP_INCLUDED

#ifdef _MSC_VER
#pragma warning(push, 1)
#endif

#include <memory>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <libtorrent/config.hpp>

#include "libtorrent/extensions/reputation_export.hpp"

namespace libtorrent
{
	struct plugin;
	struct lt_identify_plugin;

	// create_reputation_plugin will throw this if the supplied password
	// is not the one which was used to encrypt the secret key in the reputation database
	struct TORRENT_REPUTATION_EXPORT bad_reputation_password : std::exception
	{
		virtual char const* what() const throw() { return "invalid reputation password"; }
	};

	struct TORRENT_REPUTATION_EXPORT reputation_handle
	{
		reputation_handle() {}
		reputation_handle(std::shared_ptr<plugin> repman)
			: reputation_plugin(repman) {}

		// get the client's global ratio
		double global_ratio();
		// pass this to session::add_extension() to register the plugin
		std::shared_ptr<plugin> reputation_plugin;
	};

	// create a reputation plugin instance
	// parameters:
	// identity - The instance of the identity plugin to use.
	//            This must be passed to session::add_extension() to register it with the session
	//            It is not necessary to populate the plugin's key, it will be loaded from the reputation
	//            database or generated if no database is found.
	// storage_path - Path to a directory to store the reputation database in.
	// sk_password - A password to use to encrypt/decrypt the secret key stored in the reputaion database
	//               Can be empty in which case anyone with the database file can extract the secret key
	// The reputation_plugin in the returned handler may be empty if there was a fatal error while
	// constructing the plugin
	TORRENT_REPUTATION_EXPORT reputation_handle create_reputation_plugin(lt_identify_plugin& identity
		, std::string const& storage_path
		, std::string const& sk_password);
}

#endif // REPUTATION_MANAGER_HPP_INCLUDED
