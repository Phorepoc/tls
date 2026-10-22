// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tls_conf.h -- SSL.DLL's runtime switches, read from a tiny text file (\resource\ssl\ssl.ini on any drive; a copy on
// C: wins over the ROM's, so a user or an image builder can change them without rebuilding anything):
//
//     # comment
//     tls13 = 0              # 1 (default): offer TLS 1.3; 0: at most TLS 1.2, for servers / middleboxes that break 1.3
//     session_cache = 0      # 1 (default): resume TLS sessions; 0: every connection does a full handshake
//     session_persist = 0    # 1 (default): keep the session cache across process restarts (a file in the process's
//                            # private data); 0: in memory only
//
// Unknown keys and malformed lines are ignored. Plain C++, no Symbian types (host-tested).
#ifndef PHOREPOC_TLS_CONF_H
#define PHOREPOC_TLS_CONF_H

#include <stddef.h>

struct phtls_conf
	{
	int tls13;
	int session_cache;
	int session_persist;
	};

void phtls_conf_defaults(phtls_conf* aConf);
void phtls_conf_parse(phtls_conf* aConf, const char* aText, size_t aLen);

#endif
