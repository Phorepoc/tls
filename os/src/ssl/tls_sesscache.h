// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tls_sesscache.h -- the TLS client session cache of SSL.DLL: a small bounded store of exported mbedTLS sessions
// (tickets), keyed by host:port, with an expiry, serialisable to a file. Plain C++ over libc and mbedTLS (no Symbian
// types), so a host test links the very same code. It does no locking and no file I/O: tlsconnection_mbed.cpp wraps
// the calls in its lock and does the (atomic) file writes.
#ifndef PHOREPOC_TLS_SESSCACHE_H
#define PHOREPOC_TLS_SESSCACHE_H

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/ssl.h"

#define PHSC_MAX_ENTRIES 16			// bound on cached sessions
#define PHSC_MAX_AGE 86400u			// seconds: no session outlives a day, whatever its ticket lifetime hint says
#define PHSC_MAX_BLOB 16384u		// a session larger than this (a huge certificate chain) is not cached
#define PHSC_KEYLEN 192				// "host:port"

#define PHSC_FLAG_SINGLE_USE 1		// TLS 1.3 tickets: handed out once (RFC 8446 section 4.6.1)

struct phsc_entry
	{
	char key[PHSC_KEYLEN];			// empty = free slot
	uint64_t expiry;				// unix seconds
	uint32_t stamp;					// last use (LRU)
	uint32_t len;
	unsigned char flags;
	unsigned char* blob;			// mbedtls_ssl_session_save() output (malloc)
	};

struct phsc
	{
	phsc_entry e[PHSC_MAX_ENTRIES];
	uint32_t clock;
	};

// An all-zero phsc is a valid empty cache (static storage needs no constructor).
void phsc_clear(phsc* c);			// frees every blob
// host is compared case-insensitively; returns 0 on success (the blob is copied)
int phsc_put(phsc* c, const char* host, unsigned port, const unsigned char* blob, size_t len, unsigned char flags,
			 uint64_t now, uint32_t lifetime);
// A malloc'd copy of the blob (caller frees) or NULL: unknown, expired (dropped), or used up (single-use entries are
// removed as they are handed out).
unsigned char* phsc_take(phsc* c, const char* host, unsigned port, uint64_t now, size_t* len, unsigned char* flags);
void phsc_remove(phsc* c, const char* host, unsigned port);
int phsc_count(const phsc* c);

// File image: "PHSC", version, entries, CRC-32. serialize with buf == NULL returns the size needed; 0 = nothing to
// write. deserialize merges into c (entries already there win), skips expired ones and returns the number added, or
// -1 if the image is damaged (then c is untouched).
size_t phsc_serialize(const phsc* c, uint64_t now, unsigned char* buf, size_t cap);
int phsc_deserialize(phsc* c, const unsigned char* buf, size_t len, uint64_t now);

// ---- the mbedTLS side -----------------------------------------------------------------------------------------
// Export the connection's session for the cache. 0 = *blob (malloc) / *len / *flags / *lifetime are set; non-zero =
// not cacheable: the certificate did not verify cleanly (a user-accepted certificate is never resumed silently), no
// ticket or session id, too big, or already exported.
int phtls_session_export(const mbedtls_ssl_context* ssl, unsigned char** blob, size_t* len, unsigned char* flags,
						 uint32_t* lifetime);
// Offer a cached session on a connection that has not started its handshake (hostname already set). 0 = offered.
// *cert / *certLen: the server certificate (DER, malloc: caller frees) the session was established with, if kept.
int phtls_session_import(mbedtls_ssl_context* ssl, const unsigned char* blob, size_t len, unsigned char** cert,
						 size_t* certLen);

#endif
