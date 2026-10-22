// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tls_sesscache.cpp -- see tls_sesscache.h.
#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "phorepoc_mbedtls_config.h"
#endif
#define MBEDTLS_ALLOW_PRIVATE_ACCESS	// ticket_len / ticket_lifetime / verify_result of the session

#include <stdlib.h>
#include <string.h>

#include "tls_sesscache.h"

// ---- keys ---------------------------------------------------------------------------------------------------------
static int MakeKey(char* key, const char* host, unsigned port)
	{
	size_t n = 0;
	if (!host || !host[0])
		return -1;
	for (const char* p = host; *p; ++p)
		{
		if (n + 12 >= PHSC_KEYLEN)
			return -1;
		char ch = *p;
		key[n++] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
		}
	key[n++] = ':';
	char digits[12];
	int d = 0;
	do { digits[d++] = (char)('0' + port % 10); port /= 10; } while (port && d < 10);
	while (d)
		key[n++] = digits[--d];
	key[n] = 0;
	return 0;
	}

static phsc_entry* Find(phsc* c, const char* key)
	{
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		if (c->e[i].key[0] && strcmp(c->e[i].key, key) == 0)
			return &c->e[i];
	return NULL;
	}

static void Drop(phsc_entry* e)
	{
	free(e->blob);
	memset(e, 0, sizeof(*e));
	}

static void Expire(phsc* c, uint64_t now)
	{
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		if (c->e[i].key[0] && c->e[i].expiry <= now)
			Drop(&c->e[i]);
	}

// a free slot, else the least recently used one
static phsc_entry* Slot(phsc* c)
	{
	phsc_entry* lru = &c->e[0];
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		{
		if (!c->e[i].key[0])
			return &c->e[i];
		if ((int32_t)(c->e[i].stamp - lru->stamp) < 0)
			lru = &c->e[i];
		}
	Drop(lru);
	return lru;
	}

void phsc_clear(phsc* c)
	{
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		Drop(&c->e[i]);
	c->clock = 0;
	}

int phsc_count(const phsc* c)
	{
	int n = 0;
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		if (c->e[i].key[0])
			++n;
	return n;
	}

static int PutKey(phsc* c, const char* key, const unsigned char* blob, size_t len, unsigned char flags,
				  uint64_t expiry)
	{
	if (!blob || len == 0 || len > PHSC_MAX_BLOB)
		return -1;
	unsigned char* copy = (unsigned char*)malloc(len);
	if (!copy)
		return -1;
	memcpy(copy, blob, len);
	phsc_entry* e = Find(c, key);
	if (e)
		Drop(e);
	else
		e = Slot(c);
	strcpy(e->key, key);
	e->expiry = expiry;
	e->stamp = ++c->clock;
	e->len = (uint32_t)len;
	e->flags = flags;
	e->blob = copy;
	return 0;
	}

int phsc_put(phsc* c, const char* host, unsigned port, const unsigned char* blob, size_t len, unsigned char flags,
			 uint64_t now, uint32_t lifetime)
	{
	char key[PHSC_KEYLEN];
	if (MakeKey(key, host, port))
		return -1;
	if (lifetime == 0 || lifetime > PHSC_MAX_AGE)
		lifetime = PHSC_MAX_AGE;
	Expire(c, now);
	return PutKey(c, key, blob, len, flags, now + lifetime);
	}

unsigned char* phsc_take(phsc* c, const char* host, unsigned port, uint64_t now, size_t* len, unsigned char* flags)
	{
	char key[PHSC_KEYLEN];
	if (MakeKey(key, host, port))
		return NULL;
	Expire(c, now);
	phsc_entry* e = Find(c, key);
	if (!e)
		return NULL;
	unsigned char* copy = (unsigned char*)malloc(e->len);
	if (!copy)
		return NULL;
	memcpy(copy, e->blob, e->len);
	*len = e->len;
	if (flags)
		*flags = e->flags;
	if (e->flags & PHSC_FLAG_SINGLE_USE)
		Drop(e);
	else
		e->stamp = ++c->clock;
	return copy;
	}

void phsc_remove(phsc* c, const char* host, unsigned port)
	{
	char key[PHSC_KEYLEN];
	if (MakeKey(key, host, port))
		return;
	phsc_entry* e = Find(c, key);
	if (e)
		Drop(e);
	}

// ---- the file image -----------------------------------------------------------------------------------------------
static uint32_t Crc32(const unsigned char* p, size_t n)
	{
	uint32_t crc = 0xFFFFFFFFu;
	while (n--)
		{
		crc ^= *p++;
		for (int k = 0; k < 8; ++k)
			crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
		}
	return ~crc;
	}

static void Put32(unsigned char* p, uint32_t v)
	{
	p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
	}

static uint32_t Get32(const unsigned char* p)
	{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	}

// header: "PHSC" u32 version(1) u32 count; per entry: u8 keylen, key, u8 flags, u32 expiry lo, u32 expiry hi, u32 len,
// blob; trailer: u32 crc32 of everything before it
size_t phsc_serialize(const phsc* c, uint64_t now, unsigned char* buf, size_t cap)
	{
	size_t need = 12;
	uint32_t count = 0;
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		if (c->e[i].key[0] && c->e[i].expiry > now)
			{
			need += 1 + strlen(c->e[i].key) + 1 + 12 + c->e[i].len;
			++count;
			}
	if (count == 0)
		return 0;
	need += 4;
	if (!buf)
		return need;
	if (cap < need)
		return 0;
	unsigned char* p = buf;
	memcpy(p, "PHSC", 4);
	Put32(p + 4, 1);
	Put32(p + 8, count);
	p += 12;
	for (int i = 0; i < PHSC_MAX_ENTRIES; ++i)
		{
		const phsc_entry* e = &c->e[i];
		if (!e->key[0] || e->expiry <= now)
			continue;
		size_t kl = strlen(e->key);
		*p++ = (unsigned char)kl;
		memcpy(p, e->key, kl);
		p += kl;
		*p++ = e->flags;
		Put32(p, (uint32_t)e->expiry);
		Put32(p + 4, (uint32_t)(e->expiry >> 32));
		Put32(p + 8, e->len);
		p += 12;
		memcpy(p, e->blob, e->len);
		p += e->len;
		}
	Put32(p, Crc32(buf, (size_t)(p - buf)));
	return need;
	}

int phsc_deserialize(phsc* c, const unsigned char* buf, size_t len, uint64_t now)
	{
	if (len < 16 || memcmp(buf, "PHSC", 4) != 0 || Get32(buf + 4) != 1)
		return -1;
	if (Crc32(buf, len - 4) != Get32(buf + len - 4))
		return -1;
	uint32_t count = Get32(buf + 8);
	if (count > PHSC_MAX_ENTRIES)
		return -1;
	// validate the whole image before touching the cache
	const unsigned char* p = buf + 12;
	const unsigned char* end = buf + len - 4;
	for (uint32_t i = 0; i < count; ++i)
		{
		if (p >= end)
			return -1;
		size_t kl = *p++;
		if (kl == 0 || kl >= PHSC_KEYLEN || (size_t)(end - p) < kl + 13)
			return -1;
		p += kl + 13;
		uint32_t bl = Get32(p - 4);
		if (bl == 0 || bl > PHSC_MAX_BLOB || (size_t)(end - p) < bl)
			return -1;
		p += bl;
		}
	if (p != end)
		return -1;
	int added = 0;
	p = buf + 12;
	for (uint32_t i = 0; i < count; ++i)
		{
		char key[PHSC_KEYLEN];
		size_t kl = *p++;
		memcpy(key, p, kl);
		key[kl] = 0;
		p += kl;
		unsigned char flags = *p++;
		uint64_t expiry = (uint64_t)Get32(p) | ((uint64_t)Get32(p + 4) << 32);
		uint32_t bl = Get32(p + 8);
		p += 12;
		if (expiry > now && expiry <= now + PHSC_MAX_AGE && !Find(c, key) && PutKey(c, key, p, bl, flags, expiry) == 0)
			++added;
		p += bl;
		}
	return added;
	}

// ---- mbedTLS ------------------------------------------------------------------------------------------------------
// A cache entry is: u32 length of the server's end-entity certificate (DER; 0 = none), the certificate, then the
// mbedtls_ssl_session_save() image. The certificate is there because a TLS 1.3 session image does not carry it, and
// the platform's UI (ServerCert, the page info) wants to show the server certificate of a resumed connection too.
static const size_t KMaxCert = 8192;

int phtls_session_export(const mbedtls_ssl_context* ssl, unsigned char** blob, size_t* len, unsigned char* flags,
						 uint32_t* lifetime)
	{
	mbedtls_ssl_session s;
	mbedtls_ssl_session_init(&s);
	int rc = mbedtls_ssl_get_session(ssl, &s);
	if (rc == 0)
		{
		// fail closed: only a session whose certificate verified cleanly against the trust anchors is resumable
		const int tls13 = s.tls_version == MBEDTLS_SSL_VERSION_TLS1_3;
		const int has12 = s.id_len > 0 || s.ticket_len > 0;
		if (s.verify_result != 0 || (!tls13 && !has12) || (tls13 && s.ticket_len == 0))
			rc = -1;
		}
	if (rc == 0)
		{
		const mbedtls_x509_crt* peer = mbedtls_ssl_get_peer_cert(ssl);
		const size_t certLen = (peer && peer->raw.p && peer->raw.len <= KMaxCert) ? peer->raw.len : 0;
		size_t need = 0;
		(void)mbedtls_ssl_session_save(&s, NULL, 0, &need);
		if (need == 0 || 4 + certLen + need > PHSC_MAX_BLOB)
			rc = -1;
		else
			{
			unsigned char* out = (unsigned char*)malloc(4 + certLen + need);
			size_t used = 0;
			if (!out || mbedtls_ssl_session_save(&s, out + 4 + certLen, need, &used) != 0)
				{
				free(out);
				rc = -1;
				}
			else
				{
				Put32(out, (uint32_t)certLen);
				if (certLen)
					memcpy(out + 4, peer->raw.p, certLen);
				*blob = out;
				*len = 4 + certLen + used;
				*flags = (s.tls_version == MBEDTLS_SSL_VERSION_TLS1_3) ? PHSC_FLAG_SINGLE_USE : 0;
				*lifetime = s.ticket_lifetime;
				}
			}
		}
	mbedtls_ssl_session_free(&s);
	return rc;
	}

int phtls_session_import(mbedtls_ssl_context* ssl, const unsigned char* blob, size_t len, unsigned char** cert,
						 size_t* certLen)
	{
	if (cert)
		*cert = NULL;
	if (certLen)
		*certLen = 0;
	if (len < 4)
		return -1;
	const size_t cl = Get32(blob);
	if (cl > KMaxCert || len < 4 + cl)
		return -1;
	mbedtls_ssl_session s;
	mbedtls_ssl_session_init(&s);
	// (verify_result is not checked here: a TLS 1.3 image does not store one, and only clean sessions are exported)
	int rc = mbedtls_ssl_session_load(&s, blob + 4 + cl, len - 4 - cl);
	if (rc == 0)
		rc = mbedtls_ssl_set_session(ssl, &s);		// copies
	mbedtls_ssl_session_free(&s);
	if (rc == 0 && cl && cert && certLen)
		{
		*cert = (unsigned char*)malloc(cl);
		if (*cert)
			{
			memcpy(*cert, blob + 4, cl);
			*certLen = cl;
			}
		}
	return rc;
	}
