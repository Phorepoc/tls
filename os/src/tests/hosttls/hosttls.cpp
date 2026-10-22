// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// hosttls.cpp -- host test of SSL.DLL's portable parts, built with the ssl.dll's own mbedTLS configuration
// (host_config.h) and the very sources the DLL compiles: tls_sesscache.cpp, tls_stubcert.cpp, tls_conf.cpp.
//   - a real mbedTLS client (configured as tlsconnection_mbed.cpp does) talks to a real mbedTLS server over memory
//     pipes; the test proves a second connection RESUMES the first one's session (the server counts the tickets it
//     accepted; the client sees no certificate verification), for TLS 1.2 and 1.3, across a simulated process restart
//     (the cache serialised, destroyed, rebuilt from the file image), and that a refused / damaged / unverified /
//     expired / other-host session never resumes and never breaks the handshake;
//   - the display certificate keeps subject, issuer, serial and validity and parses again with mbedTLS;
//   - the runtime configuration file parser.
// usage: hosttls <dir with server.crt server.key p521.crt>
#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "host_config.h"
#endif
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"

#include "tls_sesscache.h"
#include "tls_stubcert.h"
#include "tls_conf.h"

// ---- mbedtls_hardware_poll: the DLL's is euser's Math::Random; the host's is /dev/urandom -------------------------
extern "C" int mbedtls_hardware_poll(void*, unsigned char* out, size_t len, size_t* olen)
	{
	FILE* f = fopen("/dev/urandom", "rb");
	if (!f)
		return -1;
	*olen = fread(out, 1, len, f);
	fclose(f);
	return 0;
	}

static int gFail;
#define CHECK(cond, ...) do { if (cond) printf("  ok    " __VA_ARGS__); else { ++gFail; printf("  FAIL  " __VA_ARGS__); } printf("\n"); } while (0)

// ---- memory pipes -------------------------------------------------------------------------------------------------
struct Pipe { unsigned char d[1 << 17]; size_t n; };
struct Ends { Pipe* in; Pipe* out; };

static int PipeSend(void* ctx, const unsigned char* b, size_t l)
	{
	Pipe* o = ((Ends*)ctx)->out;
	if (o->n + l > sizeof(o->d))
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;
	memcpy(o->d + o->n, b, l);
	o->n += l;
	return (int)l;
	}

static int PipeRecv(void* ctx, unsigned char* b, size_t l)
	{
	Pipe* i = ((Ends*)ctx)->in;
	if (i->n == 0)
		return MBEDTLS_ERR_SSL_WANT_READ;
	size_t n = l < i->n ? l : i->n;
	memcpy(b, i->d, n);
	memmove(i->d, i->d + n, i->n - n);
	i->n -= n;
	return (int)n;
	}

// ---- the server -------------------------------------------------------------------------------------------------
static mbedtls_entropy_context gEntropy;
static mbedtls_ctr_drbg_context gDrbg;
static mbedtls_x509_crt gServerCert;
static mbedtls_pk_context gServerKey;
static mbedtls_ssl_config gSrvConf;
static mbedtls_ssl_ticket_context gTickets;
static int gTicketsAccepted;

static int TicketWrite(void* c, const mbedtls_ssl_session* s, unsigned char* start, const unsigned char* end,
					   size_t* tlen, uint32_t* lifetime)
	{
	return mbedtls_ssl_ticket_write(c, s, start, end, tlen, lifetime);
	}

static int TicketParse(void* c, mbedtls_ssl_session* s, unsigned char* buf, size_t len)
	{
	int rc = mbedtls_ssl_ticket_parse(c, s, buf, len);
	if (rc == 0)
		++gTicketsAccepted;
	return rc;
	}

static void NewTicketKey()
	{
	mbedtls_ssl_ticket_free(&gTickets);
	mbedtls_ssl_ticket_init(&gTickets);
	mbedtls_ssl_ticket_setup(&gTickets, mbedtls_ctr_drbg_random, &gDrbg, MBEDTLS_CIPHER_AES_256_GCM, 3600);
	}

static int SetupServer(const char* dir)
	{
	char path[512];
	mbedtls_x509_crt_init(&gServerCert);
	mbedtls_pk_init(&gServerKey);
	mbedtls_ssl_config_init(&gSrvConf);
	mbedtls_ssl_ticket_init(&gTickets);
	snprintf(path, sizeof(path), "%s/server.crt", dir);
	if (mbedtls_x509_crt_parse_file(&gServerCert, path))
		return -1;
	snprintf(path, sizeof(path), "%s/server.key", dir);
	if (mbedtls_pk_parse_keyfile(&gServerKey, path, NULL, mbedtls_ctr_drbg_random, &gDrbg))
		return -2;
	if (mbedtls_ssl_config_defaults(&gSrvConf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
									MBEDTLS_SSL_PRESET_DEFAULT))
		return -3;
	mbedtls_ssl_conf_rng(&gSrvConf, mbedtls_ctr_drbg_random, &gDrbg);
	if (mbedtls_ssl_conf_own_cert(&gSrvConf, &gServerCert, &gServerKey))
		return -4;
	NewTicketKey();
	mbedtls_ssl_conf_session_tickets_cb(&gSrvConf, TicketWrite, TicketParse, &gTickets);
	mbedtls_ssl_conf_new_session_tickets(&gSrvConf, 1);		// (TLS 1.3: tickets sent per full handshake)
	return 0;
	}

// ---- the client, configured as tlsconnection_mbed.cpp does ------------------------------------------------------
static int gVerifyCalls;
static int VerifyCb(void*, mbedtls_x509_crt*, int, uint32_t*)
	{
	++gVerifyCalls;
	return 0;
	}

struct Conn
	{
	int handshakeOk;
	int fullVerify;			// the certificate was verified: a full handshake, not a resumption
	int serverAccepted;		// tickets the server accepted during this connection
	int version;
	int echoed;
	};

// One complete connection: handshake against a fresh server context, the way StartClientHandshake + the read loop do
// (import before the handshake, export after a TLS 1.2 handshake or on a TLS 1.3 ticket).
static Conn Connect(phsc* cache, const char* host, unsigned port, int tls13, int trustServer, int useCache,
					uint64_t now, int* exported)
	{
	Conn r;
	memset(&r, 0, sizeof(r));
	static Pipe c2s, s2c;
	c2s.n = s2c.n = 0;
	Ends ce = { &s2c, &c2s }, se = { &c2s, &s2c };

	mbedtls_ssl_config cc;
	mbedtls_ssl_context cs, ss;
	mbedtls_ssl_config_init(&cc);
	mbedtls_ssl_init(&cs);
	mbedtls_ssl_init(&ss);
	mbedtls_ssl_config_defaults(&cc, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_min_tls_version(&cc, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&cc, tls13 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_rng(&cc, mbedtls_ctr_drbg_random, &gDrbg);
	if (trustServer)
		mbedtls_ssl_conf_ca_chain(&cc, &gServerCert, NULL);
	mbedtls_ssl_conf_authmode(&cc, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_verify(&cc, VerifyCb, NULL);
	mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(&cc, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
	mbedtls_ssl_setup(&cs, &cc);
	mbedtls_ssl_set_hostname(&cs, host);
	mbedtls_ssl_set_bio(&cs, &ce, PipeSend, PipeRecv, NULL);
	mbedtls_ssl_setup(&ss, &gSrvConf);
	mbedtls_ssl_set_bio(&ss, &se, PipeSend, PipeRecv, NULL);

	if (useCache)
		{
		size_t len = 0;
		unsigned char fl = 0;
		unsigned char* blob = phsc_take(cache, host, port, now, &len, &fl);
		if (blob)
			{
			int irc = phtls_session_import(&cs, blob, len, NULL, NULL);
			if (getenv("HOSTTLS_DEBUG"))
				fprintf(stderr, "   import rc %d (blob %u bytes)\n", irc, (unsigned)len);
			free(blob);
			}
		else if (getenv("HOSTTLS_DEBUG"))
			fprintf(stderr, "   no cached session\n");
		}

	gVerifyCalls = 0;
	const int accepted0 = gTicketsAccepted;
	int crc = MBEDTLS_ERR_SSL_WANT_READ, src = MBEDTLS_ERR_SSL_WANT_READ;
	for (int i = 0; i < 100 && (crc || src); ++i)
		{
		if (crc == MBEDTLS_ERR_SSL_WANT_READ || crc == MBEDTLS_ERR_SSL_WANT_WRITE)
			crc = mbedtls_ssl_handshake(&cs);
		if (src == MBEDTLS_ERR_SSL_WANT_READ || src == MBEDTLS_ERR_SSL_WANT_WRITE)
			src = mbedtls_ssl_handshake(&ss);
		if ((crc && crc != MBEDTLS_ERR_SSL_WANT_READ && crc != MBEDTLS_ERR_SSL_WANT_WRITE)
			|| (src && src != MBEDTLS_ERR_SSL_WANT_READ && src != MBEDTLS_ERR_SSL_WANT_WRITE))
			break;
		}
	r.handshakeOk = crc == 0 && src == 0;
	if (getenv("HOSTTLS_DEBUG")) fprintf(stderr, "   handshake crc=-0x%x src=-0x%x s2c=%u c2s=%u\n", -crc, -src, (unsigned)s2c.n, (unsigned)c2s.n);
	r.fullVerify = gVerifyCalls > 0;
	r.serverAccepted = gTicketsAccepted - accepted0;
	if (r.handshakeOk)
		{
		r.version = mbedtls_ssl_get_version_number(&cs);
		const uint32_t flags = mbedtls_ssl_get_verify_result(&cs);
		(void)flags;
		auto capture = [&]()
			{
			unsigned char* blob = NULL;
			size_t len = 0;
			unsigned char fl = 0;
			uint32_t life = 0;
			int xrc = phtls_session_export(&cs, &blob, &len, &fl, &life);
			if (getenv("HOSTTLS_DEBUG")) fprintf(stderr, "   export rc %d\n", xrc);
			if (xrc == 0)
				{
				phsc_put(cache, host, port, blob, len, fl, now, life);
				free(blob);
				if (exported)
					++*exported;
				}
			};
		if (r.version == MBEDTLS_SSL_VERSION_TLS1_2)
			capture();
		// the application data exchange; on TLS 1.3 the client's read is where the ticket arrives
		const unsigned char ping[] = "ping";
		{ int wrc = mbedtls_ssl_write(&ss, ping, 4); if (getenv("HOSTTLS_DEBUG")) fprintf(stderr, "   server write rc %d, s2c %u\n", wrc, (unsigned)s2c.n); }
		for (int i = 0; i < 10; ++i)
			{
			unsigned char buf[64];
			int n = mbedtls_ssl_read(&cs, buf, sizeof(buf));
			if (getenv("HOSTTLS_DEBUG")) fprintf(stderr, "   read -> -0x%x (%d) s2c left %u\n", n < 0 ? -n : 0, n, (unsigned)s2c.n);
			if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
				{
				capture();
				continue;
				}
			if (n == MBEDTLS_ERR_SSL_WANT_READ && s2c.n > 0)
				continue;			// (bytes are waiting in the pipe: ask again)
			if (n == 4 && memcmp(buf, "ping", 4) == 0)
				r.echoed = 1;
			break;
			}
		}
	mbedtls_ssl_free(&cs);
	mbedtls_ssl_free(&ss);
	mbedtls_ssl_config_free(&cc);
	return r;
	}

// ---- the tests ----------------------------------------------------------------------------------------------------
static void TestResume(int tls13, const char* title, uint64_t now)
	{
	printf("%s\n", title);
	phsc cache;
	memset(&cache, 0, sizeof(cache));
	int exported = 0;
	Conn a = Connect(&cache, "resume.test", 443, tls13, 1, 1, now, &exported);
	CHECK(a.handshakeOk && a.echoed, "first connection completes and carries data");
	CHECK(a.version == (tls13 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2), "negotiated TLS 1.%d", tls13 ? 3 : 2);
	CHECK(a.fullVerify && a.serverAccepted == 0, "first connection is a full handshake (certificate verified, no ticket)");
	CHECK(phsc_count(&cache) == 1, "one session cached (%d)", phsc_count(&cache));

	Conn b = Connect(&cache, "resume.test", 443, tls13, 1, 1, now + 5, &exported);
	CHECK(b.handshakeOk && b.echoed, "second connection completes");
	CHECK(!b.fullVerify && b.serverAccepted == 1, "second connection RESUMES (server accepted the ticket, no certificate verification)");
	CHECK(phsc_count(&cache) == 1, "a fresh ticket replaced the used one (%d)", phsc_count(&cache));

	// the same without the cache is a full handshake (the control for the lines above)
	Conn c = Connect(&cache, "resume.test", 443, tls13, 1, 0, now + 6, NULL);
	CHECK(c.handshakeOk && c.fullVerify && c.serverAccepted == 0, "no cache: full handshake");

	// across a process restart: serialise, destroy, rebuild from the file image
	size_t need = phsc_serialize(&cache, now + 7, NULL, 0);
	unsigned char* img = (unsigned char*)malloc(need ? need : 1);
	size_t got = phsc_serialize(&cache, now + 7, img, need);
	CHECK(need > 0 && got == need, "file image of %u bytes", (unsigned)need);
	phsc_clear(&cache);
	CHECK(phsc_count(&cache) == 0, "cache emptied (process gone)");
	int added = phsc_deserialize(&cache, img, need, now + 8);
	CHECK(added == 1, "file image loaded back (%d entry)", added);
	Conn d = Connect(&cache, "resume.test", 443, tls13, 1, 1, now + 9, &exported);
	CHECK(d.handshakeOk && !d.fullVerify && d.serverAccepted == 1, "resumes after the restart");

	// a damaged image is refused whole and leaves the cache alone
	int before = phsc_count(&cache);
	img[need / 2] ^= 0x5a;
	CHECK(phsc_deserialize(&cache, img, need, now + 10) == -1 && phsc_count(&cache) == before, "damaged image rejected");
	CHECK(phsc_deserialize(&cache, img, 7, now + 10) == -1, "truncated image rejected");
	free(img);

	// the server forgets its ticket key (restart / rotation): the stale ticket is refused, the handshake still works
	NewTicketKey();
	Conn e = Connect(&cache, "resume.test", 443, tls13, 1, 1, now + 11, &exported);
	CHECK(e.handshakeOk && e.echoed && e.fullVerify && e.serverAccepted == 0, "stale ticket: falls back to a full handshake");

	// other port / other host do not share a session
	Conn f = Connect(&cache, "resume.test", 8443, tls13, 1, 1, now + 12, &exported);
	CHECK(f.handshakeOk && f.fullVerify, "same host, other port: no resumption");
	Conn g = Connect(&cache, "other.test", 443, tls13, 1, 1, now + 13, &exported);
	CHECK(g.handshakeOk && g.fullVerify, "other host: no resumption");
	CHECK(phsc_take(&cache, "RESUME.TEST", 443, now + 14, &need, NULL) != NULL, "host key is case-insensitive");

	// a session that expired is not offered
	CHECK(phsc_take(&cache, "resume.test", 443, now + PHSC_MAX_AGE + 100, &need, NULL) == NULL, "expired session not offered");
	phsc_clear(&cache);

	// an untrusted certificate (user-accepted in the DLL): never cached, so never resumed silently
	int ex0 = exported;
	Conn h = Connect(&cache, "resume.test", 443, tls13, 0, 1, now + 15, &exported);
	CHECK(h.handshakeOk && exported == ex0 && phsc_count(&cache) == 0, "unverified certificate: session not cached");
	phsc_clear(&cache);
	}

static void TestBounds(uint64_t now)
	{
	printf("bounded cache\n");
	phsc cache;
	memset(&cache, 0, sizeof(cache));
	unsigned char blob[100];
	memset(blob, 7, sizeof(blob));
	char host[32];
	for (int i = 0; i < 24; ++i)
		{
		snprintf(host, sizeof(host), "h%d.test", i);
		phsc_put(&cache, host, 443, blob, sizeof(blob), 0, now, 3600);
		if (i == 3)
			{
			size_t l;
			free(phsc_take(&cache, "h0.test", 443, now, &l, NULL));		// h0 becomes recently used
			}
		}
	CHECK(phsc_count(&cache) == PHSC_MAX_ENTRIES, "never more than %d entries (%d)", PHSC_MAX_ENTRIES, phsc_count(&cache));
	size_t l;
	unsigned char* t = phsc_take(&cache, "h23.test", 443, now, &l, NULL);
	CHECK(t != NULL, "newest entry kept");
	free(t);
	t = phsc_take(&cache, "h1.test", 443, now, &l, NULL);
	CHECK(t == NULL, "least recently used entry evicted");
	free(t);
	// the lifetime hint is honoured, capped at a day
	phsc_clear(&cache);
	phsc_put(&cache, "a.test", 443, blob, sizeof(blob), 0, now, 60);
	phsc_put(&cache, "b.test", 443, blob, sizeof(blob), 0, now, 10 * 86400);
	CHECK(phsc_take(&cache, "a.test", 443, now + 61, &l, NULL) == NULL, "ticket lifetime of 60 s honoured");
	t = phsc_take(&cache, "b.test", 443, now + 86000, &l, NULL);
	CHECK(t != NULL, "long lifetime kept within a day");
	free(t);
	CHECK(phsc_take(&cache, "b.test", 443, now + 86401, &l, NULL) == NULL, "capped at 24 h");
	CHECK(phsc_put(&cache, "c.test", 443, blob, PHSC_MAX_BLOB + 1, 0, now, 60) != 0, "oversized session refused");
	phsc_clear(&cache);
	}

static void Dump(const mbedtls_x509_name* n, char* out, size_t cap)
	{
	mbedtls_x509_dn_gets(out, cap, n);
	}

static void TestStub(const char* dir)
	{
	printf("display certificate\n");
	static const char* files[] = { "p521.crt", "server.crt" };
	for (int f = 0; f < 2; ++f)
		{
		char path[512];
		snprintf(path, sizeof(path), "%s/%s", dir, files[f]);
		mbedtls_x509_crt real;
		mbedtls_x509_crt_init(&real);
		if (mbedtls_x509_crt_parse_file(&real, path))
			{
			CHECK(0, "%s parses with mbedTLS", files[f]);
			continue;
			}
		for (int style = 0; style < 2; ++style)
			{
			unsigned char* der = NULL;
			size_t len = phstub_build(&real, style, &der);
			CHECK(len > 0 && der, "%s style %d: built (%u bytes)", files[f], style, (unsigned)len);
			mbedtls_x509_crt stub;
			mbedtls_x509_crt_init(&stub);
			int rc = len ? mbedtls_x509_crt_parse_der(&stub, der, len) : -1;
			CHECK(rc == 0, "%s style %d: parses again as X.509 (rc %d)", files[f], style, rc);
			if (rc == 0)
				{
				char a[512], b[512];
				Dump(&stub.subject, a, sizeof(a));
				Dump(&real.subject, b, sizeof(b));
				if (style == PHSTUB_FULL_NAMES)
					CHECK(strcmp(a, b) == 0, "subject kept: %s", a);
				else
					CHECK(strstr(b, a + 3) != NULL, "subject reduced to a name of the original: %s", a);
				Dump(&stub.issuer, a, sizeof(a));
				Dump(&real.issuer, b, sizeof(b));
				if (style == PHSTUB_FULL_NAMES)
					CHECK(strcmp(a, b) == 0, "issuer kept");
				CHECK(stub.valid_from.year == real.valid_from.year && stub.valid_from.mon == real.valid_from.mon
					  && stub.valid_from.day == real.valid_from.day && stub.valid_from.hour == real.valid_from.hour
					  && stub.valid_from.min == real.valid_from.min && stub.valid_from.sec == real.valid_from.sec,
					  "valid-from kept (%04d-%02d-%02d)", stub.valid_from.year, stub.valid_from.mon, stub.valid_from.day);
				CHECK(stub.valid_to.year == real.valid_to.year && stub.valid_to.mon == real.valid_to.mon
					  && stub.valid_to.day == real.valid_to.day && stub.valid_to.sec == real.valid_to.sec,
					  "valid-to kept (%04d-%02d-%02d)", stub.valid_to.year, stub.valid_to.mon, stub.valid_to.day);
				CHECK(stub.serial.len == real.serial.len && memcmp(stub.serial.p, real.serial.p, real.serial.len) == 0,
					  "serial kept");
				CHECK(mbedtls_pk_get_type(&stub.pk) == MBEDTLS_PK_RSA, "placeholder key is RSA (the platform parser knows it)");
				}
			mbedtls_x509_crt_free(&stub);
			free(der);
			}
		mbedtls_x509_crt_free(&real);
		}
	}

static void TestConf()
	{
	printf("runtime configuration\n");
	phtls_conf c;
	phtls_conf_defaults(&c);
	CHECK(c.tls13 == 1 && c.session_cache == 1 && c.session_persist == 1, "defaults: everything on");
	const char t1[] = "# comment\r\ntls13 = 0   # off\r\nsession_cache=OFF\nbogus=1\nsession_persist = maybe\n";
	phtls_conf_parse(&c, t1, sizeof(t1) - 1);
	CHECK(c.tls13 == 0 && c.session_cache == 0 && c.session_persist == 1, "tls13=0, session_cache=OFF, junk ignored");
	const char t2[] = "tls13=yes\nsession_cache = 1";
	phtls_conf_parse(&c, t2, sizeof(t2) - 1);
	CHECK(c.tls13 == 1 && c.session_cache == 1, "back on (no trailing newline)");
	phtls_conf_parse(&c, "", 0);
	phtls_conf_parse(&c, "=\n=1\n   \n#\n", 11);
	CHECK(c.tls13 == 1, "empty / malformed input is harmless");
	}

int main(int argc, char** argv)
	{
	if (argc < 2)
		{
		fprintf(stderr, "usage: hosttls <cert dir>\n");
		return 2;
		}
	setvbuf(stdout, NULL, _IONBF, 0);
	mbedtls_entropy_init(&gEntropy);
	mbedtls_ctr_drbg_init(&gDrbg);
	if (psa_crypto_init() != PSA_SUCCESS || mbedtls_ctr_drbg_seed(&gDrbg, mbedtls_entropy_func, &gEntropy, (const unsigned char*)"t", 1))
		return 2;
	int rc = SetupServer(argv[1]);
	if (rc)
		{
		fprintf(stderr, "server setup failed: %d\n", rc);
		return 2;
		}
	const uint64_t now = (uint64_t)time(NULL);
	TestResume(0, "TLS 1.2 session resumption", now);
	TestResume(1, "TLS 1.3 session resumption", now);
	TestBounds(now);
	TestStub(argv[1]);
	TestConf();
	printf(gFail ? "\n%d FAILED\n" : "\nall passed\n", gFail);
	return gFail ? 1 : 0;
	}
