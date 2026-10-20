/* Copyright The Phorepoc Authors
 * SPDX-License-Identifier: Apache-2.0 */

/* ossl_ssl.c -- a drop-in libssl.dll for Open C's OpenSSL 0.9.8g ABI, with TLS 1.2/1.3 from mbedTLS 3.6.
 *
 * Contract: the 215 frozen ordinals of the 2010 libsslu.def; the public
 * 0.9.8 structs keep their layout (the 2010 headers, <openssl/ssl.h>); libcrypto.dll stays the stock 0.9.8g, and this
 * library hands out and takes REAL 0.9.8 objects from it:
 *   - SSL_CTX->cert_store (+0x0C) is a real X509_STORE (X509_STORE_new): Qt adds its CA certificates to it and sets
 *     its verify_cb. Its X509 objects become mbedTLS trust anchors (i2d_X509 -> DER) at each handshake.
 *   - SSL_CIPHER: a static table in the 0.9.8 layout (valid at +0, name at +4, strength_bits/alg_bits at +24/+28,
 *     which Qt reads), SSL_CIPHER_description in the 0.9.8 text format ("name proto Kx= Au= Enc= Mac=").
 *   - the peer chain: the server's DER certificates through d2i_X509 into a STACK of X509 (SSL_get_peer_cert_chain),
 *     the leaf with a reference (SSL_get_peer_certificate).
 *   - records go through the caller's BIOs (BIO_read/BIO_write: Qt's memory BIOs, javassl's socket BIO, the connect
 *     BIO under BIO_f_ssl) -- they are mbedTLS's send/recv callbacks.
 *   - verification: mbedTLS verifies (OPTIONAL mode, flags per chain depth); each error goes, as an X509_V_ERR_* code,
 *     through a real X509_STORE_CTX (error, error_depth, current_cert) to the SSL's verify callback (else the store's
 *     verify_cb), and fails the handshake when verify_mode has SSL_VERIFY_PEER and the callback says so, as 0.9.8's
 *     ssl_verify_cert_chain does. The host name is NOT checked (0.9.8 never did; Qt checks it itself).
 * Our own state lives AFTER the public struct in one allocation (SSLX / CTXX): the SSL* / SSL_CTX* callers hold point
 * at the 0.9.8 struct, whose layout is untouched.
 * Every *_method() gives TLS 1.2 + 1.3 (negotiated); SSLv2/SSLv3/TLS 1.0 are never spoken. Client side only (the
 * shared mbedTLS build has no server): SSL_accept fails cleanly.
 * The ordinals this file does not implement are ossl_stubs.c (fail safely, SSL error queued).
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "pe_engine.h"

#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#define SSL_CTRL_SET_TLSEXT_HOSTNAME	55	/* (OpenSSL 0.9.8f+; the 2010 export of tls1.h uses it without defining it) */
#endif

#ifdef PHOREPOC_LIBSSL_TRACE
extern void ossl_trace(const char *fmt, ...);
#define LTRACE(...) ossl_trace(__VA_ARGS__)
#else
#define LTRACE(...) do { } while (0)
#endif

/* the layout callers read: a build-time check */
typedef char assert_cert_store_at_0x0c[(offsetof(SSL_CTX, cert_store) == 0x0C) ? 1 : -1];
typedef char assert_cipher_valid_at_0[(offsetof(SSL_CIPHER, valid) == 0) ? 1 : -1];
typedef char assert_cipher_name_at_4[(offsetof(SSL_CIPHER, name) == 4) ? 1 : -1];
typedef char assert_cipher_bits_at_24[(offsetof(SSL_CIPHER, strength_bits) == 24 && offsetof(SSL_CIPHER, alg_bits) == 28) ? 1 : -1];

/* ------------------------------------------------------------------------------------------------------------ */
/* our objects: the 0.9.8 struct first, our state after it                                                        */

typedef struct
	{
	SSL_CTX pub;
	pe_trust *trust;			/* CA files: load_verify_locations + the default bundle */
	int default_paths;			/* SSL_CTX_set_default_verify_paths called */
	int default_loaded;
	pe_cred *cred;				/* use_certificate / use_PrivateKey */
	int verify_depth;
	} CTXX;

typedef struct
	{
	SSL pub;
	pe_conn *conn;
	int started;
	int hs_done;
	int failed;
	int err_kind;				/* SSL_ERROR_* of the last operation */
	char *sni;					/* SSL_set_tlsext_host_name */
	STACK *peer;				/* STACK_OF(X509), leaf first (when it parsed) */
	int leaf_ok;
	SSL_CIPHER dyn;				/* a negotiated suite the table does not list */
	int verify_depth;
	} SSLX;

#define CX(c) ((CTXX *)(c))
#define SX(s) ((SSLX *)(s))

/* ------------------------------------------------------------------------------------------------------------ */
/* methods: one per role; which *_method() was called changes nothing else                                       */

static const SSL_METHOD m_client = { 0x0303 };
static const SSL_METHOD m_server = { 0x0303 };
static const SSL_METHOD m_both = { 0x0303 };
#define METHOD(m) ((SSL_METHOD *)&(m))

EXPORT_C SSL_METHOD *SSLv23_client_method(void) { return METHOD(m_client); }
EXPORT_C SSL_METHOD *SSLv23_server_method(void) { return METHOD(m_server); }
EXPORT_C SSL_METHOD *SSLv23_method(void) { return METHOD(m_both); }
EXPORT_C SSL_METHOD *SSLv2_client_method(void) { return METHOD(m_client); }
EXPORT_C SSL_METHOD *SSLv2_server_method(void) { return METHOD(m_server); }
EXPORT_C SSL_METHOD *SSLv2_method(void) { return METHOD(m_both); }
EXPORT_C SSL_METHOD *SSLv3_client_method(void) { return METHOD(m_client); }
EXPORT_C SSL_METHOD *SSLv3_server_method(void) { return METHOD(m_server); }
EXPORT_C SSL_METHOD *SSLv3_method(void) { return METHOD(m_both); }
EXPORT_C SSL_METHOD *TLSv1_client_method(void) { return METHOD(m_client); }
EXPORT_C SSL_METHOD *TLSv1_server_method(void) { return METHOD(m_server); }
EXPORT_C SSL_METHOD *TLSv1_method(void) { return METHOD(m_both); }

/* ------------------------------------------------------------------------------------------------------------ */
/* ciphers: what phorepoc_mbedtls_config.h enables, OpenSSL names                                                 */

typedef struct
	{
	SSL_CIPHER c;				/* first: an SSL_CIPHER* into the table is a CIPHER_ENT* */
	int iana;
	const char *proto, *kx, *au, *enc, *mac;
	} CIPHER_ENT;

#define CE(n, id, pr, kx, au, enc, mac, bits) \
	{ { 1, n, 0x03000000UL | (id), 0, 0, 0, bits, bits, 0, 0 }, id, pr, kx, au, enc, mac }

static const CIPHER_ENT k_ciphers[] =
	{
	CE("TLS_AES_128_GCM_SHA256",        0x1301, "TLSv1.3", "any",  "any",   "AESGCM(128)", "AEAD", 128),
	CE("TLS_AES_256_GCM_SHA384",        0x1302, "TLSv1.3", "any",  "any",   "AESGCM(256)", "AEAD", 256),
	CE("TLS_CHACHA20_POLY1305_SHA256",  0x1303, "TLSv1.3", "any",  "any",   "CHACHA20/POLY1305(256)", "AEAD", 256),
	CE("ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02B, "TLSv1.2", "ECDH", "ECDSA", "AESGCM(128)", "AEAD", 128),
	CE("ECDHE-RSA-AES128-GCM-SHA256",   0xC02F, "TLSv1.2", "ECDH", "RSA",   "AESGCM(128)", "AEAD", 128),
	CE("ECDHE-ECDSA-AES256-GCM-SHA384", 0xC02C, "TLSv1.2", "ECDH", "ECDSA", "AESGCM(256)", "AEAD", 256),
	CE("ECDHE-RSA-AES256-GCM-SHA384",   0xC030, "TLSv1.2", "ECDH", "RSA",   "AESGCM(256)", "AEAD", 256),
	CE("ECDHE-ECDSA-CHACHA20-POLY1305", 0xCCA9, "TLSv1.2", "ECDH", "ECDSA", "CHACHA20/POLY1305(256)", "AEAD", 256),
	CE("ECDHE-RSA-CHACHA20-POLY1305",   0xCCA8, "TLSv1.2", "ECDH", "RSA",   "CHACHA20/POLY1305(256)", "AEAD", 256),
	CE("ECDHE-ECDSA-AES128-SHA256",     0xC023, "TLSv1.2", "ECDH", "ECDSA", "AES(128)", "SHA256", 128),
	CE("ECDHE-RSA-AES128-SHA256",       0xC027, "TLSv1.2", "ECDH", "RSA",   "AES(128)", "SHA256", 128),
	CE("ECDHE-ECDSA-AES256-SHA384",     0xC024, "TLSv1.2", "ECDH", "ECDSA", "AES(256)", "SHA384", 256),
	CE("ECDHE-RSA-AES256-SHA384",       0xC028, "TLSv1.2", "ECDH", "RSA",   "AES(256)", "SHA384", 256),
	CE("ECDHE-ECDSA-AES128-SHA",        0xC009, "TLSv1.2", "ECDH", "ECDSA", "AES(128)", "SHA1", 128),
	CE("ECDHE-RSA-AES128-SHA",          0xC013, "TLSv1.2", "ECDH", "RSA",   "AES(128)", "SHA1", 128),
	CE("ECDHE-ECDSA-AES256-SHA",        0xC00A, "TLSv1.2", "ECDH", "ECDSA", "AES(256)", "SHA1", 256),
	CE("ECDHE-RSA-AES256-SHA",          0xC014, "TLSv1.2", "ECDH", "RSA",   "AES(256)", "SHA1", 256),
	CE("AES128-GCM-SHA256",             0x009C, "TLSv1.2", "RSA",  "RSA",   "AESGCM(128)", "AEAD", 128),
	CE("AES256-GCM-SHA384",             0x009D, "TLSv1.2", "RSA",  "RSA",   "AESGCM(256)", "AEAD", 256),
	CE("AES128-SHA256",                 0x003C, "TLSv1.2", "RSA",  "RSA",   "AES(128)", "SHA256", 128),
	CE("AES256-SHA256",                 0x003D, "TLSv1.2", "RSA",  "RSA",   "AES(256)", "SHA256", 256),
	CE("AES128-SHA",                    0x002F, "TLSv1.2", "RSA",  "RSA",   "AES(128)", "SHA1", 128),
	CE("AES256-SHA",                    0x0035, "TLSv1.2", "RSA",  "RSA",   "AES(256)", "SHA1", 256),
	};
#define N_CIPHERS ((int)(sizeof(k_ciphers) / sizeof(k_ciphers[0])))

static const CIPHER_ENT *cipher_ent(const SSL_CIPHER *c)
	{
	int i;
	for (i = 0; i < N_CIPHERS; i++)
		if (c == &k_ciphers[i].c)
			return &k_ciphers[i];
	return NULL;
	}

static STACK *cipher_stack(void)
	{
	int i;
	STACK *sk = sk_new_null();
	if (!sk)
		return NULL;
	for (i = 0; i < N_CIPHERS; i++)
		if (!sk_push(sk, (char *)&k_ciphers[i].c))
			{
			sk_free(sk);
			return NULL;
			}
	return sk;
	}

EXPORT_C char *SSL_CIPHER_description(SSL_CIPHER *c, char *buf, int len)
	{
	const CIPHER_ENT *e = c ? cipher_ent(c) : NULL;
	if (buf == NULL)
		{
		len = 128;
		buf = (char *)OPENSSL_malloc(len);
		if (buf == NULL)
			return "OPENSSL_malloc Error";
		}
	else if (len < 128)
		return "Buffer too small";
	if (e)
		snprintf(buf, len, "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s\n", e->c.name, e->proto, e->kx, e->au, e->enc, e->mac);
	else
		snprintf(buf, len, "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s\n", (c && c->name) ? c->name : "(NONE)",
		         "unknown", "unknown", "unknown", "unknown", "unknown");
	return buf;
	}

EXPORT_C const char *SSL_CIPHER_get_name(const SSL_CIPHER *c)
	{
	return (c && c->name) ? c->name : "(NONE)";
	}

EXPORT_C int SSL_CIPHER_get_bits(const SSL_CIPHER *c, int *alg_bits)
	{
	if (!c)
		return 0;
	if (alg_bits)
		*alg_bits = c->alg_bits;
	return c->strength_bits;
	}

EXPORT_C char *SSL_CIPHER_get_version(const SSL_CIPHER *c)
	{
	const CIPHER_ENT *e = c ? cipher_ent(c) : NULL;
	if (!c)
		return "(NONE)";
	return (char *)(e ? e->proto : "unknown");
	}

/* ------------------------------------------------------------------------------------------------------------ */
/* library init + error strings                                                                                   */

static int g_ssl_strings_loaded;
static ERR_STRING_DATA g_ssl_str_functs[] =
	{
	{ ERR_PACK(ERR_LIB_SSL, 0, 0), "SSL routines (mbedTLS)" },
	{ 0, NULL }
	};
static ERR_STRING_DATA g_ssl_str_reasons[] =
	{
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SSL_HANDSHAKE_FAILURE), "tls handshake failure" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_CERTIFICATE_VERIFY_FAILED), "certificate verify failed" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_READ_BIO_NOT_SET), "read bio not set" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_WRITE_BIO_NOT_SET), "write bio not set" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_NULL_SSL_CTX), "null ssl ctx" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_NULL_SSL_METHOD_PASSED), "null ssl method passed" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_PROTOCOL_IS_SHUTDOWN), "protocol is shutdown" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_UNSUPPORTED_SSL_VERSION), "unsupported (server side / SSLv2 / SSLv3)" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_NO_CERTIFICATE_ASSIGNED), "no certificate assigned" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_NO_PRIVATE_KEY_ASSIGNED), "no private key assigned" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_BAD_SSL_FILETYPE), "bad ssl filetype" },
	{ ERR_PACK(ERR_LIB_SSL, 0, SSL_R_X509_LIB), "x509 lib" },
	{ ERR_PACK(ERR_LIB_SSL, 0, ERR_R_DISABLED), "not implemented by the mbedTLS libssl" },
	{ 0, NULL }
	};

EXPORT_C void ERR_load_SSL_strings(void)
	{
	if (g_ssl_strings_loaded)
		return;
	g_ssl_strings_loaded = 1;
	ERR_load_strings(ERR_LIB_SSL, g_ssl_str_functs);
	ERR_load_strings(ERR_LIB_SSL, g_ssl_str_reasons);
	}

EXPORT_C void SSL_load_error_strings(void)
	{
	ERR_load_crypto_strings();
	ERR_load_SSL_strings();
	}

EXPORT_C int SSL_library_init(void)
	{
	/* 0.9.8 registered its SSL ciphers/digests with EVP here; callers may rely on EVP lookups afterwards */
	OPENSSL_add_all_algorithms_noconf();
	if (pe_global_init())
		{
		LTRACE("psa_crypto_init failed");
		return 0;
		}
	return 1;
	}

/* push an error with the mbedTLS text as its data */
static void ssl_err_mbed(int func, int reason, int mbed_err)
	{
	char buf[120];
	SSLerr(func, reason);
	if (mbed_err)
		{
		pe_error_string(mbed_err, buf, sizeof(buf));
		ERR_add_error_data(1, buf);
		}
	}

/* ------------------------------------------------------------------------------------------------------------ */
/* SSL_CTX                                                                                                        */

EXPORT_C SSL_CTX *SSL_CTX_new(SSL_METHOD *meth)
	{
	CTXX *c;
	if (meth == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);
		return NULL;
		}
	pe_global_init();
	c = (CTXX *)calloc(1, sizeof(*c));
	if (c == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	c->pub.method = meth;
	c->pub.references = 1;
	c->pub.session_cache_mode = SSL_SESS_CACHE_SERVER;
	c->pub.session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
	c->pub.session_timeout = 300;
	c->pub.verify_mode = SSL_VERIFY_NONE;
	c->pub.max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
	c->verify_depth = -1;
	c->pub.cert_store = X509_STORE_new();
	c->pub.cipher_list = cipher_stack();
	c->trust = pe_trust_new();
	c->cred = pe_cred_new();
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, c, &c->pub.ex_data);
	if (!c->pub.cert_store || !c->pub.cipher_list || !c->trust || !c->cred)
		{
		SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
		SSL_CTX_free(&c->pub);
		return NULL;
		}
	return &c->pub;
	}

EXPORT_C void SSL_CTX_free(SSL_CTX *ctx)
	{
	CTXX *c = CX(ctx);
	if (ctx == NULL)
		return;
	if (CRYPTO_add(&ctx->references, -1, CRYPTO_LOCK_SSL_CTX) > 0)
		return;
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, &ctx->ex_data);
	if (ctx->cert_store)
		X509_STORE_free(ctx->cert_store);
	if (ctx->cipher_list)
		sk_free(ctx->cipher_list);
	pe_trust_free(c->trust);
	pe_cred_free(c->cred);
	free(c);
	}

EXPORT_C long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
	{
	long l;
	if (ctx == NULL)
		return 0;
	switch (cmd)
		{
	case SSL_CTRL_OPTIONS:
		return (long)(ctx->options |= (unsigned long)larg);
	case SSL_CTRL_MODE:
		return (long)(ctx->mode |= (unsigned long)larg);
	case SSL_CTRL_GET_READ_AHEAD:
		return ctx->read_ahead;
	case SSL_CTRL_SET_READ_AHEAD:
		l = ctx->read_ahead;
		ctx->read_ahead = (int)larg;
		return l;
	case SSL_CTRL_SET_MSG_CALLBACK_ARG:
		ctx->msg_callback_arg = parg;
		return 1;
	case SSL_CTRL_GET_MAX_CERT_LIST:
		return ctx->max_cert_list;
	case SSL_CTRL_SET_MAX_CERT_LIST:
		l = ctx->max_cert_list;
		ctx->max_cert_list = larg;
		return l;
	case SSL_CTRL_SET_SESS_CACHE_SIZE:
		l = (long)ctx->session_cache_size;
		ctx->session_cache_size = (unsigned long)larg;
		return l;
	case SSL_CTRL_GET_SESS_CACHE_SIZE:
		return (long)ctx->session_cache_size;
	case SSL_CTRL_SET_SESS_CACHE_MODE:
		l = ctx->session_cache_mode;
		ctx->session_cache_mode = (int)larg;
		return l;
	case SSL_CTRL_GET_SESS_CACHE_MODE:
		return ctx->session_cache_mode;
	case SSL_CTRL_EXTRA_CHAIN_CERT:
		{
		/* 0.9.8 takes ownership of the X509: it becomes DER in our chain and is released here */
		X509 *x = (X509 *)parg;
		int n = x ? i2d_X509(x, NULL) : 0;
		unsigned char *der, *p;
		int ok = 0;
		if (n > 0 && (der = (unsigned char *)malloc(n)) != NULL)
			{
			p = der;
			i2d_X509(x, &p);
			ok = pe_cred_add_chain_der(CX(ctx)->cred, der, n) == 0;
			free(der);
			}
		if (x)
			X509_free(x);
		return ok;
		}
	default:
		return 0;				/* session statistics (no session cache), temp keys (no server) */
		}
	}

EXPORT_C int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
	{
	/* mbedTLS's own preference list (TLS 1.3 + ECDHE AEAD first) always applies; a request is accepted as long as it
	 * could name something (Qt passes back names from SSL_get_ciphers) */
	if (ctx == NULL || str == NULL || *str == 0)
		{
		SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
		return 0;
		}
	return 1;
	}

EXPORT_C int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
	{
	if (ctx == NULL)
		return 0;
	CX(ctx)->default_paths = 1;		/* the CA bundle is loaded at the first handshake that needs it */
	return 1;
	}

EXPORT_C int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath)
	{
	int ok = 1;
	if (ctx == NULL || (CAfile == NULL && CApath == NULL))
		return 0;
	if (CAfile)
		{
		int n = pe_trust_add_file(CX(ctx)->trust, CAfile);
		LTRACE("load_verify_locations file %s -> %d", CAfile, n);
		if (n < 0)
			{
			SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
			ok = 0;
			}
		}
	if (CApath)
		{
		int n = pe_trust_add_path(CX(ctx)->trust, CApath);
		LTRACE("load_verify_locations dir %s -> %d", CApath, n);
		if (n < 0)
			{
			SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
			ok = 0;
			}
		}
	return ok;
	}

EXPORT_C void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*cb)(int, X509_STORE_CTX *))
	{
	if (ctx == NULL)
		return;
	ctx->verify_mode = mode;
	ctx->default_verify_callback = cb;
	}

EXPORT_C void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
	{
	if (ctx)
		CX(ctx)->verify_depth = depth;
	}

EXPORT_C int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)
	{
	return ctx ? ctx->verify_mode : 0;
	}

EXPORT_C int SSL_CTX_get_verify_depth(const SSL_CTX *ctx)
	{
	return ctx ? CX(ctx)->verify_depth : -1;
	}

EXPORT_C int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int, X509_STORE_CTX *)
	{
	return ctx ? ctx->default_verify_callback : NULL;
	}

EXPORT_C X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)
	{
	return ctx ? ctx->cert_store : NULL;
	}

EXPORT_C void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)
	{
	if (ctx == NULL)
		return;
	if (ctx->cert_store != NULL && ctx->cert_store != store)
		X509_STORE_free(ctx->cert_store);
	ctx->cert_store = store;
	}

EXPORT_C void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode)
	{
	if (ctx)
		ctx->quiet_shutdown = mode;
	}

EXPORT_C int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx)
	{
	return ctx ? ctx->quiet_shutdown : 0;
	}

EXPORT_C long SSL_CTX_set_timeout(SSL_CTX *ctx, long t)
	{
	long l;
	if (ctx == NULL)
		return 0;
	l = ctx->session_timeout;
	ctx->session_timeout = t;
	return l;
	}

EXPORT_C long SSL_CTX_get_timeout(const SSL_CTX *ctx)
	{
	return ctx ? ctx->session_timeout : 0;
	}

EXPORT_C void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *, int, int))
	{
	if (ctx)
		ctx->info_callback = cb;	/* kept; this engine reports no state transitions */
	}

EXPORT_C void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *, int, int)
	{
	return ctx ? ctx->info_callback : NULL;
	}

EXPORT_C int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                                      CRYPTO_EX_free *free_func)
	{
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, argl, argp, new_func, dup_func, free_func);
	}

EXPORT_C int SSL_CTX_set_ex_data(SSL_CTX *ctx, int idx, void *arg)
	{
	return ctx ? CRYPTO_set_ex_data(&ctx->ex_data, idx, arg) : 0;
	}

EXPORT_C void *SSL_CTX_get_ex_data(const SSL_CTX *ctx, int idx)
	{
	return ctx ? CRYPTO_get_ex_data(&ctx->ex_data, idx) : NULL;
	}

/* ---- own certificate / key (client authentication) ---- */

static int x509_to_der(X509 *x, unsigned char **der)
	{
	int n = x ? i2d_X509(x, NULL) : 0;
	unsigned char *p;
	*der = NULL;
	if (n <= 0 || (*der = (unsigned char *)malloc(n)) == NULL)
		return 0;
	p = *der;
	return i2d_X509(x, &p);
	}

EXPORT_C int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
	{
	unsigned char *der;
	int n, ok;
	if (ctx == NULL || x == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	n = x509_to_der(x, &der);
	ok = n > 0 && pe_cred_set_cert_der(CX(ctx)->cred, der, n) == 0;
	free(der);
	if (!ok)
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, SSL_R_X509_LIB);
	return ok;
	}

EXPORT_C int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
	{
	(void)type;					/* PEM or DER: mbedTLS tells them apart */
	if (ctx == NULL || file == NULL || pe_cred_set_cert_file(CX(ctx)->cred, file))
		{
		SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_X509_LIB);
		return 0;
		}
	return 1;
	}

static int key_der_to_ctx(SSL_CTX *ctx, unsigned char *der, int n, int func)
	{
	int ok = n > 0 && pe_cred_set_key_der(CX(ctx)->cred, der, n) == 0;
	if (der)
		{
		memset(der, 0, n > 0 ? n : 0);
		free(der);
		}
	if (!ok)
		SSLerr(func, SSL_R_NO_PRIVATE_KEY_ASSIGNED);
	return ok;
	}

EXPORT_C int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
	{
	unsigned char *der = NULL, *p;
	int n;
	if (ctx == NULL || pkey == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	n = i2d_PrivateKey(pkey, NULL);
	if (n > 0 && (der = (unsigned char *)malloc(n)) != NULL)
		{
		p = der;
		n = i2d_PrivateKey(pkey, &p);
		}
	return key_der_to_ctx(ctx, der, n, SSL_F_SSL_CTX_USE_PRIVATEKEY);
	}

EXPORT_C int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
	{
	unsigned char *der = NULL, *p;
	int n;
	if (ctx == NULL || rsa == NULL)
		{
		SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	n = i2d_RSAPrivateKey(rsa, NULL);
	if (n > 0 && (der = (unsigned char *)malloc(n)) != NULL)
		{
		p = der;
		n = i2d_RSAPrivateKey(rsa, &p);
		}
	return key_der_to_ctx(ctx, der, n, SSL_F_SSL_CTX_USE_RSAPRIVATEKEY);
	}

EXPORT_C int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
	{
	(void)type;
	if (ctx == NULL || file == NULL || pe_cred_set_key_file(CX(ctx)->cred, file))
		{
		SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_NO_PRIVATE_KEY_ASSIGNED);
		return 0;
		}
	return 1;
	}

EXPORT_C int SSL_CTX_check_private_key(const SSL_CTX *ctx)
	{
	if (ctx == NULL || !pe_cred_has_cert(CX(ctx)->cred))
		{
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY, SSL_R_NO_CERTIFICATE_ASSIGNED);
		return 0;
		}
	if (!pe_cred_has_key(CX(ctx)->cred))
		{
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY, SSL_R_NO_PRIVATE_KEY_ASSIGNED);
		return 0;
		}
	if (!pe_cred_check(CX(ctx)->cred))
		{
		SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY, SSL_R_X509_LIB);
		return 0;
		}
	return 1;
	}

/* ------------------------------------------------------------------------------------------------------------ */
/* SSL                                                                                                            */

static void ssl_reset_state(SSL *s)
	{
	SSLX *x = SX(s);
	if (x->conn)
		pe_conn_free(x->conn);
	x->conn = pe_conn_new();
	x->started = x->hs_done = x->failed = 0;
	x->err_kind = SSL_ERROR_NONE;
	if (x->peer)
		sk_pop_free(x->peer, (void (*)(void *))X509_free);
	x->peer = NULL;
	x->leaf_ok = 0;
	s->verify_result = X509_V_OK;
	s->shutdown = 0;
	s->rwstate = SSL_NOTHING;
	s->state = SSL_ST_BEFORE | (s->server ? SSL_ST_ACCEPT : SSL_ST_CONNECT);
	}

EXPORT_C SSL *SSL_new(SSL_CTX *ctx)
	{
	SSLX *x;
	SSL *s;
	if (ctx == NULL)
		{
		SSLerr(SSL_F_SSL_NEW, SSL_R_NULL_SSL_CTX);
		return NULL;
		}
	x = (SSLX *)calloc(1, sizeof(*x));
	if (x == NULL)
		{
		SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
		return NULL;
		}
	s = &x->pub;
	s->method = ctx->method;
	s->version = ctx->method->version;
	/* as 0.9.8: a method that can accept makes a server until SSL_set_connect_state / SSL_connect */
	s->server = (ctx->method != METHOD(m_client)) ? 1 : 0;
	s->ctx = ctx;
	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	s->verify_mode = ctx->verify_mode;
	s->verify_callback = ctx->default_verify_callback;
	s->options = ctx->options;
	s->mode = ctx->mode;
	s->max_cert_list = ctx->max_cert_list;
	s->read_ahead = ctx->read_ahead;
	s->quiet_shutdown = ctx->quiet_shutdown;
	s->msg_callback = ctx->msg_callback;
	s->msg_callback_arg = ctx->msg_callback_arg;
	s->references = 1;
	x->verify_depth = CX(ctx)->verify_depth;
	CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);
	ssl_reset_state(s);
	if (x->conn == NULL)
		{
		SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
		SSL_free(s);
		return NULL;
		}
	return s;
	}

EXPORT_C void SSL_free(SSL *s)
	{
	SSLX *x = SX(s);
	if (s == NULL)
		return;
	if (CRYPTO_add(&s->references, -1, CRYPTO_LOCK_SSL) > 0)
		return;
	CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);
	/* the BIOs belong to the SSL (0.9.8 ssl_lib.c SSL_free) */
	if (s->rbio != NULL)
		BIO_free_all(s->rbio);
	if (s->wbio != NULL && s->wbio != s->rbio)
		BIO_free_all(s->wbio);
	if (x->conn)
		pe_conn_free(x->conn);
	if (x->peer)
		sk_pop_free(x->peer, (void (*)(void *))X509_free);
	if (s->cipher_list)
		sk_free(s->cipher_list);
	free(x->sni);
	if (s->ctx)
		SSL_CTX_free(s->ctx);
	free(x);
	}

EXPORT_C int SSL_clear(SSL *s)
	{
	if (s == NULL)
		return 0;
	ssl_reset_state(s);
	return SX(s)->conn != NULL;
	}

EXPORT_C void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
	{
	if (s == NULL)
		return;
	if (s->rbio != NULL && s->rbio != rbio)
		BIO_free_all(s->rbio);
	if (s->wbio != NULL && s->wbio != wbio && s->rbio != s->wbio)
		BIO_free_all(s->wbio);
	s->rbio = rbio;
	s->wbio = wbio;
	}

EXPORT_C BIO *SSL_get_rbio(const SSL *s)
	{
	return s ? s->rbio : NULL;
	}

EXPORT_C BIO *SSL_get_wbio(const SSL *s)
	{
	return s ? s->wbio : NULL;
	}

EXPORT_C int SSL_set_fd(SSL *s, int fd)
	{
	BIO *bio;
	if (s == NULL)
		return 0;
	bio = BIO_new(BIO_s_socket());
	if (bio == NULL)
		{
		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
		return 0;
		}
	BIO_set_fd(bio, fd, BIO_NOCLOSE);
	SSL_set_bio(s, bio, bio);
	return 1;
	}

static int bio_fd(BIO *b)
	{
	int fd = -1;
	if (b != NULL)
		BIO_ctrl(b, BIO_C_GET_FD, 0, (char *)&fd);
	return fd;
	}

EXPORT_C int SSL_get_fd(const SSL *s)
	{
	return s ? bio_fd(s->rbio) : -1;
	}

EXPORT_C int SSL_get_rfd(const SSL *s)
	{
	return s ? bio_fd(s->rbio) : -1;
	}

EXPORT_C int SSL_get_wfd(const SSL *s)
	{
	return s ? bio_fd(s->wbio) : -1;
	}

EXPORT_C void SSL_set_connect_state(SSL *s)
	{
	if (s == NULL)
		return;
	s->server = 0;
	s->shutdown = 0;
	s->state = SSL_ST_CONNECT | SSL_ST_BEFORE;
	}

EXPORT_C void SSL_set_accept_state(SSL *s)
	{
	if (s == NULL)
		return;
	s->server = 1;
	s->shutdown = 0;
	s->state = SSL_ST_ACCEPT | SSL_ST_BEFORE;
	}

EXPORT_C long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
	{
	SSLX *x = SX(s);
	long l;
	if (s == NULL)
		return 0;
	switch (cmd)
		{
	case SSL_CTRL_OPTIONS:
		return (long)(s->options |= (unsigned long)larg);
	case SSL_CTRL_MODE:
		return (long)(s->mode |= (unsigned long)larg);
	case SSL_CTRL_GET_READ_AHEAD:
		return s->read_ahead;
	case SSL_CTRL_SET_READ_AHEAD:
		l = s->read_ahead;
		s->read_ahead = (int)larg;
		return l;
	case SSL_CTRL_SET_MSG_CALLBACK_ARG:
		s->msg_callback_arg = parg;
		return 1;
	case SSL_CTRL_GET_MAX_CERT_LIST:
		return s->max_cert_list;
	case SSL_CTRL_SET_MAX_CERT_LIST:
		l = s->max_cert_list;
		s->max_cert_list = larg;
		return l;
	case SSL_CTRL_SET_TLSEXT_HOSTNAME:
		if (larg != TLSEXT_NAMETYPE_host_name)
			return 0;
		free(x->sni);
		x->sni = NULL;
		if (parg != NULL)
			{
			size_t n = strlen((const char *)parg);
			if (n == 0 || n > 255)
				{
				SSLerr(SSL_F_SSL_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME);
				return 0;
				}
			x->sni = (char *)malloc(n + 1);
			if (x->sni == NULL)
				return 0;
			memcpy(x->sni, parg, n + 1);
			}
		return 1;
	default:
		return 0;				/* session reuse / renegotiation counters / temp keys: none here */
		}
	}

/* ---- the transport: the caller's BIOs ---- */

static int io_send(void *arg, unsigned char *buf, int len)
	{
	SSL *s = (SSL *)arg;
	int n;
	if (s->wbio == NULL)
		return PE_IO_ERR;
	n = BIO_write(s->wbio, buf, len);
	if (n > 0)
		{
		BIO_ctrl(s->wbio, BIO_CTRL_FLUSH, 0, NULL);
		return n;
		}
	if (BIO_should_retry(s->wbio))
		{
		s->rwstate = SSL_WRITING;
		return PE_IO_WANT;
		}
	return PE_IO_ERR;
	}

static int io_recv(void *arg, unsigned char *buf, int len)
	{
	SSL *s = (SSL *)arg;
	int n;
	if (s->rbio == NULL)
		return PE_IO_ERR;
	n = BIO_read(s->rbio, buf, len);
	if (n > 0)
		return n;
	if (BIO_should_retry(s->rbio))
		{
		s->rwstate = SSL_READING;
		return PE_IO_WANT;
		}
	return n == 0 ? 0 : PE_IO_ERR;
	}

/* ---- trust anchors ---- */

static void ctx_load_default_paths(CTXX *c)
	{
	char path[] = "c:\\resource\\ssl\\ca-bundle.crt";
	char d;
	if (!c->default_paths || c->default_loaded)
		return;
	c->default_loaded = 1;
	/* the bundle the SSL.DLL drop-in uses (\resource\ssl\ on any drive, C: first; the ROM copy on Z:) */
	for (d = 'c'; d <= 'z'; d++)
		{
		FILE *f;
		path[0] = d;
		f = fopen(path, "rb");
		if (f == NULL)
			continue;
		fclose(f);
		LTRACE("default CA bundle %s: %d certificates", path, pe_trust_add_file(c->trust, path));
		return;
		}
	LTRACE("default CA bundle: none found");
	}

/* the X509_STORE's certificates (Qt puts the system CA certificates there) -> per-connection anchors */
static int store_to_conn(X509_STORE *st, pe_conn *conn)
	{
	int i, n = 0;
	if (st == NULL || st->objs == NULL)
		return 0;
	CRYPTO_r_lock(CRYPTO_LOCK_X509_STORE);
	for (i = 0; i < sk_num(st->objs); i++)
		{
		X509_OBJECT *o = (X509_OBJECT *)sk_value(st->objs, i);
		unsigned char *der;
		int len;
		if (o == NULL || o->type != X509_LU_X509 || o->data.x509 == NULL)
			continue;
		len = x509_to_der(o->data.x509, &der);
		if (len > 0 && pe_conn_add_ca_der(conn, der, len) == 0)
			n++;
		free(der);
		}
	CRYPTO_r_unlock(CRYPTO_LOCK_X509_STORE);
	return n;
	}

/* SNI for BIO_new_ssl_connect users: the connect BIO's host name ("host:port" -> "host") */
static void connect_bio_host(BIO *b, char *out, int outlen)
	{
	const char *h;
	int i;
	out[0] = 0;
	if (b == NULL || b->method == NULL || b->method->type != BIO_TYPE_CONNECT)
		return;
	h = (const char *)BIO_ptr_ctrl(b, BIO_C_GET_CONNECT, 0);
	if (h == NULL)
		return;
	for (i = 0; i < outlen - 1 && h[i] && h[i] != ':' && h[i] != '/'; i++)
		out[i] = h[i];
	out[i] = 0;
	}

/* ---- the peer's chain as 0.9.8 X509 objects ---- */

static void build_peer_chain(SSL *s)
	{
	SSLX *x = SX(s);
	int i, n = pe_conn_peer_count(x->conn);
	x->peer = sk_new_null();
	x->leaf_ok = 0;
	if (x->peer == NULL)
		return;
	for (i = 0; i < n; i++)
		{
		const unsigned char *der = NULL, *p;
		int len = pe_conn_peer_der(x->conn, i, &der);
		X509 *c;
		p = der;
		c = len > 0 ? d2i_X509(NULL, &p, len) : NULL;
		if (c == NULL)
			{
			LTRACE("peer certificate %d (%d bytes): d2i_X509 failed", i, len);
			continue;
			}
		sk_push(x->peer, (char *)c);
		if (i == 0)
			x->leaf_ok = 1;
		}
	}

/* ---- verification: mbedTLS's per-depth flags -> 0.9.8 X509_V_ERR_* through the verify callbacks ---- */

static int is_self_issued(X509 *c)
	{
	return c != NULL && X509_NAME_cmp(X509_get_subject_name(c), X509_get_issuer_name(c)) == 0;
	}

/* one error out of `*f` (clears what it reports); 0 = none left */
static int next_verify_error(unsigned *f, int depth, int nchain, X509 *cert)
	{
	*f &= ~(unsigned)(PE_BAD_CN_MISMATCH | PE_BAD_SKIP_VERIFY);	/* no name check in 0.9.8 */
	if (*f == 0)
		return 0;
	if (*f & PE_BAD_NOT_TRUSTED)
		{
		*f &= ~(unsigned)PE_BAD_NOT_TRUSTED;
		if (is_self_issued(cert))
			return depth == 0 ? X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT : X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
		if (depth == 0 && nchain <= 1)
			return X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
		return X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
		}
	if (*f & PE_BAD_FUTURE)
		{
		*f &= ~(unsigned)PE_BAD_FUTURE;
		return X509_V_ERR_CERT_NOT_YET_VALID;
		}
	if (*f & PE_BAD_EXPIRED)
		{
		*f &= ~(unsigned)PE_BAD_EXPIRED;
		return X509_V_ERR_CERT_HAS_EXPIRED;
		}
	if (*f & PE_BAD_REVOKED)
		{
		*f &= ~(unsigned)PE_BAD_REVOKED;
		return X509_V_ERR_CERT_REVOKED;
		}
	if (*f & (PE_BAD_KEY_USAGE | PE_BAD_EXT_KEY_USAGE | PE_BAD_NS_CERT_TYPE))
		{
		*f &= ~(unsigned)(PE_BAD_KEY_USAGE | PE_BAD_EXT_KEY_USAGE | PE_BAD_NS_CERT_TYPE);
		return X509_V_ERR_INVALID_PURPOSE;
		}
	if (*f & (PE_BAD_MD | PE_BAD_PK | PE_BAD_KEY))
		{
		*f &= ~(unsigned)(PE_BAD_MD | PE_BAD_PK | PE_BAD_KEY);
		return X509_V_ERR_CERT_SIGNATURE_FAILURE;
		}
	*f = 0;
	return X509_V_ERR_CERT_UNTRUSTED;
	}

EXPORT_C int SSL_get_ex_data_X509_STORE_CTX_idx(void)
	{
	static int idx = -1;
	if (idx < 0)
		idx = X509_STORE_CTX_get_ex_new_index(0, "SSL for verify callback", NULL, NULL, NULL);
	return idx;
	}

/* 1 = accept the peer */
static int verify_peer(SSL *s)
	{
	SSLX *x = SX(s);
	X509_STORE *store = s->ctx->cert_store;
	int (*cb)(int, X509_STORE_CTX *) = s->verify_callback;
	X509_STORE_CTX *sctx = NULL;
	int nchain = x->peer ? sk_num(x->peer) : 0;
	int depths = pe_conn_verify_depths(x->conn);
	long result = X509_V_OK;
	int accept = 1;
	int d;
	if (cb == NULL && store != NULL)
		cb = store->verify_cb;
	if (depths == 0 && pe_conn_verify_flags(x->conn) != 0)
		depths = 1;				/* no anchors at all: mbedTLS flagged the chain without walking it */
	for (d = depths - 1; d >= 0 && accept; d--)
		{
		unsigned f = pe_conn_verify_flags_at(x->conn, d);
		X509 *cert = (d < nchain && (d > 0 || x->leaf_ok)) ? (X509 *)sk_value(x->peer, d) : NULL;
		int err;
		if (depths == 1 && f == 0)
			f = pe_conn_verify_flags(x->conn);
		while ((err = next_verify_error(&f, d, nchain, cert)) != 0)
			{
			int ok = 0;
			result = err;
			LTRACE("verify: depth %d error %d (%s)", d, err, X509_verify_cert_error_string(err));
			if (cb != NULL)
				{
				if (sctx == NULL)
					{
					sctx = X509_STORE_CTX_new();
					if (sctx != NULL)
						{
						X509_STORE_CTX_init(sctx, store, x->leaf_ok ? (X509 *)sk_value(x->peer, 0) : NULL, x->peer);
						X509_STORE_CTX_set_ex_data(sctx, SSL_get_ex_data_X509_STORE_CTX_idx(), s);
						}
					}
				if (sctx != NULL)
					{
					sctx->error = err;
					sctx->error_depth = d;
					sctx->current_cert = cert;
					ok = cb(0, sctx);
					}
				}
			if (!ok && (s->verify_mode & SSL_VERIFY_PEER))
				{
				accept = 0;
				break;
				}
			}
		}
	if (sctx != NULL)
		X509_STORE_CTX_free(sctx);
	s->verify_result = result;
	return accept;
	}

/* ---- the handshake ---- */

static int set_err(SSL *s, int kind)
	{
	SX(s)->err_kind = kind;
	return kind;
	}

static int do_handshake(SSL *s)
	{
	SSLX *x = SX(s);
	int r;
	if (x->hs_done && !x->failed)
		return 1;
	if (x->failed)
		{
		set_err(s, SSL_ERROR_SSL);
		return -1;
		}
	if (!x->started)
		{
		char host[256];
		const char *sni = x->sni;
		CTXX *c = CX(s->ctx);
		int nstore;
		if (s->rbio == NULL)
			{
			SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_READ_BIO_NOT_SET);
			set_err(s, SSL_ERROR_SSL);
			return -1;
			}
		if (s->wbio == NULL)
			{
			SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_WRITE_BIO_NOT_SET);
			set_err(s, SSL_ERROR_SSL);
			return -1;
			}
		if (s->server)
			{
			/* the shared mbedTLS build is a TLS client */
			SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_UNSUPPORTED_SSL_VERSION);
			x->failed = 1;
			set_err(s, SSL_ERROR_SSL);
			return -1;
			}
		if (sni == NULL)
			{
			connect_bio_host(s->rbio, host, sizeof(host));
			if (host[0])
				sni = host;
			}
		nstore = store_to_conn(s->ctx->cert_store, x->conn);
		ctx_load_default_paths(c);
		LTRACE("connect: sni=%s anchors: store %d + files %d", sni ? sni : "(none)", nstore, pe_trust_count(c->trust));
		if (pe_conn_start(x->conn, 0, sni, c->trust, c->cred, io_send, io_recv, s))
			{
			ssl_err_mbed(SSL_F_SSL_DO_HANDSHAKE, SSL_R_SSL_HANDSHAKE_FAILURE, pe_conn_last_error(x->conn));
			x->failed = 1;
			set_err(s, SSL_ERROR_SSL);
			return -1;
			}
		x->started = 1;
		s->state = SSL_ST_CONNECT;
		}
	r = pe_conn_handshake(x->conn);
	switch (r)
		{
	case PE_OK:
		x->hs_done = 1;
		s->state = SSL_ST_OK;
		s->rwstate = SSL_NOTHING;
		build_peer_chain(s);
		if (!verify_peer(s))
			{
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_CERTIFICATE_VERIFY_FAILED);
			LTRACE("handshake done, certificate refused (verify result %d)", (int)s->verify_result);
			pe_conn_close_notify(x->conn);
			x->failed = 1;
			set_err(s, SSL_ERROR_SSL);
			return -1;
			}
		LTRACE("handshake ok: %s %s, verify result %d, peer chain %d",
		       pe_conn_version_str(x->conn), pe_conn_suite_name(x->conn), (int)s->verify_result,
		       x->peer ? sk_num(x->peer) : 0);
		set_err(s, SSL_ERROR_NONE);
		return 1;
	case PE_WANT_READ:
		s->rwstate = SSL_READING;
		set_err(s, SSL_ERROR_WANT_READ);
		return -1;
	case PE_WANT_WRITE:
		s->rwstate = SSL_WRITING;
		set_err(s, SSL_ERROR_WANT_WRITE);
		return -1;
	case PE_EOF:
	case PE_CLOSED:
	case PE_IOERR:
		LTRACE("handshake: transport %s", r == PE_IOERR ? "error" : "closed");
		x->failed = 1;
		set_err(s, SSL_ERROR_SYSCALL);
		return -1;
	default:
		{
#ifdef PHOREPOC_LIBSSL_TRACE
		char buf[120];
		pe_error_string(pe_conn_last_error(x->conn), buf, sizeof(buf));
		LTRACE("handshake failed: -0x%x %s", -pe_conn_last_error(x->conn), buf);
#endif
		ssl_err_mbed(SSL_F_SSL_DO_HANDSHAKE, SSL_R_SSL_HANDSHAKE_FAILURE, pe_conn_last_error(x->conn));
		x->failed = 1;
		set_err(s, SSL_ERROR_SSL);
		return -1;
		}
		}
	}

EXPORT_C int SSL_do_handshake(SSL *s)
	{
	return s ? do_handshake(s) : -1;
	}

EXPORT_C int SSL_connect(SSL *s)
	{
	if (s == NULL)
		return -1;
	if (!SX(s)->started)
		s->server = 0;
	return do_handshake(s);
	}

EXPORT_C int SSL_accept(SSL *s)
	{
	if (s == NULL)
		return -1;
	if (!SX(s)->started)
		s->server = 1;
	return do_handshake(s);
	}

/* a read/write result -> 0.9.8 return value + SSL_get_error kind */
static int io_result(SSL *s, int r, int func)
	{
	SSLX *x = SX(s);
	switch (r)
		{
	case PE_WANT_READ:
		s->rwstate = SSL_READING;
		set_err(s, SSL_ERROR_WANT_READ);
		return -1;
	case PE_WANT_WRITE:
		s->rwstate = SSL_WRITING;
		set_err(s, SSL_ERROR_WANT_WRITE);
		return -1;
	case PE_CLOSED:
		s->shutdown |= SSL_RECEIVED_SHUTDOWN;
		set_err(s, SSL_ERROR_ZERO_RETURN);
		return 0;
	case PE_EOF:
		set_err(s, SSL_ERROR_SYSCALL);
		return 0;
	case PE_IOERR:
		set_err(s, SSL_ERROR_SYSCALL);
		return -1;
	default:
		ssl_err_mbed(func, ERR_R_INTERNAL_ERROR, pe_conn_last_error(x->conn));
		set_err(s, SSL_ERROR_SSL);
		return -1;
		}
	}

EXPORT_C int SSL_read(SSL *s, void *buf, int num)
	{
	int r;
	if (s == NULL)
		return -1;
	if (s->shutdown & SSL_RECEIVED_SHUTDOWN)
		{
		set_err(s, SSL_ERROR_ZERO_RETURN);
		return 0;
		}
	if (!SX(s)->hs_done || SX(s)->failed)
		{
		r = do_handshake(s);
		if (r <= 0)
			return r;
		}
	if (num <= 0)
		{
		set_err(s, SSL_ERROR_NONE);
		return 0;
		}
	r = pe_conn_read(SX(s)->conn, (unsigned char *)buf, num);
	if (r > 0)
		{
		s->rwstate = SSL_NOTHING;
		set_err(s, SSL_ERROR_NONE);
		return r;
		}
	return io_result(s, r, SSL_F_SSL_READ);
	}

EXPORT_C int SSL_write(SSL *s, const void *buf, int num)
	{
	int r;
	if (s == NULL)
		return -1;
	if (s->shutdown & SSL_SENT_SHUTDOWN)
		{
		SSLerr(SSL_F_SSL_WRITE, SSL_R_PROTOCOL_IS_SHUTDOWN);
		set_err(s, SSL_ERROR_SSL);
		return -1;
		}
	if (!SX(s)->hs_done || SX(s)->failed)
		{
		r = do_handshake(s);
		if (r <= 0)
			return r;
		}
	if (num <= 0)
		{
		set_err(s, SSL_ERROR_NONE);
		return 0;
		}
	r = pe_conn_write(SX(s)->conn, (const unsigned char *)buf, num);
	if (r > 0)
		{
		s->rwstate = SSL_NOTHING;
		set_err(s, SSL_ERROR_NONE);
		return r;
		}
	return io_result(s, r, SSL_F_SSL_WRITE);
	}

EXPORT_C int SSL_pending(const SSL *s)
	{
	return (s && SX(s)->hs_done) ? pe_conn_pending(SX(s)->conn) : 0;
	}

EXPORT_C int SSL_shutdown(SSL *s)
	{
	SSLX *x = SX(s);
	if (s == NULL)
		return -1;
	if (!x->hs_done || x->failed)
		return 1;
	if (!(s->shutdown & SSL_SENT_SHUTDOWN))
		{
		if (!s->quiet_shutdown)
			{
			int r = pe_conn_close_notify(x->conn);
			if (r == PE_WANT_WRITE)
				{
				s->rwstate = SSL_WRITING;
				set_err(s, SSL_ERROR_WANT_WRITE);
				return -1;
				}
			}
		s->shutdown |= SSL_SENT_SHUTDOWN;
		}
	return (s->shutdown & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
	}

EXPORT_C int SSL_get_error(const SSL *s, int i)
	{
	int k;
	if (i > 0)
		return SSL_ERROR_NONE;
	if (s == NULL)
		return SSL_ERROR_SSL;
	k = SX(s)->err_kind;
	if (k != SSL_ERROR_NONE)
		return k;
	if (ERR_peek_error() != 0)
		return SSL_ERROR_SSL;
	return (i == 0 && (s->shutdown & SSL_RECEIVED_SHUTDOWN)) ? SSL_ERROR_ZERO_RETURN : SSL_ERROR_SYSCALL;
	}

EXPORT_C int SSL_want(const SSL *s)
	{
	return s ? s->rwstate : SSL_NOTHING;
	}

EXPORT_C int SSL_state(const SSL *s)
	{
	return s ? s->state : 0;
	}

EXPORT_C const char *SSL_state_string(const SSL *s)
	{
	return (s && SX(s)->hs_done) ? "SSLOK " : "UNKWN ";
	}

EXPORT_C const char *SSL_state_string_long(const SSL *s)
	{
	if (s == NULL)
		return "unknown state";
	if (SX(s)->failed)
		return "error";
	if (SX(s)->hs_done)
		return "SSL negotiation finished successfully";
	return SX(s)->started ? "TLS handshake in progress" : "before/connect initialization";
	}

EXPORT_C const char *SSL_rstate_string(const SSL *s)
	{
	(void)s;
	return "RD";
	}

EXPORT_C const char *SSL_rstate_string_long(const SSL *s)
	{
	(void)s;
	return "read done";
	}

EXPORT_C const char *SSL_alert_type_string(int value)
	{
	value >>= 8;
	return value == 1 ? "W" : value == 2 ? "F" : "U";
	}

EXPORT_C const char *SSL_alert_type_string_long(int value)
	{
	value >>= 8;
	return value == 1 ? "warning" : value == 2 ? "fatal" : "unknown";
	}

EXPORT_C const char *SSL_alert_desc_string(int value)
	{
	(void)value;
	return "UK";
	}

EXPORT_C const char *SSL_alert_desc_string_long(int value)
	{
	(void)value;
	return "unknown";
	}

EXPORT_C int SSL_get_shutdown(const SSL *s)
	{
	return s ? s->shutdown : 0;
	}

EXPORT_C void SSL_set_shutdown(SSL *s, int mode)
	{
	if (s)
		s->shutdown = mode;
	}

EXPORT_C void SSL_set_quiet_shutdown(SSL *s, int mode)
	{
	if (s)
		s->quiet_shutdown = mode;
	}

EXPORT_C int SSL_get_quiet_shutdown(const SSL *s)
	{
	return s ? s->quiet_shutdown : 0;
	}

EXPORT_C int SSL_version(const SSL *s)
	{
	int v = s ? pe_conn_version(SX(s)->conn) : 0;
	return v ? v : (s ? s->version : 0);
	}

EXPORT_C const char *SSL_get_version(const SSL *s)
	{
	return (s && SX(s)->hs_done) ? pe_conn_version_str(SX(s)->conn) : "unknown";
	}

EXPORT_C SSL_METHOD *SSL_get_ssl_method(SSL *s)
	{
	return s ? s->method : NULL;
	}

EXPORT_C SSL_CTX *SSL_get_SSL_CTX(const SSL *s)
	{
	return s ? s->ctx : NULL;
	}

EXPORT_C SSL_CTX *SSL_set_SSL_CTX(SSL *s, SSL_CTX *ctx)
	{
	if (s == NULL)
		return NULL;
	if (ctx == NULL || ctx == s->ctx)
		return s->ctx;
	if (SX(s)->started)
		return s->ctx;			/* the connection is configured already */
	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
	SSL_CTX_free(s->ctx);
	s->ctx = ctx;
	return ctx;
	}

EXPORT_C STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s)
	{
	if (s == NULL)
		return NULL;
	if (s->cipher_list)
		return s->cipher_list;
	return s->ctx ? s->ctx->cipher_list : NULL;
	}

EXPORT_C SSL_CIPHER *SSL_get_current_cipher(const SSL *s)
	{
	SSLX *x = SX(s);
	int i, id;
	if (s == NULL || !x->hs_done)
		return NULL;
	id = pe_conn_suite(x->conn);
	for (i = 0; i < N_CIPHERS; i++)
		if (k_ciphers[i].iana == id)
			return (SSL_CIPHER *)&k_ciphers[i].c;
	x->dyn.valid = 1;
	x->dyn.name = pe_conn_suite_name(x->conn);
	x->dyn.id = 0x03000000UL | (unsigned long)id;
	return &x->dyn;
	}

EXPORT_C X509 *SSL_get_peer_certificate(const SSL *s)
	{
	X509 *c;
	if (s == NULL || !SX(s)->leaf_ok || SX(s)->peer == NULL)
		return NULL;
	c = (X509 *)sk_value(SX(s)->peer, 0);
	if (c)
		CRYPTO_add(&c->references, 1, CRYPTO_LOCK_X509);
	return c;
	}

EXPORT_C STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)
	{
	return s ? SX(s)->peer : NULL;
	}

EXPORT_C long SSL_get_verify_result(const SSL *s)
	{
	return s ? s->verify_result : X509_V_ERR_APPLICATION_VERIFICATION;
	}

EXPORT_C void SSL_set_verify_result(SSL *s, long v)
	{
	if (s)
		s->verify_result = v;
	}

EXPORT_C void SSL_set_verify(SSL *s, int mode, int (*cb)(int, X509_STORE_CTX *))
	{
	if (s == NULL)
		return;
	s->verify_mode = mode;
	if (cb != NULL)
		s->verify_callback = cb;
	}

EXPORT_C void SSL_set_verify_depth(SSL *s, int depth)
	{
	if (s)
		SX(s)->verify_depth = depth;
	}

EXPORT_C int SSL_get_verify_mode(const SSL *s)
	{
	return s ? s->verify_mode : 0;
	}

EXPORT_C int SSL_get_verify_depth(const SSL *s)
	{
	return s ? SX(s)->verify_depth : -1;
	}

EXPORT_C int (*SSL_get_verify_callback(const SSL *s))(int, X509_STORE_CTX *)
	{
	return s ? s->verify_callback : NULL;
	}

EXPORT_C void SSL_set_info_callback(SSL *s, void (*cb)(const SSL *, int, int))
	{
	if (s)
		s->info_callback = cb;
	}

EXPORT_C void (*SSL_get_info_callback(const SSL *s))(const SSL *, int, int)
	{
	return s ? s->info_callback : NULL;
	}

EXPORT_C long SSL_get_default_timeout(const SSL *s)
	{
	(void)s;
	return 300;
	}

EXPORT_C int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                                  CRYPTO_EX_free *free_func)
	{
	return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp, new_func, dup_func, free_func);
	}

EXPORT_C int SSL_set_ex_data(SSL *s, int idx, void *arg)
	{
	return s ? CRYPTO_set_ex_data(&s->ex_data, idx, arg) : 0;
	}

EXPORT_C void *SSL_get_ex_data(const SSL *s, int idx)
	{
	return s ? CRYPTO_get_ex_data(&s->ex_data, idx) : NULL;
	}

/* ------------------------------------------------------------------------------------------------------------ */
/* BIO_f_ssl: an SSL as a filter BIO (the logic of 0.9.8 bio_ssl.c, without renegotiation)                        */

typedef struct
	{
	SSL *ssl;
	} BIO_SSL;

static int bssl_write(BIO *b, const char *out, int outl);
static int bssl_read(BIO *b, char *out, int outl);
static int bssl_puts(BIO *b, const char *str);
static long bssl_ctrl(BIO *b, int cmd, long num, void *ptr);
static int bssl_new(BIO *b);
static int bssl_free(BIO *b);
static long bssl_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp);

static const BIO_METHOD k_bio_ssl =
	{
	BIO_TYPE_SSL, "ssl",
	bssl_write,
	bssl_read,
	bssl_puts,
	NULL,
	bssl_ctrl,
	bssl_new,
	bssl_free,
	bssl_callback_ctrl,
	};

EXPORT_C BIO_METHOD *BIO_f_ssl(void)
	{
	return (BIO_METHOD *)&k_bio_ssl;
	}

static int bssl_new(BIO *b)
	{
	BIO_SSL *bs = (BIO_SSL *)calloc(1, sizeof(*bs));
	if (bs == NULL)
		return 0;
	b->init = 0;
	b->ptr = (char *)bs;
	b->flags = 0;
	return 1;
	}

static int bssl_free(BIO *b)
	{
	BIO_SSL *bs;
	if (b == NULL)
		return 0;
	bs = (BIO_SSL *)b->ptr;
	if (bs != NULL && bs->ssl != NULL)
		SSL_shutdown(bs->ssl);
	if (b->shutdown)
		{
		if (b->init && bs != NULL && bs->ssl != NULL)
			SSL_free(bs->ssl);
		b->init = 0;
		b->flags = 0;
		}
	free(bs);
	b->ptr = NULL;
	return 1;
	}

static void bssl_retry(BIO *b, SSL *ssl, int ret)
	{
	switch (SSL_get_error(ssl, ret))
		{
	case SSL_ERROR_WANT_READ:
		BIO_set_retry_read(b);
		break;
	case SSL_ERROR_WANT_WRITE:
		BIO_set_retry_write(b);
		break;
	default:
		break;
		}
	}

static int bssl_read(BIO *b, char *out, int outl)
	{
	SSL *ssl;
	int ret;
	if (out == NULL)
		return 0;
	ssl = ((BIO_SSL *)b->ptr)->ssl;
	BIO_clear_retry_flags(b);
	ret = SSL_read(ssl, out, outl);
	bssl_retry(b, ssl, ret);
	b->retry_reason = 0;
	return ret;
	}

static int bssl_write(BIO *b, const char *out, int outl)
	{
	SSL *ssl;
	int ret;
	if (out == NULL)
		return 0;
	ssl = ((BIO_SSL *)b->ptr)->ssl;
	BIO_clear_retry_flags(b);
	ret = SSL_write(ssl, out, outl);
	bssl_retry(b, ssl, ret);
	b->retry_reason = 0;
	return ret;
	}

static int bssl_puts(BIO *b, const char *str)
	{
	return bssl_write(b, str, (int)strlen(str));
	}

static long bssl_ctrl(BIO *b, int cmd, long num, void *ptr)
	{
	BIO_SSL *bs = (BIO_SSL *)b->ptr;
	SSL *ssl = bs->ssl;
	BIO *bio;
	long ret = 1;
	if (ssl == NULL && cmd != BIO_C_SET_SSL)
		return 0;
	switch (cmd)
		{
	case BIO_CTRL_RESET:
		SSL_shutdown(ssl);
		SSL_clear(ssl);
		if (b->next_bio != NULL)
			ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
		else if (ssl->rbio != NULL)
			ret = BIO_ctrl(ssl->rbio, cmd, num, ptr);
		break;
	case BIO_CTRL_INFO:
		ret = 0;
		break;
	case BIO_C_SSL_MODE:
		if (num)
			SSL_set_connect_state(ssl);
		else
			SSL_set_accept_state(ssl);
		break;
	case BIO_C_SET_SSL:
		if (ssl != NULL)
			bssl_free(b), bssl_new(b), bs = (BIO_SSL *)b->ptr;
		b->shutdown = (int)num;
		ssl = (SSL *)ptr;
		bs->ssl = ssl;
		bio = SSL_get_rbio(ssl);
		if (bio != NULL)
			{
			if (b->next_bio != NULL)
				BIO_push(bio, b->next_bio);
			b->next_bio = bio;
			CRYPTO_add(&bio->references, 1, CRYPTO_LOCK_BIO);
			}
		b->init = 1;
		break;
	case BIO_C_GET_SSL:
		if (ptr != NULL)
			*(SSL **)ptr = ssl;
		else
			ret = 0;
		break;
	case BIO_CTRL_GET_CLOSE:
		ret = b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown = (int)num;
		break;
	case BIO_CTRL_WPENDING:
		ret = ssl->wbio ? BIO_ctrl(ssl->wbio, cmd, num, ptr) : 0;
		break;
	case BIO_CTRL_PENDING:
		ret = SSL_pending(ssl);
		if (ret == 0 && ssl->rbio)
			ret = BIO_ctrl(ssl->rbio, BIO_CTRL_PENDING, 0, NULL);
		break;
	case BIO_CTRL_FLUSH:
		BIO_clear_retry_flags(b);
		ret = ssl->wbio ? BIO_ctrl(ssl->wbio, cmd, num, ptr) : 1;
		BIO_copy_next_retry(b);
		break;
	case BIO_CTRL_PUSH:
		if (b->next_bio != NULL && b->next_bio != ssl->rbio)
			{
			SSL_set_bio(ssl, b->next_bio, b->next_bio);
			CRYPTO_add(&b->next_bio->references, 1, CRYPTO_LOCK_BIO);
			}
		break;
	case BIO_CTRL_POP:
		if (ssl->rbio != ssl->wbio)
			BIO_free_all(ssl->wbio);
		if (b->next_bio != NULL)
			CRYPTO_add(&b->next_bio->references, 1, CRYPTO_LOCK_BIO);
		ssl->wbio = NULL;
		ssl->rbio = NULL;
		break;
	case BIO_C_DO_STATE_MACHINE:
		BIO_clear_retry_flags(b);
		b->retry_reason = 0;
		ret = (long)SSL_do_handshake(ssl);
		switch (SSL_get_error(ssl, (int)ret))
			{
		case SSL_ERROR_WANT_READ:
			BIO_set_flags(b, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
			break;
		case SSL_ERROR_WANT_WRITE:
			BIO_set_flags(b, BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY);
			break;
		default:
			break;
			}
		break;
	case BIO_CTRL_DUP:
		ret = 0;				/* no SSL_dup */
		break;
	case BIO_C_GET_FD:
		ret = ssl->rbio ? BIO_ctrl(ssl->rbio, cmd, num, ptr) : -1;
		break;
	case BIO_CTRL_SET_CALLBACK:
		ret = 0;
		break;
	case BIO_CTRL_GET_CALLBACK:
		*(void (**)(const SSL *, int, int))ptr = SSL_get_info_callback(ssl);
		break;
	default:
		ret = ssl->rbio ? BIO_ctrl(ssl->rbio, cmd, num, ptr) : 0;
		break;
		}
	return ret;
	}

static long bssl_callback_ctrl(BIO *b, int cmd, bio_info_cb *fp)
	{
	SSL *ssl = ((BIO_SSL *)b->ptr)->ssl;
	(void)fp;
	if (ssl == NULL)
		return 0;
	if (cmd == BIO_CTRL_SET_CALLBACK)
		return 0;				/* (0.9.8 routed it to SSL_set_info_callback; nothing is reported here) */
	return ssl->rbio ? BIO_callback_ctrl(ssl->rbio, cmd, fp) : 0;
	}

EXPORT_C BIO *BIO_new_ssl(SSL_CTX *ctx, int client)
	{
	BIO *ret;
	SSL *ssl;
	if ((ret = BIO_new(BIO_f_ssl())) == NULL)
		return NULL;
	if ((ssl = SSL_new(ctx)) == NULL)
		{
		BIO_free(ret);
		return NULL;
		}
	if (client)
		SSL_set_connect_state(ssl);
	else
		SSL_set_accept_state(ssl);
	BIO_set_ssl(ret, ssl, BIO_CLOSE);
	return ret;
	}

EXPORT_C BIO *BIO_new_ssl_connect(SSL_CTX *ctx)
	{
	BIO *con, *ssl, *ret;
	if ((con = BIO_new(BIO_s_connect())) == NULL)
		return NULL;
	if ((ssl = BIO_new_ssl(ctx, 1)) == NULL)
		{
		BIO_free(con);
		return NULL;
		}
	if ((ret = BIO_push(ssl, con)) == NULL)
		{
		BIO_free(ssl);
		BIO_free(con);
		return NULL;
		}
	return ret;
	}

EXPORT_C BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx)
	{
	BIO *buf, *ssl, *ret;
	if ((buf = BIO_new(BIO_f_buffer())) == NULL)
		return NULL;
	if ((ssl = BIO_new_ssl_connect(ctx)) == NULL)
		{
		BIO_free(buf);
		return NULL;
		}
	if ((ret = BIO_push(buf, ssl)) == NULL)
		{
		BIO_free_all(ssl);
		BIO_free(buf);
		return NULL;
		}
	return ret;
	}

EXPORT_C void BIO_ssl_shutdown(BIO *b)
	{
	for (; b != NULL; b = b->next_bio)
		if (b->method != NULL && b->method->type == BIO_TYPE_SSL)
			{
			SSL_shutdown(((BIO_SSL *)b->ptr)->ssl);
			break;
			}
	}
