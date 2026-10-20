/* Copyright The Phorepoc Authors
 * SPDX-License-Identifier: Apache-2.0 */

/* pe_engine.c -- the mbedTLS 3.6 engine under the libssl.dll drop-in (see pe_engine.h).
 *
 * One pe_conn = one mbedtls_ssl_context + its own mbedtls_ssl_config (so each SSL's SNI, trust anchors and client
 * credentials stay independent, as they are per SSL in OpenSSL). Randomness: PSA (psa_generate_random via
 * mbedtls_psa_get_random) -- TLS 1.3 needs psa_crypto_init() anyway, and PSA's DRBG is seeded from
 * mbedtls_hardware_poll (tools/phorepoc-x86/mbedtls/entropy_symbian.cpp = euser's Math::Random).
 *
 * Verification runs in MBEDTLS_SSL_VERIFY_OPTIONAL mode: mbedTLS always finishes the handshake and records every
 * certificate's flags per chain depth (pe_vrfy); the OpenSSL side then decides, as 0.9.8 does, from verify_mode and
 * the application's verify callback (ossl_ssl.c ssl_verify_peer).
 */
#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "phorepoc_mbedtls_config.h"	/* the one TLS configuration (the prebuilt x32 archive's) */
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/psa_util.h"
#include "psa/crypto.h"

#include "pe_engine.h"

struct pe_trust
	{
	mbedtls_x509_crt crt;
	int n;
	};

struct pe_cred
	{
	mbedtls_x509_crt crt;
	mbedtls_pk_context pk;
	int ncrt;
	int haskey;
	};

struct pe_conn
	{
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;		/* per-connection anchors; its tail is linked to the shared list while in use */
	int nca;
	mbedtls_x509_crt *ca_tail;	/* != NULL while ca's tail points into a pe_trust */
	int started;
	pe_io_fn send;
	pe_io_fn recv;
	void *io_arg;
	int io_failed;
	int last_err;
	unsigned vflags[PE_MAX_DEPTH];
	int vdepths;
	};

static int g_psa_ready;

int pe_global_init(void)
	{
	if (!g_psa_ready)
		{
		if (psa_crypto_init() != PSA_SUCCESS)
			return -1;
		g_psa_ready = 1;
		}
	return 0;
	}

static int crt_count(const mbedtls_x509_crt *c)
	{
	int n = 0;
	for (; c != NULL && c->raw.p != NULL; c = c->next)
		n++;
	return n;
	}

/* ---- trust anchors from files ---- */

pe_trust *pe_trust_new(void)
	{
	pe_trust *t = (pe_trust *)calloc(1, sizeof(*t));
	if (t)
		mbedtls_x509_crt_init(&t->crt);
	return t;
	}

void pe_trust_free(pe_trust *t)
	{
	if (!t)
		return;
	mbedtls_x509_crt_free(&t->crt);
	free(t);
	}

int pe_trust_add_file(pe_trust *t, const char *path)
	{
	int before, rc;
	if (!t || !path || pe_global_init())
		return -1;
	before = crt_count(&t->crt);
	rc = mbedtls_x509_crt_parse_file(&t->crt, path);	/* > 0 = that many could not be parsed (skipped) */
	t->n = crt_count(&t->crt);
	if (rc < 0 && t->n == before)
		return -1;
	return t->n - before;
	}

int pe_trust_add_path(pe_trust *t, const char *dir)
	{
	int before, rc;
	if (!t || !dir || pe_global_init())
		return -1;
	before = crt_count(&t->crt);
	rc = mbedtls_x509_crt_parse_path(&t->crt, dir);
	t->n = crt_count(&t->crt);
	if (rc < 0 && t->n == before)
		return -1;
	return t->n - before;
	}

int pe_trust_count(const pe_trust *t)
	{
	return t ? t->n : 0;
	}

/* ---- own credentials ---- */

pe_cred *pe_cred_new(void)
	{
	pe_cred *c = (pe_cred *)calloc(1, sizeof(*c));
	if (c)
		{
		mbedtls_x509_crt_init(&c->crt);
		mbedtls_pk_init(&c->pk);
		}
	return c;
	}

void pe_cred_free(pe_cred *c)
	{
	if (!c)
		return;
	mbedtls_x509_crt_free(&c->crt);
	mbedtls_pk_free(&c->pk);
	free(c);
	}

int pe_cred_set_cert_der(pe_cred *c, const unsigned char *der, int len)
	{
	if (!c || !der || len <= 0 || pe_global_init())
		return -1;
	mbedtls_x509_crt_free(&c->crt);
	mbedtls_x509_crt_init(&c->crt);
	c->ncrt = 0;
	if (mbedtls_x509_crt_parse_der(&c->crt, der, (size_t)len))
		return -1;
	c->ncrt = crt_count(&c->crt);
	return 0;
	}

int pe_cred_add_chain_der(pe_cred *c, const unsigned char *der, int len)
	{
	if (!c || !der || len <= 0 || pe_global_init())
		return -1;
	if (mbedtls_x509_crt_parse_der(&c->crt, der, (size_t)len))
		return -1;
	c->ncrt = crt_count(&c->crt);
	return 0;
	}

int pe_cred_set_cert_file(pe_cred *c, const char *path)
	{
	if (!c || !path || pe_global_init())
		return -1;
	mbedtls_x509_crt_free(&c->crt);
	mbedtls_x509_crt_init(&c->crt);
	c->ncrt = 0;
	if (mbedtls_x509_crt_parse_file(&c->crt, path) < 0)
		return -1;
	c->ncrt = crt_count(&c->crt);
	return c->ncrt > 0 ? 0 : -1;
	}

int pe_cred_set_key_der(pe_cred *c, const unsigned char *der, int len)
	{
	if (!c || !der || len <= 0 || pe_global_init())
		return -1;
	mbedtls_pk_free(&c->pk);
	mbedtls_pk_init(&c->pk);
	c->haskey = 0;
	if (mbedtls_pk_parse_key(&c->pk, der, (size_t)len, NULL, 0, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE))
		return -1;
	c->haskey = 1;
	return 0;
	}

int pe_cred_set_key_file(pe_cred *c, const char *path)
	{
	if (!c || !path || pe_global_init())
		return -1;
	mbedtls_pk_free(&c->pk);
	mbedtls_pk_init(&c->pk);
	c->haskey = 0;
	if (mbedtls_pk_parse_keyfile(&c->pk, path, NULL, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE))
		return -1;
	c->haskey = 1;
	return 0;
	}

int pe_cred_has_cert(const pe_cred *c)
	{
	return c && c->ncrt > 0;
	}

int pe_cred_has_key(const pe_cred *c)
	{
	return c && c->haskey;
	}

int pe_cred_check(pe_cred *c)
	{
	if (!pe_cred_has_cert(c) || !pe_cred_has_key(c))
		return 0;
	return mbedtls_pk_check_pair(&c->crt.pk, &c->pk, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE) == 0;
	}

/* ---- connections ---- */

pe_conn *pe_conn_new(void)
	{
	pe_conn *p = (pe_conn *)calloc(1, sizeof(*p));
	if (!p)
		return NULL;
	mbedtls_ssl_init(&p->ssl);
	mbedtls_ssl_config_init(&p->conf);
	mbedtls_x509_crt_init(&p->ca);
	return p;
	}

void pe_conn_free(pe_conn *p)
	{
	if (!p)
		return;
	mbedtls_ssl_free(&p->ssl);
	mbedtls_ssl_config_free(&p->conf);
	if (p->ca_tail)
		p->ca_tail->next = NULL;		/* the shared list belongs to the SSL_CTX */
	mbedtls_x509_crt_free(&p->ca);
	free(p);
	}

int pe_conn_add_ca_der(pe_conn *p, const unsigned char *der, int len)
	{
	if (!p || p->started || !der || len <= 0 || pe_global_init())
		return -1;
	if (mbedtls_x509_crt_parse_der(&p->ca, der, (size_t)len))
		return -1;						/* (e.g. an algorithm this build leaves out): skipped */
	p->nca++;
	return 0;
	}

static int pe_send(void *ctx, const unsigned char *buf, size_t len)
	{
	pe_conn *p = (pe_conn *)ctx;
	int n = p->send(p->io_arg, (unsigned char *)buf, len > 0x40000000 ? 0x40000000 : (int)len);
	if (n > 0)
		return n;
	if (n == PE_IO_WANT)
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	p->io_failed = 1;
	return MBEDTLS_ERR_NET_SEND_FAILED;
	}

static int pe_recv(void *ctx, unsigned char *buf, size_t len)
	{
	pe_conn *p = (pe_conn *)ctx;
	int n = p->recv(p->io_arg, buf, len > 0x40000000 ? 0x40000000 : (int)len);
	if (n >= 0)
		return n;						/* 0 = EOF */
	if (n == PE_IO_WANT)
		return MBEDTLS_ERR_SSL_WANT_READ;
	p->io_failed = 1;
	return MBEDTLS_ERR_NET_RECV_FAILED;
	}

/* every certificate of the chain, root first: record its flags by depth, keep going (OPTIONAL mode) */
static int pe_vrfy(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
	{
	pe_conn *p = (pe_conn *)ctx;
	(void)crt;
	if (depth >= 0 && depth < PE_MAX_DEPTH)
		{
		p->vflags[depth] |= *flags;
		if (depth + 1 > p->vdepths)
			p->vdepths = depth + 1;
		}
	return 0;
	}

int pe_conn_start(pe_conn *p, int server, const char *hostname, pe_trust *shared, pe_cred *cred,
                  pe_io_fn send, pe_io_fn recv, void *io_arg)
	{
	mbedtls_x509_crt *chain = NULL;
	int rc;
	if (!p || p->started || !send || !recv)
		return -1;
	if (pe_global_init())
		{
		p->last_err = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
		return -1;
		}
	if (server)
		{
		/* the shared mbedTLS build is client-only (phorepoc_mbedtls_config.h has no MBEDTLS_SSL_SRV_C) */
		p->last_err = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
		return -1;
		}
	p->send = send;
	p->recv = recv;
	p->io_arg = io_arg;
	rc = mbedtls_ssl_config_defaults(&p->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
	                                 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc)
		{
		p->last_err = rc;
		return -1;
		}
	mbedtls_ssl_conf_min_tls_version(&p->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
	mbedtls_ssl_conf_max_tls_version(&p->conf, MBEDTLS_SSL_VERSION_TLS1_3);
#else
	mbedtls_ssl_conf_max_tls_version(&p->conf, MBEDTLS_SSL_VERSION_TLS1_2);
#endif
	mbedtls_ssl_conf_rng(&p->conf, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE);
	mbedtls_ssl_conf_authmode(&p->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_verify(&p->conf, pe_vrfy, p);

	/* anchors: the X509_STORE's certificates, then the SSL_CTX's files (one list: link our tail to the shared head) */
	if (p->nca > 0)
		{
		mbedtls_x509_crt *t = &p->ca;
		while (t->next)
			t = t->next;
		if (shared && shared->n > 0)
			{
			t->next = &shared->crt;
			p->ca_tail = t;
			}
		chain = &p->ca;
		}
	else if (shared && shared->n > 0)
		chain = &shared->crt;
	mbedtls_ssl_conf_ca_chain(&p->conf, chain, NULL);

	if (pe_cred_has_cert(cred) && pe_cred_has_key(cred))
		{
		rc = mbedtls_ssl_conf_own_cert(&p->conf, &cred->crt, &cred->pk);
		if (rc)
			{
			p->last_err = rc;
			return -1;
			}
		}
	rc = mbedtls_ssl_setup(&p->ssl, &p->conf);
	if (rc)
		{
		p->last_err = rc;
		return -1;
		}
	/* NULL = no SNI and no name check -- OpenSSL 0.9.8 never checked the name; its callers (Qt) do it themselves */
	rc = mbedtls_ssl_set_hostname(&p->ssl, (hostname && *hostname) ? hostname : NULL);
	if (rc)
		{
		p->last_err = rc;
		return -1;
		}
	mbedtls_ssl_set_bio(&p->ssl, p, pe_send, pe_recv, NULL);
	p->started = 1;
	return 0;
	}

static int pe_map(pe_conn *p, int rc)
	{
	switch (rc)
		{
	case MBEDTLS_ERR_SSL_WANT_READ:
		return PE_WANT_READ;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return PE_WANT_WRITE;
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		return PE_CLOSED;
	case MBEDTLS_ERR_SSL_CONN_EOF:
		return PE_EOF;
	default:
		break;
		}
	p->last_err = rc;
	if (p->io_failed)
		return PE_IOERR;
	return PE_FAIL;
	}

int pe_conn_handshake(pe_conn *p)
	{
	int rc;
	if (!p || !p->started)
		return PE_FAIL;
	p->io_failed = 0;
	rc = mbedtls_ssl_handshake(&p->ssl);
	if (rc == 0)
		return PE_OK;
	return pe_map(p, rc);
	}

int pe_conn_read(pe_conn *p, unsigned char *buf, int len)
	{
	int rc;
	if (!p || !p->started || len < 0)
		return PE_FAIL;
	p->io_failed = 0;
	for (;;)
		{
		rc = mbedtls_ssl_read(&p->ssl, buf, (size_t)len);
		if (rc == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
			continue;					/* TLS 1.3 post-handshake message: not data */
		break;
		}
	if (rc > 0)
		return rc;
	if (rc == 0)
		return len == 0 ? 0 : PE_EOF;	/* the transport closed without close_notify */
	return pe_map(p, rc);
	}

int pe_conn_write(pe_conn *p, const unsigned char *buf, int len)
	{
	int done = 0;
	if (!p || !p->started || len < 0)
		return PE_FAIL;
	p->io_failed = 0;
	while (done < len)
		{
		int rc = mbedtls_ssl_write(&p->ssl, buf + done, (size_t)(len - done));
		if (rc > 0)
			{
			done += rc;
			continue;
			}
		if (done > 0 && (rc == MBEDTLS_ERR_SSL_WANT_WRITE || rc == MBEDTLS_ERR_SSL_WANT_READ))
			break;						/* partial: report what went */
		return pe_map(p, rc);
		}
	return done;
	}

int pe_conn_close_notify(pe_conn *p)
	{
	int rc;
	if (!p || !p->started)
		return PE_OK;
	rc = mbedtls_ssl_close_notify(&p->ssl);
	return rc == 0 ? PE_OK : pe_map(p, rc);
	}

int pe_conn_pending(pe_conn *p)
	{
	return (p && p->started) ? (int)mbedtls_ssl_get_bytes_avail(&p->ssl) : 0;
	}

int pe_conn_version(pe_conn *p)
	{
	if (!p || !p->started || !mbedtls_ssl_is_handshake_over(&p->ssl))
		return 0;
	return (int)mbedtls_ssl_get_version_number(&p->ssl);
	}

const char *pe_conn_version_str(pe_conn *p)
	{
	switch (pe_conn_version(p))
		{
	case 0x0303:
		return "TLSv1.2";
	case 0x0304:
		return "TLSv1.3";
	default:
		return "unknown";
		}
	}

int pe_conn_suite(pe_conn *p)
	{
	if (!pe_conn_version(p))
		return 0;
	return mbedtls_ssl_get_ciphersuite_id_from_ssl(&p->ssl);
	}

const char *pe_conn_suite_name(pe_conn *p)
	{
	const char *n = pe_conn_version(p) ? mbedtls_ssl_get_ciphersuite(&p->ssl) : NULL;
	return n ? n : "(NONE)";
	}

int pe_conn_peer_count(pe_conn *p)
	{
	if (!p || !p->started)
		return 0;
	return crt_count(mbedtls_ssl_get_peer_cert(&p->ssl));
	}

int pe_conn_peer_der(pe_conn *p, int idx, const unsigned char **der)
	{
	const mbedtls_x509_crt *c;
	if (!p || !p->started || !der)
		return 0;
	for (c = mbedtls_ssl_get_peer_cert(&p->ssl); c != NULL && c->raw.p != NULL; c = c->next, idx--)
		if (idx == 0)
			{
			*der = c->raw.p;
			return (int)c->raw.len;
			}
	return 0;
	}

int pe_conn_verify_depths(pe_conn *p)
	{
	return p ? p->vdepths : 0;
	}

unsigned pe_conn_verify_flags_at(pe_conn *p, int depth)
	{
	if (!p || depth < 0 || depth >= PE_MAX_DEPTH)
		return 0;
	return p->vflags[depth];
	}

unsigned pe_conn_verify_flags(pe_conn *p)
	{
	if (!p || !p->started)
		return 0;
	return (unsigned)mbedtls_ssl_get_verify_result(&p->ssl);
	}

int pe_conn_last_error(pe_conn *p)
	{
	return p ? p->last_err : 0;
	}

void pe_error_string(int err, char *buf, int len)
	{
	if (!buf || len <= 0)
		return;
	mbedtls_strerror(err, buf, (size_t)len);
	}
