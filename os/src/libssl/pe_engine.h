/* Copyright The Phorepoc Authors
 * SPDX-License-Identifier: Apache-2.0 */

/* pe_engine.h -- the mbedTLS side of the libssl.dll drop-in, behind a plain C interface.
 *
 * The OpenSSL 0.9.8 side (ossl_ssl.c) never includes an mbedTLS header and this side never includes an OpenSSL one:
 * the two APIs share names ("ssl.h", "x509.h", SSL_* macros), so they meet only here. Types are opaque.
 */
#ifndef PE_ENGINE_H
#define PE_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pe_trust pe_trust;	/* trust anchors from files (a CA bundle), parsed once per SSL_CTX */
typedef struct pe_cred pe_cred;		/* our own certificate chain + private key (client authentication) */
typedef struct pe_conn pe_conn;		/* one TLS connection */

/* transport callbacks (the caller's 0.9.8 BIOs): > 0 = bytes moved; 0 = EOF (recv only) */
#define PE_IO_ERR	(-1)
#define PE_IO_WANT	(-2)		/* non-blocking BIO: retry later */
typedef int (*pe_io_fn)(void *arg, unsigned char *buf, int len);

/* results of handshake / read / write (> 0 = bytes for read/write, PE_OK = handshake done) */
#define PE_OK			0
#define PE_FAIL			(-1)	/* protocol / verification / setup failure: pe_conn_last_error() */
#define PE_WANT_READ	(-2)
#define PE_WANT_WRITE	(-3)
#define PE_CLOSED		(-4)	/* the peer sent close_notify */
#define PE_EOF			(-5)	/* the transport ended without close_notify */
#define PE_IOERR		(-6)	/* the transport failed */

/* per-certificate verification flags (the mbedTLS MBEDTLS_X509_BADCERT_* values) */
#define PE_BAD_EXPIRED		0x01
#define PE_BAD_REVOKED		0x02
#define PE_BAD_CN_MISMATCH	0x04
#define PE_BAD_NOT_TRUSTED	0x08
#define PE_BAD_MISSING		0x40
#define PE_BAD_SKIP_VERIFY	0x80
#define PE_BAD_OTHER		0x0100
#define PE_BAD_FUTURE		0x0200
#define PE_BAD_KEY_USAGE	0x0800
#define PE_BAD_EXT_KEY_USAGE	0x1000
#define PE_BAD_NS_CERT_TYPE	0x2000
#define PE_BAD_MD			0x4000
#define PE_BAD_PK			0x8000
#define PE_BAD_KEY			0x010000

#define PE_MAX_DEPTH	16

int pe_global_init(void);			/* PSA crypto (TLS 1.3); idempotent; 0 = ok */

pe_trust *pe_trust_new(void);
void pe_trust_free(pe_trust *t);
int pe_trust_add_file(pe_trust *t, const char *path);	/* PEM/DER bundle; returns certificates added (>= 0) or -1 */
int pe_trust_add_path(pe_trust *t, const char *dir);	/* every file in a directory; same */
int pe_trust_count(const pe_trust *t);

pe_cred *pe_cred_new(void);
void pe_cred_free(pe_cred *c);
int pe_cred_set_cert_der(pe_cred *c, const unsigned char *der, int len);	/* replaces the chain; 0 = ok */
int pe_cred_add_chain_der(pe_cred *c, const unsigned char *der, int len);	/* appends (extra chain certs) */
int pe_cred_set_cert_file(pe_cred *c, const char *path);
int pe_cred_set_key_der(pe_cred *c, const unsigned char *der, int len);
int pe_cred_set_key_file(pe_cred *c, const char *path);
int pe_cred_has_cert(const pe_cred *c);
int pe_cred_has_key(const pe_cred *c);
int pe_cred_check(pe_cred *c);			/* 1 = the key matches the certificate */

pe_conn *pe_conn_new(void);
void pe_conn_free(pe_conn *p);
int pe_conn_add_ca_der(pe_conn *p, const unsigned char *der, int len);	/* per-connection anchors (the X509_STORE) */
/* configure + set up; `hostname` = SNI (NULL = none, and no name check), `shared`/`cred` may be NULL and must
 * outlive the connection; 0 = ok */
int pe_conn_start(pe_conn *p, int server, const char *hostname, pe_trust *shared, pe_cred *cred,
                  pe_io_fn send, pe_io_fn recv, void *io_arg);
int pe_conn_handshake(pe_conn *p);
int pe_conn_read(pe_conn *p, unsigned char *buf, int len);
int pe_conn_write(pe_conn *p, const unsigned char *buf, int len);
int pe_conn_close_notify(pe_conn *p);
int pe_conn_pending(pe_conn *p);
int pe_conn_version(pe_conn *p);			/* 0x0303 = TLS 1.2, 0x0304 = TLS 1.3, 0 = none */
const char *pe_conn_version_str(pe_conn *p);	/* "TLSv1.2" / "TLSv1.3" */
int pe_conn_suite(pe_conn *p);				/* the IANA cipher-suite id, 0 = none */
const char *pe_conn_suite_name(pe_conn *p);	/* mbedTLS's name for it */
int pe_conn_peer_count(pe_conn *p);			/* the peer's chain as sent, leaf first */
int pe_conn_peer_der(pe_conn *p, int idx, const unsigned char **der);	/* returns the length */
int pe_conn_verify_depths(pe_conn *p);		/* 1 + the deepest depth the verify callback saw (0 = not run) */
unsigned pe_conn_verify_flags_at(pe_conn *p, int depth);
unsigned pe_conn_verify_flags(pe_conn *p);	/* mbedtls_ssl_get_verify_result */
int pe_conn_last_error(pe_conn *p);			/* the last mbedTLS error code */
void pe_error_string(int err, char *buf, int len);

#ifdef __cplusplus
}
#endif
#endif
