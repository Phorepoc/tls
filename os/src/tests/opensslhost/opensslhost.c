// Copyright The Phorepoc Authors
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
//
// opensslhost.c -- host test of the OpenSSL engine's configuration: the library built with the same Configure options as
// recipes/build_openssl.sh, the seed provider (os/src/openssl/seed_symbian.cpp, over a getrandom shim of Math::Random),
// and the engine's I/O model (two memory BIOs, SSL_set1_host, SSL_VERIFY_NONE + SSL_get_verify_result) in a TLS 1.3
// client <-> server handshake and data exchange, both ends in this process. Prints "[opensslhost] PASS" or fails.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

extern int phorepoc_openssl_seed_init(void);
#define CHECK(c) do { if (!(c)) { printf("[opensslhost] FAIL line %d: %s\n", __LINE__, #c); ERR_print_errors_fp(stdout); return 1; } } while (0)

static int make_cert(EVP_PKEY** key, X509** cert, const char* host)
{
    *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    if (!*key) return 0;
    X509* x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, *key);
    X509_NAME* n = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char*)host, -1, -1, 0);
    X509_set_issuer_name(x, n);
    char san[256];
    snprintf(san, sizeof san, "DNS:%s", host);
    X509V3_CTX c;
    X509V3_set_ctx_nodb(&c);
    X509V3_set_ctx(&c, x, x, NULL, NULL, 0);
    X509_EXTENSION* e = X509V3_EXT_conf_nid(NULL, &c, NID_subject_alt_name, san);
    X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
    if (!X509_sign(x, *key, EVP_sha256())) return 0;
    *cert = x;
    return 1;
}

// move all ciphertext from one side's write BIO into the other side's read BIO
static int pump(BIO* from, BIO* to)
{
    char buf[2048];
    int total = 0, n;
    while ((n = BIO_read(from, buf, sizeof buf)) > 0) { BIO_write(to, buf, n); total += n; }
    return total;
}

static int run(const char* certhost, const char* expecthost, int expect_verify_ok)
{
    EVP_PKEY* key;
    X509* cert;
    CHECK(make_cert(&key, &cert, certhost));

    SSL_CTX* sctx = SSL_CTX_new(TLS_server_method());
    CHECK(SSL_CTX_use_certificate(sctx, cert) == 1 && SSL_CTX_use_PrivateKey(sctx, key) == 1);
    // the client exactly as tlsconnection_openssl.cpp ConstructL / SetOpt(KSoSSLDomainName)
    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(cctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), cert);

    SSL *c = SSL_new(cctx), *s = SSL_new(sctx);
    BIO *crb = BIO_new(BIO_s_mem()), *cwb = BIO_new(BIO_s_mem()), *srb = BIO_new(BIO_s_mem()), *swb = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(crb, -1);
    BIO_set_mem_eof_return(srb, -1);
    SSL_set_bio(c, crb, cwb);
    SSL_set_bio(s, srb, swb);
    SSL_set_connect_state(c);
    SSL_set_accept_state(s);
    CHECK(SSL_set_tlsext_host_name(c, expecthost) == 1 && SSL_set1_host(c, expecthost) == 1);

    int cdone = 0, sdone = 0;
    for (int i = 0; i < 20 && !(cdone && sdone); i++)
    {
        if (!cdone) { int rc = SSL_do_handshake(c); if (rc == 1) cdone = 1; else CHECK(SSL_get_error(c, rc) == SSL_ERROR_WANT_READ); }
        pump(cwb, srb);
        if (!sdone) { int rc = SSL_do_handshake(s); if (rc == 1) sdone = 1; else CHECK(SSL_get_error(s, rc) == SSL_ERROR_WANT_READ); }
        pump(swb, crb);
    }
    CHECK(cdone && sdone);
    long vr = SSL_get_verify_result(c);
    printf("[opensslhost] %s: %s %s verify=%ld (%s)\n", expecthost, SSL_get_version(c),
           SSL_CIPHER_get_name(SSL_get_current_cipher(c)), vr, X509_verify_cert_error_string(vr));
    CHECK((vr == X509_V_OK) == expect_verify_ok);
    if (expect_verify_ok)
    {
        CHECK(SSL_version(c) == TLS1_3_VERSION);
        // data both ways; a read before data is WANT_READ
        char out[64];
        size_t got = 0, w;
        CHECK(SSL_read_ex(c, out, sizeof out, &got) == 0 && SSL_get_error(c, 0) == SSL_ERROR_WANT_READ);
        CHECK(SSL_write_ex(c, "GET / ping", 10, &w) == 1 && w == 10);
        pump(cwb, srb);
        CHECK(SSL_read_ex(s, out, sizeof out, &got) == 1 && got == 10 && memcmp(out, "GET / ping", 10) == 0);
        CHECK(SSL_write_ex(s, "pong", 4, &w) == 1);
        pump(swb, crb);
        CHECK(SSL_read_ex(c, out, sizeof out, &got) == 1 && got == 4 && memcmp(out, "pong", 4) == 0);
        // close_notify -> ZERO_RETURN
        SSL_shutdown(s);
        pump(swb, crb);
        CHECK(SSL_read_ex(c, out, sizeof out, &got) == 0 && SSL_get_error(c, 0) == SSL_ERROR_ZERO_RETURN);
    }
    SSL_free(c);
    SSL_free(s);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    X509_free(cert);
    EVP_PKEY_free(key);
    return 0;
}

// ---- sessions, ALPN and parallel handshakes (the features of the engine's ssl.ini / KPhSo* options) ------------------
struct pair
{
    SSL *c, *s;
    BIO *crb, *cwb, *srb, *swb;
    int cdone, sdone;
};

static unsigned char* g_blob;       // the cached session, i2d_SSL_SESSION (what the engine keeps in the cache)
static int g_blob_len;
static int g_new_sessions;

static int new_session_cb(SSL* ssl, SSL_SESSION* sess)
{
    (void)ssl;
    int len = i2d_SSL_SESSION(sess, NULL);
    free(g_blob);
    g_blob = malloc(len);
    unsigned char* p = g_blob;
    g_blob_len = i2d_SSL_SESSION(sess, &p);
    g_new_sessions++;
    return 0;                       // we did not take the reference
}

static int alpn_select_cb(SSL* s, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned inlen, void* arg)
{
    (void)s; (void)arg;
    if (SSL_select_next_proto((unsigned char**)out, outlen, (const unsigned char*)"\x02h2", 3, in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

static int new_pair(struct pair* p, SSL_CTX* cctx, SSL_CTX* sctx, const char* host)
{
    memset(p, 0, sizeof *p);
    p->c = SSL_new(cctx);
    p->s = SSL_new(sctx);
    p->crb = BIO_new(BIO_s_mem()); p->cwb = BIO_new(BIO_s_mem());
    p->srb = BIO_new(BIO_s_mem()); p->swb = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(p->crb, -1);
    BIO_set_mem_eof_return(p->srb, -1);
    SSL_set_bio(p->c, p->crb, p->cwb);
    SSL_set_bio(p->s, p->srb, p->swb);
    SSL_set_connect_state(p->c);
    SSL_set_accept_state(p->s);
    return SSL_set_tlsext_host_name(p->c, host) == 1 && SSL_set1_host(p->c, host) == 1;
}

static int step(struct pair* p)         // one round of both handshakes; 0 = a real error
{
    if (!p->cdone) { int rc = SSL_do_handshake(p->c); if (rc == 1) p->cdone = 1; else if (SSL_get_error(p->c, rc) != SSL_ERROR_WANT_READ) return 0; }
    pump(p->cwb, p->srb);
    if (!p->sdone) { int rc = SSL_do_handshake(p->s); if (rc == 1) p->sdone = 1; else if (SSL_get_error(p->s, rc) != SSL_ERROR_WANT_READ) return 0; }
    pump(p->swb, p->crb);
    return 1;
}

static int handshake(struct pair* p)
{
    for (int i = 0; i < 20 && !(p->cdone && p->sdone); i++)
        if (!step(p)) return 0;
    return p->cdone && p->sdone;
}

static int sessions(int version, const char* name)
{
    EVP_PKEY* key; X509* cert;
    CHECK(make_cert(&key, &cert, "ph.example"));
    SSL_CTX* sctx = SSL_CTX_new(TLS_server_method());
    CHECK(SSL_CTX_use_certificate(sctx, cert) == 1 && SSL_CTX_use_PrivateKey(sctx, key) == 1);
    SSL_CTX_set_alpn_select_cb(sctx, alpn_select_cb, NULL);
    // the client as ConstructL: the session cache through the new-session callback only (no internal store)
    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(cctx, version);
    SSL_CTX_set_max_proto_version(cctx, version);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), cert);

    g_new_sessions = 0;
    struct pair a, b;
    CHECK(new_pair(&a, cctx, sctx, "ph.example"));
    CHECK(SSL_set_alpn_protos(a.c, (const unsigned char*)"\x02h2\x08http/1.1", 12) == 0);   // 0 = success
    CHECK(handshake(&a));
    const unsigned char* sel; unsigned sl = 0;
    SSL_get0_alpn_selected(a.c, &sel, &sl);
    CHECK(sl == 2 && memcmp(sel, "h2", 2) == 0);
    CHECK(SSL_get_verify_result(a.c) == X509_V_OK);
    CHECK(!SSL_session_reused(a.c));
    // TLS 1.3 tickets arrive after the handshake, in the first read; TLS 1.2 had its session in the handshake
    char out[16]; size_t got;
    pump(a.swb, a.crb);
    (void)SSL_read_ex(a.c, out, sizeof out, &got);
    CHECK(g_new_sessions >= 1 && g_blob_len > 0);
    printf("[opensslhost] %s: session cached, %d bytes (%d callbacks)\n", name, g_blob_len, g_new_sessions);

    // the second connection offers it back from the serialized image
    CHECK(new_pair(&b, cctx, sctx, "ph.example"));
    const unsigned char* q = g_blob;
    SSL_SESSION* sess = d2i_SSL_SESSION(NULL, &q, g_blob_len);
    CHECK(sess && SSL_set_session(b.c, sess) == 1);
    SSL_SESSION_free(sess);
    CHECK(handshake(&b));
    CHECK(SSL_session_reused(b.c));
    CHECK(SSL_get_verify_result(b.c) == X509_V_OK);
    CHECK(SSL_version(b.c) == version);
    X509* peer = SSL_get1_peer_certificate(b.c);       // a resumed connection still has the server certificate (the UI wants it)
    CHECK(peer != NULL);
    X509_free(peer);
    printf("[opensslhost] %s: resumed (%s)\n", name, SSL_get_version(b.c));

    SSL_free(a.c); SSL_free(a.s); SSL_free(b.c); SSL_free(b.s);
    SSL_CTX_free(cctx); SSL_CTX_free(sctx);
    X509_free(cert); EVP_PKEY_free(key);
    return 0;
}

// N handshakes in flight at once, interleaved a flight at a time (what several connections of one process do)
static int parallel(int n)
{
    EVP_PKEY* key; X509* cert;
    CHECK(make_cert(&key, &cert, "ph.example"));
    SSL_CTX* sctx = SSL_CTX_new(TLS_server_method());
    CHECK(SSL_CTX_use_certificate(sctx, cert) == 1 && SSL_CTX_use_PrivateKey(sctx, key) == 1);
    X509_STORE* shared = X509_STORE_new();           // the process-wide trust anchors: one store, each connection's ctx +1
    X509_STORE_add_cert(shared, cert);
    struct pair* p = calloc(n, sizeof *p);
    SSL_CTX** cctx = calloc(n, sizeof *cctx);
    for (int i = 0; i < n; i++)
    {
        cctx[i] = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(cctx[i], SSL_VERIFY_NONE, NULL);
        SSL_CTX_set1_cert_store(cctx[i], shared);
        CHECK(new_pair(&p[i], cctx[i], sctx, "ph.example"));
    }
    for (int round = 0; round < 20; round++)
        for (int i = 0; i < n; i++)
            if (!(p[i].cdone && p[i].sdone)) CHECK(step(&p[i]));
    for (int i = 0; i < n; i++)
        CHECK(p[i].cdone && p[i].sdone && SSL_get_verify_result(p[i].c) == X509_V_OK);
    for (int i = 0; i < n; i++) { SSL_free(p[i].c); SSL_free(p[i].s); SSL_CTX_free(cctx[i]); }
    X509_STORE_free(shared);                         // (the last reference)
    SSL_CTX_free(sctx);
    free(p); free(cctx);
    X509_free(cert); EVP_PKEY_free(key);
    printf("[opensslhost] %d parallel handshakes over one shared trust store: ok\n", n);
    return 0;
}

int main(void)
{
    CHECK(phorepoc_openssl_seed_init());
    unsigned char r[16];
    CHECK(RAND_bytes(r, sizeof r) == 1);        // the DRBG seeds from the seed provider
    int rc = run("ph.example", "ph.example", 1);                // trusted, name matches
    if (!rc) rc = run("ph.example", "other.example", 0);        // trusted, wrong name: handshake completes, verify fails
    if (!rc) rc = sessions(TLS1_3_VERSION, "TLS 1.3");
    if (!rc) rc = sessions(TLS1_2_VERSION, "TLS 1.2");
    if (!rc) rc = parallel(16);
    if (rc) return rc;
    printf("[opensslhost] PASS\n");
    return 0;
}
