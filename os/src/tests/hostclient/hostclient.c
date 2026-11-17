// Copyright The Phorepoc Authors
// SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0

// hostclient.c -- a host HTTPS GET client configured as the OpenSSL engine of SSL.DLL (tlsconnection_openssl.cpp):
// TLS 1.2..1.3, OpenSSL's default suite / group / signature lists, SNI, no ALPN unless asked, memory BIOs over
// the host's socket (the build has no-sock). For grading the ClientHello with external tests (SSL Labs client test).
// usage: hostclient <host> <port> <path> [alpn] [notls13]   -> body on stdout, handshake summary on stderr
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int phorepoc_openssl_seed_init(void);

static int Pump(SSL* ssl, BIO* rb, BIO* wb, int fd, int rc)
	{
	char buf[8192];
	int n;
	while ((n = BIO_read(wb, buf, sizeof buf)) > 0)
		if (send(fd, buf, n, 0) != n) return -1;
	int e = SSL_get_error(ssl, rc);
	if (e == SSL_ERROR_WANT_READ)
		{
		n = recv(fd, buf, sizeof buf, 0);
		if (n <= 0) return 0;
		BIO_write(rb, buf, n);
		return 1;
		}
	return e == SSL_ERROR_WANT_WRITE ? 1 : 0;
	}

int main(int argc, char** argv)
	{
	if (argc < 4) return 2;
	int alpn = 0, tls13 = 1;
	for (int i = 4; i < argc; ++i) { if (!strcmp(argv[i], "alpn")) alpn = 1; if (!strcmp(argv[i], "notls13")) tls13 = 0; }
	if (!phorepoc_openssl_seed_init()) return 1;
	struct addrinfo hints = {0}, *ai;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(argv[1], argv[2], &hints, &ai)) { fprintf(stderr, "resolve failed\n"); return 1; }
	int fd = socket(ai->ai_family, SOCK_STREAM, 0);
	if (connect(fd, ai->ai_addr, ai->ai_addrlen)) { fprintf(stderr, "connect failed\n"); return 1; }
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, tls13 ? TLS1_3_VERSION : TLS1_2_VERSION);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_IGNORE_UNEXPECTED_EOF);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20");   /* as tlsconnection_openssl.cpp */
	SSL_CTX_set1_sigalgs_list(ctx, "ed25519:ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA+SHA256:RSA+SHA384:RSA+SHA512");
	if (getenv("HC_CIPHERS")) SSL_CTX_set_cipher_list(ctx, getenv("HC_CIPHERS"));
	if (getenv("HC_GROUPS")) SSL_CTX_set1_groups_list(ctx, getenv("HC_GROUPS"));
	if (alpn) SSL_CTX_set_alpn_protos(ctx, (const unsigned char*)"\x08http/1.1", 9);
	SSL* ssl = SSL_new(ctx);
	BIO* rb = BIO_new(BIO_s_mem()); BIO* wb = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl, rb, wb);
	SSL_set_tlsext_host_name(ssl, argv[1]);
	SSL_set_connect_state(ssl);
	int rc;
	while ((rc = SSL_do_handshake(ssl)) != 1)
		{
		int p = Pump(ssl, rb, wb, fd, rc);
		if (p <= 0) { fprintf(stderr, "handshake failed\n"); ERR_print_errors_fp(stderr); return 1; }
		}
	{ char b[8192]; int n; while ((n = BIO_read(wb, b, sizeof b)) > 0) send(fd, b, n, 0); }
	fprintf(stderr, "negotiated %s %s\n", SSL_get_version(ssl), SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	char req[512];
	int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Phorepoc-hostclient\r\nAccept: */*\r\nConnection: close\r\n\r\n", argv[3], argv[1], argv[2]);
	rc = SSL_write(ssl, req, n);
	Pump(ssl, rb, wb, fd, rc);
	char buf[4096];
	for (;;)
		{
		rc = SSL_read(ssl, buf, sizeof buf);
		if (rc > 0) { fwrite(buf, 1, rc, stdout); continue; }
		if (Pump(ssl, rb, wb, fd, rc) <= 0) break;
		}
	return 0;
	}
