// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// hostclient.cpp -- a host HTTPS GET client configured as SSL.DLL / curl's mbedTLS front end configures its client
// (TLS 1.2..1.3, the library's default suite / group / signature lists, SNI, no ALPN unless asked), for grading the
// ClientHello with external tests (Qualys SSL Labs client test).
// usage: hostclient <host> <port> <path> [alpn] [notls13]   -> response body on stdout, handshake summary on stderr
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "psa/crypto.h"

extern "C" int mbedtls_hardware_poll(void*, unsigned char* out, size_t len, size_t* olen)
	{
	FILE* f = fopen("/dev/urandom", "rb");
	if (!f) return -1;
	*olen = fread(out, 1, len, f);
	fclose(f);
	return 0;
	}

static int Send(void* c, const unsigned char* b, size_t l) { ssize_t n = send(*(int*)c, b, l, 0); return n < 0 ? -1 : (int)n; }
static int Recv(void* c, unsigned char* b, size_t l) { ssize_t n = recv(*(int*)c, b, l, 0); return n < 0 ? -1 : (int)n; }

int main(int argc, char** argv)
	{
	if (argc < 4) return 2;
	bool alpn = false, tls13 = true;
	for (int i = 4; i < argc; ++i) { if (!strcmp(argv[i], "alpn")) alpn = true; if (!strcmp(argv[i], "notls13")) tls13 = false; }
	psa_crypto_init();
	addrinfo hints = {}, *ai;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(argv[1], argv[2], &hints, &ai)) { fprintf(stderr, "resolve failed\n"); return 1; }
	int fd = socket(ai->ai_family, SOCK_STREAM, 0);
	if (connect(fd, ai->ai_addr, ai->ai_addrlen)) { fprintf(stderr, "connect failed\n"); return 1; }
	mbedtls_ssl_context ssl; mbedtls_ssl_config conf; mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg;
	mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf); mbedtls_entropy_init(&ent); mbedtls_ctr_drbg_init(&drbg);
	mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char*)"hc", 2);
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_max_tls_version(&conf, tls13 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	static const char* protos[] = { "http/1.1", NULL };
	if (alpn) mbedtls_ssl_conf_alpn_protocols(&conf, protos);
	mbedtls_ssl_setup(&ssl, &conf);
	mbedtls_ssl_set_hostname(&ssl, argv[1]);
	mbedtls_ssl_set_bio(&ssl, &fd, Send, Recv, NULL);
	int r;
	while ((r = mbedtls_ssl_handshake(&ssl)) == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {}
	if (r) { fprintf(stderr, "handshake failed -0x%x\n", -r); return 1; }
	fprintf(stderr, "negotiated %s %s\n", mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));
	char req[512];
	int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s:%s\r\nUser-Agent: Phorepoc-hostclient\r\nAccept: */*\r\nConnection: close\r\n\r\n", argv[3], argv[1], argv[2]);
	for (int o = 0; o < n;) { r = mbedtls_ssl_write(&ssl, (unsigned char*)req + o, n - o); if (r > 0) o += r; else if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) return 1; }
	unsigned char buf[4096];
	for (;;)
		{
		r = mbedtls_ssl_read(&ssl, buf, sizeof buf);
		if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE || r == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) continue;
		if (r <= 0) break;
		fwrite(buf, 1, r, stdout);
		}
	return 0;
	}
