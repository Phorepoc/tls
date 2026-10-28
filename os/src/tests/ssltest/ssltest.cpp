// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// ssltest.cpp -- drives Open C's OpenSSL 0.9.8 API the way its real users do (javassl: a socket fd;
// Qt: SSL_CTX_new(SSLv23_client_method()) + SNI + SSL_get_peer_certificate), against the mbedTLS libssl.dll drop-in
// (shim/phorepoc/libssl_mbed). Not Symbian source.
//
// Command line: [host [port]] (default example.com 443). Every line on the debug port starts "[ssltest]":
//   TCP connect (Open C getaddrinfo/socket/connect; DNS retried while the network comes up) ->
//   SSL_CTX_new / set_default_verify_paths / set_verify(PEER, logging callback) -> SSL_new / SSL_set_fd /
//   SNI (SSL_ctrl 55) -> SSL_connect -> version, cipher (+ SSL_CIPHER_description), peer subject/issuer, chain,
//   verify result -> SSL_write a GET -> SSL_read: the status line + the byte count -> SSL_shutdown.
// Ends with "[ssltest] RESULT PASS" (an HTTP status line arrived over TLS) or "[ssltest] RESULT FAIL <why>".
#include <e32std.h>
#include <e32debug.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef PHOREPOC_SSLTEST_FILELOG
// a phone has no debug port: every "[ssltest]" line is appended to C:\data\ssltest.txt instead
#include <stdarg.h>
#include <net/if.h>
struct TSslTestFileLog
	{
	static void Printf(const char* aFmt, ...)
		{
		FILE* f = fopen("c:\\data\\ssltest.txt", "a");
		if (!f)
			return;
		va_list ap;
		va_start(ap, aFmt);
		vfprintf(f, aFmt, ap);
		va_end(ap);
		fputc('\n', f);
		fclose(f);
		}
	};
#define RDebug TSslTestFileLog
#endif

#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#endif

static int VerifyCb(int aOk, X509_STORE_CTX* aCtx)
	{
	// log each error and carry on (the verify result is reported after the handshake)
	if (!aOk)
		RDebug::Printf("[ssltest] verify callback: depth %d error %d (%s)", aCtx->error_depth, aCtx->error,
		               X509_verify_cert_error_string(aCtx->error));
	return 1;
	}

static void LogSslErrors(const char* aWhat)
	{
	unsigned long e;
	int n = 0;
	while ((e = ERR_get_error()) != 0 && n++ < 6)
		{
		char buf[200];
		ERR_error_string_n(e, buf, sizeof(buf));
		RDebug::Printf("[ssltest] %s: %s", aWhat, buf);
		}
	}

static int Fail(const char* aWhy)
	{
	RDebug::Printf("[ssltest] RESULT FAIL %s", aWhy);
	return 1;
	}

static int TcpConnect(const char* aHost, const char* aPort)
	{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	for (int attempt = 1; attempt <= 30; attempt++)
		{
		struct addrinfo* res = NULL;
		int rc = getaddrinfo(aHost, aPort, &hints, &res);
		if (rc != 0 || res == NULL)
			{
			RDebug::Printf("[ssltest] getaddrinfo(%s) attempt %d: %d", aHost, attempt, rc);
			User::After(2000000);
			continue;
			}
		const struct sockaddr_in* sin = (const struct sockaddr_in*)res->ai_addr;
		const unsigned char* a = (const unsigned char*)&sin->sin_addr;
		RDebug::Printf("[ssltest] %s -> %d.%d.%d.%d", aHost, a[0], a[1], a[2], a[3]);
		int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) == 0)
			{
			freeaddrinfo(res);
			return fd;
			}
		RDebug::Printf("[ssltest] connect attempt %d failed (fd %d)", attempt, fd);
		if (fd >= 0)
			close(fd);
		freeaddrinfo(res);
		User::After(2000000);
		}
	return -1;
	}

static int Run(const char* aHost, const char* aPort)
	{
	SSL_library_init();
	SSL_load_error_strings();

	int fd = TcpConnect(aHost, aPort);
	if (fd < 0)
		return Fail("tcp connect");
	RDebug::Printf("[ssltest] tcp connected (fd %d)", fd);

	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
	if (!ctx)
		{
		LogSslErrors("SSL_CTX_new");
		close(fd);
		return Fail("SSL_CTX_new");
		}
	SSL_CTX_set_default_verify_paths(ctx);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, VerifyCb);
	RDebug::Printf("[ssltest] ciphers offered: %d, cert_store %s", sk_num((STACK*)ctx->cipher_list),
	               ctx->cert_store ? "set" : "NULL");

	SSL* ssl = SSL_new(ctx);
	if (!ssl || !SSL_set_fd(ssl, fd))
		{
		LogSslErrors("SSL_new/SSL_set_fd");
		close(fd);
		return Fail("SSL_new");
		}
	SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)aHost);

	int r = SSL_connect(ssl);
	if (r <= 0)
		{
		RDebug::Printf("[ssltest] SSL_connect -> %d, SSL_get_error %d", r, SSL_get_error(ssl, r));
		LogSslErrors("SSL_connect");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		close(fd);
		return Fail("handshake");
		}

	SSL_CIPHER* c = SSL_get_current_cipher(ssl);
	char desc[160];
	RDebug::Printf("[ssltest] version %s, cipher %s", SSL_get_version(ssl), SSL_CIPHER_get_name(c));
	if (c)
		{
		char* d = SSL_CIPHER_description(c, desc, sizeof(desc));
		char* nl = strchr(d, '\n');
		if (nl)
			*nl = 0;
		RDebug::Printf("[ssltest] description: %s", d);
		}
	X509* peer = SSL_get_peer_certificate(ssl);
	if (peer)
		{
		char name[256];
		X509_NAME_oneline(X509_get_subject_name(peer), name, sizeof(name));
		RDebug::Printf("[ssltest] peer subject: %s", name);
		X509_NAME_oneline(X509_get_issuer_name(peer), name, sizeof(name));
		RDebug::Printf("[ssltest] peer issuer: %s", name);
		X509_free(peer);
		}
	else
		RDebug::Printf("[ssltest] peer certificate: NONE");
	STACK* chain = (STACK*)SSL_get_peer_cert_chain(ssl);
	long vr = SSL_get_verify_result(ssl);
	RDebug::Printf("[ssltest] peer chain %d, verify result %d (%s)", chain ? sk_num(chain) : -1, (int)vr,
	               X509_verify_cert_error_string(vr));

	char req[300];
	int n = snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: ssltest (Phorepoc)\r\n"
	                 "Connection: close\r\n\r\n", aHost);
	r = SSL_write(ssl, req, n);
	RDebug::Printf("[ssltest] SSL_write -> %d of %d", r, n);

	char buf[1024];
	char first[160] = "";
	int total = 0;
	for (;;)
		{
		r = SSL_read(ssl, buf, sizeof(buf) - 1);
		if (r <= 0)
			{
			RDebug::Printf("[ssltest] SSL_read -> %d, SSL_get_error %d", r, SSL_get_error(ssl, r));
			break;
			}
		if (total == 0)
			{
			buf[r] = 0;
			int i = 0;
			while (i < (int)sizeof(first) - 1 && buf[i] && buf[i] != '\r' && buf[i] != '\n')
				first[i] = buf[i], i++;
			first[i] = 0;
			RDebug::Printf("[ssltest] response: %s", first);
			}
		total += r;
		}
	RDebug::Printf("[ssltest] read %d bytes", total);
	RDebug::Printf("[ssltest] SSL_shutdown -> %d", SSL_shutdown(ssl));
	SSL_free(ssl);				// (frees the socket BIO; the fd is BIO_NOCLOSE)
	SSL_CTX_free(ctx);
	close(fd);
	if (strncmp(first, "HTTP/", 5) != 0)
		return Fail("no HTTP status line");
	RDebug::Printf("[ssltest] RESULT PASS");
	return 0;
	}

GLDEF_C TInt E32Main()
	{
	char host[128] = "example.com";
	char port[16] = "443";
	TBuf<256> cmd;
	if (User::CommandLineLength() <= cmd.MaxLength())
		User::CommandLine(cmd);
	TBuf8<256> cmd8;
	cmd8.Copy(cmd);
	TLex8 lex(cmd8);
	TPtrC8 t = lex.NextToken();
	if (t.Length() > 0 && t.Length() < (TInt)sizeof(host))
		{
		memcpy(host, t.Ptr(), t.Length());
		host[t.Length()] = 0;
		}
	t.Set(lex.NextToken());
	if (t.Length() > 0 && t.Length() < (TInt)sizeof(port))
		{
		memcpy(port, t.Ptr(), t.Length());
		port[t.Length()] = 0;
		}
	// Open C has no default connection (on a phone): the rest of the line names the access point
	// (setdefaultif), e.g. "example.com 443 Phorepoc WLAN"
	lex.SkipSpace();
	t.Set(lex.Remainder());
	if (t.Length() > 0 && t.Length() < IFNAMSIZ)
		{
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		memcpy(ifr.ifr_name, t.Ptr(), t.Length());
		RDebug::Printf("[ssltest] setdefaultif(%s) -> %d", ifr.ifr_name, setdefaultif(&ifr));
		}
	RDebug::Printf("[ssltest] start: %s:%s", host, port);
	TInt rc = Run(host, port);
	RDebug::Printf("[ssltest] done");
	return rc;
	}
