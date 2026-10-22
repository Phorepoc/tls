// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tls_stubcert.cpp -- see tls_stubcert.h.
#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "phorepoc_mbedtls_config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "mbedtls/sha256.h"
#include "mbedtls/oid.h"
#include "tls_stubcert.h"

namespace
{

// A growing DER buffer; every Tlv() wraps what the caller appended since Begin().
struct TDer
	{
	unsigned char* p;
	size_t len, cap;
	bool bad;
	};

void Reserve(TDer& d, size_t n)
	{
	if (d.bad || d.len + n <= d.cap)
		return;
	size_t cap = d.cap ? d.cap : 512;
	while (cap < d.len + n)
		cap *= 2;
	unsigned char* np = (unsigned char*)realloc(d.p, cap);
	if (!np)
		{
		d.bad = true;
		return;
		}
	d.p = np;
	d.cap = cap;
	}

void Raw(TDer& d, const unsigned char* data, size_t n)
	{
	Reserve(d, n);
	if (d.bad)
		return;
	memcpy(d.p + d.len, data, n);
	d.len += n;
	}

// tag + definite length, then the content already in aBody
void WrapInto(TDer& out, unsigned char aTag, const TDer& aBody)
	{
	unsigned char hdr[6];
	size_t h = 0;
	hdr[h++] = aTag;
	size_t n = aBody.len;
	if (n < 0x80)
		hdr[h++] = (unsigned char)n;
	else if (n < 0x100)
		{ hdr[h++] = 0x81; hdr[h++] = (unsigned char)n; }
	else if (n < 0x10000)
		{ hdr[h++] = 0x82; hdr[h++] = (unsigned char)(n >> 8); hdr[h++] = (unsigned char)n; }
	else
		{ hdr[h++] = 0x83; hdr[h++] = (unsigned char)(n >> 16); hdr[h++] = (unsigned char)(n >> 8); hdr[h++] = (unsigned char)n; }
	Raw(out, hdr, h);
	Raw(out, aBody.p, aBody.len);
	if (aBody.bad)
		out.bad = true;
	}

void Prim(TDer& out, unsigned char aTag, const unsigned char* data, size_t n)
	{
	TDer body = { const_cast<unsigned char*>(data), n, n, false };
	WrapInto(out, aTag, body);
	}

// an unsigned INTEGER from big-endian magnitude bytes (adds the 0 pad when the top bit is set)
void UInt(TDer& out, const unsigned char* mag, size_t n)
	{
	while (n > 1 && mag[0] == 0)
		{ ++mag; --n; }
	TDer body = { NULL, 0, 0, false };
	if (n == 0 || (mag[0] & 0x80))
		{
		const unsigned char z = 0;
		Raw(body, &z, 1);
		}
	if (n)
		Raw(body, mag, n);
	WrapInto(out, 0x02, body);
	free(body.p);
	}

// the common AlgorithmIdentifier shape: SEQUENCE { OID, NULL }
void AlgId(TDer& out, const unsigned char* oidBytes, size_t n)
	{
	TDer body = { NULL, 0, 0, false };
	Prim(body, 0x06, oidBytes, n);
	const unsigned char nul[2] = { 0x05, 0x00 };
	Raw(body, nul, 2);
	WrapInto(out, 0x30, body);
	free(body.p);
	}

// X.509 Time: UTCTime for 1950..2049, GeneralizedTime otherwise
void Time(TDer& out, const mbedtls_x509_time& t)
	{
	char s[16];
	int n = 0;
	bool utc = t.year >= 1950 && t.year < 2050;
	int y = t.year;
	if (utc)
		{
		y %= 100;
		s[n++] = (char)('0' + y / 10);
		s[n++] = (char)('0' + y % 10);
		}
	else
		{
		s[n++] = (char)('0' + (y / 1000) % 10);
		s[n++] = (char)('0' + (y / 100) % 10);
		s[n++] = (char)('0' + (y / 10) % 10);
		s[n++] = (char)('0' + y % 10);
		}
	const int f[5] = { t.mon, t.day, t.hour, t.min, t.sec };
	for (int i = 0; i < 5; ++i)
		{
		s[n++] = (char)('0' + (f[i] / 10) % 10);
		s[n++] = (char)('0' + f[i] % 10);
		}
	s[n++] = 'Z';
	Prim(out, utc ? 0x17 : 0x18, (const unsigned char*)s, (size_t)n);
	}

// Name { SET { SEQUENCE { cn OID, UTF8String } } } from the best single attribute of an mbedTLS name list
void SimpleName(TDer& out, const mbedtls_x509_name* aName)
	{
	static const unsigned char kCn[3] = { 0x55, 0x04, 0x03 };
	static const unsigned char kO[3] = { 0x55, 0x04, 0x0A };
	const mbedtls_x509_name* pick = NULL;
	for (int pass = 0; pass < 3 && !pick; ++pass)
		for (const mbedtls_x509_name* n = aName; n; n = n->next)
			{
			bool is3 = n->oid.len == 3 && n->val.len > 0;
			bool match = pass == 0 ? (is3 && memcmp(n->oid.p, kCn, 3) == 0)
					   : pass == 1 ? (is3 && memcmp(n->oid.p, kO, 3) == 0)
					   : n->val.len > 0;
			if (match)
				{ pick = n; break; }
			}
	static const char kUnknown[] = "Unknown";
	const unsigned char* val = pick ? pick->val.p : (const unsigned char*)kUnknown;
	size_t vlen = pick ? pick->val.len : sizeof(kUnknown) - 1;
	if (vlen > 200)
		vlen = 200;
	TDer atv = { NULL, 0, 0, false };
	Prim(atv, 0x06, kCn, 3);
	Prim(atv, 0x0C, val, vlen);
	TDer seq = { NULL, 0, 0, false }, set = { NULL, 0, 0, false };
	WrapInto(seq, 0x30, atv);
	WrapInto(set, 0x31, seq);
	WrapInto(out, 0x30, set);
	free(atv.p); free(seq.p); free(set.p);
	}

const unsigned char kSha1WithRsa[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
const unsigned char kRsaEncryption[9] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

}	// namespace

size_t phstub_build(const mbedtls_x509_crt* aCrt, int aNameStyle, unsigned char** aOut)
	{
	*aOut = NULL;
	if (!aCrt || !aCrt->raw.p || !aCrt->subject_raw.p || !aCrt->issuer_raw.p)
		return 0;

	// 128 bytes of key material and "signature" from the real certificate's hash
	unsigned char h[32], block[128];
	mbedtls_sha256(aCrt->raw.p, aCrt->raw.len, h, 0);
	for (int i = 0; i < 4; ++i)
		memcpy(block + i * 32, h, 32);

	TDer tbs = { NULL, 0, 0, false };
	TDer t = { NULL, 0, 0, false };
	// version [0] v3
	static const unsigned char kVer[5] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
	Raw(tbs, kVer, 5);
	// serial number
	UInt(tbs, aCrt->serial.p ? aCrt->serial.p : block, aCrt->serial.p ? aCrt->serial.len : 4);
	// signature algorithm
	AlgId(tbs, kSha1WithRsa, sizeof(kSha1WithRsa));
	// issuer
	if (aNameStyle == PHSTUB_FULL_NAMES)
		Raw(tbs, aCrt->issuer_raw.p, aCrt->issuer_raw.len);
	else
		SimpleName(tbs, &aCrt->issuer);
	// validity
	t.len = 0;
	Time(t, aCrt->valid_from);
	Time(t, aCrt->valid_to);
	WrapInto(tbs, 0x30, t);
	t.len = 0;
	// subject
	if (aNameStyle == PHSTUB_FULL_NAMES)
		Raw(tbs, aCrt->subject_raw.p, aCrt->subject_raw.len);
	else
		SimpleName(tbs, &aCrt->subject);
	// subjectPublicKeyInfo: rsaEncryption, modulus = the hash block (top and bottom bits set), e = 65537
	{
	unsigned char mod[128];
	memcpy(mod, block, 128);
	mod[0] |= 0x80;
	mod[127] |= 0x01;
	static const unsigned char kE[3] = { 0x01, 0x00, 0x01 };
	TDer pk = { NULL, 0, 0, false }, seq = { NULL, 0, 0, false }, bits = { NULL, 0, 0, false }, spki = { NULL, 0, 0, false };
	UInt(pk, mod, 128);
	UInt(pk, kE, 3);
	WrapInto(seq, 0x30, pk);
	const unsigned char unused = 0;
	Raw(bits, &unused, 1);
	Raw(bits, seq.p, seq.len);
	AlgId(spki, kRsaEncryption, sizeof(kRsaEncryption));
	WrapInto(spki, 0x03, bits);
	WrapInto(tbs, 0x30, spki);
	free(pk.p); free(seq.p); free(bits.p); free(spki.p);
	}

	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature BIT STRING }
	TDer body = { NULL, 0, 0, false };
	WrapInto(body, 0x30, tbs);
	AlgId(body, kSha1WithRsa, sizeof(kSha1WithRsa));
	{
	TDer sig = { NULL, 0, 0, false };
	const unsigned char unused = 0;
	Raw(sig, &unused, 1);
	Raw(sig, block, 128);
	WrapInto(body, 0x03, sig);
	free(sig.p);
	}
	TDer cert = { NULL, 0, 0, false };
	WrapInto(cert, 0x30, body);
	const bool bad = cert.bad || body.bad || tbs.bad || !cert.p;
	free(tbs.p); free(t.p); free(body.p);
	if (bad)
		{
		free(cert.p);
		return 0;
		}
	*aOut = cert.p;
	return cert.len;
	}
