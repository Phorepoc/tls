// Copyright The Phorepoc Authors
// SPDX-License-Identifier: Apache-2.0

// tls_stubcert.h -- a "display copy" of a server certificate for Symbian's own X.509 parser.
//
// The platform's x509.dll (and the security dialog / browser page info built on it) predates today's certificates:
// it fails to parse an ECDSA key on a newer curve, RSA-PSS keys and so on, and some callers crash on the NULL that
// results. When that happens SSL.DLL hands out this instead: a well-formed v3 certificate carrying the real
// certificate's subject, issuer, serial number and validity period (all extracted with mbedTLS) but a placeholder
// RSA key and signature. It is for display only -- the real certificate was verified by mbedTLS, and the placeholder
// never takes part in any trust decision. The placeholder key is derived from the SHA-256 of the real certificate, so
// two different certificates look different and the same one always looks the same.
#ifndef PHOREPOC_TLS_STUBCERT_H
#define PHOREPOC_TLS_STUBCERT_H

#include <stddef.h>

#include "mbedtls/x509_crt.h"

enum
	{
	PHSTUB_FULL_NAMES = 0,		// subject / issuer copied verbatim from the real certificate
	PHSTUB_SIMPLE_NAMES = 1		// a name carrying just a common name (or organisation): for parsers that choke on
								// the original's attribute types or string encodings
	};

// Builds the DER of the display certificate into a malloc'd buffer (caller frees); returns its length or 0.
size_t phstub_build(const mbedtls_x509_crt* aCrt, int aNameStyle, unsigned char** aOut);

#endif
