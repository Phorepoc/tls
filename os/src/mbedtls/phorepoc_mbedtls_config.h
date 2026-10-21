/* Copyright The Phorepoc Authors
 * SPDX-License-Identifier: Apache-2.0 */

/* phorepoc_mbedtls_config.h -- mbedTLS 3.6 for the ssl.dll and libssl.dll front ends
 * and for curl's mbedTLS backend, on Open C / P.I.P.S.. The algorithm set: TLS 1.2 and 1.3 client, ECDHE, AES-GCM,
 * ChaCha20-Poly1305, SNI, EMS, ETM -- one TLS engine for the ssl.dll drop-in and the browser. The platform
 * differences: this runs on a real libc (calloc/free,
 * time, snprintf, files), and curl needs PEM + file I/O (the CA bundle), error strings, ALPN, public-key writing
 * (pinning) and the version module. Entropy: mbedtls_hardware_poll (entropy_symbian.cpp,
 * euser's Math::Random -- the kernel RNG).
 */
#ifndef PHOREPOC_MBEDTLS_CONFIG_H
#define PHOREPOC_MBEDTLS_CONFIG_H

/* --- platform: the Open C libc, our entropy source --- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE               /* certificate validity (gmtime_r) */
#define MBEDTLS_FS_IO                        /* the CA bundle file */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT         /* mbedtls_hardware_poll -> Math::Random */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
/* x32 has __int128, so bignum would divide with libgcc's __udivti3 -- which our images do not link: mbedTLS's
 * own long division instead */
#define MBEDTLS_NO_UDBL_DIVISION

/* --- TLS client --- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_ALPN                     /* curl offers http/1.1 */
#define MBEDTLS_SSL_SESSION_TICKETS
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
/* (static-RSA key exchange and the CBC suites are left out on purpose: no forward secrecy / padding-oracle class;
 * SSL Labs grades them WEAK. ECDHE with AES-GCM or ChaCha20-Poly1305 only; servers that offer nothing else fail.) */
/* TLS 1.3: mbedTLS 3.6 does 1.3 only through PSA crypto (psa_crypto_init() before the first handshake:
 * curl does it, so does the ssl.dll drop-in); (EC)DHE key exchange only, no PSK */
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE  /* the fake ChangeCipherSpec middleboxes expect */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_USE_PSA_CRYPTO
#define MBEDTLS_HKDF_C

/* --- ciphers, hashes, public key --- */
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_GCM_C
/* MBEDTLS_CIPHER_MODE_CBC: not defined, see above */
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C                        /* (TLS 1.2 PRF helpers / PEM, not as a signature hash) */
#define MBEDTLS_SHA1_C                       /* many root certificates are SHA-1 self-signed */
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C                   /* curl's pinned public key */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT        /* rsa_pss_rsae_* in signature_algorithms: TLS 1.3 servers with RSA certificates (GitHub) need them */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C                  /* the CA bundle is PEM */
#define MBEDTLS_PEM_WRITE_C                  /* WebKit's certificate chain is PEM (OpenSSLHelperMbedTLS.cpp) */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_ERROR_C                      /* curl reports mbedtls_strerror() */
#define MBEDTLS_VERSION_C

#endif /* PHOREPOC_MBEDTLS_CONFIG_H */
