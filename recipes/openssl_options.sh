# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
#
# The OpenSSL Configure options of the Phorepoc build (sourced by build_openssl.sh and the host test): a TLS client
# library with no assembler, threads, sockets, engines, legacy provider, dso, QUIC, DTLS, apps or tests, and the
# FIPS/old algorithms switched off. Entropy comes from the seed provider (os/src/openssl/seed_symbian.cpp), not the OS.
OPENSSL_OPTIONS=(
    no-asm no-shared no-threads no-dso no-engine no-legacy no-tests no-apps no-docs
    no-sock no-dgram no-ui-console no-async no-autoload-config no-comp no-ssl3 no-dtls no-srp no-ocsp no-cms no-ts
    no-ct no-afalgeng no-ktls no-secure-memory no-quic no-fips no-pic no-http
    no-posix-io no-atexit no-autoerrinit no-egd no-cmp no-deprecated no-weak-ssl-ciphers no-ssl-trace no-ec2m
    no-sctp no-gost no-idea no-seed no-bf no-cast no-rc2 no-rc4 no-rc5 no-md2 no-md4 no-mdc2 no-rmd160 no-whirlpool
    no-camellia no-aria no-sm2 no-sm3 no-sm4 no-dsa no-dh
    --with-rand-seed=none
)
