#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
#
# fetch_openssl.sh -- the pinned OpenSSL release tarball (openssl.lock, SHA-256 checked) unpacked into
# $PHOREPOC_BUILD/tls/openssl-src.
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
. "$TLS/openssl.lock"
tarball=$TLS_BUILD/dl/openssl-$OPENSSL_VERSION.tar.gz
fetch_verified "$OPENSSL_URL" "$OPENSSL_SHA256" "$tarball"
if grep -q "OPENSSL_VERSION_STR *\"$OPENSSL_VERSION\"" "$OPENSSL_SRC/VERSION.dat" 2>/dev/null \
   || grep -q "^MAJOR=3" "$OPENSSL_SRC/VERSION.dat" 2>/dev/null && grep -q "^MINOR=${OPENSSL_VERSION#3.}" "$OPENSSL_SRC/VERSION.dat" 2>/dev/null; then
    echo "OpenSSL $OPENSSL_VERSION: $OPENSSL_SRC"
    exit 0
fi
rm -rf "$OPENSSL_SRC" "$TLS_BUILD/unpack-ossl"
mkdir -p "$TLS_BUILD/unpack-ossl"
tar -xzf "$tarball" -C "$TLS_BUILD/unpack-ossl"
mv "$TLS_BUILD/unpack-ossl/openssl-$OPENSSL_VERSION" "$OPENSSL_SRC"
rmdir "$TLS_BUILD/unpack-ossl"
echo "OpenSSL $OPENSSL_VERSION: $OPENSSL_SRC"
