#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# fetch_mbedtls.sh -- the pinned mbedTLS release tarball (mbedtls.lock, SHA-256 checked) unpacked into
# $PHOREPOC_BUILD/tls/mbedtls-src. The release tarball is self-contained (the git tag needs a submodule).
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
. "$TLS/mbedtls.lock"
tarball=$TLS_BUILD/dl/mbedtls-$MBEDTLS_VERSION.tar.bz2
fetch_verified "$MBEDTLS_URL" "$MBEDTLS_SHA256" "$tarball"
if grep -q "MBEDTLS_VERSION_STRING *\"$MBEDTLS_VERSION\"" "$MBEDTLS_SRC/include/mbedtls/build_info.h" 2>/dev/null; then
    echo "mbedTLS $MBEDTLS_VERSION: $MBEDTLS_SRC"
    exit 0
fi
rm -rf "$MBEDTLS_SRC" "$TLS_BUILD/unpack"
mkdir -p "$TLS_BUILD/unpack"
tar -xjf "$tarball" -C "$TLS_BUILD/unpack"
mv "$TLS_BUILD/unpack/mbedtls-$MBEDTLS_VERSION" "$MBEDTLS_SRC"
rmdir "$TLS_BUILD/unpack"
echo "mbedTLS $MBEDTLS_VERSION: $MBEDTLS_SRC"
