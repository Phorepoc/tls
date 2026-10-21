#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# run.sh <host> <port> <path> [alpn] [notls13] -- build hostclient.cpp against the ssl.dll's own mbedTLS configuration
# (TLS=/tls; MBEDTLS_CFG_DIR overrides the directory holding phorepoc_mbedtls_config.h) in the toolchain container
# (volume at /build) and run it.
set -eu
TLS=${TLS:-/tls}
export PHOREPOC_BUILD=${PHOREPOC_BUILD:-/build}
export PHOREPOC_PDK=${PHOREPOC_PDK:-/nonexistent}
bash "$TLS/recipes/fetch_mbedtls.sh" >&2
SRC=$PHOREPOC_BUILD/tls/mbedtls-src
CFG=${MBEDTLS_CFG_DIR:-$TLS/os/src/mbedtls}
OBJ=$PHOREPOC_BUILD/tls/hostclient-obj
INC="-I$SRC/include -I$SRC/library -I$CFG -I$TLS/os/src/tests/hostclient"
export INC OBJ
cc1() { gcc -O1 -w $INC '-DMBEDTLS_CONFIG_FILE="hc_config.h"' -c "$1" -o "$OBJ/$(basename "$1" .c).o"; }
export -f cc1
mkdir -p "$OBJ"
stamp=$(cat "$CFG/phorepoc_mbedtls_config.h" "$TLS/os/src/tests/hostclient/hc_config.h" | sha256sum | cut -c1-16)
if [ ! -f "$OBJ/libmbed-$stamp.a" ]; then
    rm -f "$OBJ"/*.o "$OBJ"/libmbed-*.a
    ls "$SRC"/library/*.c | xargs -P "$(nproc)" -n1 bash -c 'cc1 "$0"' >&2
    ar rcs "$OBJ/libmbed-$stamp.a" "$OBJ"/*.o
fi
g++ -O1 -w $INC '-DMBEDTLS_CONFIG_FILE="hc_config.h"' "$TLS/os/src/tests/hostclient/hostclient.cpp" "$OBJ/libmbed-$stamp.a" -o "$OBJ/hostclient" >&2
"$OBJ/hostclient" "$@"
