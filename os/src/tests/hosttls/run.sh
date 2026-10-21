#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# run.sh -- build and run the host test (hosttls.cpp) inside the toolchain container, no device or emulator needed:
#
#   docker volume create tls-build
#   docker run --rm -v tls-build:/build -v <this repository>:/tls ghcr.io/phorepoc/base \
#       bash /tls/os/src/tests/hosttls/run.sh
#
# mbedTLS is fetched and verified by recipes/fetch_mbedtls.sh into /build/tls/mbedtls-src (kept in the volume, with the
# compiled objects, so a re-run only rebuilds the test). The mbedTLS configuration is the ssl.dll's own
# (phorepoc_mbedtls_config.h) plus the server side the test's peer needs (host_config.h).
set -eu
TLS=${TLS:-/tls}
export PHOREPOC_BUILD=${PHOREPOC_BUILD:-/build}
export PHOREPOC_PDK=${PHOREPOC_PDK:-/nonexistent}
bash "$TLS/recipes/fetch_mbedtls.sh"
SRC=$PHOREPOC_BUILD/tls/mbedtls-src
OBJ=$PHOREPOC_BUILD/tls/hosttls-obj
CERTS=$PHOREPOC_BUILD/tls/hosttls-certs
INC="-I$SRC/include -I$SRC/library -I$TLS/os/src/mbedtls -I$TLS/os/src/tests/hosttls -I$TLS/os/src/ssl"
export INC OBJ
cc1() { gcc -O1 -w $INC '-DMBEDTLS_CONFIG_FILE="host_config.h"' -c "$1" -o "$OBJ/$(basename "$1" .c).o"; }
export -f cc1
mkdir -p "$OBJ" "$CERTS"

# the mbedTLS objects (PSA drivers included), once per configuration
stamp=$(cat "$TLS/os/src/mbedtls/phorepoc_mbedtls_config.h" "$TLS/os/src/tests/hosttls/host_config.h" | sha256sum | cut -c1-16)
if [ ! -f "$OBJ/libmbed-$stamp.a" ]; then
    rm -f "$OBJ"/*.o "$OBJ"/libmbed-*.a
    ls "$SRC"/library/*.c | xargs -P "$(nproc)" -n1 bash -c 'cc1 "$0"'
    ar rcs "$OBJ/libmbed-$stamp.a" "$OBJ"/*.o
fi

# the test certificates: an ECDSA P-256 server certificate and an ECDSA P-521 one (the kind the platform's parser
# does not know), with names and validity the display-certificate test checks
if [ ! -f "$CERTS/server.crt" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/server.key"
    openssl req -x509 -new -key "$CERTS/server.key" -out "$CERTS/server.crt" -days 3650 -sha256 \
        -subj "/C=SE/O=Resume Test/CN=resume.test" \
        -addext "subjectAltName=DNS:resume.test,DNS:other.test"
    openssl ecparam -name secp521r1 -genkey -noout -out "$CERTS/p521.key"
    openssl req -x509 -new -key "$CERTS/p521.key" -out "$CERTS/p521.crt" -days 400 -sha384 \
        -subj "/C=DE/ST=Bayern/O=Example AG/OU=Web/CN=p521.example.org" \
        -addext "subjectAltName=DNS:p521.example.org"
fi

g++ -O1 -std=c++11 -Wall -Wno-unused-function $INC '-DMBEDTLS_CONFIG_FILE="host_config.h"' \
    "$TLS/os/src/tests/hosttls/hosttls.cpp" \
    "$TLS/os/src/ssl/tls_sesscache.cpp" "$TLS/os/src/ssl/tls_stubcert.cpp" "$TLS/os/src/ssl/tls_conf.cpp" \
    "$OBJ/libmbed-$stamp.a" -o "$OBJ/hosttls"
"$OBJ/hosttls" "$CERTS"
