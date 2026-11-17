#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
#
# run_openssl.sh <host> <port> <path> [alpn] [notls13] -- build a native OpenSSL with recipes/openssl_options.sh (once, kept in
# the volume) and hostclient.c, and run it. In the toolchain container with the volume at /build and the repository at /tls.
. "$(dirname "${BASH_SOURCE[0]}")/../../../../recipes/env.sh"
. "$TLS/recipes/openssl_options.sh"
set -e
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bash "$TLS/recipes/fetch_openssl.sh" >&2
B=$TLS_BUILD/openssl-host
stamp=$(cat "$TLS/recipes/openssl_options.sh" | sha256sum | cut -c1-16)
if [ ! -f "$B/.built-$stamp" ]; then
    rm -rf "$B"; mkdir -p "$B"; cd "$B"
    perl "$OPENSSL_SRC/Configure" linux-x86_64 "${OPENSSL_OPTIONS[@]}" --prefix=/opt/openssl-host > configure.log 2>&1 || { tail configure.log >&2; exit 1; }
    make -j "${JOBS:-$(nproc)}" build_libs > make.log 2>&1 || { grep -m5 error make.log >&2; exit 1; }
    g++ -O1 -I"$TLS/os/src/tests/opensslhost/shim" -I"$B/include" -I"$OPENSSL_SRC/include" -c "$TLS/os/src/openssl/seed_symbian.cpp" -o seed.o
    touch ".built-$stamp"
fi
cd "$B"
gcc -O1 -w -I"$B/include" -I"$OPENSSL_SRC/include" "$here/hostclient.c" seed.o libssl.a libcrypto.a -lstdc++ -o hostclient
./hostclient "$@"
