#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
#
# run.sh -- the host test of the OpenSSL engine (opensslhost.c). Runs in the toolchain container (perl, gcc, g++ and the
# fetched OpenSSL, recipes/fetch_openssl.sh): builds a NATIVE libssl/libcrypto with the same Configure options as
# recipes/build_openssl.sh (recipes/openssl_options.sh), compiles the real seed provider (seed_symbian.cpp over the
# shim/e32math.h getrandom stand-in), and runs a TLS 1.3 handshake + data exchange through memory BIOs.
. "$(dirname "${BASH_SOURCE[0]}")/../../../../recipes/env.sh"
. "$TLS/recipes/openssl_options.sh"
set -e
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
B=$TLS_BUILD/openssl-host
rm -rf "$B"; mkdir -p "$B"; cd "$B"
perl "$OPENSSL_SRC/Configure" linux-x86_64 "${OPENSSL_OPTIONS[@]}" --prefix=/opt/openssl-host > configure.log 2>&1 || { tail configure.log; exit 1; }
make -j "${JOBS:-$(nproc)}" build_libs > make.log 2>&1 || { grep -m5 error make.log; exit 1; }
g++ -O1 -I"$here/shim" -I"$B/include" -I"$OPENSSL_SRC/include" -c "$TLS/os/src/openssl/seed_symbian.cpp" -o seed.o
gcc -O1 -I"$B/include" -I"$OPENSSL_SRC/include" "$here/opensslhost.c" seed.o libssl.a libcrypto.a -lstdc++ -o opensslhost
./opensslhost
