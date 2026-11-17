#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only
#
# build.sh -- fetch and build everything the registry entries need: mbedTLS (x32 archive), OpenSSL (the x32 archives,
# unless ENGINE=mbedtls; build_openssl.sh --arm makes the ARM ones), the CA bundle.
# Inside the toolchain container, with PHOREPOC_PDK / PHOREPOC_CORE / PHOREPOC_BUILD set (see README.md).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bash "$here/recipes/fetch_mbedtls.sh"
bash "$here/recipes/build_mbedtls.sh"
if [ "${ENGINE:-openssl}" = openssl ]; then
    bash "$here/recipes/fetch_openssl.sh"
    bash "$here/recipes/build_openssl.sh"
fi
bash "$here/recipes/fetch_cacert.sh"
