#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# build.sh -- fetch and build everything the registry entries need: mbedTLS (x32 archive), the CA bundle.
# Inside the toolchain container, with PHOREPOC_PDK / PHOREPOC_CORE / PHOREPOC_BUILD set (see README.md).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bash "$here/recipes/fetch_mbedtls.sh"
bash "$here/recipes/build_mbedtls.sh"
bash "$here/recipes/fetch_cacert.sh"
