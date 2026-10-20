# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the recipes. Runs inside the toolchain container (ghcr.io/phorepoc/base), like the pdk's build tools:
#   PHOREPOC_PDK     the pdk checkout (tools/openc_cflags.py)
#   PHOREPOC_BUILD   all generated files (default: $PHOREPOC_CORE/build)
set -eu
TLS=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${PHOREPOC_BUILD:=${PHOREPOC_CORE:-$TLS/../core}/build}"
: "${PHOREPOC_PDK:=$TLS/../pdk}"
TLS_BUILD=$PHOREPOC_BUILD/tls
MBEDTLS_SRC=$TLS_BUILD/mbedtls-src

# fetch_verified URL SHA256 OUTFILE -- download unless OUTFILE already has that hash; fail on a mismatch
fetch_verified() {
    local url=$1 want=$2 out=$3 got
    if [ -f "$out" ] && [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$want" ]; then return 0; fi
    mkdir -p "$(dirname "$out")"
    curl -fsSL --retry 3 -o "$out.part" "$url"
    got=$(sha256sum "$out.part" | cut -d' ' -f1)
    if [ "$got" != "$want" ]; then
        rm -f "$out.part"
        echo "sha256 mismatch for $url: got $got, want $want" >&2
        return 1
    fi
    mv "$out.part" "$out"
}
