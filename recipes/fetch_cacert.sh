#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# fetch_cacert.sh -- Mozilla's CA bundle as published by curl (cacert.lock, SHA-256 checked) -> the file the
# registry stages into the ROM as \resource\ssl\ca-bundle.crt: $PHOREPOC_BUILD/thirdparty/x86/res/ca-bundle.crt.
# To move to a newer bundle: pick the newest cacert-<date>.pem at https://curl.se/ca/ and update cacert.lock.
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
. "$TLS/cacert.lock"
out=$PHOREPOC_BUILD/thirdparty/x86/res/ca-bundle.crt
fetch_verified "$CACERT_URL" "$CACERT_SHA256" "$out"
echo "CA bundle $CACERT_DATE: $out"
