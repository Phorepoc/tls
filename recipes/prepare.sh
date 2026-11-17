#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only

# recipes/prepare.sh -- run by the build before the components (pdk docs/layering.md), on the host: mbedTLS and the CA
# bundle at their pinned versions; for x32 mbedTLS is also built here (the ARM builds compile it as components, and the
# libssl.dll front ends use it). The board's TLS engine behind SSL.DLL is OpenSSL unless ENGINE=mbedtls
# (registry/components_tls.py): OpenSSL 3.5 is fetched at its pinned version and built as static archives for the
# architecture (x32, or arm).
set -eu
: "${PHOREPOC_BUILD:?}" "${PHOREPOC_PDK:?}" "${PHOREPOC_ARCH:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"; ROOT="$(dirname "$HERE")"   # (the folder of all the checkouts)
docker run --rm -v "$ROOT:$ROOT" -v "$PHOREPOC_BUILD:$PHOREPOC_BUILD" -w "$HERE" \
	-e PHOREPOC_BUILD -e PHOREPOC_PDK -e PHOREPOC_CORE -e PHOREPOC_SYMBIAN -e PHOREPOC_ADAPTATIONS -e PHOREPOC_ARCH -e ENGINE \
	"${PHOREPOC_IMAGE:-ghcr.io/phorepoc/base:latest}" bash -c 'set -e; bash recipes/fetch_mbedtls.sh; bash recipes/fetch_cacert.sh
		if [ "$PHOREPOC_ARCH" = x32 ]; then bash recipes/build_mbedtls.sh; fi
		if [ "${ENGINE:-openssl}" = openssl ]; then
			bash recipes/fetch_openssl.sh
			if [ "$PHOREPOC_ARCH" = x32 ]; then bash recipes/build_openssl.sh; else bash recipes/build_openssl.sh --arm; fi
		fi'
