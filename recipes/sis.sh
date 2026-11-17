#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only
#
# sis.sh -- the pdk's package.yml runs it after the components (package.conf): the SSL.DLL drop-in for older Symbian phones
# as $PHOREPOC_BUILD/sis/tls-legacy-arm.sis -- ssl.dll (mbedTLS inside), the CA bundle, and the licence files with the
# written source offer.
#
# Package UID 0xE7016F00 (Phorepoc's own range, unprotected: no signature is needed for the UID). It is NOT the DLL's UID3
# (0x10001842, a protected UID of the Symbian release). Phorepoc images carry a ROM stub with this UID
# (z:\system\install\ssl_stub.sis, the registry's rom_stub), so on Phorepoc OS the package counts as installed and, with no
# ROM-upgrade flag, this package can never eclipse the image's own ssl.dll (installationplanner.cpp
# IsValidEclipsingUpgradeL: an eclipse of a ROM file needs an SA package with that flag, the stub's UID and a trusted signature).
# So the SIS has no --rom-upgrade: it is for stock phones, whose installer has to be patched anyway (README.md).
#
# ARM only, self-signed (a stock Symbian^3 installer asks once). The version is the release's.
set -eu
: "${PHOREPOC_BUILD:?}" "${PHOREPOC_PDK:?}"
REPO=$(cd "$(dirname "$0")/.." && pwd)
LIC=
for f in "$REPO/LICENSES/Apache-2.0.txt" "$REPO/LICENSES/Phorepoc-Build-Output-Exception-1.0.txt" "$REPO/LICENSE" "$REPO/NOTICE" "$REPO/SOURCE-OFFER.txt"; do
    LIC="$LIC --file $f=!:/resource/phorepoc-tls/licences/$(basename "$f")"
done
mkdir -p "$PHOREPOC_BUILD/sis"
# (from Git Bash on Windows: MSYS2_ARG_CONV_EXCL='*', or the !:/ paths are rewritten)
python3 "$PHOREPOC_PDK/tools/make_sis.py" ssl_legacy --arm --uid 0xE7016F00 --version "${PHOREPOC_PACKAGE_VERSION:-1.0.0}" \
    --name "Phorepoc TLS for older phones" --vendor Phorepoc $LIC \
    --out "$PHOREPOC_BUILD/sis/tls-legacy-arm.sis"
