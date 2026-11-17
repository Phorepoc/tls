#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only WITH LicenseRef-Phorepoc-Build-Output-Exception-1.0
#
# build_openssl.sh [--arm] -- OpenSSL 3.5 (fetch_openssl.sh first) as static libcrypto.a + libssl.a for Open C.
#
# Runs inside the toolchain container. OpenSSL's own Configure/make drive the build (out of tree, target
# linux-generic32, no assembler, no threads, no sockets, no engines/legacy/dso/apps/tests); the compiler is a
# wrapper that adds the Open C client line from the pdk (tools/openc_cflags.py), the same one build_mbedtls.sh uses.
#   x32 (default):  gcc / ar            -> $PHOREPOC_BUILD/thirdparty/x86/lib/{libcrypto,libssl}.a
#   --arm:          arm-none-eabi-gcc   -> $PHOREPOC_BUILD/thirdparty/arm/lib/{libcrypto,libssl}.a
# and the public headers (with the generated ones) in $PHOREPOC_BUILD/thirdparty/include/openssl3/openssl/ (one place for both architectures,
# a separate directory: Open C's own stdapis/openssl headers are the 0.9.8 API and must not be picked up))
# Entropy is not from the OS: the engine registers a seed source on the kernel RNG (os/src/openssl/seed_symbian.cpp).
# JOBS=n sets the parallelism (default: all cores).
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
set +e
ARM=
[ "${1:-}" = "--arm" ] && ARM=1
SRC=$OPENSSL_SRC
JOBS=${JOBS:-$(nproc)}
[ -f "$SRC/Configure" ] || { echo "no OpenSSL at $SRC (run recipes/fetch_openssl.sh)"; exit 1; }

if [ -n "$ARM" ]; then
    CC=arm-none-eabi-gcc; AR=arm-none-eabi-ar; ARCH=arm
    mapfile -t XFLAGS < <(python3 "$PHOREPOC_PDK/tools/openc_cflags.py" --std=gnu11 --arm)
else
    CC=gcc; AR=ar; ARCH=x86
    mapfile -t XFLAGS < <(python3 "$PHOREPOC_PDK/tools/openc_cflags.py" --std=gnu11)
fi
[ "${#XFLAGS[@]}" -gt 10 ] || { echo "openc_cflags.py failed"; exit 1; }
XF=()
for f in "${XFLAGS[@]}"; do [ "$f" = "-w" ] || XF+=("$f"); done
# (OpenSSL's own include/ first: the Open C line carries stdapis/openssl, the 0.9.8 headers of the same names)
XF+=(-Wno-attributes -fmax-errors=5 -DOPENSSL_NO_SECURE_MEMORY -DNO_SYSLOG -D__STDC_NO_ATOMICS__ -U__linux -U__linux__ -Ulinux -include sys/select.h)
[ -z "$ARM" ] && XF+=(-fno-tree-switch-conversion)       # as build_mbedtls.sh: no negative-offset switch tables

OUT=$PHOREPOC_BUILD/thirdparty/$ARCH
B=$TLS_BUILD/openssl-$ARCH
rm -rf "$B"; mkdir -p "$B" "$OUT/lib"; INC3=$PHOREPOC_BUILD/thirdparty/include/openssl3; mkdir -p "$INC3"
printf '%s\n' "${XF[@]}" > "$B/.flags"
# the compiler wrapper: the flags file holds one flag per line (some contain spaces: -Dwchar_t=unsigned short)
cat > "$B/cc.sh" <<WRAP
#!/usr/bin/env bash
mapfile -t F < "$B/.flags"
exec $CC -I$B/include -I$SRC/include "\${F[@]}" "\$@"
WRAP
chmod +x "$B/cc.sh"

cd "$B"
. "$TLS/recipes/openssl_options.sh"
perl "$SRC/Configure" linux-generic32 "${OPENSSL_OPTIONS[@]}" \
    --prefix=/opt/openssl CC="$B/cc.sh" CFLAGS="-O2" > "$B/configure.log" 2>&1 \
    || { tail -20 "$B/configure.log"; exit 1; }
make -k -j "$JOBS" build_libs AR="$AR" ARFLAGS=r RANLIB=true > "$B/make.log" 2>&1
rc=$?
if [ $rc -ne 0 ]; then grep -E "error" "$B/make.log" | sort | uniq -c | sort -rn | head -25; tail -3 "$B/make.log"; exit 1; fi
cp libcrypto.a libssl.a "$OUT/lib/"
rm -rf "$INC3/openssl"; mkdir -p "$INC3/openssl"
cp "$SRC"/include/openssl/*.h include/openssl/*.h "$INC3/openssl/"
echo "libcrypto/libssl: $OUT/lib ($(du -k "$OUT/lib/libcrypto.a" | cut -f1) KB + $(du -k "$OUT/lib/libssl.a" | cut -f1) KB)"
