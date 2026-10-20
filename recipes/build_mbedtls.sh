#!/usr/bin/env bash
# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0
#
# build_mbedtls.sh [--arm] -- mbedTLS (fetch_mbedtls.sh first) as one static archive for Open C / P.I.P.S.
#
# Runs inside the toolchain container. Every library/*.c is compiled with the Open C client line from the pdk
# (tools/openc_cflags.py); modules the configuration (os/src/mbedtls/phorepoc_mbedtls_config.h) leaves out compile
# to nothing.
#   x32 (default):  gcc / ar                          -> $PHOREPOC_BUILD/thirdparty/x86/lib/libmbedtls.a
#   --arm:          arm-none-eabi-gcc / -ar           -> $PHOREPOC_BUILD/thirdparty/arm/lib/libmbedtls.a
# (the ssl_ph / ssl_legacy / libssl_ph registry entries compile the library sources straight into the DLL on ARM;
# the archive is for ports that link mbedTLS statically, e.g. curl)
# JOBS=n sets the parallelism (default: all cores).
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
set +e
ARM=
[ "${1:-}" = "--arm" ] && ARM=1
SRC=$MBEDTLS_SRC
JOBS=${JOBS:-$(nproc)}
[ -f "$SRC/include/mbedtls/build_info.h" ] || { echo "no mbedTLS at $SRC (run recipes/fetch_mbedtls.sh)"; exit 1; }
grep -q 'MBEDTLS_VERSION_STRING *"3\.6' "$SRC/include/mbedtls/build_info.h" || { echo "expected mbedTLS 3.6.x"; exit 1; }

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
# (-iquote library/ and mbedTLS's include/ ahead of the Open C line: its stdapis/openssl headers share names)
XF+=(-Werror=implicit-function-declaration -Werror=implicit-int -Wno-attributes -fmax-errors=5
     "-DMBEDTLS_CONFIG_FILE=\"phorepoc_mbedtls_config.h\"" -iquote "$SRC/library" -I"$TLS/os/src/mbedtls" -I"$SRC/include")
# ARM: platform_util.c knows no clock there -> entropy_symbian.cpp's mbedtls_ms_time
[ -n "$ARM" ] && XF+=(-DMBEDTLS_PLATFORM_MS_TIME_ALT)
# x32: GCC turns some switches into lookup tables indexed with a negative offset (.rodata.CSWTCH.n - 8); that is
# a relocation lld rejects (R_X86_64_32 out of range). Plain compare chains link with either linker.
[ -z "$ARM" ] && XF+=(-fno-tree-switch-conversion)

OUT=$PHOREPOC_BUILD/thirdparty/$ARCH
od=$TLS_BUILD/obj-$ARCH; ld=$TLS_BUILD/logs-$ARCH
rm -rf "$od" "$ld"; mkdir -p "$od" "$ld" "$OUT/lib"
printf '%s\n' "${XF[@]}" > "$od/.flags"
compile_one() {
    local s=$1 od=$2 ld=$3 cc=$4
    local base; base=$(basename "$s" .c)
    mapfile -t F < "$od/.flags"
    if "$cc" "${F[@]}" -c "$s" -o "$od/$base.o" > "$ld/$base.log" 2>&1; then
        echo "OK $s" >> "$od/.status"
    else
        echo "FAIL $s" >> "$od/.status"
    fi
}
export -f compile_one
ls "$SRC"/library/*.c | xargs -P "$JOBS" -I{} bash -c 'compile_one "$@"' _ {} "$od" "$ld" "$CC"
n_ok=$(grep -c '^OK' "$od/.status"); n_fail=$(grep -c '^FAIL' "$od/.status")
echo "libmbedtls: $n_ok ok, $n_fail failed"
if [ "$n_fail" -gt 0 ]; then
    for f in $(grep '^FAIL' "$od/.status" | head -8 | awk '{print $2}'); do
        echo "--- $(basename "$f")"; grep -m3 "error" "$ld/$(basename "$f" .c).log"
    done
    exit 1
fi
rm -f "$OUT/lib/libmbedtls.a"; "$AR" rcs "$OUT/lib/libmbedtls.a" "$od"/*.o
echo "libmbedtls: $OUT/lib/libmbedtls.a"
