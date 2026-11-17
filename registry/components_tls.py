# Copyright The Phorepoc Authors
# SPDX-License-Identifier: AGPL-3.0-only

r"""components_tls -- the tls layer's components (merged into core's registry when this repository is built:
PHOREPOC_ADAPTATIONS=<board adaptations>:<tls>, see the pdk's tools/emitter/paths.py).

OS paths are relative to the merged OS tree. mbedTLS is not in the tree: recipes/fetch_mbedtls.sh unpacks the pinned
release to $PHOREPOC_BUILD/tls/mbedtls-src (its include dir goes in through `flags`; the ARM builds compile its
library/*.c into the DLL through `extra`, as ".tls/..." = BUILD-relative). recipes/build_mbedtls.sh makes the x32
archive $PHOREPOC_BUILD/thirdparty/x86/lib/libmbedtls.a and recipes/fetch_cacert.sh the CA bundle the ROM stages as
\resource\ssl\ca-bundle.crt."""
import glob
import os

from paths import BUILD, OS_ROOT

MBEDTLS_SRC = os.path.join(BUILD, "tls/mbedtls-src")
MBEDTLS_INC = ["-I", os.path.join(MBEDTLS_SRC, "include"), "-iquote", os.path.join(MBEDTLS_SRC, "library"),
               # no switch lookup tables: GCC addresses one as `table - first case`, and PSA's switches start at large
               # constants (PSA_ALG_*), so on x32 the address goes below 0 -- R_X86_64_32 out of range at link time
               "-fno-tree-switch-conversion"]
MBEDTLS_CFG = "MBEDTLS_CONFIG_FILE=<phorepoc_mbedtls_config.h>"   # (angle brackets: a quoted -D does not survive the shell)
CA_BUNDLE = "resource\\ssl\\ca-bundle.crt=thirdparty/x86/res/ca-bundle.crt"
SSL_INI = "resource\\ssl\\ssl.ini=data/ssl.ini"
SSL_DEF = "oss.FCL.sf.os.networkingsrv/networksecurity/tls/eabi/sslU.def"
LIBSSL_DEF = "oss.FCL.sf.os.ossrv/ssl/libssl/eabi/libsslu.def"


# The TLS engine behind SSL.DLL on the boards: OpenSSL 3.5 by default, ENGINE=mbedtls for mbedTLS (recipes/fetch_openssl.sh +
# build_openssl.sh [--arm]; static libssl.a + libcrypto.a, no mbedTLS in the DLL); see "the engine switch" at the end.
# The OpenSSL 3 headers precede Open C's own <openssl/...> (the 0.9.8 API) through `incs_first`.
ENGINE = os.environ.get("ENGINE", "openssl").lower()
OPENSSL_INC = os.path.join(BUILD, "thirdparty/include/openssl3")   # one dir for both architectures (both are 32-bit little-endian: the generated headers are the same)
OPENSSL_MMP = os.path.join(OS_ROOT, "src/ssl/ssl_openssl.mmp")


def _openssl(arch):
    """The overrides that turn an SSL.DLL entry into its OpenSSL-engine build (arch: x86 = x32, arm)."""
    lib = f"thirdparty/{arch}/lib/"
    return dict(mmp=OPENSSL_MMP, incs_first=[OPENSSL_INC.format(arch=arch)], arm_incs_first=True, flags=[],
                extra=[], **({"arm_archives": [lib + "libssl.a", lib + "libcrypto.a"]} if arch == "arm" else
                             {"x32_archives": [lib + "libssl.a", lib + "libcrypto.a"]}))


def _mbedtls_sources():
    """The library sources the ARM builds compile into the DLL (empty until fetch_mbedtls.sh has run)."""
    return sorted(".tls/mbedtls-src/library/" + os.path.basename(p) for p in glob.glob(os.path.join(MBEDTLS_SRC, "library/*.c")))


COMPONENTS = {
    # SSL.DLL for Phorepoc on ARM: our drop-in in place of the 2010 networksecurity/tls SSL.MMP (core's `ssl` entry),
    # with mbedTLS compiled in
    "ssl_ph": dict(mmp=os.path.join(OS_ROOT, "src/ssl/ssl_mbed.mmp"), rom="ssl.dll",
                   cdriver=True, allow_wsd=True,
                   **{"def": SSL_DEF},
                   flags=MBEDTLS_INC,
                   defs=[MBEDTLS_CFG, "__SOFTFP=", "MBEDTLS_PLATFORM_MS_TIME_ALT"],
                   rom_data=[CA_BUNDLE, SSL_INI],
                   extra=_mbedtls_sources()),
    # the same drop-in as a RAM-loaded image for a stock Symbian OS 9.x phone (Belle): the stock loader's image
    # format and exception model (device=True). It is the released package (tls-legacy-arm.sis, recipes/sis.sh): package_only
    # (never part of `build --all`: its image is also called ssl.dll, like ssl_ph's), with the CA bundle beside it. No
    # PHOREPOC_SSL_FILELOG: that appends a line per connection (host names) to C:\data\ssl_trace.txt without bound, fine on
    # a test phone and wrong in a release; add it to `defs` for a debugging build.
    "ssl_legacy": dict(mmp=os.path.join(OS_ROOT, "src/ssl/ssl_mbed.mmp"), rom="ssl.dll",
                       cdriver=True, allow_wsd=True, device=True, package_only=True, arm_only=True,
                       **{"def": SSL_DEF},
                       flags=MBEDTLS_INC,
                       defs=[MBEDTLS_CFG, "__SOFTFP=", "MBEDTLS_PLATFORM_MS_TIME_ALT", "PHOREPOC_SSL_TRACE"],
                       rom_data=[CA_BUNDLE],
                       extra=_mbedtls_sources()),
    # Open C's libssl.dll (OpenSSL 0.9.8g ABI) on ARM, mbedTLS compiled in
    "libssl_ph": dict(mmp=os.path.join(OS_ROOT, "src/libssl/libssl_mbed.mmp"), rom="libssl.dll",
                      cdriver=True, allow_wsd=True,
                      **{"def": LIBSSL_DEF},
                      flags=MBEDTLS_INC,
                      defs=[MBEDTLS_CFG, "__SOFTFP=", "MBEDTLS_PLATFORM_MS_TIME_ALT", "PHOREPOC_LIBSSL_TRACE"],
                      extra=_mbedtls_sources()),
    # Open C's libssl.dll (OpenSSL 0.9.8g ABI: QtNetwork, javassl, Internet Radio) with TLS 1.2/1.3 from mbedTLS, for
    # x32 (links the prebuilt archive). Clients name it `LIBRARY libssl_mbed.lib`. Its CA bundle is the one the
    # `ssl` entry puts in the ROM (\resource\ssl\ca-bundle.crt).
    "libssl_mbed": dict(mmp=os.path.join(OS_ROOT, "src/libssl/libssl_mbed.mmp"), rom="libssl.dll",
                        cdriver=True, allow_wsd=True,
                        **{"def": LIBSSL_DEF},
                        flags=MBEDTLS_INC,
                        defs=["__SOFTFP=", "PHOREPOC_LIBSSL_TRACE"],
                        x32_archives=["thirdparty/x86/lib/libmbedtls.a"]),
    # the OpenSSL 0.9.8 API smoke test over libssl_mbed (TCP + TLS to example.com:443, "[ssltest]" lines)
    "ssltest": dict(mmp=os.path.join(OS_ROOT, "src/tests/ssltest/ssltest.mmp"), defs=["__SOFTFP="]),
    # which SSL.DLL a stock phone's loader picks (writes C:\data\sslprobe.txt)
    "sslprobe": dict(mmp=os.path.join(OS_ROOT, "src/tests/sslprobe/sslprobe.mmp"), device=True),
    # does SSL.DLL resume TLS sessions? three https connections, "[sslresume] PASS" (C:\data\sslresume.txt)
    "sslresume": dict(mmp=os.path.join(OS_ROOT, "src/tests/sslresume/sslresume.mmp"), defs=["__SOFTFP="]),
}

# core's `ssl` keeps the 2010 SSL.MMP (the ARM device build of the release's own TLS); with this layer its x32 build is
# ours (SSL_2010=1 in the environment keeps the 2010 one on x32 too).
EXTEND = {} if os.environ.get("SSL_2010") else {
    "ssl": dict(x32_mmp=os.path.join(OS_ROOT, "src/ssl/ssl_mbed.mmp"),
                **{"def": SSL_DEF},
                flags=MBEDTLS_INC,
                x32_archives=["thirdparty/x86/lib/libmbedtls.a"],
                rom_data=[CA_BUNDLE, SSL_INI],
                # the ROM stub (the pdk's tools/rom_stubs.py -> z:\system\install\ssl_stub.sis) carrying the legacy package's
                # UID (recipes/sis.sh): SWI then sees "Phorepoc TLS for older phones" as installed on every image of this layer,
                # and a stray tls-legacy-arm.sis (no ROM-upgrade flag) can never eclipse the image's own ssl.dll.
                # Catalogue hides the listing there (index: compatibility.builtin_on_phorepoc)
                rom_stub=dict(uid=0xE7016F00, name="Phorepoc TLS", files=[r"sys\bin\ssl.dll"])),
}


# ---- the engine switch ----------------------------------------------------------------------------------------------
# ENGINE selects the TLS engine behind SSL.DLL in the BOARD builds (the `ssl` x32 entry, `ssl_ph` on ARM):
#   openssl (the default)  OpenSSL 3.5: static libssl.a + libcrypto.a, recipes/build_openssl.sh [--arm]
#   mbedtls                mbedTLS 3.6, as before
# `ssl_legacy` -- the SIS drop-in for Symbian OS 9.x phones -- is mbedTLS whatever ENGINE says: it is small (~265 KB
# against ~2.1 MB), and it is what the phones were tested with. The libssl.dll front ends (libssl_ph, libssl_mbed: the
# OpenSSL 0.9.8 ABI) stay on mbedTLS too; their exports are the same either way (the .def files are not touched).
# The ARM entries link the ARM archives, core's `ssl` the x32 ones (the OpenSSL 3 headers precede Open C's own
# <openssl/...>, the 0.9.8 API, through incs_first).
if ENGINE == "openssl":
    # ssl_ph is an ARM component, but the bulk build of an x32 board compiles it too: it links the x32 archives there
    _a = _openssl("arm")
    COMPONENTS["ssl_ph"].update(mmp=_a["mmp"], incs_first=_a["incs_first"], arm_incs_first=True, flags=[], extra=[],
                                arm_archives=_a["arm_archives"], x32_archives=_openssl("x86")["x32_archives"],
                                defs=["__SOFTFP="])
    if "ssl" in EXTEND:
        _x = _openssl("x86")
        EXTEND["ssl"].update(x32_mmp=_x["mmp"], incs_first=_x["incs_first"], flags=[], x32_archives=_x["x32_archives"])
elif ENGINE != "mbedtls":
    raise SystemExit("ENGINE must be openssl (default) or mbedtls, not " + ENGINE)
