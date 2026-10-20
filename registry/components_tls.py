# Copyright The Phorepoc Authors
# SPDX-License-Identifier: Apache-2.0

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
MBEDTLS_INC = ["-I", os.path.join(MBEDTLS_SRC, "include"), "-iquote", os.path.join(MBEDTLS_SRC, "library")]
MBEDTLS_CFG = "MBEDTLS_CONFIG_FILE=<phorepoc_mbedtls_config.h>"   # (angle brackets: a quoted -D does not survive the shell)
CA_BUNDLE = "resource\\ssl\\ca-bundle.crt=thirdparty/x86/res/ca-bundle.crt"
SSL_DEF = "oss.FCL.sf.os.networkingsrv/networksecurity/tls/eabi/sslU.def"
LIBSSL_DEF = "oss.FCL.sf.os.ossrv/ssl/libssl/eabi/libsslu.def"


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
                   rom_data=[CA_BUNDLE],
                   extra=_mbedtls_sources()),
    # the same drop-in as a RAM-loaded image for a stock Symbian OS 9.x phone (Nokia 701): the stock loader's image
    # format and exception model (device=True); trace lines go to C:\data\ssl_trace.txt (a phone has no debug port)
    "ssl_legacy": dict(mmp=os.path.join(OS_ROOT, "src/ssl/ssl_mbed.mmp"), rom="ssl.dll",
                       cdriver=True, allow_wsd=True, device=True,
                       **{"def": SSL_DEF},
                       flags=MBEDTLS_INC,
                       defs=[MBEDTLS_CFG, "__SOFTFP=", "MBEDTLS_PLATFORM_MS_TIME_ALT",
                             "PHOREPOC_SSL_TRACE", "PHOREPOC_SSL_FILELOG"],
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
}

# core's `ssl` keeps the 2010 SSL.MMP (the ARM device build of the release's own TLS); with this layer its x32 build is
# ours (SSL_2010=1 in the environment keeps the 2010 one on x32 too).
EXTEND = {} if os.environ.get("SSL_2010") else {
    "ssl": dict(x32_mmp=os.path.join(OS_ROOT, "src/ssl/ssl_mbed.mmp"),
                **{"def": SSL_DEF},
                flags=MBEDTLS_INC,
                x32_archives=["thirdparty/x86/lib/libmbedtls.a"],
                rom_data=[CA_BUNDLE]),
}
