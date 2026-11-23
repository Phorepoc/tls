# tls

Symbian's own TLS stops at TLS 1.0, so most of today's web refuses to talk to it. This repository replaces it with
TLS 1.2 and 1.3, modern ciphers and certificate checks against Mozilla's root certificates. There are two engines
behind the same `SSL.DLL`:

- **[OpenSSL](https://github.com/openssl/openssl) 3.5 LTS** is what [Phorepoc OS](https://github.com/Phorepoc) images
  use on their boards (x32 PCs, ARM phones and the boards to come).
- **[mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.6** is what the drop-in for older Symbian phones uses: it is about
  a tenth of the size.

It replaces two libraries:

- **`SSL.DLL`** sits behind the system's `SecureSocket`, which the network stack and the browsers use. It's a drop-in
  replacement with the same exports as the original.
- **`libssl.dll`** offers Open C's OpenSSL 0.9.8 interface, which Qt, Java, Internet Radio and other Open C programs
  use, with modern TLS behind it (mbedTLS, whichever engine `SSL.DLL` has).

This repository does not keep copies of OpenSSL, mbedTLS or the certificate bundle. The recipes download the exact versions in
`openssl.lock`, `mbedtls.lock` and `cacert.lock` and check their SHA-256.

## On older Symbian phones

On a phone running Symbian OS 9.x (S60 3rd and 5th Edition, Symbian^3, Anna and Belle), the Phorepoc `SSL.DLL` can be dropped in
to replace the system one. It has been tested on a Belle phone, where the stock browser loads https pages over
TLS 1.3. S60 3rd and 5th Edition phones haven't been tested yet.

It needs a phone with platform security hacked, because the Phorepoc `SSL.DLL` has to take the place of the one in ROM. It goes
on `C:`, `E:` or `F:`, along with its hash in `C:\sys\hash\ssl.dll`.

It comes as a package, `tls-legacy-arm.sis` (a GitHub release of this repository; [Catalogue](https://github.com/Phorepoc/catalogue)
lists it for older phones). The installer of a stock phone refuses it, because a file of the ROM may only be replaced by
a package signed for that and flagged as a ROM upgrade, so it needs the same patched installer (for example ROMPatcher's) and
then writes the hash for you. It is ARM only, self-signed, with `mbedTLS` and the CA bundle inside; uninstall it to get the
stock TLS back. Its package UID is `0xE7016F00`. `libssl.dll` (the Open C interface) is not in the package yet.

On Phorepoc OS the package is not offered, and cannot take effect: images that include this repository carry a ROM stub
(`z:\system\install\ssl_stub.sis`, the registry's `rom_stub`) with the same UID, so the installer treats the package as
installed, and a package without the ROM-upgrade flag, which this one is, can't replace a ROM file.

If you'd rather not hack your phone, have a look at
[shinovon/symbian-tls](https://github.com/shinovon/symbian-tls). It's an independent project that replaces the system
TLS on stock phones as a regular installable package, all the way back to Symbian OS 7.0.

## Building

This repository is built together with the OS, like a device repository. Inside the toolchain container, with
[core](https://github.com/Phorepoc/core), the [pdk](https://github.com/Phorepoc/pdk) and the Symbian source available:

```sh
export PHOREPOC_PDK=/pdk PHOREPOC_CORE=/core PHOREPOC_OS_ROOT=/core/os PHOREPOC_SYMBIAN=/symbian PHOREPOC_BUILD=/build
export PHOREPOC_ADAPTATIONS=<device repositories>:/tls
bash /tls/build.sh                     # OpenSSL and mbedTLS (x32 archives) and the certificate bundle
python3 /pdk/tools/emitter/build_mmp_x32.py ssl libssl_mbed ssltest
```

`recipes/build_mbedtls.sh --arm` builds mbedTLS for ARM. On ARM, the components compile mbedTLS straight into the DLL;
`recipes/build_openssl.sh --arm` builds the OpenSSL archives the ARM board build links. ENGINE=mbedtls skips OpenSSL.

## How `SSL.DLL` behaves

**It resumes sessions.** A connection to a server you've talked to recently skips most of the handshake, which makes
pages noticeably faster. Up to 16 sessions are remembered per host and port, for as long as the server allows and never
more than 24 hours. They're kept in memory and in a file in the program's private folder, so they survive a restart.
Only sessions whose certificate checked out cleanly are remembered. If you accepted a certificate by hand in the
security dialog, you'll be asked again every time.

**It shows certificates the old system can't read.** The system's certificate parser is older than many of today's
certificates, so on its own it would show the user nothing. When that happens, the security dialog gets a stand-in
with the real subject, issuer, serial number and dates. It's only for display. mbedTLS has already checked the real
certificate.

**It can be tuned** with `\resource\ssl\ssl.ini` on any drive, where a copy on `C:` wins over the one in ROM:

```
tls13 = 0              # stop at TLS 1.2, for servers and middleboxes that break on 1.3 (default 1)
session_cache = 0      # always do a full handshake (default 1)
session_persist = 0    # keep sessions in memory only, not in a file (default 1)
```

**It supports ALPN for apps that ask.** The system's secure socket interface has no way to choose a protocol such as
HTTP/2, so Phorepoc added one. Call `SetOpt(0x50480002, KSolInetSSL, "h2,http/1.1")` before the handshake and
`GetOpt(0x50480002, KSolInetSSL, des)` afterwards to see which was picked. `GetOpt(0x50480001, KSolInetSSL, int)`
tells you whether the connection resumed a session.

## Tests

`os/src/tests/hosttls/run.sh` runs on your computer, in the toolchain container. It builds mbedTLS with exactly the
settings the DLL uses and connects a real client to a real server in memory. It checks that the second connection
resumes the first, over both TLS 1.2 and 1.3, and also after the cache went through its file. It also checks that a
session never resumes when it shouldn't, for example for another host, after expiry or when the certificate wasn't
verified. The `docker run` line is at the top of the script.

`os/src/tests/opensslhost/run.sh` does the same for the OpenSSL engine: it builds OpenSSL with the Configure options of
`recipes/openssl_options.sh` and the real seed provider, and runs the engine's I/O model (two memory BIOs,
`SSL_set1_host`, verify result read afterwards). It checks a TLS 1.3 handshake and data both ways, a name mismatch,
session resumption over TLS 1.3 and 1.2 through a serialised session image, ALPN, and sixteen handshakes in flight over
one shared trust store. `os/src/tests/hostclient/run_openssl.sh <host> <port> <path>` connects the engine's
configuration to a real server to grade its ClientHello.

`sslresume` runs on a phone or in a VM image. It makes three https connections to the same server and prints
`[sslresume] PASS` when the second and third resumed. Run it twice to see the cache survive a restart.

## What's in here

- `os/src/ssl/` is `SSL.DLL`, one file per engine (`tlsconnection_mbed.cpp`, `tlsconnection_openssl.cpp`). The session
  cache, the stand-in certificate and the settings parser are split out so
  they can be tested on a computer.
- `os/src/libssl/` is `libssl.dll`.
- `os/src/mbedtls/` has the Phorepoc mbedTLS configuration and its source of randomness on Phorepoc OS.
- `os/src/tests/` has the tests above, plus `ssltest` for the OpenSSL interface and `sslprobe`, which shows which
  `SSL.DLL` a phone actually loads.
- `os/src/openssl/` has the OpenSSL engine's source of randomness.
- `recipes/` downloads and builds OpenSSL and mbedTLS and downloads the certificates. `build.sh` runs them all.
- `registry/components_tls.py` lists the components.

## Licensing

This is Phorepoc code, licensed under the [GNU Affero General Public License, version 3 only](LICENSE) (`AGPL-3.0-only`), with the [additional terms](ADDITIONAL-TERMS.md) its section 7 allows: keep the attribution "Phorepoc, founded by Kyriakos Bompotis" and the legal notices (also where your version shows notices, such as an About screen), and no rights to the Phorepoc names and logos ([TRADEMARKS.md](TRADEMARKS.md)). If you run a modified version for users over a network, AGPL section 13 asks you to offer them its source.

What you build with it is yours: the [Phorepoc Build Output Exception](LICENSES/Phorepoc-Build-Output-Exception-1.0.txt) lets you distribute the programs, libraries and packages you make with these tools, including the runtime pieces that end up in them, under any licence. `NOTICE` lists the runtime files it covers.

OpenSSL 3 is Apache-2.0 (`LICENSES/Apache-2.0.txt`). mbedTLS is used under its Apache-2.0 option, and the certificate bundle is MPL-2.0 data. `NOTICE` has the details.

Phorepoc is dual-licensed. Commercial licences or licence exceptions (for example to ship it inside a closed product without the AGPL obligations) are available on request from the founder, Kyriakos Bompotis.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) for the licence grant they need.

## Engines

| build | engine behind `SSL.DLL` | switch |
|---|---|---|
| a board image (x32 or ARM) | OpenSSL 3.5 | the default |
| a board image, mbedTLS instead | mbedTLS 3.6 | `ENGINE=mbedtls` in the build's environment |
| the drop-in for older Symbian phones (`ssl_legacy`) | mbedTLS 3.6 | always |

`ENGINE` is read by `registry/components_tls.py` (which component uses which `.mmp`) and `recipes/prepare.sh` (which
libraries get built). `libssl.dll` is mbedTLS in every build; its exports don't depend on the engine.

```sh
bash /tls/recipes/fetch_openssl.sh           # the pinned tarball (openssl.lock, SHA-256 checked)
bash /tls/recipes/build_openssl.sh           # x32 archives (--arm: ARM) -> thirdparty/<arch>/lib/{libssl,libcrypto}.a
python3 /pdk/tools/emitter/build_mmp_x32.py ssl                   # OpenSSL engine
ENGINE=mbedtls python3 /pdk/tools/emitter/build_mmp_x32.py ssl    # mbedTLS engine
bash /tls/os/src/tests/opensslhost/run.sh    # host test of the OpenSSL engine (see Tests)
```

`os/src/ssl/tlsconnection_openssl.cpp` is `tlsconnection_mbed.cpp` with the engine calls replaced (SSL_* over two memory
BIOs; the transport AOs, the three client ops and the security dialog are the same), and it has the same options:
`ssl.ini`, ALPN, session resumption, a lower-cased server name, and the failure lines on the debug port. What differs:

- OpenSSL here is built without threads (`recipes/openssl_options.sh`: no asm, sockets, engines, legacy, DTLS, QUIC;
  client focus) and linked statically, so every call into it runs under one process-wide lock on one process-wide heap.
  A worker thread's heap dies with the thread; OpenSSL's library state and the trust anchors outlive it. Handshakes of
  several threads take turns. The mbedTLS engine's lock (for its PSA key slots) does the same job.
- The trust anchors are one `X509_STORE` per process, shared by every connection.
- Sessions are `i2d_SSL_SESSION` images in the same cache container (`tls_sesscache.cpp`, built with `PHSC_NO_MBEDTLS`),
  in its own file (`phtls_ossl_sess.dat`: the two engines' images are not interchangeable).
- Entropy is the kernel RNG through a seed-source provider (`os/src/openssl/seed_symbian.cpp`).
- Not ported yet: the stand-in certificate for the platform's older X.509 parser (`tls_stubcert.cpp` reads the
  certificate with mbedTLS), and the exact `bad_certificate` alert when the user refuses a certificate (OpenSSL sends
  `close_notify`).
- The size: the OpenSSL `ssl.dll` is about 2 MB, the mbedTLS one about 265 KB.

The OpenSSL 3 headers are put ahead of Open C's `<openssl/...>` (the 0.9.8 API) with `incs_first`.
