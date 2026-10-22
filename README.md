# tls

Phorepoc's TLS for Symbian: two front ends over a modern TLS engine, for [Phorepoc](https://github.com/Phorepoc)
boards and for legacy Symbian OS 9.x phones.

| front end | what |
|---|---|
| `SSL.DLL` | the provider behind Symbian's `SecureSocket` (what the network stack and the browsers use), at the 2010 ordinals, in place of the release's TLS 1.0 one |
| `libssl.dll` | Open C's OpenSSL 0.9.8g API (QtNetwork, javassl, Internet Radio, Open C programs), with TLS 1.2 / 1.3 behind it |

| engine | status |
|---|---|
| [mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.6 (pinned: `mbedtls.lock`) | today: TLS 1.2 and 1.3 client, ECDHE, AES-GCM, ChaCha20-Poly1305, SNI, certificate verification against Mozilla's roots |
| OpenSSL 3.x | planned, for modern boards |

mbedTLS and the CA bundle are not copied here: `recipes/` fetches them at pinned versions (SHA-256 in `mbedtls.lock`,
`cacert.lock`).

## Targets

- Phorepoc boards (x86-64 / x32, ARM): built with the OS, in the ROM.
- Legacy Symbian OS 9.x phones (S60 3rd / 5th Edition, Symbian^3, Anna, Belle), where `SSL.DLL` is dropped in on a
  hacked phone. Tested on a Nokia 701: the stock browser loads https over TLS 1.3. Installing on a stock phone needs a
  platform-security hack, because our `SSL.DLL` has to eclipse the ROM one from `C:`, `E:` or `F:` (plus
  `C:\sys\hash\ssl.dll`). The S60 3rd and 5th Edition phones are untested; an older-OS build must only import `euser`
  ordinals that every 9.x has.

## Layout

| path | what |
|---|---|
| `os/src/ssl/` | `tlsconnection_mbed.cpp`, `ssl_mbed.mmp`: SSL.DLL; `tls_sesscache`, `tls_stubcert`, `tls_conf`: its portable, host-tested parts |
| `os/src/libssl/` | the libssl.dll sources, `libssl_mbed.mmp`, `gen_stubs.py` (the ordinals not implemented get safe stubs) |
| `os/src/mbedtls/` | our mbedTLS configuration and platform port (entropy) |
| `os/src/tests/` | `hosttls` (host test), `sslresume` (session resumption on a device), `ssltest` (OpenSSL 0.9.8 API smoke test), `sslprobe` (which SSL.DLL a phone's loader picks) |
| `recipes/` | fetch and build mbedTLS, fetch the CA bundle |
| `registry/components_tls.py` | the components: `ssl_ph`, `ssl_legacy` (the RAM-loaded phone build), `libssl_ph`, `libssl_mbed`, `ssltest`, `sslprobe`, and the extension of core's `ssl` |
| `mbedtls.lock`, `cacert.lock` | the pins |
| `build.sh` | all the recipes, start to end |

## Building

This repository is a layer, like the adaptations: it adds its `os/` to the OS tree and its registry entries to core's
(`registry/components_*.py`; its `EXTEND` table makes core's `ssl` build ours on x32). Inside the toolchain container,
with [core](https://github.com/Phorepoc/core), the [pdk](https://github.com/Phorepoc/pdk) and the Symbian source mounted,
run the recipes first, then build with the layer on `PHOREPOC_ADAPTATIONS`:

```sh
export PHOREPOC_PDK=/pdk PHOREPOC_CORE=/core PHOREPOC_OS_ROOT=/core/os PHOREPOC_SYMBIAN=/symbian PHOREPOC_BUILD=/build
export PHOREPOC_ADAPTATIONS=<board adaptations>:/tls
bash /tls/build.sh                     # mbedTLS (x32 archive), the CA bundle
python3 /pdk/tools/emitter/build_mmp_x32.py ssl libssl_mbed ssltest
```

`recipes/build_mbedtls.sh --arm` makes the ARM archive; the ARM entries (`ssl_ph`, `ssl_legacy`, `libssl_ph`) compile
mbedTLS's sources into the DLL instead.

## Behaviour of `SSL.DLL`

- **Session resumption.** A clean TLS 1.2 handshake (session ticket or id) and every TLS 1.3 ticket are remembered per
  `host:port`, at most 16 sessions, each for the server's ticket lifetime and never more than 24 hours; a TLS 1.3 ticket
  is used once. The cache lives in memory for the process and in a file in the process's private data
  (`phtls_sess.dat`, written to a temporary file and renamed over the old one; a damaged file is ignored). Only a
  session whose certificate verified cleanly against the trust anchors is cached: a certificate the user accepted in
  the security dialog is asked about again every time. `FlushSessionCache()` empties it.
- **Trust anchors** are parsed once per process and shared by all connections.
- **Certificates the platform cannot parse.** `x509.dll` predates today's certificates (ECDSA on newer curves, ...). When
  it cannot parse the server certificate, `ServerCert()` and the security dialog get a display copy instead of `NULL`:
  the real subject, issuer, serial number and validity, a placeholder RSA key and signature (`os/src/ssl/tls_stubcert.h`).
  It is for display only; the real certificate has been verified by mbedTLS.
- **Switches**, in `\resource\ssl\ssl.ini` on any drive (a copy on `C:` wins over the ROM's), read for each new
  connection:

  ```
  tls13 = 0              # at most TLS 1.2, for servers and middleboxes that break 1.3 (default 1)
  session_cache = 0      # every connection does a full handshake (default 1)
  session_persist = 0    # keep the session cache in memory only (default 1)
  ```
- **ALPN** is not part of Symbian's `MSecureSocket` interface, so there is a Phorepoc option for clients that know about
  it: `SetOpt(0x50480002, KSolInetSSL, "h2,http/1.1")` before the handshake, `GetOpt(0x50480002, KSolInetSSL, des)`
  for the selected protocol. `GetOpt(0x50480001, KSolInetSSL, int)` says whether the connection resumed a session.

## Tests

- `os/src/tests/hosttls/run.sh` (host, in the toolchain container, no device or emulator): builds mbedTLS with the DLL's
  own configuration, runs a real client against a real server in memory, and proves a second connection resumes the
  first (TLS 1.2 and 1.3, also after the cache went through its file image, and that a refused ticket, other port or
  host, expired or unverified session never resumes nor breaks the handshake); checks the display certificate and the
  `ssl.ini` parser. See the header of the script for the `docker run` line.
- `sslresume` (device or VirtualBox image): three https connections to one host; `[sslresume] PASS` when the second
  and third resumed (`C:\data\sslresume.txt`). Build with the other components (`build_mmp_x32.py sslresume`), run
  `sslresume.exe [host [port]]`; run it twice to see the cache survive a process restart, and with `tls13 = 0` in
  `ssl.ini` to see the TLS 1.2 path.

## Related projects

- [shinovon/symbian-tls](https://github.com/shinovon/symbian-tls) ([nnproject.cc/tls](https://nnproject.cc/tls)):
  an independent replacement of the system SSL component for stock phones, from Symbian OS v7.0 on (mbedTLS on
  EKA2, BearSSL on EKA1), installed as a SIS. A good choice for an unmodified older phone; this repo is the TLS layer
  of the Phorepoc images.

## Licence

Apache-2.0 (see `LICENSE`), copyright The Phorepoc Authors (`AUTHORS`). mbedTLS is used under its Apache-2.0 option and
the CA bundle is MPL-2.0 data; `NOTICE` has the details.

Contributions are welcome under the same terms: add yourself to `AUTHORS`.
