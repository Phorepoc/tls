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
| `os/src/ssl/` | `tlsconnection_mbed.cpp`, `ssl_mbed.mmp`: SSL.DLL |
| `os/src/libssl/` | the libssl.dll sources, `libssl_mbed.mmp`, `gen_stubs.py` (the ordinals not implemented get safe stubs) |
| `os/src/mbedtls/` | our mbedTLS configuration and platform port (entropy) |
| `os/src/tests/` | `ssltest` (OpenSSL 0.9.8 API smoke test), `sslprobe` (which SSL.DLL a phone's loader picks) |
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

## Related projects

- [shinovon/symbian-tls](https://github.com/shinovon/symbian-tls) ([nnproject.cc/tls](https://nnproject.cc/tls)):
  an independent replacement of the system SSL component for stock phones, from Symbian OS v7.0 on (mbedTLS on
  EKA2, BearSSL on EKA1), installed as a SIS. A good choice for an unmodified older phone; this repo is the TLS layer
  of the Phorepoc images.

## Licence

Apache-2.0 (see `LICENSE`), copyright The Phorepoc Authors (`AUTHORS`). mbedTLS is used under its Apache-2.0 option and
the CA bundle is MPL-2.0 data; `NOTICE` has the details.

Contributions are welcome under the same terms: add yourself to `AUTHORS`.
