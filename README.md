# tls

Symbian's own TLS stops at TLS 1.0, so most of today's web refuses to talk to it. This repository replaces it with
[mbedTLS](https://github.com/Mbed-TLS/mbedtls) 3.6, which brings TLS 1.2 and 1.3 with modern ciphers and certificate
checks against Mozilla's root certificates. It's built into every [Phorepoc](https://github.com/Phorepoc) image, and
it works on older Symbian phones too.

It replaces two libraries:

- **`SSL.DLL`** sits behind Symbian's `SecureSocket`, which the network stack and the browsers use. It's a drop-in
  replacement with the same exports as the original.
- **`libssl.dll`** offers Open C's OpenSSL 0.9.8 interface, which Qt, Java, Internet Radio and other Open C programs
  use, with modern TLS behind it.

We don't keep copies of mbedTLS or the certificate bundle here. The recipes download the exact versions in
`mbedtls.lock` and `cacert.lock` and check their SHA-256.

## On older Symbian phones

On a phone running Symbian OS 9.x (S60 3rd and 5th Edition, Symbian^3, Anna and Belle), you can drop our `SSL.DLL` in
to replace the system one. We've tested it on a Nokia 701 with Belle, where the stock browser loads https pages over
TLS 1.3. S60 3rd and 5th Edition phones haven't been tested yet.

It needs a phone with platform security hacked, because our `SSL.DLL` has to take the place of the one in ROM. It goes
on `C:`, `E:` or `F:`, along with its hash in `C:\sys\hash\ssl.dll`.

If you'd rather not hack your phone, have a look at
[shinovon/symbian-tls](https://github.com/shinovon/symbian-tls). It's an independent project that replaces the system
TLS on stock phones as a regular installable package, all the way back to Symbian OS 7.0.

## Building

This repository is built together with the OS, like a device repository. Inside the toolchain container, with
[core](https://github.com/Phorepoc/core), the [pdk](https://github.com/Phorepoc/pdk) and the Symbian source available:

```sh
export PHOREPOC_PDK=/pdk PHOREPOC_CORE=/core PHOREPOC_OS_ROOT=/core/os PHOREPOC_SYMBIAN=/symbian PHOREPOC_BUILD=/build
export PHOREPOC_ADAPTATIONS=<device repositories>:/tls
bash /tls/build.sh                     # mbedTLS and the certificate bundle
python3 /pdk/tools/emitter/build_mmp_x32.py ssl libssl_mbed ssltest
```

`recipes/build_mbedtls.sh --arm` builds mbedTLS for ARM. On ARM, the components compile mbedTLS straight into the DLL.

## How `SSL.DLL` behaves

**It resumes sessions.** A connection to a server you've talked to recently skips most of the handshake, which makes
pages noticeably faster. Up to 16 sessions are remembered per host and port, for as long as the server allows and never
more than 24 hours. They're kept in memory and in a file in the program's private folder, so they survive a restart.
Only sessions whose certificate checked out cleanly are remembered. If you accepted a certificate by hand in the
security dialog, you'll be asked again every time.

**It shows certificates the old system can't read.** Symbian's certificate parser is older than many of today's
certificates, so on its own it would show the user nothing. When that happens, the security dialog gets a stand-in
with the real subject, issuer, serial number and dates. It's only for display. mbedTLS has already checked the real
certificate.

**It can be tuned** with `\resource\ssl\ssl.ini` on any drive, where a copy on `C:` wins over the one in ROM:

```
tls13 = 0              # stop at TLS 1.2, for servers and middleboxes that break on 1.3 (default 1)
session_cache = 0      # always do a full handshake (default 1)
session_persist = 0    # keep sessions in memory only, not in a file (default 1)
```

**It supports ALPN for apps that ask.** Symbian's secure socket interface has no way to choose a protocol such as
HTTP/2, so we added one. Call `SetOpt(0x50480002, KSolInetSSL, "h2,http/1.1")` before the handshake and
`GetOpt(0x50480002, KSolInetSSL, des)` afterwards to see which was picked. `GetOpt(0x50480001, KSolInetSSL, int)`
tells you whether the connection resumed a session.

## Tests

`os/src/tests/hosttls/run.sh` runs on your computer, in the toolchain container. It builds mbedTLS with exactly the
settings the DLL uses and connects a real client to a real server in memory. It checks that the second connection
resumes the first, over both TLS 1.2 and 1.3, and also after the cache went through its file. It also checks that a
session never resumes when it shouldn't, for example for another host, after expiry or when the certificate wasn't
verified. The `docker run` line is at the top of the script.

`sslresume` runs on a phone or in the VirtualBox image. It makes three https connections to the same server and prints
`[sslresume] PASS` when the second and third resumed. Run it twice to see the cache survive a restart.

## What's in here

- `os/src/ssl/` is `SSL.DLL`. The session cache, the stand-in certificate and the settings parser are split out so
  they can be tested on a computer.
- `os/src/libssl/` is `libssl.dll`.
- `os/src/mbedtls/` has our mbedTLS configuration and its source of randomness on Symbian.
- `os/src/tests/` has the tests above, plus `ssltest` for the OpenSSL interface and `sslprobe`, which shows which
  `SSL.DLL` a phone actually loads.
- `recipes/` downloads and builds mbedTLS and downloads the certificates. `build.sh` runs them all.
- `registry/components_tls.py` lists the components.

## License

Apache-2.0. mbedTLS is used under its Apache-2.0 option, and the certificate bundle is MPL-2.0 data. `NOTICE` has the
details.

Contributions are welcome under the same terms. Add your name to `AUTHORS` in your first pull request.
