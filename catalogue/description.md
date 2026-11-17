Symbian's own TLS stops at TLS 1.0, so most of today's web refuses to talk to it. This package replaces the system's
`SSL.DLL` with one that speaks TLS 1.2 and 1.3, modern ciphers and checks certificates against Mozilla's root
certificates. It is the same drop-in as Phorepoc OS uses, with the small mbedTLS engine inside. It resumes sessions, so
pages you visit again load faster.

**It needs a phone whose installer is patched.** `SSL.DLL` is part of the phone's ROM and this copy has to take its
place, which a stock installer refuses (platform security). Install it only on a phone where you already have that
patch (for example ROMPatcher's installer patch). It works with the stock browser and everything else that uses the
system's secure sockets. It has been tested on a Belle phone; S60 3rd and 5th Edition phones have not been
tested yet.

To go back to the stock TLS, uninstall the package.

Phorepoc OS already has this built in, so Catalogue does not offer it there.

If you would rather not patch your phone, see shinovon/symbian-tls: an independent project that replaces the system TLS
as an ordinary installable package.
