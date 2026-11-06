# Security

`tiny-dist-audit` reads local artifacts and never opens a socket. Its attack
surface is the archive parser, so that is where the tests point.

## Reporting

Open a private security advisory on this repository. Please include the
artifact that triggered the problem, ideally as a minimal generator script.

## Known limits (by design, documented so nobody over-trusts a green check)

- The signature is **HMAC-SHA256**, which is symmetric. It detects tampering
  after signing; it does not prove who signed, and it is not a substitute for
  Sigstore, in-toto, or a public-key signature.
- `find_risky_paths()` matches **path names only**. A token inside
  `settings.py` is not detected.
- `check()` compares against a baseline you supply. It does not fetch anything
  from PyPI, so it cannot tell you a published file differs from your local one.
- Zip entries are read into memory to hash them; a decompression bomb in an
  untrusted wheel can exhaust memory. Do not point this at artifacts you have
  not already decided to install.

## Deliberate refusals

- `sign()` raises on an empty key rather than producing an unsigned manifest
  that looks signed.
- `verify()` returns `False` for a missing or unknown signature scheme. A
  fail-open verifier is exactly the bug this library exists to catch.
