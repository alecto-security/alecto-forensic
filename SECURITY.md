# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through GitHub's private security advisories:
open the repository's **Security** tab and choose **Report a vulnerability**.

Do not open a public issue for a security report.

We aim to acknowledge reports within 72 hours and will coordinate disclosure
with you before any public advisory.

## Scope

This tool parses untrusted binary data from disk images, and it verifies
packages it may not have produced. Bugs that matter most to us:

- **Parser safety:** a panic, hang, stack overflow, unbounded allocation or
  out-of-bounds read while carving a hostile or malformed image.
- **Read-only guarantee:** any path where the tool writes to, truncates or
  otherwise modifies the image or a source file.
- **Network capability:** any network-capable crate entering `Cargo.lock`
  (including the fuzz workspace), or any network syscall at runtime.
- **Package verification:** a tampered stream, a stray file, a traversal
  path or a forged manifest that passes `verify-package`.
- **Authorization bypass:** `extract` writing a package without an operator
  and an authorization reference, or overwriting an existing package.

## Known limitations (not bugs)

The following are documented design limits, listed in [docs/SPEC.md](docs/SPEC.md)
and in the README. Reports about them are welcome, but they are feature work,
not vulnerabilities:

- Unrecovered non-video regions are not itemised in `gaps.json`; the remaining
  coverage is `image_bytes - carved_bytes`.
- An image with no H.264 start code yields no streams and no gaps, and exits
  `0`. Read `carved_bytes` before trusting an empty result.
- F0 carves H.264 Annex-B only, recovers no timestamps or channels, and always
  reports `confidence: low`.
- The final NAL of a run can include trailing non-video bytes up to the next
  `00 00 00/01/02` sequence. Every index entry says so.
- The package is not fsynced. `SHA256SUMS` is written last; if it is missing,
  the package is incomplete.
- Sandboxing (seccomp or a container) is deployment work, not enforced by the
  binary.
- No vendor filesystem has been parsed or tested yet.

See the README "Known limits" section for the full list.
