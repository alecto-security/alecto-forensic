# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The extraction package schema is versioned separately by its `v` field (see
[docs/SPEC.md](docs/SPEC.md)).

## [Unreleased]

## [0.1.0] - 2026-10-19

First public release. MVP: format-agnostic H.264 carving (F0).

### Added

- `detect`, which scans an image and reports what would be recovered, writing
  nothing.
- `extract`, which reads an image read-only, hashes every byte, and writes an
  extraction package (Contract C3) to a new directory.
- `verify-package`, which checks `SHA256SUMS`, every indexed stream's hash and
  size, the image hash cross-references, and rejects stray files and traversal
  paths.
- H.264 Annex-B NAL scanning and stream grouping: bounded memory, 8 MiB reads,
  no filesystem knowledge. Recovered streams are byte-identical to the bytes
  on the image.
- Honest gaps: interleaved data, candidates without an SPS or IDR, candidates
  under `--min-bytes`, and NALs over `--max-nal` are recorded in `gaps.json`
  with reasons. Partial coverage exits `1`.
- Authorization is required: `extract` refuses without an operator and an
  authorization reference, and a package is written once.
- QA matrix F-T1 to F-T6 in `tests/forensic.rs`, including the read-only
  guarantee, the no-network dependency check, and a deterministic hostile-input
  test.
- Coverage-guided fuzzing with `cargo-fuzz`: `fuzz_nal_scanner` and
  `fuzz_manifest_parser`, seeded from the test data.
- Nightly, non-blocking fuzz CI job that publishes findings as artifacts.

### Changed

- The `SHA256SUMS` parsing in `verify-package` is now a pure
  `parse_manifest` function, so it can be fuzzed without a filesystem. Behavior
  is unchanged.
- The scanner and carver accept an explicit read-chunk size for tests and
  fuzzing. Production still uses 8 MiB.

### Fixed

- `verify-package` no longer follows symlinked directories while walking a
  package, so a hostile package containing a symlink loop can no longer make it
  recurse forever.

### Security

- The no-network build check now covers `fuzz/Cargo.lock` as well as the root
  `Cargo.lock`.
- Package verification rejects absolute, drive-prefixed and `.`/`..` paths in
  both `SHA256SUMS` and `index.json`.

### Documentation

- `docs/SPEC.md`: a self-contained specification of the extraction package,
  `verify-package` rules, exit codes, recovery method, fuzzing, and known
  limits. An examiner needs no other repository to read a package.
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md` for
  the public launch.
- `LICENSE`: Apache-2.0.

[Unreleased]: https://github.com/alecto-security/alecto-forensic/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alecto-security/alecto-forensic/releases/tag/v0.1.0
