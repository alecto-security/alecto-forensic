# Contributing

Thanks for your interest. Issues, bug reports, and pull requests are welcome.

## Setup

- Rust stable (`rustup`).
- ffmpeg + ffprobe on `PATH` for the real-encoder round-trip test. Without
  them, that one test skips itself and the rest still run.
- Nightly Rust and `cargo-fuzz` for the fuzz targets:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo run --example gen_fuzz_corpus      # regenerate fuzz/seeds/
```

Windows, Linux, and macOS are all supported. If a change only works on one OS,
say so in the PR.

## The rules that are not negotiable

1. **No network, ever.** No network-capable crate may enter `Cargo.lock` or
   `fuzz/Cargo.lock`. `tests/forensic.rs::ft2_dependency_tree_has_no_network_crates`
   fails the build if one does. Do not add one "temporarily".
2. **Never write to the image or any source.** Open read-only. Hash every byte
   read. `detect` writes nothing.
3. **Never write evidence bundles.** This repo writes extraction packages. A
   separate custody product seals bundles.
4. **Never invent data.** No timestamp, channel, codec or confidence the
   parser did not earn. Unknown is `null`; F0 confidence is `low`.
5. **Never skip silently.** Omitted or rejected regions go to `gaps.json` with
   a reason. New skip paths need a new reason.
6. **Extracted streams stay byte-identical.** No transcoding, no reordering,
   no inserting parsers or start codes into a recovered stream.
7. **Authority is required.** `extract` refuses without an operator and an
   authorization reference.
8. **The package is a contract (C3).** `docs/SPEC.md` and `src/package.rs`
   define a format external examiners rely on. A breaking change bumps the `v`
   field and is documented; it never mutates a released version.

## Fuzzing is part of the job

`tests/forensic.rs::ft6_hostile_inputs_do_not_panic` is a fast deterministic
net, not proof. Any change to `src/scan.rs`, `src/carve.rs` or the manifest
parsing in `src/verify.rs` must:

- extend that test with the new hostile shape, and
- run both fuzz targets locally before opening the PR:

```bash
mkdir -p fuzz/corpus/fuzz_nal_scanner fuzz/corpus/fuzz_manifest_parser
cargo +nightly fuzz run fuzz_nal_scanner \
  fuzz/corpus/fuzz_nal_scanner fuzz/seeds/fuzz_nal_scanner -- -max_len=4096
cargo +nightly fuzz run fuzz_manifest_parser \
  fuzz/corpus/fuzz_manifest_parser fuzz/seeds/fuzz_manifest_parser -- -max_len=4096
```

CI runs both nightly on a schedule. A crash artifact is a blocker: triage it,
fix it, and add the seed to `fuzz/seeds/` via `examples/gen_fuzz_corpus.rs`.

## Pull requests

- Describe the problem and the fix; link the issue if there is one.
- Use Conventional Commits: `feat(scan): ...`, `fix(verify): ...`, `docs: ...`.
- Add tests for behavior changes. `tests/forensic.rs` is the QA matrix;
  `src/*` unit tests cover parsing and boundaries.
- `cargo clippy --all-targets` and `cargo test` clean before submitting.
- Do not bump the package version without updating `docs/SPEC.md` and
  `CHANGELOG.md`.

## Scope we will not merge

- A vendor filesystem parser without a real, consented sample disk and a clear
  legal position for that format.
- Any network, upload or telemetry path.
- Any code that writes to the source image or a live disk.
- AI/ML analysis of the recovered video.
