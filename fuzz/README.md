# Fuzzing

Two libFuzzer targets cover the code that reads untrusted bytes. Both live in
their own workspace, so `cargo test` and `cargo clippy` at the repo root never
build them and `libfuzzer-sys` never enters the root `Cargo.lock`.

| Target | Covers |
|--------|--------|
| `fuzz_nal_scanner` | `src/scan.rs` (Annex-B NAL scanner) and `src/carve.rs` (stream grouper). |
| `fuzz_manifest_parser` | `src/verify.rs` (package `SHA256SUMS` parser) and, for JSON-looking input, the package record deserializers. |

## Setup

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Run

The committed seeds are in `fuzz/seeds/<target>/`. libFuzzer writes new units
to the first corpus directory, so keep the seeds read-only and use a scratch
corpus:

```bash
mkdir -p fuzz/corpus/fuzz_nal_scanner fuzz/corpus/fuzz_manifest_parser

cargo +nightly fuzz run fuzz_nal_scanner \
  fuzz/corpus/fuzz_nal_scanner fuzz/seeds/fuzz_nal_scanner \
  -- -max_len=4096 -timeout=60

cargo +nightly fuzz run fuzz_manifest_parser \
  fuzz/corpus/fuzz_manifest_parser fuzz/seeds/fuzz_manifest_parser \
  -- -max_len=4096 -timeout=60
```

`fuzz/corpus/`, `fuzz/artifacts/` and `fuzz/target/` are ignored. Crashes land
in `fuzz/artifacts/<target>/` and must be triaged before a parser change ships.

The scanner harness uses a 1 KiB read chunk and small parameters
(`merge_gap` 1 KiB, `max_nal` 2 KiB, inputs up to 4 KiB). This exercises the
cross-chunk boundary logic constantly and runs far faster than the production
8 MiB path. It does not change the bytes the scanner sees or what `extract`
recovers.

Coverage note: because inputs are capped at 4 KiB, the scanner's
`compact()` path (reached only after 4 MiB of consumed input) is **not**
fuzzed. It is covered by
`tests/forensic.rs::streams_across_chunk_boundaries_are_intact`, which carves
a 22 MiB synthetic image across the 8 MiB read boundaries.

## Seeds

Seeds are generated from the same deterministic helpers the integration tests
use, so the corpus starts from the shapes that already have named tests
(clean stream, interleaved gap, trailing bytes, oversize NAL, truncated start
code, unterminated NAL, malformed and traversal manifests):

```bash
cargo run --example gen_fuzz_corpus
```

Add a seed by adding a case to `examples/gen_fuzz_corpus.rs`, rerunning it, and
committing the new file. Do not hand-edit binaries under `fuzz/seeds/`.

## CI

`.github/workflows/ci.yml` runs both targets nightly (and on manual dispatch)
for 30 minutes each. The job is non-blocking: `continue-on-error` keeps it from
blocking a release, and every finding is uploaded as an artifact.
