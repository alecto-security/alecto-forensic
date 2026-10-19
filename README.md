<p align="center">
  <a href="https://github.com/alecto-security/alecto-forensic/actions/workflows/ci.yml"><img src="https://github.com/alecto-security/alecto-forensic/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/rust-stable-orange.svg" alt="Rust stable">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg" alt="Platform">
</p>

<h1 align="center">alecto-forensic</h1>

<p align="center">
  <strong>Read the image, never the disk.</strong>
</p>

<p align="center">
  Offline, read-only carving of video from recorder disk images into a verifiable extraction package.<br>
  No network. No writes to the source. No invented metadata.
</p>

<p align="center">
  <strong>Status:</strong> MVP, format-agnostic H.264 carving (F0) only. Spec: <a href="docs/SPEC.md">docs/SPEC.md</a>.
</p>

---

## What it is, and is not

| It does | It never does |
|---------|---------------|
| reads a disk **image** file, read-only, hashing every byte it reads | touch a live disk or write to the image |
| carves H.264 Annex-B streams with no filesystem knowledge | transcode, reorder or alter a recovered stream |
| writes an extraction package to a new directory | write sealed evidence bundles or hold custody |
| records omitted and rejected regions in `gaps.json`, with reasons | skip a region silently |
| reports `confidence: low`, `channel: null`, no timestamps | invent a timestamp, channel or codec |
| links zero network-capable crates (CI enforces it) | talk to anything on the network |

It parses untrusted binary data, so it is isolated on purpose. A separate
custody product can seal a package into a bundle; this repo stops at the
package and never writes one.

## The whole point, in 20 seconds

```console
$ alecto-forensic detect disk.img
image    4294967296 bytes, sha256 9f3c…b7d1
streams  2
  #0001 184160000 bytes, 26112 NALs, 4 range(s), first at 1048576
  #0002 96000000 bytes, 12840 NALs, 1 range(s), first at 2401234944
gaps     3

$ alecto-forensic extract disk.img --out ./pkg \
    --operator "Jane Examiner" --authorization "OWNER-AUTH-2026-0001" \
    --write-blocker tableau-t35u
package  ./pkg
streams  2
gaps     3
image    9f3c…b7d1

$ alecto-forensic verify-package ./pkg
package OK

$ alecto-forensic verify-package ./pkg      # one flipped byte
extracted/stream_0001.h264: hash mismatch
```

The recovered streams are byte-for-byte what was on the image. The package
records where every range came from and what was not recovered.

## Workflow

```text
1. Owner authorizes reading the disk.
2. Hardware write-blocker + imaging tool -> image file     (outside this tool)
3. alecto-forensic extract image.img --out pkg             (read-only, hashes every byte)
4. a custody step seals pkg into an evidence bundle        (outside this repo)
```

## Quick start

You need Rust stable. ffmpeg + ffprobe on `PATH` only for the real-encoder
round-trip test; without them it skips itself.

```bash
cargo test
cargo run -- detect disk.img
cargo run -- extract disk.img --out ./pkg \
  --operator "Jane Examiner" --authorization "OWNER-AUTH-2026-0001" \
  --write-blocker tableau-t35u
cargo run -- verify-package ./pkg
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean. For `extract`: a package was written with **no** recorded gaps. |
| `1` | Package written **with gaps recorded**. Partial coverage is not a silent pass. |
| `2` | Failure, including a hash mismatch against the acquisition record or a package that fails verification. |
| `3` | Configuration error: missing operator or authorization, a non-empty output directory, or an unreadable acquisition file. Nothing is written. |

Full rules: [docs/SPEC.md](docs/SPEC.md).

## What F0 does

Scans the image for H.264 Annex-B NAL units, groups runs into candidate
streams, and copies them out byte-for-byte. It needs no filesystem knowledge,
so:

- `confidence` is always `low`; timestamps and channels are `null`. Nothing is
  invented.
- Runs separated by up to `--merge-gap` bytes (default 256 KiB) are joined; the
  omitted bytes are `interleaved_data_omitted` gaps, and `index.json` lists
  every image range a stream came from.
- Candidates with no SPS or IDR, or under `--min-bytes`, are rejected and
  recorded as gaps. NALs larger than `--max-nal` are rejected, not buffered.
- Memory stays bounded: the image is read once in 8 MiB chunks.

Parameters: `--merge-gap` (bytes), `--min-bytes`, `--max-nal`.

## Fuzzing

The binary reads hostile bytes, so the parser is fuzzed, not just tested.
`tests/forensic.rs::ft6_hostile_inputs_do_not_panic` is a fast deterministic
net; two `cargo-fuzz` targets add coverage guidance:

| Target | Covers |
|--------|--------|
| `fuzz_nal_scanner` | NAL scanner and stream grouper (`src/scan.rs`, `src/carve.rs`) |
| `fuzz_manifest_parser` | Package manifest parser used by `verify-package` (`src/verify.rs`) |

Both start from seeds generated from the test data
(`cargo run --example gen_fuzz_corpus`). CI runs them nightly, non-blocking,
and uploads every finding as an artifact. How to run them locally:
[fuzz/README.md](fuzz/README.md).

<!-- FUZZ-RESULTS -->

## Known limits (stated, not hidden)

Honesty is the product. These are real limits of F0, not hypotheticals.

### Truncated input

- **A truncated final NAL is recovered to end of image.** It ends where the
  image ends, with trailing zero bytes trimmed. Nothing is inferred.
- **A truncated start code is dropped.** `00 00 01` as the last bytes, with no
  header byte, produces no event and **no gap entry**.
- **A start code across a read boundary is found.** The scanner keeps the last
  two bytes between reads; this is covered by tests.

### Malformed and garbage input

- **Garbage is not itemised.** Only decisions the parser made become gaps
  (interleaved omission, rejected candidates, oversize NALs). Image bytes that
  never form a start code produce no gap entry. Their extent is visible only as
  `image_bytes - carved_bytes` in `gaps.json`.
- **An image with no start code yields zero streams, zero gaps, and exit `0`.**
  The exit code does not mean "recovered something". Check `carved_bytes`
  against `image_bytes` before trusting an empty result.
- **Skipped NAL types are silent.** Units with the forbidden bit set, or a type
  outside `1, 5, 6, 7, 8, 9`, are dropped without a gap entry.
- **Oversize NALs are rejected, not buffered**, with a
  `nal_exceeds_max_size` gap. Scanning resumes after the start code.
- **A run's final NAL can swallow trailing non-video bytes** up to the next
  `00 00 00`, `00 00 01` or `00 00 02` sequence when no zero padding follows
  it. Every index entry carries a note saying so. This cannot be fixed without
  filesystem knowledge; a test pins it.

### Format and metadata

- **H.264 Annex-B only.** H.265, MPEG-4, MJPEG and vendor containers are not
  parsed. Vendor filesystem parsers come only when a real, consented disk
  needs one.
- **No timestamps.** Recorder clock resets (for example to 1970) cannot yet be
  detected. `start_utc`, `end_utc` and `channel` are `null`; ordering is image
  offset.
- **Raw NAL units, not a container.** No frame rate is guessed and no container
  is added.

### Package and operations

- **The package is not fsynced.** `SHA256SUMS` is written last; if it is
  present and verification is clean, every listed file was written and is
  intact. If it is missing, the package is incomplete.
- **A package is written once.** `extract` refuses a non-empty output
  directory; it never overwrites.
- **`verify-package` does not follow symlinks in the tree.** A symlink is
  reported as a stray entry, so a hostile package cannot make verification
  walk a loop.
- **Sandboxing is deployment work.** A seccomp profile or container on the
  cradle is not enforced by the binary.
- **No vendor disk has been tested.** Carving is verified on synthetic images
  and a real encoder's stream, not on a recorder's filesystem. Do not represent
  F0 output as a complete recovery.

## Contract C3: the extraction package

The package layout, every JSON field, the `verify-package` rules, exit codes,
recovery method and the full known-limits list are specified in
**[docs/SPEC.md](docs/SPEC.md)**. That document is self-contained: an examiner
with a package and the spec needs nothing else.

## Security

Vulnerability reports: see [SECURITY.md](SECURITY.md). Documented limits above
are feature work, not vulnerabilities. The tool never writes to the source and
links no network-capable crate; both are enforced by tests.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built by <a href="https://github.com/alecto-security">Alecto Security</a>. We move first.</sub>
</p>
