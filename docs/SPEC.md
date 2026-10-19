# ΛLECTΘ Forensic — Specification

This document defines what `alecto-forensic` does, the **extraction package**
it writes (Contract C3), the rules `verify-package` applies, and the limits
the tool operates under. It is written to stand alone: an examiner who has a
package and this document can understand it without access to any other
Alecto repository or document.

The extraction package is the public contract. The `v` field versions it;
breaking changes bump `v`, they never mutate a released version.

## Purpose

Take a read-only **image** of a recorder's hard disk and recover the video
from it, byte-exact, together with a record of where every recovered byte came
from and what could not be recovered.

It addresses a common situation: a recorder uses a proprietary on-disk format,
and the disk must be read without touching (or reinserting) it, because
reinserting a disk can reset the recorder clock and orphan its own recordings.

## Scope

In scope:

- Read a disk **image file**. Never a live disk.
- Carve H.264 Annex-B streams with no filesystem knowledge (F0).
- Copy recovered streams out byte-for-byte.
- Record omitted and rejected regions with offsets and reasons, and the total
  recovered against the image size.
- Write a self-describing extraction package and verify it.

Out of scope:

- Writing to, repairing or mounting the source disk or image.
- Any network access. The binary links no network-capable crate, and CI
  fails the build if one appears in the dependency tree.
- Defeating encryption without the owner's authority.
- Producing sealed evidence bundles. This repo stops at the package; a
  separate custody product seals bundles from it.
- AI or analysis of the recovered video.

## Separation

| Forensic does | Forensic never does |
|---------------|---------------------|
| read an image, carve, log | touch the network |
| write an extraction package to a new directory | write to the image or any source |
| report confidence and gaps honestly | write sealed bundles or hold custody |
| require an operator and an authorization reference | invent timestamps, channels or confidence |

## Workflow

```text
1. Owner authorizes reading the disk.
2. Hardware write-blocker + imaging tool -> image file   (outside this tool)
3. alecto-forensic extract image.img --out pkg           (read-only, hashes every byte)
4. a subsequent custody step seals pkg into an evidence bundle
```

Steps 1 and 2 are the operator's; this tool does not acquire disks.

## CLI

```console
alecto-forensic detect <image> [--json] [--merge-gap N] [--min-bytes N] [--max-nal N]
alecto-forensic extract <image> --out <dir> (--operator O --authorization A | --acquisition file.json)
                                [--write-blocker W] [--json] [--merge-gap N] [--min-bytes N] [--max-nal N]
alecto-forensic verify-package <dir> [--json]
```

- `detect` scans and reports. It writes nothing.
- `extract` writes a new package directory. The directory must not already
  contain files: a package is written once.
- `verify-package` checks a package and prints one line per problem.

`extract` requires an `operator` (at least 3 characters) and an
`authorization` reference (at least 3 characters) — the owner's authority to
read this disk. Without them the command exits `3` and writes nothing.

### Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `--merge-gap` | `262144` (256 KiB) | Join runs of NAL units separated by at most this many bytes of other data. The omitted bytes become a `interleaved_data_omitted` gap. |
| `--min-bytes` | `4096` | Candidates smaller than this are rejected as noise (`candidate_rejected_too_small`). |
| `--max-nal` | `16777216` (16 MiB) | A NAL unit larger than this is rejected, not buffered (`nal_exceeds_max_size`). |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. `extract` wrote a package with no recorded gaps; `detect` scanned; `verify-package` found no problem. |
| `1` | `extract` wrote a package **with gaps recorded**. Partial coverage is not a silent pass. |
| `2` | Failure: I/O error, a hash mismatch against the acquisition record, or `verify-package` found problems. |
| `3` | Configuration error: missing operator, missing authorization reference, an output directory that is not empty, or an unreadable/unknown `--acquisition` file. Nothing is written. |

## Contract C3: the extraction package

```text
extraction-<id>/
├── acquisition.json   image hash, operator, time, write-blocker, authorization
├── image.sha256       hash of the image file as received
├── parser.json        tool, version, format id, parameters
├── index.json         one entry per recovered stream
├── extracted/         recovered streams, byte-exact as found on the image
├── gaps.json          regions omitted or rejected, with offsets and reasons
├── parser-log.jsonl   append-only record of every decision
└── SHA256SUMS         hashes of every other file in the package
```

Every file in the directory except `SHA256SUMS` itself is covered by
`SHA256SUMS`. `SHA256SUMS` is written last.

### `acquisition.json`

```json
{
  "v": 1,
  "image_file": "disk.img",
  "image_sha256": "<hex>",
  "image_bytes": 4294967296,
  "operator": "Jane Examiner",
  "acquired_at": "2026-10-02T14:03:00Z",
  "write_blocker": "tableau-t35u",
  "authorization": "OWNER-AUTH-2026-0001",
  "tool": "alecto-forensic 0.1.0 extract"
}
```

- `image_sha256` and `image_bytes` are computed by reading the whole image
  once, front to back, while carving. Every byte read is hashed.
- `write_blocker` is optional and records the model/id of the write-blocker
  used during acquisition.
- `authorization` is a reference to the owner's authority (a case number or
  a signed form id). It is recorded, not validated.

### `image.sha256`

A single line, `sha256sum` format: `<hex>  <image file name>`.

### `parser.json`

```json
{
  "v": 1,
  "tool": "alecto-forensic",
  "version": "0.1.0",
  "format": "h264-annexb-carve",
  "params": { "merge_gap": 262144, "min_bytes": 4096, "max_nal": 16777216 }
}
```

`format` identifies the recovery method, not a vendor filesystem. The
parameters are exactly those used for this run.

### `index.json`

```json
{
  "v": 1,
  "image_sha256": "<hex>",
  "entries": [
    {
      "id": 1,
      "channel": null,
      "start_utc": null,
      "end_utc": null,
      "file": "extracted/stream_0001.h264",
      "codec": "h264",
      "image_ranges": [{ "offset": 102400, "length": 1200000 }],
      "bytes": 1200000,
      "sha256": "<hex>",
      "nal_count": 211,
      "clock_note": "format-agnostic carve: no timestamps recovered; order is image offset only",
      "confidence": "low",
      "notes": [
        "the final NAL of each run may include trailing non-video bytes up to the next 00 00 00, 00 00 01 or 00 00 02 sequence"
      ]
    }
  ]
}
```

- `file` is always under `extracted/`.
- `image_ranges` lists every image range the stream's bytes came from, in
  order. More than one range means interleaved data was left out between
  them; each omitted span is a `gaps.json` entry with reason
  `interleaved_data_omitted`.
- `bytes` and `sha256` describe the file in `extracted/` (the concatenation
  of the ranges).
- F0 carving never invents metadata: `channel`, `start_utc` and `end_utc`
  are `null`, and `confidence` is always `low`. A stream's only ordering is
  its position on the image.
- `notes` carries every limit that applies to that entry, so the warning
  travels with the data rather than living only in a README.

### `gaps.json`

```json
{
  "v": 1,
  "image_bytes": 4294967296,
  "carved_bytes": 1200000,
  "gaps": [
    { "offset": 1302400, "length": 5008, "reason": "interleaved_data_omitted" },
    { "offset": 2000000, "length": 30, "reason": "candidate_rejected_too_small" }
  ]
}
```

Reasons:

| Reason | Meaning |
|--------|---------|
| `interleaved_data_omitted` | Non-video data between two joined runs, no longer than `--merge-gap`. |
| `candidate_rejected_no_sps_or_idr` | A run with neither an SPS (type 7) nor an IDR (type 5). Not decodable on its own. |
| `candidate_rejected_too_small` | A run smaller than `--min-bytes`. |
| `nal_exceeds_max_size` | A NAL unit larger than `--max-nal`. Rejected, not buffered; scanning resumes after its start code. |

`carved_bytes` is the total number of bytes copied into `extracted/`
(including any trailing non-video bytes a final NAL swallowed).
`image_bytes - carved_bytes` is image data that was not recovered. It is
**not** itemised: see "Known limits", coverage accounting.

### `parser-log.jsonl`

One JSON object per line, in order: a `start` event, then one `stream` event
per recovered stream, one `gap` event per gap, then a `done` event. It is
append-only for the duration of a run and is covered by `SHA256SUMS`.

### `SHA256SUMS`

`sha256sum` format, one line per file: `<hex>  <relative path>`. Paths use
`/` separators. `SHA256SUMS` does not list itself.

## `verify-package` rules

`verify-package <dir>` returns no problems (exit `0`) only if all of the
following hold. Otherwise it prints each problem and exits `2`.

1. `SHA256SUMS` exists.
2. Every non-blank line parses as `<digest><two spaces><relative path>`.
   A line is rejected if the digest is not exactly 64 characters, or the
   path is empty or not a plain relative path (absolute, drive-prefixed, or
   containing `.` or `..` components).
3. Every listed path exists, is a regular file, and hashes to its listed
   digest.
4. Every file present in the directory tree, except `SHA256SUMS` itself, is
   listed in `SHA256SUMS`. A stray file is a problem. The tree walk does not
   follow symlinks: a symlink is an entry, never a directory.
5. `acquisition.json` and `index.json` exist and parse.
6. Both carry `"v": 1`.
7. `acquisition.json.image_sha256` equals `index.json.image_sha256`.
8. `image.sha256` starts with `acquisition.json.image_sha256`.
9. Every `index.json` entry's `file` is a plain relative path under
   `extracted/`, exists, and its bytes hash to the entry's `sha256` and have
   the entry's `bytes` length.

What `verify-package` deliberately does **not** do: re-run the parser, judge
whether recovery was complete, or check `gaps.json` and `parser.json`
against the image. It establishes that the package is intact and internally
consistent, nothing more. Completeness is `detect` plus the operator's
judgement against `gaps.json`.

## Recovery method (F0)

1. The image is read once, front to back, in bounded memory (8 MiB chunks),
   hashing every byte read.
2. The scanner finds H.264 Annex-B start codes (`00 00 01`, with an optional
   leading zero making it `00 00 00 01`) and reads the NAL unit that
   follows. A NAL payload cannot contain `00 00 00`, `00 00 01` or
   `00 00 02` (emulation prevention), so the first such triple ends the NAL.
3. NAL units whose forbidden bit is set, or whose type is not one of
   `1, 5, 6, 7, 8, 9`, are skipped.
4. NAL units are grouped into runs. Runs separated by at most `--merge-gap`
   bytes are joined; a zero run shorter than 4 KiB is treated as start-code
   padding and included. Other separating bytes are recorded as an
   `interleaved_data_omitted` gap.
5. A run is kept if it contains an SPS or an IDR and is at least
   `--min-bytes`; otherwise it becomes a gap.
6. Each kept run is copied out of the image into `extracted/`, byte-for-byte,
   and hashed.

No byte of a recovered stream is altered, and no byte is invented.

## Known limits (stated, not hidden)

Honesty is the product here. Everything below is a real limit of the current
implementation, not a hypothetical.

### Coverage accounting

- **Unrecovered regions are not itemised.** Only *decisions the parser made*
  become `gaps.json` entries (interleaved omission, rejected candidates,
  oversize NALs). Image bytes that never formed a start code at all — the
  bulk of a proprietary filesystem, leading and trailing slack, encrypted
  regions — produce **no gap entry**. Their existence is visible only as
  `image_bytes - carved_bytes` in `gaps.json`.
- **Consequence:** an image made of pure garbage that contains no start code
  yields zero streams, zero gap entries, and exit code `0`. The exit code
  does **not** signal "nothing was recovered". Read `carved_bytes` against
  `image_bytes`.
- Skipped NAL types (2, 3, 4, 10+, or any unit with the forbidden bit set)
  are dropped **without** a gap entry: they are neither recovered nor
  reported.
- A start code with no following header byte (a truncated start code at end
  of image) is dropped without a gap entry.

### Truncated input

- **Truncated final NAL:** a NAL with no terminator before end of image is
  accepted and ends at end of image, with trailing zero bytes trimmed.
  Whatever was on the image is recovered; nothing is inferred.
- **Truncated start code:** `00 00 01` as the last bytes of the image, with
  no header byte, is not an event and is not recorded.
- **Truncated on a chunk boundary:** the scanner keeps the last two bytes
  across reads, so a start code that straddles a read boundary is still
  found. This is covered by tests, not left to chance.

### Malformed and hostile input

- **Parser is memory-bounded and panic-free against hostile images.** The
  scanner reads 8 MiB at a time, a NAL larger than `--max-nal` is rejected
  rather than buffered, and `extract` fails closed on I/O errors. The
  coverage-guided fuzz targets (`fuzz/fuzz_targets/`, see "Fuzzing") plus
  the in-repo hostile-input test are the evidence for this claim; the numbers
  from the last local run are in `README.md`.
- **Hostile packages:** `verify-package` parses `SHA256SUMS` and the JSON
  records of a package it may not have produced. It rejects absolute,
  drive-prefixed and `.`/`..` paths, requires a 64-character digest, and
  requires every present file to be listed. It does **not** require the digest
  to be hexadecimal (a non-hex digest simply never matches). The tree walk does
  not follow symlinks, so a symlink loop cannot hang it; a symlink is reported
  as a stray entry, and a listed symlink to a regular file is hashed through
  the link.

### Format and metadata

- **H.264 Annex-B only.** H.265, MPEG-4, MJPEG and vendor containers are not
  parsed. Vendor filesystem parsers (Hikvision, Dahua-family `.dav`,
  RAYSHARP) are future work, scoped only when a real, consented disk needs
  one.
- **No timestamps, no channels.** F0 has no filesystem knowledge, so
  `start_utc`, `end_utc` and `channel` are `null` and `confidence` is `low`.
  Recorder clock resets (for example to 1970) cannot be detected yet.
- **A run's final NAL can swallow trailing non-video bytes** up to the next
  `00 00 00`, `00 00 01` or `00 00 02` sequence when no zero padding follows
  it. Every index entry carries a note saying so. This cannot be fixed
  without filesystem knowledge; it is pinned by a test.
- **Streams are raw Annex-B NAL units**, not a container. Some players need
  a container or a frame rate; this tool does not add one and does not guess
  a frame rate.

### Package durability

- **The package is not fsynced.** Files are written and closed; there is no
  `fsync` barrier before the process exits. `SHA256SUMS` is written last, so
  if it is present and `verify-package` is clean, every listed file was
  written and is intact. If `SHA256SUMS` is missing, treat the package as
  incomplete.
- **A package is written once.** `extract` refuses an output directory that
  already contains files. Re-extraction into the same directory is an error,
  not an overwrite.

### Operational

- **Sandboxing is deployment work.** A seccomp profile or container on the
  forensic cradle is not enforced by the binary. The binary does enforce
  that no network-capable crate is in its dependency tree.
- **No vendor disk has been tested.** Carving is verified on synthetic
  images and on a real encoder's stream, not on a recorder's actual
  filesystem. Do not represent F0 output as a complete recovery.
- Parsing vendor formats can raise reverse-engineering and licensing
  questions. Review them before shipping a vendor parser.

## Test plan

| ID | Test | Acceptance |
|----|------|-----------|
| F-T1 | Read-only guarantee | image hash before and after is identical; file opened read-only |
| F-T2 | No network | dependency tree (including fuzz targets) contains no network-capable crate |
| F-T3 | Carve a known H.264 stream from a synthetic image | recovered bytes match the source |
| F-T4 | Corrupt region | recorded in `gaps.json`, not skipped silently |
| F-T5 | Format-agnostic carve | no timestamps or channels invented |
| F-T6 | Fuzz each parser | no crash or hang over the fuzz budget |
| F-T7 | Downstream bundle | the sealed bundle verifies (covered in the custody product) |

F-T1 to F-T6 run in `tests/forensic.rs` and the unit tests in `src/`.
F-T6 additionally runs as coverage-guided fuzzing: see "Fuzzing".

## Fuzzing

Two `cargo-fuzz` (libFuzzer) targets cover the code that touches untrusted
bytes:

| Target | Covers |
|--------|--------|
| `fuzz_nal_scanner` | The Annex-B NAL scanner and stream grouper (`src/scan.rs`, `src/carve.rs`). |
| `fuzz_manifest_parser` | The package manifest parser used by `verify-package` (`src/verify.rs`). |

The corpus is seeded from the test data (`fuzz/seeds/`). Last local campaign,
2026-10-19 (nightly + ASAN, `-max_len=4096 -rss_limit_mb=2048 -timeout=60`):

| Target | Duration | Execs | Final coverage | Result |
|--------|----------|-------|----------------|--------|
| `fuzz_nal_scanner` | 20 min | 23.9M | cov 446 / ft 1568; no new feature for the final 4.0M execs | no crash, timeout or slow unit |
| `fuzz_manifest_parser` | 30 min | 118.7M | cov 2065 / ft 8945; no new edge for the final 45.5M execs | no crash, timeout or slow unit |

Both runs saturated; `fuzz_manifest_parser` coverage includes the in-context
`serde_json` record parsers it also exercises. No artifact was produced.
`fuzz/README.md` has the commands.

Inputs are capped at 4 KiB, so the scanner's `compact()` path (reached only
after 4 MiB of consumed input) is covered by the 22 MiB cross-chunk
integration test, not by fuzzing. That limit is stated rather than implied.

Fuzzing is required before a parser change touches a real disk: a change to
`src/scan.rs`, `src/carve.rs` or the manifest parsing in `src/verify.rs`
must extend `tests/forensic.rs::ft6_hostile_inputs_do_not_panic` and be run
under both fuzz targets.

## Open questions

- Which vendor format first. Interviews decide, not guesswork.
- The legal position on parsing vendor filesystems, which differs by
  jurisdiction.
- Whether encrypted drives are in scope at all.
- Sourcing a variety of real, consented sample disks.
