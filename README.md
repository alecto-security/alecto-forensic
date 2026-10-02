# alecto-forensic

Read a recorder's disk **image** (never the disk), recover the video, and write an extraction package. This codebase parses untrusted binary data, so it is isolated on purpose: no network, no writes to the source, and no evidence bundles. `alecto-gateway ingest` turns a package into a sealed bundle.

**Status:** MVP, format-agnostic carving (F0) only. Spec: `alecto-docs/engineering/build/forensic-spec.md`. Boundaries: `alecto-docs/engineering/architecture/codebase-map.md` and ADR-0005.

```bash
cargo test
cargo run -- detect disk.img                       # report only, writes nothing
cargo run -- extract disk.img --out ./pkg \
  --operator "Jane Examiner" --authorization "OWNER-AUTH-2026-0001" --write-blocker tableau-t35u
cargo run -- verify-package ./pkg
```

Exit codes: `0` clean, `1` package written with gaps recorded, `2` failure, `3` config error (for example no authorization reference).

## Workflow

```text
1. Owner authorizes reading the disk
2. Hardware write-blocker + imaging tool -> disk.img (outside this repo)
3. alecto-forensic extract disk.img --out pkg   (read-only, hashes every byte)
4. alecto-gateway ingest pkg ...                (gateway repo; seals the bundle)
```

## What F0 does

Scans the image for H.264 Annex-B NAL units, groups runs into candidate streams, and copies them out byte-for-byte. It needs no filesystem knowledge, so:

- `confidence` is always `low`, and timestamps and channels are `null`. Nothing is invented.
- Runs separated by up to `--merge-gap` bytes (default 256 KiB) are joined; the omitted bytes are listed in `gaps.json` as `interleaved_data_omitted`, and `index.json` lists every image range a stream came from.
- Candidates with no SPS or IDR, or under `--min-bytes`, are rejected and recorded as gaps. NALs larger than `--max-nal` are rejected, not buffered.
- Memory stays bounded: the image is read once in 8 MiB chunks.

## Known limits (stated, not hidden)

- **Trailing bytes:** a run's final NAL ends at the next `00 00 00/01/02` sequence. If non-video bytes follow it with no zero padding, they are included in that NAL. Every index entry carries a note saying so.
- **H.264 Annex-B only.** H.265 and vendor containers are not parsed. Vendor filesystem parsers (Hikvision, Dahua, RAYSHARP) come only when a real consented disk needs one.
- **No timestamps** until a vendor parser exists. Recorder clock resets (for example to 1970) cannot yet be detected.
- **Fuzzing:** `tests/forensic.rs` has a deterministic hostile-input smoke test. Coverage-guided `cargo-fuzz` is still required before this touches real disks.
- **Sandboxing** (seccomp or a container on the cradle) is deployment work, not enforced by the binary. The test suite does enforce that no network-capable crate is in the dependency tree.
- Parsing vendor formats can raise reverse-engineering and licensing questions. Counsel review first, per `alecto-docs/operations/legal-gates.md`.

## Contract C3

See `src/package.rs` for the package layout and `index.json` schema. Every file is covered by `SHA256SUMS`; `verify-package` also checks each stream against its index entry and the image hash against `acquisition.json`.
