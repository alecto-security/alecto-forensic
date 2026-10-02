# AGENTS.md: AI entry point for alecto-forensic

Instructions for AI coding agents working in this repo. Read fully before writing code.

## Repo purpose

Read a recorder's disk **image**, recover video, and write an extraction package. This repo parses untrusted binary data and is isolated on purpose.

## Non-negotiable rules

1. **No network, ever.** No network-capable crate may enter `Cargo.lock`; `tests/forensic.rs` fails the build if one does.
2. **Never write to the image or any source.** Open read-only. Hash every byte read.
3. **Never write evidence bundles.** `alecto-gateway ingest` seals packages. This repo writes packages only.
4. **Never invent data.** No timestamps, channels or confidence the parser did not earn. Unknown is `null`, F0 confidence is `low`.
5. **Never skip silently.** Omitted or rejected regions go to `gaps.json` with a reason.
6. **Parser changes need hostile-input coverage.** Extend `ft6_hostile_inputs_do_not_panic`; run `cargo-fuzz` before any real disk.
7. **Authority is required.** `extract` refuses without an operator and an authorization reference.
8. **Package schema is a contract (C3).** Change it with a version bump and update `alecto-gateway/src/ingest.rs`.

## Source of truth

Spec: sibling `alecto-docs/engineering/build/forensic-spec.md`. Boundaries: `alecto-docs/engineering/architecture/codebase-map.md`.

## Stack

Rust, `clap` CLI, no async runtime, streaming scan in bounded memory.
