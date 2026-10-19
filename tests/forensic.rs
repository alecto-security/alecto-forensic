//! QA matrix F-T1..F-T6; the test plan is in `docs/SPEC.md`.
//! F-T7 (a downstream sealed bundle) is covered outside this repo.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use alecto_forensic::carve::{carve, Params};
use alecto_forensic::package::{extract, sha256_file, AcquisitionInput, Index};
use alecto_forensic::verify::verify_package;
use tempfile::TempDir;

/// Deterministic bytes with no zero byte, so noise can never form a start code.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((x >> 33) as u8 % 255) + 1
        })
        .collect()
}

fn nal(sc4: bool, header: u8, payload_len: usize, seed: u64) -> Vec<u8> {
    let mut v = if sc4 { vec![0, 0, 0, 1] } else { vec![0, 0, 1] };
    v.push(header);
    v.extend(noise(payload_len, seed));
    v
}

/// SPS, PPS, IDR, then `frames` P slices. Ends on a non-zero byte like a real stream.
fn fake_stream(frames: usize, seed: u64) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend(nal(true, 0x67, 20, seed));
    s.extend(nal(true, 0x68, 6, seed + 1));
    s.extend(nal(true, 0x65, 2000, seed + 2));
    for i in 0..frames {
        s.extend(nal(false, 0x41, 800, seed + 10 + i as u64));
    }
    s
}

fn write_image(dir: &Path, name: &str, parts: &[Vec<u8>]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, parts.concat()).unwrap();
    p
}

fn input() -> AcquisitionInput {
    AcquisitionInput {
        operator: "Jane Examiner".into(),
        authorization: "OWNER-AUTH-2026-0001".into(),
        write_blocker: Some("tableau-t35u".into()),
        acquired_at: None,
        image_sha256: None,
    }
}

fn separate() -> Params {
    Params { merge_gap: 1000, ..Params::default() }
}

fn offset_of(parts: &[Vec<u8>], idx: usize) -> u64 {
    parts[..idx].iter().map(|p| p.len() as u64).sum()
}

// F-T3: carve known streams out of a synthetic image, byte-for-byte.
#[test]
fn ft3_carves_known_streams_exactly() {
    let dir = TempDir::new().unwrap();
    let (s1, s2) = (fake_stream(6, 1), fake_stream(9, 2));
    let parts = vec![noise(100_000, 7), s1.clone(), vec![0; 512], noise(50_000, 8), s2.clone(), vec![0; 2048], noise(70_000, 9)];
    let image = write_image(dir.path(), "disk.img", &parts);
    let out = dir.path().join("pkg");
    let summary = extract(&image, &out, &input(), &separate()).unwrap();
    assert_eq!(summary.streams, 2);
    assert_eq!(fs::read(out.join("extracted/stream_0001.h264")).unwrap(), s1);
    assert_eq!(fs::read(out.join("extracted/stream_0002.h264")).unwrap(), s2);
    let index: Index = serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    assert_eq!(index.entries[0].image_ranges[0].offset, offset_of(&parts, 1));
    assert_eq!(index.entries[1].image_ranges[0].offset, offset_of(&parts, 4));
    assert!(verify_package(&out).unwrap().is_empty());
}

// F-T4: omitted and rejected regions are recorded, never silently skipped.
#[test]
fn ft4_interleaved_data_and_rejects_are_recorded_as_gaps() {
    let dir = TempDir::new().unwrap();
    let (s1, s2) = (fake_stream(6, 1), fake_stream(6, 2));
    // A tiny SPS-only fragment: too small to be a recording.
    let fragment = nal(true, 0x67, 30, 99);
    let parts = vec![noise(1000, 1), s1.clone(), vec![0; 8], noise(5000, 2), s2.clone(), vec![0; 100], noise(400_000, 3), fragment];
    let image = write_image(dir.path(), "disk.img", &parts);
    let out = dir.path().join("pkg");
    // Default merge_gap (256 KiB) joins the first two runs and omits the 5 KB between them.
    let summary = extract(&image, &out, &input(), &Params::default()).unwrap();
    assert_eq!(summary.streams, 1);
    assert_eq!(summary.exit_code, 1, "gaps recorded means partial");
    let merged = fs::read(out.join("extracted/stream_0001.h264")).unwrap();
    assert_eq!(merged, [s1, s2].concat());
    let gaps: alecto_forensic::package::Gaps = serde_json::from_slice(&fs::read(out.join("gaps.json")).unwrap()).unwrap();
    let reasons: Vec<&str> = gaps.gaps.iter().map(|g| g.reason.as_str()).collect();
    assert!(reasons.contains(&"interleaved_data_omitted"), "{reasons:?}");
    assert!(reasons.contains(&"candidate_rejected_too_small"), "{reasons:?}");
    let omitted = gaps.gaps.iter().find(|g| g.reason == "interleaved_data_omitted").unwrap();
    assert_eq!(omitted.length, 5008);
    let log = fs::read_to_string(out.join("parser-log.jsonl")).unwrap();
    assert!(log.contains("\"event\":\"gap\""));
}

// Known limit, pinned so it is visible: with no zero byte after a run, its final NAL
// swallows the following bytes until the next terminator. The index warns about it.
#[test]
fn trailing_bytes_without_padding_are_swallowed_and_flagged() {
    let dir = TempDir::new().unwrap();
    let s1 = fake_stream(4, 31);
    let parts = vec![noise(500, 1), s1.clone(), noise(300, 2), vec![0; 64]];
    let image = write_image(dir.path(), "disk.img", &parts);
    let out = dir.path().join("pkg");
    extract(&image, &out, &input(), &separate()).unwrap();
    let got = fs::read(out.join("extracted/stream_0001.h264")).unwrap();
    assert_eq!(got.len(), s1.len() + 300);
    assert!(got.starts_with(&s1));
    let index: Index = serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    assert!(index.entries[0].notes.iter().any(|n| n.contains("trailing non-video bytes")));
}

// F-T5: format-agnostic carving never invents timestamps.
#[test]
fn ft5_no_timestamps_are_invented() {
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(500, 1), fake_stream(5, 3), vec![0; 64]]);
    let out = dir.path().join("pkg");
    extract(&image, &out, &input(), &separate()).unwrap();
    let index: Index = serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    let e = &index.entries[0];
    assert!(e.start_utc.is_none() && e.end_utc.is_none() && e.channel.is_none());
    assert_eq!(e.confidence, "low");
    assert!(e.clock_note.contains("no timestamps"));
}

// F-T1: the image is only ever read. A read-only file extracts fine and is unchanged.
#[test]
fn ft1_image_is_read_only_and_unchanged() {
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(2000, 1), fake_stream(4, 5), vec![0; 100]]);
    let before = sha256_file(&image).unwrap();
    let mut perms = fs::metadata(&image).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&image, perms).unwrap();
    let out = dir.path().join("pkg");
    let summary = extract(&image, &out, &input(), &separate()).unwrap();
    assert_eq!(summary.image_sha256, before.0);
    assert_eq!(sha256_file(&image).unwrap(), before);
    // Make it deletable again for the temp dir cleanup on Windows.
    let mut perms = fs::metadata(&image).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&image, perms).unwrap();
}

// F-T2: no network capability in the dependency tree, including the fuzz
// workspace. `fuzz/Cargo.lock` is committed so this check needs no fuzz run.
#[test]
fn ft2_dependency_tree_has_no_network_crates() {
    let banned = [
        "reqwest", "hyper", "tokio", "axum", "ureq", "isahc", "surf", "curl", "openssl", "native-tls",
        "rustls", "mio", "socket2", "h2", "tower", "warp", "actix", "async-std",
    ];
    let locks = [
        concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"),
        concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/Cargo.lock"),
    ];
    for path in locks {
        let lock = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        for name in banned {
            assert!(
                !lock.contains(&format!("name = \"{name}\"")),
                "network-capable crate {name} is in the dependency tree of {path}"
            );
        }
    }
}

// F-T6: fuzz-style smoke. Hostile input must never panic or hang.
// The coverage-guided harnesses are in `fuzz/`; this stays as a fast,
// deterministic regression net that runs on every `cargo test`.
#[test]
fn ft6_hostile_inputs_do_not_panic() {
    let p = Params { max_nal: 1 << 20, ..Params::default() };
    let run = |data: &[u8]| {
        let c = carve(data, &p).unwrap();
        assert_eq!(c.image_bytes, data.len() as u64);
    };
    run(&[]);
    run(&[0]);
    run(&[0, 0, 1]);
    run(&[0, 0, 1, 0x67]);
    run(&vec![0u8; 1 << 20]);
    run(&vec![0xFFu8; 1 << 20]);
    run(&[0, 0, 1, 0x67].repeat(100_000));
    run(&[0, 0, 0, 1, 0x65, 0x55].repeat(100_000));
    // Unterminated huge NAL.
    let mut huge = vec![0, 0, 1, 0x65];
    huge.extend(vec![0x55u8; 5 << 20]);
    run(&huge);
    // Mutations of a valid stream.
    let base = fake_stream(30, 11);
    let mut x = 12345u64;
    for _ in 0..300 {
        let mut d = base.clone();
        for _ in 0..8 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let i = (x >> 33) as usize % d.len();
            d[i] = (x >> 17) as u8;
        }
        if x.is_multiple_of(3) {
            d.truncate((x >> 20) as usize % d.len());
        }
        run(&d);
    }
}

// Chunk and compaction boundaries: a NAL straddling 8 MiB, streams far apart.
#[test]
fn streams_across_chunk_boundaries_are_intact() {
    let dir = TempDir::new().unwrap();
    let (s1, s2, s3) = (fake_stream(10, 21), fake_stream(10, 22), fake_stream(10, 23));
    let chunk = 8usize << 20;
    let pad1 = chunk - 5000; // s1 starts just before the first chunk boundary
    let parts = vec![noise(pad1, 1), s1.clone(), vec![0; 300], noise(9 << 20, 2), s2.clone(), vec![0; 300], noise(13 << 20, 3), s3.clone(), vec![0; 300]];
    let image = write_image(dir.path(), "big.img", &parts);
    let out = dir.path().join("pkg");
    let summary = extract(&image, &out, &input(), &separate()).unwrap();
    assert_eq!(summary.streams, 3);
    assert_eq!(fs::read(out.join("extracted/stream_0001.h264")).unwrap(), s1);
    assert_eq!(fs::read(out.join("extracted/stream_0002.h264")).unwrap(), s2);
    assert_eq!(fs::read(out.join("extracted/stream_0003.h264")).unwrap(), s3);
    assert_eq!(summary.image_sha256, sha256_file(&image).unwrap().0);
}

// Package integrity.
#[test]
fn verify_package_catches_tamper_and_strays() {
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(500, 1), fake_stream(5, 3), vec![0; 64]]);
    let out = dir.path().join("pkg");
    extract(&image, &out, &input(), &separate()).unwrap();
    assert!(verify_package(&out).unwrap().is_empty());

    let target = out.join("extracted/stream_0001.h264");
    let mut b = fs::read(&target).unwrap();
    b[10] ^= 0xFF;
    fs::write(&target, b).unwrap();
    let problems = verify_package(&out).unwrap();
    assert!(problems.iter().any(|p| p.contains("stream_0001.h264") && p.contains("hash mismatch")), "{problems:?}");

    fs::write(out.join("stray.txt"), b"x").unwrap();
    assert!(verify_package(&out).unwrap().iter().any(|p| p.contains("stray.txt")));
}

#[test]
fn verify_rejects_index_path_outside_the_package() {
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(500, 1), fake_stream(5, 3), vec![0; 64]]);
    let out = dir.path().join("pkg");
    extract(&image, &out, &input(), &separate()).unwrap();

    let mut index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).unwrap()).unwrap();
    index["entries"][0]["file"] = "../outside.h264".into();
    fs::write(out.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();

    let problems = verify_package(&out).unwrap();
    assert!(
        problems.iter().any(|p| p.contains("path rejected")),
        "traversal path in index.json was not rejected: {problems:?}"
    );
}

// A hostile package with a symlink loop must be reported, never walked forever.
#[cfg(unix)]
#[test]
fn hostile_symlink_loop_is_reported_not_followed() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(500, 1), fake_stream(5, 3), vec![0; 64]]);
    let out = dir.path().join("pkg");
    extract(&image, &out, &input(), &separate()).unwrap();
    symlink(".", out.join("loopdir")).unwrap();
    let problems = verify_package(&out).unwrap();
    assert!(problems.iter().any(|p| p.contains("loopdir")), "{problems:?}");
}

#[test]
fn acquisition_rules_are_enforced() {
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(500, 1), fake_stream(5, 3), vec![0; 64]]);

    let mut no_auth = input();
    no_auth.authorization = String::new();
    assert!(extract(&image, &dir.path().join("a"), &no_auth, &separate()).is_err());

    let mut no_op = input();
    no_op.operator = "x".into();
    assert!(extract(&image, &dir.path().join("b"), &no_op, &separate()).is_err());

    let mut wrong_hash = input();
    wrong_hash.image_sha256 = Some("0".repeat(64));
    let err = extract(&image, &dir.path().join("c"), &wrong_hash, &separate()).unwrap_err();
    assert!(err.to_string().contains("image hash mismatch"));
    assert!(!dir.path().join("c").exists(), "nothing written on a hash mismatch");

    let mut right_hash = input();
    right_hash.image_sha256 = Some(sha256_file(&image).unwrap().0);
    extract(&image, &dir.path().join("d"), &right_hash, &separate()).unwrap();

    // A package is written once.
    assert!(extract(&image, &dir.path().join("d"), &input(), &separate()).is_err());
}

// CLI: exit codes and the no-op `detect`.
#[test]
fn cli_detect_extract_verify() {
    let dir = TempDir::new().unwrap();
    let image = write_image(dir.path(), "disk.img", &[noise(500, 1), fake_stream(5, 3), vec![0; 64]]);
    let bin = env!("CARGO_BIN_EXE_alecto-forensic");

    let out = Command::new(bin).args(["detect", image.to_str().unwrap()]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("streams  1"));
    assert!(!dir.path().join("pkg").exists(), "detect writes nothing");

    let pkg = dir.path().join("pkg");
    let status = Command::new(bin)
        .args(["extract", image.to_str().unwrap(), "--out", pkg.to_str().unwrap(), "--operator", "Jane Examiner", "--authorization", "OWNER-AUTH-1", "--merge-gap", "1000"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));

    let v = Command::new(bin).args(["verify-package", pkg.to_str().unwrap()]).output().unwrap();
    assert_eq!(v.status.code(), Some(0));

    // Missing authorization is a config error (exit 3), and writes nothing.
    let bad = dir.path().join("bad");
    let status = Command::new(bin)
        .args(["extract", image.to_str().unwrap(), "--out", bad.to_str().unwrap(), "--operator", "Jane Examiner"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(3));
    assert!(!bad.exists());

    fs::write(pkg.join("index.json"), b"{}").unwrap();
    let v = Command::new(bin).args(["verify-package", pkg.to_str().unwrap()]).output().unwrap();
    assert_eq!(v.status.code(), Some(2));
}

// Realism check: a stream produced by a real encoder survives carving unchanged.
#[test]
fn real_h264_from_ffmpeg_round_trips() {
    let dir = TempDir::new().unwrap();
    let stream = dir.path().join("real.h264");
    let ok = Command::new("ffmpeg")
        .args(["-v", "error", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10", "-t", "3", "-c:v", "libx264", "-bsf:v", "h264_mp4toannexb", "-f", "h264", "-y"])
        .arg(&stream)
        .status();
    if !matches!(ok, Ok(s) if s.success()) {
        eprintln!("ffmpeg unavailable, skipping");
        return;
    }
    let real = fs::read(&stream).unwrap();
    // Real encoders can end a stream with trailing zero bytes; trim the way the carver does.
    let mut trimmed = real.clone();
    while trimmed.last() == Some(&0) {
        trimmed.pop();
    }
    let parts = vec![noise(30_000, 4), real, vec![0; 1024], noise(10_000, 5)];
    let image = write_image(dir.path(), "disk.img", &parts);
    let out = dir.path().join("pkg");
    let summary = extract(&image, &out, &input(), &separate()).unwrap();
    assert_eq!(summary.streams, 1);
    assert_eq!(fs::read(out.join("extracted/stream_0001.h264")).unwrap(), trimmed);

    // And ffprobe agrees it is H.264 with frames.
    let probe = Command::new("ffprobe")
        .args(["-v", "error", "-select_streams", "v:0", "-count_frames", "-show_entries", "stream=codec_name,nb_read_frames", "-of", "csv=p=0"])
        .arg(out.join("extracted/stream_0001.h264"))
        .output();
    if let Ok(p) = probe {
        let text = String::from_utf8_lossy(&p.stdout).to_string();
        assert!(text.contains("h264"), "{text}");
        assert!(text.contains("30"), "expected 30 frames, got {text}");
    }
}
