//! Regenerate the committed fuzz seeds under `fuzz/seeds/`.
//!
//! The seed bytes are produced by the same deterministic helpers the
//! integration tests use, so the fuzz corpus starts from the exact shapes that
//! already have named tests (`tests/forensic.rs`).
//!
//! ```console
//! cargo run --example gen_fuzz_corpus
//! ```

use std::fs;
use std::path::{Path, PathBuf};

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

fn seeds_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds")
}

fn write(dir: &str, name: &str, bytes: &[u8]) {
    let dir = seeds_root().join(dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), bytes).unwrap();
}

fn scanner_seeds() {
    let d = "fuzz_nal_scanner";
    write(d, "empty", &[]);
    write(d, "one-zero", &[0]);
    write(d, "start-code-3", &[0, 0, 1]);
    write(d, "sps-only", &[0, 0, 1, 0x67]);
    write(d, "zeros-4k", &vec![0u8; 4096]);
    write(d, "ff-4k", &vec![0xFFu8; 4096]);
    write(d, "noise-4k", &noise(4096, 7));
    write(d, "sc3-repeat", &[0, 0, 1, 0x67].repeat(64));
    write(d, "sc4-repeat", &[0, 0, 0, 1, 0x65, 0x55].repeat(64));

    // One clean (small) stream surrounded by noise.
    write(
        d,
        "one-stream",
        &[noise(200, 1), fake_stream(0, 3), vec![0; 64]].concat(),
    );
    // Two runs joined across a 500-byte interleaved gap, then a 2 KB gap, then
    // an SPS-only fragment: exercises merge, split and rejection together.
    let mut two = noise(100, 1);
    two.extend_from_slice(&nal(true, 0x67, 20, 2));
    two.extend_from_slice(&nal(true, 0x65, 300, 3));
    two.extend_from_slice(&[0; 8]);
    two.extend_from_slice(&noise(500, 4));
    two.extend_from_slice(&nal(true, 0x67, 20, 5));
    two.extend_from_slice(&nal(true, 0x65, 300, 6));
    two.extend_from_slice(&[0; 100]);
    two.extend_from_slice(&noise(2000, 7));
    two.extend_from_slice(&nal(true, 0x67, 30, 8));
    write(d, "two-streams-gap", &two);
    // The pinned trailing-bytes case: a run followed by noise with no zero padding.
    write(
        d,
        "trailing-bytes",
        &[noise(200, 1), fake_stream(0, 31), noise(100, 2), vec![0; 32]].concat(),
    );
    // A NAL larger than the harness `max_nal` (2048): rejected, not buffered.
    write(
        d,
        "oversize-nal",
        &[vec![0, 0, 1, 0x65], vec![0x55u8; 3000]].concat(),
    );
    // A start code with no header byte, at end of image.
    write(d, "truncated-start-code", &[noise(100, 5), vec![0, 0, 1]].concat());
    // A NAL with no terminator: it ends at end of image.
    write(
        d,
        "unterminated-nal",
        &[vec![0, 0, 1, 0x65], vec![0x11u8; 1000]].concat(),
    );
}

fn manifest_seeds() {
    let d = "fuzz_manifest_parser";
    let hex = "a".repeat(64);
    let hex_b = "b".repeat(64);

    write(
        d,
        "valid",
        format!("{hex}  acquisition.json\n{hex_b}  extracted/stream_0001.h264\n").as_bytes(),
    );
    write(
        d,
        "malformed",
        b"not-a-hash  file\nnospace\n\n   \ndeadbeef  short\n".as_slice(),
    );
    write(d, "traversal", format!("{hex}  ../outside\n").as_bytes());
    write(d, "absolute", format!("{hex}  /etc/shadow\n").as_bytes());
    write(d, "long-digest", format!("{}  file\n", "a".repeat(65)).as_bytes());
    // A non-hex digest is accepted by the length check; it simply never matches.
    write(d, "non-hex-digest", format!("{}  file\n", "z".repeat(64)).as_bytes());
    write(d, "empty-lines", b"\n\n  \n\t\n".as_slice());
    write(
        d,
        "index-json",
        br#"{"v":1,"image_sha256":"aa","entries":[]}"#.as_slice(),
    );
}

fn main() {
    scanner_seeds();
    manifest_seeds();
    println!("seeds written under {}", seeds_root().display());
}
