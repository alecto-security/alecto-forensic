#![no_main]
//! Coverage-guided fuzzing of the Annex-B NAL scanner and the stream grouper.
//!
//! Invariants checked on every input (all of them must hold for *hostile*
//! bytes, not just well-formed video):
//!
//! - the scanner never panics and every NAL lies inside the input, is
//!   non-empty, uses a known NAL type, and never overlaps the previous NAL;
//! - a NAL payload never contains `00 00 00`, `00 00 01` or `00 00 02`
//!   (the Annex-B emulation-prevention promise the terminator search relies on);
//! - `carve` hashes every byte it reads (`image_sha256` covers the whole input)
//!   and every reported range and gap lies inside the input;
//! - a stream only survives if it has an SPS or an IDR and meets `min_bytes`.
//!
//! A small read chunk is used deliberately: it hits the cross-chunk boundary
//! logic on every few kilobytes instead of every 8 MiB, and it is roughly a
//! thousand times faster to fuzz. It does not change the bytes seen.

use alecto_forensic::carve::{carve_with_chunk, Params};
use alecto_forensic::scan::{Event, Scanner};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

/// Deliberately small: exercises the read-boundary code paths constantly.
const CHUNK: usize = 1024;

/// Upper bound on an input; kept in step with `-max_len` in the run docs.
const MAX_LEN: usize = 1 << 12;

fn params() -> Params {
    Params {
        merge_gap: 1024,
        min_bytes: 64,
        max_nal: 2048,
    }
}

/// True when `hay` contains `00 00 0X` with `X <= 2`.
fn has_start_or_terminator(hay: &[u8]) -> bool {
    hay.windows(3).any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 2)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return;
    }
    let p = params();

    // 1. The scanner on its own.
    let mut prev_end = 0u64;
    let mut scanner = Scanner::with_read_chunk(data, p.max_nal, CHUNK);
    while let Some(ev) = scanner.next_event().expect("a slice never errors") {
        match ev {
            Event::Nal(n) => {
                assert!(
                    matches!(n.nal_type, 1 | 5 | 6 | 7 | 8 | 9),
                    "unknown NAL type {}",
                    n.nal_type
                );
                assert!(n.sc_offset < n.end, "empty NAL");
                assert!((n.end as usize) <= data.len(), "NAL ends past the input");
                assert!(n.sc_offset >= prev_end, "NALs overlap");
                // Past the start code and header there must be no new start code
                // and no terminator, or the scanner ended this NAL too early.
                let from = n.sc_offset as usize + 4;
                let to = n.end as usize;
                assert!(from <= to, "NAL shorter than its start code");
                assert!(
                    !has_start_or_terminator(&data[from..to]),
                    "payload contains 00 00 0X"
                );
                prev_end = n.end;
            }
            Event::Rejected { offset, reason } => {
                assert_eq!(reason, "nal_exceeds_max_size");
                assert!((offset as usize) <= data.len(), "rejected offset past the input");
            }
        }
    }

    // 2. The full carve path over the same bytes.
    let carved = carve_with_chunk(data, &p, CHUNK).expect("a slice never errors");
    assert_eq!(carved.image_bytes, data.len() as u64);
    let mut hasher = Sha256::new();
    hasher.update(data);
    assert_eq!(carved.image_sha256, hex::encode(hasher.finalize()));

    for s in &carved.streams {
        assert!(s.has_sps || s.has_idr, "kept a stream with no SPS and no IDR");
        assert!(s.bytes() >= p.min_bytes, "kept a stream under min_bytes");
        let mut total = 0u64;
        let mut prev_end = 0u64;
        for (i, r) in s.ranges.iter().enumerate() {
            assert!(r.length > 0, "empty range");
            assert!((r.offset + r.length) as usize <= data.len(), "range past the input");
            if i > 0 {
                assert!(r.offset >= prev_end, "ranges out of order");
            }
            prev_end = r.offset + r.length;
            total += r.length;
        }
        assert_eq!(total, s.bytes());
    }
    for g in &carved.gaps {
        assert!((g.offset + g.length) as usize <= data.len(), "gap past the input");
        assert!(!g.reason.is_empty());
    }
});
