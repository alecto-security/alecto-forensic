#![no_main]
//! Coverage-guided fuzzing of the package manifest parser used by
//! `verify-package`, plus the JSON records that `verify-package` reads.
//!
//! `verify-package` may be run on a package this tool did not produce, so both
//! the `SHA256SUMS` parser and the JSON records must survive hostile bytes.
//!
//! Invariants checked on every input:
//!
//! - no panic, on either grammar;
//! - every accepted manifest entry has a 64-character digest and a relative
//!   path that cannot traverse out of the package directory;
//! - parsing is deterministic, and every non-blank line is either accepted or
//!   reported as a problem — nothing disappears silently.

use std::path::{Component, Path};

use alecto_forensic::package::{Acquisition, Gaps, Index};
use alecto_forensic::verify::parse_manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (entries, problems) = parse_manifest(&text);

    for e in &entries {
        assert_eq!(e.digest.len(), 64, "accepted a digest that is not 64 chars");
        assert!(!e.path.starts_with('/'), "accepted an absolute path: {}", e.path);
        assert!(
            Path::new(&e.path)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "accepted a non-normal path: {}",
            e.path
        );
    }
    let lines = text.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(
        entries.len() + problems.len(),
        lines,
        "a line was neither accepted nor reported"
    );

    // Deterministic: the same text always parses the same way.
    let (entries_again, problems_again) = parse_manifest(&text);
    assert_eq!(entries, entries_again);
    assert_eq!(problems, problems_again);

    // Hostile JSON in the same input must never panic the record parsers.
    // Gated on a JSON-looking start so the JSON grammar does not dominate the
    // manifest corpus; `verify-package` reads these records from packages it
    // did not produce.
    if data.len() <= 64 * 1024 && data.starts_with(b"{") {
        let _ = serde_json::from_slice::<Index>(data);
        let _ = serde_json::from_slice::<Acquisition>(data);
        let _ = serde_json::from_slice::<Gaps>(data);
    }
});
