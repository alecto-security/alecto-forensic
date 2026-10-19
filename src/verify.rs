//! Package verification: SHA256SUMS, per-stream hashes, and image hash consistency.

use std::fs;
use std::path::{Component, Path};

use crate::error::{ForensicError, Result};
use crate::package::{sha256_file, Acquisition, Index, PACKAGE_VERSION};

/// One accepted line of a `SHA256SUMS` manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    pub digest: String,
    pub path: String,
}

/// A manifest path is safe when it is non-empty and made only of normal
/// components. That rejects `/x`, `../x`, `a/../b`, `.`, and on Windows the
/// drive and UNC forms `C:\x`, `C:x`, `\\server\share`.
fn safe_relative_path(rel: &str) -> bool {
    !rel.is_empty()
        && Path::new(rel)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// Parse the text of a `SHA256SUMS` manifest.
///
/// Pure: it touches no filesystem and can be fuzzed directly. Returns the
/// accepted entries, in input order, and one problem string for every malformed
/// or rejected line. A line is rejected when it does not split into a digest
/// and a path on two spaces, when the digest is not exactly 64 characters, or
/// when the path is not a plain relative path.
pub fn parse_manifest(text: &str) -> (Vec<ManifestEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Some((digest, rel)) = line.split_once("  ") else {
            problems.push(format!("SHA256SUMS: malformed line: {line}"));
            continue;
        };
        if digest.len() != 64 || !safe_relative_path(rel) {
            problems.push(format!("SHA256SUMS: rejected line: {line}"));
            continue;
        }
        entries.push(ManifestEntry {
            digest: digest.to_string(),
            path: rel.to_string(),
        });
    }
    (entries, problems)
}

/// Returns a list of problems; empty means the package is intact.
pub fn verify_package(dir: &Path) -> Result<Vec<String>> {
    let sums = match fs::read_to_string(dir.join("SHA256SUMS")) {
        Ok(s) => s,
        Err(_) => return Ok(vec!["SHA256SUMS: missing".into()]),
    };
    let (entries, mut problems) = parse_manifest(&sums);
    let listed: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
    for entry in &entries {
        let path = dir.join(&entry.path);
        if !path.is_file() {
            problems.push(format!("{}: missing", entry.path));
            continue;
        }
        match sha256_file(&path) {
            Ok((actual, _)) if actual == entry.digest => {}
            Ok(_) => problems.push(format!("{}: hash mismatch", entry.path)),
            Err(e) => problems.push(format!("{}: unreadable: {e}", entry.path)),
        }
    }
    // Files present but not covered by the manifest.
    let mut present = Vec::new();
    collect(dir, dir, &mut present)?;
    for rel in present {
        if rel != "SHA256SUMS" && !listed.contains(&rel) {
            problems.push(format!("{rel}: not covered by SHA256SUMS"));
        }
    }

    let acq: Option<Acquisition> = read_json(dir, "acquisition.json", &mut problems);
    let index: Option<Index> = read_json(dir, "index.json", &mut problems);
    if let (Some(acq), Some(index)) = (&acq, &index) {
        if acq.v != PACKAGE_VERSION || index.v != PACKAGE_VERSION {
            problems.push("unsupported package version".into());
        }
        if acq.image_sha256 != index.image_sha256 {
            problems.push("acquisition.json and index.json disagree on the image hash".into());
        }
        if let Ok(line) = fs::read_to_string(dir.join("image.sha256")) {
            if !line.starts_with(&acq.image_sha256) {
                problems.push("image.sha256 does not match acquisition.json".into());
            }
        }
        for e in &index.entries {
            if !safe_relative_path(&e.file) || !e.file.starts_with("extracted/") {
                problems.push(format!("index entry {}: path rejected", e.id));
                continue;
            }
            match sha256_file(&dir.join(&e.file)) {
                Ok((sha, bytes)) => {
                    if sha != e.sha256 || bytes != e.bytes {
                        problems.push(format!("{}: differs from its index entry", e.file));
                    }
                }
                Err(_) => problems.push(format!("{}: missing", e.file)),
            }
        }
    }
    Ok(problems)
}

fn read_json<T: serde::de::DeserializeOwned>(
    dir: &Path,
    name: &str,
    problems: &mut Vec<String>,
) -> Option<T> {
    match fs::read(dir.join(name)) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                problems.push(format!("{name}: unreadable: {e}"));
                None
            }
        },
        Err(_) => {
            problems.push(format!("{name}: missing"));
            None
        }
    }
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(ForensicError::from)? {
        let entry = entry?;
        let p = entry.path();
        // `file_type` does not follow symlinks, so a symlink to a directory is
        // listed as an entry instead of being walked. That keeps a hostile
        // package (for example `loop -> .`) from recursing forever.
        if entry.file_type()?.is_dir() {
            collect(root, &p, out)?;
        } else {
            out.push(
                p.strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn manifest_accepts_well_formed_lines() {
        let text = format!("{H}  acquisition.json\n{H}  extracted/stream_0001.h264\n");
        let (entries, problems) = parse_manifest(&text);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "acquisition.json");
        assert_eq!(entries[1].path, "extracted/stream_0001.h264");
    }

    #[test]
    fn manifest_rejects_malformed_and_escaping_lines() {
        let text = format!(
            "nospace\nshort  file\n{H}  ../outside\n{H}  /etc/passwd\n{H}  ./inside\n\n   \n{H}  ok\n"
        );
        let (entries, problems) = parse_manifest(&text);
        assert_eq!(entries.len(), 1, "only the last line is acceptable");
        assert_eq!(entries[0].path, "ok");
        assert_eq!(problems.len(), 5, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("malformed line: nospace")));
        assert!(problems.iter().any(|p| p.contains("../outside")));
        assert!(problems.iter().any(|p| p.contains("/etc/passwd")));
        assert!(problems.iter().any(|p| p.contains("./inside")));
    }

    #[cfg(windows)]
    #[test]
    fn manifest_rejects_windows_absolute_paths() {
        for path in [r"C:\outside", "C:outside", r"\\server\share\x"] {
            let text = format!("{H}  {path}\n");
            let (entries, problems) = parse_manifest(&text);
            assert!(entries.is_empty(), "accepted {path}");
            assert_eq!(problems.len(), 1);
        }
    }

    #[test]
    fn manifest_accepts_a_non_hex_digest_but_it_can_never_match() {
        // The check is length-based, not hexadecimal. A 64-'z' digest parses
        // and then fails the hash comparison; it cannot let a file through.
        let text = format!("{}  file\n", "z".repeat(64));
        let (entries, problems) = parse_manifest(&text);
        assert!(problems.is_empty());
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn every_non_blank_line_is_accepted_or_reported() {
        let text = "a\nb  c\n\n   \nd\n";
        let (entries, problems) = parse_manifest(text);
        assert_eq!(entries.len() + problems.len(), 3);
    }
}
