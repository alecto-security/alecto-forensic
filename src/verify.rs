//! Package verification: SHA256SUMS, per-stream hashes, and image hash consistency.

use std::fs;
use std::path::Path;

use crate::error::{ForensicError, Result};
use crate::package::{sha256_file, Acquisition, Index, PACKAGE_VERSION};

/// Returns a list of problems; empty means the package is intact.
pub fn verify_package(dir: &Path) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    let sums = match fs::read_to_string(dir.join("SHA256SUMS")) {
        Ok(s) => s,
        Err(_) => return Ok(vec!["SHA256SUMS: missing".into()]),
    };
    let mut listed = Vec::new();
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let Some((digest, rel)) = line.split_once("  ") else {
            problems.push(format!("SHA256SUMS: malformed line: {line}"));
            continue;
        };
        if digest.len() != 64 || rel.contains("..") || rel.starts_with('/') {
            problems.push(format!("SHA256SUMS: rejected line: {line}"));
            continue;
        }
        listed.push(rel.to_string());
        let path = dir.join(rel);
        if !path.is_file() {
            problems.push(format!("{rel}: missing"));
            continue;
        }
        match sha256_file(&path) {
            Ok((actual, _)) if actual == digest => {}
            Ok(_) => problems.push(format!("{rel}: hash mismatch")),
            Err(e) => problems.push(format!("{rel}: unreadable: {e}")),
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
            if e.file.contains("..") || e.file.starts_with('/') || !e.file.starts_with("extracted/") {
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
        let p = entry?.path();
        if p.is_dir() {
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
