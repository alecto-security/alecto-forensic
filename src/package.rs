//! Contract C3: the extraction package. Written once, into a new directory.
//!
//! ```text
//! extraction-<id>/
//! ├── acquisition.json   image hash, operator, authorization, write-blocker
//! ├── image.sha256       hash of the image as received
//! ├── parser.json        tool, version, format id, parameters
//! ├── index.json         one entry per recovered stream
//! ├── extracted/         recovered streams, byte-exact as found
//! ├── gaps.json          regions omitted or rejected, with reasons
//! ├── parser-log.jsonl   append-only record of every decision
//! └── SHA256SUMS
//! ```

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::carve::{carve, Gap, Params, Range};
use crate::error::{ForensicError, Result, EXIT_OK, EXIT_PARTIAL};

pub const PACKAGE_VERSION: u32 = 1;
pub const FORMAT_ID: &str = "h264-annexb-carve";

/// What the operator supplies about the acquisition.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionInput {
    pub operator: String,
    /// Reference to the owner's authorization (case number, signed form id).
    pub authorization: String,
    pub write_blocker: Option<String>,
    pub acquired_at: Option<String>,
    /// If the imaging tool already hashed the image, it must match what we read.
    pub image_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acquisition {
    pub v: u32,
    pub image_file: String,
    pub image_sha256: String,
    pub image_bytes: u64,
    pub operator: String,
    pub acquired_at: String,
    pub write_blocker: Option<String>,
    pub authorization: String,
    pub tool: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub id: u32,
    /// Recorder channel, when the format carries it. Unknown for format-agnostic carving.
    pub channel: Option<u32>,
    pub start_utc: Option<String>,
    pub end_utc: Option<String>,
    pub file: String,
    pub codec: String,
    /// Where the bytes came from in the image. More than one range means
    /// interleaved data was left out (see gaps.json).
    pub image_ranges: Vec<Range>,
    pub bytes: u64,
    pub sha256: String,
    pub nal_count: u64,
    pub clock_note: String,
    /// `high` | `medium` | `low`
    pub confidence: String,
    /// Limits an examiner must know about this entry.
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub v: u32,
    pub image_sha256: String,
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gaps {
    pub v: u32,
    pub image_bytes: u64,
    pub carved_bytes: u64,
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub streams: usize,
    pub gaps: usize,
    pub image_sha256: String,
    pub exit_code: i32,
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut f = File::create(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex::encode(h.finalize()), total))
}

fn log_line(log: &mut File, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *log, &value)?;
    log.write_all(b"\n")?;
    Ok(())
}

/// Extract an image into a new package directory. The image is opened read-only
/// and never written. `out` must not already contain files.
pub fn extract(
    image: &Path,
    out: &Path,
    input: &AcquisitionInput,
    params: &Params,
) -> Result<Summary> {
    if input.operator.trim().len() < 3 {
        return Err(ForensicError::config("operator required (min 3 characters)"));
    }
    if input.authorization.trim().len() < 3 {
        return Err(ForensicError::config(
            "authorization reference required (owner authority for reading this disk)",
        ));
    }
    if out.exists() && fs::read_dir(out)?.next().is_some() {
        return Err(ForensicError::config(format!(
            "output directory {} is not empty; a package is written once",
            out.display()
        )));
    }
    let image_name = image
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ForensicError::config("image path has no file name"))?
        .to_string();

    // Pass 1: scan, hash, group. Read-only.
    let carved = carve(File::open(image)?, params)?;
    if let Some(expected) = &input.image_sha256 {
        if !expected.eq_ignore_ascii_case(&carved.image_sha256) {
            return Err(ForensicError::fail(format!(
                "image hash mismatch: acquisition says {expected}, image reads as {}; refusing to extract",
                carved.image_sha256
            )));
        }
    }

    fs::create_dir_all(out.join("extracted"))?;
    let mut log = File::create(out.join("parser-log.jsonl"))?;
    log_line(
        &mut log,
        serde_json::json!({"event": "start", "ts": now(), "image": image_name, "format": FORMAT_ID}),
    )?;

    // Pass 2: copy ranges out of the image (still read-only).
    let mut img = File::open(image)?;
    let mut entries = Vec::new();
    let mut carved_bytes = 0u64;
    for (i, stream) in carved.streams.iter().enumerate() {
        let id = (i + 1) as u32;
        let rel = format!("extracted/stream_{id:04}.h264");
        let mut dst = File::create(out.join(&rel))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        for r in &stream.ranges {
            img.seek(SeekFrom::Start(r.offset))?;
            let mut left = r.length;
            let mut buf = vec![0u8; 1 << 20];
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = img.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(ForensicError::fail("image ended while copying a range"));
                }
                dst.write_all(&buf[..n])?;
                hasher.update(&buf[..n]);
                total += n as u64;
                left -= n as u64;
            }
        }
        carved_bytes += total;
        let sha = hex::encode(hasher.finalize());
        log_line(
            &mut log,
            serde_json::json!({"event": "stream", "id": id, "ranges": stream.ranges, "bytes": total, "sha256": sha, "nal_count": stream.nal_count}),
        )?;
        entries.push(IndexEntry {
            id,
            channel: None,
            start_utc: None,
            end_utc: None,
            file: rel,
            codec: "h264".into(),
            image_ranges: stream.ranges.clone(),
            bytes: total,
            sha256: sha,
            nal_count: stream.nal_count,
            clock_note: "format-agnostic carve: no timestamps recovered; order is image offset only".into(),
            confidence: "low".into(),
            notes: vec![
                "the final NAL of each run may include trailing non-video bytes up to the next 00 00 00, 00 00 01 or 00 00 02 sequence".into(),
            ],
        });
    }
    for g in &carved.gaps {
        log_line(
            &mut log,
            serde_json::json!({"event": "gap", "offset": g.offset, "length": g.length, "reason": g.reason}),
        )?;
    }
    log_line(
        &mut log,
        serde_json::json!({"event": "done", "ts": now(), "streams": entries.len(), "gaps": carved.gaps.len()}),
    )?;
    drop(log);

    write_json(
        &out.join("acquisition.json"),
        &Acquisition {
            v: PACKAGE_VERSION,
            image_file: image_name.clone(),
            image_sha256: carved.image_sha256.clone(),
            image_bytes: carved.image_bytes,
            operator: input.operator.trim().to_string(),
            acquired_at: input.acquired_at.clone().unwrap_or_else(now),
            write_blocker: input.write_blocker.clone(),
            authorization: input.authorization.trim().to_string(),
            tool: format!("alecto-forensic {} extract", env!("CARGO_PKG_VERSION")),
        },
    )?;
    fs::write(
        out.join("image.sha256"),
        format!("{}  {}\n", carved.image_sha256, image_name),
    )?;
    write_json(
        &out.join("parser.json"),
        &serde_json::json!({
            "v": PACKAGE_VERSION,
            "tool": "alecto-forensic",
            "version": env!("CARGO_PKG_VERSION"),
            "format": FORMAT_ID,
            "params": {
                "merge_gap": params.merge_gap,
                "min_bytes": params.min_bytes,
                "max_nal": params.max_nal,
            },
        }),
    )?;
    write_json(
        &out.join("index.json"),
        &Index {
            v: PACKAGE_VERSION,
            image_sha256: carved.image_sha256.clone(),
            entries,
        },
    )?;
    write_json(
        &out.join("gaps.json"),
        &Gaps {
            v: PACKAGE_VERSION,
            image_bytes: carved.image_bytes,
            carved_bytes,
            gaps: carved.gaps.clone(),
        },
    )?;
    write_sums(out)?;

    Ok(Summary {
        streams: carved.streams.len(),
        gaps: carved.gaps.len(),
        image_sha256: carved.image_sha256,
        exit_code: if carved.gaps.is_empty() { EXIT_OK } else { EXIT_PARTIAL },
    })
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            collect_files(root, &p, out)?;
        } else {
            let rel = p
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            if rel != "SHA256SUMS" {
                out.push(rel);
            }
        }
    }
    Ok(())
}

fn write_sums(root: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    let mut body = String::new();
    for rel in files {
        let (sha, _) = sha256_file(&root.join(&rel))?;
        body.push_str(&format!("{sha}  {rel}\n"));
    }
    fs::write(root.join("SHA256SUMS"), body)?;
    Ok(())
}
