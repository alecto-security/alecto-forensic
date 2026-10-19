//! F0: format-agnostic H.264 carving. Groups NALs from the scanner into
//! candidate streams. No filesystem knowledge, so confidence is always low and
//! timestamps are unknown.

use std::io::Read;

use serde::{Deserialize, Serialize};

use crate::scan::{Event, Scanner};

#[derive(Debug, Clone)]
pub struct Params {
    /// Join runs separated by at most this many bytes of other data (interleaved
    /// audio, index blocks). The omitted bytes are recorded as gaps.
    pub merge_gap: u64,
    /// Candidates smaller than this are rejected as noise.
    pub min_bytes: u64,
    /// Largest NAL accepted. Larger candidates are rejected, not buffered.
    pub max_nal: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            merge_gap: 256 * 1024,
            min_bytes: 4096,
            max_nal: 16 << 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    pub ranges: Vec<Range>,
    pub nal_count: u64,
    pub has_sps: bool,
    pub has_idr: bool,
}

impl Stream {
    pub fn bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.length).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    pub offset: u64,
    pub length: u64,
    pub reason: String,
}

#[derive(Debug)]
pub struct Carved {
    pub streams: Vec<Stream>,
    pub gaps: Vec<Gap>,
    pub image_sha256: String,
    pub image_bytes: u64,
}

/// Bytes of zeros between NALs are start-code padding, not other data.
const PADDING_MAX: u64 = 4096;

struct Building {
    stream: Stream,
    last_end: u64,
    omitted: Vec<Gap>,
}

pub fn carve<R: Read>(reader: R, params: &Params) -> std::io::Result<Carved> {
    carve_with(reader, params, None)
}

/// Like [`carve`], but reads in `chunk`-byte steps instead of the default
/// 8 MiB. Tests and fuzz targets use a small chunk to exercise the
/// cross-chunk boundary logic and to run far faster. It does not change which
/// bytes are read or what is recovered.
pub fn carve_with_chunk<R: Read>(
    reader: R,
    params: &Params,
    chunk: usize,
) -> std::io::Result<Carved> {
    carve_with(reader, params, Some(chunk))
}

fn carve_with<R: Read>(
    reader: R,
    params: &Params,
    chunk: Option<usize>,
) -> std::io::Result<Carved> {
    let mut scanner = match chunk {
        Some(chunk) => Scanner::with_read_chunk(reader, params.max_nal, chunk),
        None => Scanner::new(reader, params.max_nal),
    };
    let mut streams: Vec<Stream> = Vec::new();
    let mut gaps: Vec<Gap> = Vec::new();
    let mut current: Option<Building> = None;

    let finish = |b: Building, streams: &mut Vec<Stream>, gaps: &mut Vec<Gap>| {
        let bytes = b.stream.bytes();
        let first = b.stream.ranges.first().map_or(0, |r| r.offset);
        if !(b.stream.has_sps || b.stream.has_idr) {
            gaps.push(Gap {
                offset: first,
                length: bytes,
                reason: "candidate_rejected_no_sps_or_idr".into(),
            });
        } else if bytes < params.min_bytes {
            gaps.push(Gap {
                offset: first,
                length: bytes,
                reason: "candidate_rejected_too_small".into(),
            });
        } else {
            gaps.extend(b.omitted);
            streams.push(b.stream);
        }
    };

    while let Some(ev) = scanner.next_event()? {
        match ev {
            Event::Rejected { offset, reason } => gaps.push(Gap {
                offset,
                length: 0,
                reason: reason.into(),
            }),
            Event::Nal(n) => {
                let (is_sps, is_idr) = (n.nal_type == 7, n.nal_type == 5);
                match current.take() {
                    Some(mut b) => {
                        let gap = n.sc_offset - b.last_end;
                        if n.gap_zero && gap <= PADDING_MAX {
                            // Contiguous: extend the last range over the padding and the NAL.
                            let last = b.stream.ranges.last_mut().expect("range exists");
                            last.length = n.end - last.offset;
                        } else if gap <= params.merge_gap {
                            b.omitted.push(Gap {
                                offset: b.last_end,
                                length: gap,
                                reason: "interleaved_data_omitted".into(),
                            });
                            b.stream.ranges.push(Range {
                                offset: n.sc_offset,
                                length: n.end - n.sc_offset,
                            });
                        } else {
                            finish(b, &mut streams, &mut gaps);
                            current = Some(Building {
                                stream: Stream {
                                    ranges: vec![Range {
                                        offset: n.sc_offset,
                                        length: n.end - n.sc_offset,
                                    }],
                                    nal_count: 0,
                                    has_sps: false,
                                    has_idr: false,
                                },
                                last_end: n.end,
                                omitted: Vec::new(),
                            });
                            let cur = current.as_mut().expect("just set");
                            cur.stream.nal_count += 1;
                            cur.stream.has_sps |= is_sps;
                            cur.stream.has_idr |= is_idr;
                            continue;
                        }
                        b.last_end = n.end;
                        b.stream.nal_count += 1;
                        b.stream.has_sps |= is_sps;
                        b.stream.has_idr |= is_idr;
                        current = Some(b);
                    }
                    None => {
                        current = Some(Building {
                            stream: Stream {
                                ranges: vec![Range {
                                    offset: n.sc_offset,
                                    length: n.end - n.sc_offset,
                                }],
                                nal_count: 1,
                                has_sps: is_sps,
                                has_idr: is_idr,
                            },
                            last_end: n.end,
                            omitted: Vec::new(),
                        });
                    }
                }
            }
        }
    }
    if let Some(b) = current.take() {
        finish(b, &mut streams, &mut gaps);
    }
    let (image_sha256, image_bytes) = scanner.finish()?;
    gaps.sort_by_key(|g| g.offset);
    Ok(Carved {
        streams,
        gaps,
        image_sha256,
        image_bytes,
    })
}
