//! Streaming H.264 Annex-B NAL scanner. Reads an image once, front to back,
//! hashing every byte it reads, in bounded memory.
//!
//! Annex-B facts used: a NAL payload never contains `00 00 00`, `00 00 01` or
//! `00 00 02` (emulation prevention), so the first such triple after a NAL
//! header ends that NAL.

use std::io::{self, Read};

use sha2::{Digest, Sha256};

const CHUNK: usize = 8 << 20;
const COMPACT_AT: usize = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nal {
    /// Offset of the first byte of the start code (including a leading zero byte).
    pub sc_offset: u64,
    /// Exclusive end of the NAL payload.
    pub end: u64,
    pub nal_type: u8,
    /// Bytes between the previous event and this start code.
    pub gap_before: u64,
    /// True when every one of those bytes is zero (padding or start code lead-in).
    pub gap_zero: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Nal(Nal),
    /// A well-formed start code whose NAL was not usable.
    Rejected { offset: u64, reason: &'static str },
}

pub struct Scanner<R: Read> {
    r: R,
    buf: Vec<u8>,
    /// Absolute offset of `buf[0]`.
    base: u64,
    cur: usize,
    eof: bool,
    hasher: Sha256,
    total: u64,
    max_nal: usize,
}

fn valid_type(t: u8) -> bool {
    matches!(t, 1 | 5 | 6 | 7 | 8 | 9)
}

fn find_start_code(buf: &[u8], from: usize) -> Option<usize> {
    let n = buf.len();
    let mut i = from;
    while i + 2 < n {
        if buf[i + 2] > 1 {
            i += 3;
        } else if buf[i + 2] == 1 {
            if buf[i] == 0 && buf[i + 1] == 0 {
                return Some(i);
            }
            i += 3;
        } else if buf[i + 1] != 0 {
            i += 2;
        } else {
            i += 1;
        }
    }
    None
}

fn find_terminator(buf: &[u8], from: usize) -> Option<usize> {
    let n = buf.len();
    let mut i = from;
    while i + 2 < n {
        if buf[i + 2] > 2 {
            i += 3;
        } else if buf[i] == 0 && buf[i + 1] == 0 {
            return Some(i);
        } else {
            i += 1;
        }
    }
    None
}

impl<R: Read> Scanner<R> {
    pub fn new(r: R, max_nal: usize) -> Self {
        Self {
            r,
            buf: Vec::new(),
            base: 0,
            cur: 0,
            eof: false,
            hasher: Sha256::new(),
            total: 0,
            max_nal,
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }
        let old = self.buf.len();
        self.buf.resize(old + CHUNK, 0);
        let mut got = 0;
        // Fill the whole chunk unless EOF, so short reads never look like EOF.
        while got < CHUNK {
            let n = self.r.read(&mut self.buf[old + got..])?;
            if n == 0 {
                self.eof = true;
                break;
            }
            got += n;
        }
        self.buf.truncate(old + got);
        self.hasher.update(&self.buf[old..]);
        self.total += got as u64;
        Ok(())
    }

    fn compact(&mut self) {
        // Keep one byte before `cur` so a 4-byte start code lead zero is still visible.
        if self.cur > COMPACT_AT {
            let drop = self.cur - 1;
            self.buf.drain(..drop);
            self.base += drop as u64;
            self.cur = 1;
        }
    }

    pub fn next_event(&mut self) -> io::Result<Option<Event>> {
        loop {
            self.compact();
            // Find the next start code.
            let sc = loop {
                if let Some(p) = find_start_code(&self.buf, self.cur) {
                    // Need the NAL header byte too.
                    if p + 3 < self.buf.len() {
                        break p;
                    }
                    if self.eof {
                        self.cur = self.buf.len();
                        return Ok(None);
                    }
                    self.cur = p;
                    self.fill()?;
                    continue;
                }
                if self.eof {
                    self.cur = self.buf.len();
                    return Ok(None);
                }
                // Nothing here; keep the last two bytes (a start code may straddle) and refill.
                self.cur = self.buf.len().saturating_sub(2).max(self.cur);
                self.compact();
                self.fill()?;
            };
            let header = self.buf[sc + 3];
            let nal_type = header & 0x1F;
            let abs_sc = self.base + sc as u64;
            if header & 0x80 != 0 || !valid_type(nal_type) {
                self.cur = sc + 3;
                continue;
            }
            // A zero byte right before `00 00 01` makes it a 4-byte start code.
            let lead = sc > self.cur && self.buf[sc - 1] == 0;
            let sc_start = if lead { sc - 1 } else { sc };
            // Find the end of this NAL.
            let mut from = sc + 4;
            let end = loop {
                if let Some(p) = find_terminator(&self.buf, from) {
                    break Some(p);
                }
                if self.eof {
                    // A NAL cannot end in a zero byte; trailing zeros are padding.
                    let mut e = self.buf.len();
                    while e > sc + 4 && self.buf[e - 1] == 0 {
                        e -= 1;
                    }
                    break Some(e);
                }
                if self.buf.len() - (sc + 4) > self.max_nal {
                    break None;
                }
                from = self.buf.len().saturating_sub(2).max(sc + 4);
                self.fill()?;
            };
            let Some(end) = end else {
                self.cur = sc + 3;
                return Ok(Some(Event::Rejected {
                    offset: abs_sc,
                    reason: "nal_exceeds_max_size",
                }));
            };
            if end - (sc + 4) > self.max_nal {
                self.cur = sc + 3;
                return Ok(Some(Event::Rejected {
                    offset: abs_sc,
                    reason: "nal_exceeds_max_size",
                }));
            }
            let gap_from = self.cur;
            let gap_zero = self.buf[gap_from..sc_start].iter().all(|b| *b == 0);
            let nal = Nal {
                sc_offset: self.base + sc_start as u64,
                end: self.base + end as u64,
                nal_type,
                gap_before: (sc_start - gap_from) as u64,
                gap_zero,
            };
            self.cur = end;
            return Ok(Some(Event::Nal(nal)));
        }
    }

    /// Read to the end (so every byte is hashed) and return the image digest and size.
    pub fn finish(mut self) -> io::Result<(String, u64)> {
        while !self.eof {
            self.cur = self.buf.len();
            self.compact();
            self.fill()?;
        }
        Ok((hex::encode(self.hasher.finalize()), self.total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(data: &[u8]) -> Vec<Event> {
        let mut s = Scanner::new(data, 1 << 20);
        let mut out = Vec::new();
        while let Some(e) = s.next_event().unwrap() {
            out.push(e);
        }
        out
    }

    #[test]
    fn finds_nals_and_exact_ends() {
        // junk | 4-byte sc + SPS(7) | 3-byte sc + PPS(8) | zero padding | junk
        let mut d = vec![0xAA, 0xBB];
        d.extend([0, 0, 0, 1, 0x67, 0x11, 0x22]);
        d.extend([0, 0, 1, 0x68, 0x33]);
        d.extend([0, 0, 0, 0, 0]);
        d.extend([0xCC, 0xDD]);
        let ev = events(&d);
        assert_eq!(ev.len(), 2);
        let Event::Nal(a) = &ev[0] else { panic!() };
        assert_eq!((a.sc_offset, a.end, a.nal_type), (2, 9, 7));
        let Event::Nal(b) = &ev[1] else { panic!() };
        assert_eq!((b.sc_offset, b.end, b.nal_type), (9, 14, 8));
        assert!(b.gap_zero && b.gap_before == 0);
    }

    #[test]
    fn rejects_forbidden_bit_and_unknown_types() {
        let d = [0, 0, 1, 0xE7, 1, 2, 3, 0, 0, 1, 0x1F, 9, 9];
        assert!(events(&d).is_empty());
    }

    #[test]
    fn finish_hashes_everything() {
        let data = vec![7u8; 1000];
        let mut s = Scanner::new(&data[..], 1 << 20);
        while s.next_event().unwrap().is_some() {}
        let (sha, n) = s.finish().unwrap();
        assert_eq!(n, 1000);
        assert_eq!(sha, hex::encode(Sha256::digest(&data)));
    }

    #[test]
    fn oversize_nal_is_rejected_not_unbounded() {
        let mut d = vec![0, 0, 1, 0x65];
        d.extend(std::iter::repeat_n(0x55, 5000));
        let mut s = Scanner::new(&d[..], 1000);
        let first = s.next_event().unwrap().unwrap();
        assert!(matches!(first, Event::Rejected { reason: "nal_exceeds_max_size", .. }));
    }
}
