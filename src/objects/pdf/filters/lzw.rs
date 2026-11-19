//! PDF LZW codes use most-significant-bit-first packing and a 12-bit dictionary.
use super::Output;
use crate::objects::{ChildSink, Snapshot};
use std::io::{self, BufWriter, Write};

const CLEAR: usize = 256;
const END: usize = 257;
const FIRST: usize = 258;
const CODES: usize = 4096;

struct Bits<'a> {
    input: &'a [u8],
    pending: u32,
    count: u8,
}

impl Bits<'_> {
    fn code(&mut self, width: u8) -> Option<usize> {
        while self.count < width {
            let (&byte, rest) = self.input.split_first()?;
            self.input = rest;
            self.pending = self.pending << 8 | u32::from(byte);
            self.count += 8;
        }
        self.count -= width;
        Some(((self.pending >> self.count) & ((1 << width) - 1)) as usize)
    }
}

#[derive(Clone, Copy, Default)]
struct Entry {
    prefix: u16,
    len: u16,
    first: u8,
    last: u8,
}

pub(super) fn decode(
    data: &[u8],
    limit: u64,
    retain: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Output> {
    const STEP: u64 = 256 * 1024;
    let capacity = (limit / STEP).max(1) * STEP;
    let mut bits = Bits {
        input: data,
        pending: 0,
        count: 0,
    };
    let mut table = [Entry::default(); CODES];
    let mut word = [0u8; CODES];
    let mut out = retain.then(|| BufWriter::new(Snapshot::new(sink.temporary_directory())));
    let mut width = 9;
    let mut next = FIRST;
    let mut previous = None;
    let mut size = 0u64;
    let mut codes = 0usize;
    while let Some(code) = bits.code(width) {
        if codes.is_multiple_of(256) {
            sink.check()?;
        }
        codes += 1;
        if code == CLEAR {
            width = 9;
            next = FIRST;
            previous = None;
            continue;
        }
        if code == END || code > next {
            break;
        }
        // The next dictionary entry can name the previous word followed by its first byte.
        let mut entry = if code == next {
            let Some(old) = previous else {
                break;
            };
            old
        } else {
            code
        };
        let (first, len) = if entry < FIRST {
            (entry as u8, 1)
        } else {
            (table[entry].first, table[entry].len)
        };
        let extra = code == next;
        let len = len + u16::from(extra);
        size += u64::from(len);
        // Filling the reference buffer requests another whole block, even if EOD follows.
        if size >= capacity {
            sink.skip_declared_size(capacity.saturating_add(STEP));
            return Ok(Output::UseInput);
        }
        // Count up to that boundary without expanding the private spool past its byte budget.
        if size <= limit
            && let Some(out) = &mut out
        {
            let mut start = CODES;
            while entry >= FIRST {
                // Every prefix precedes this dictionary entry.
                start -= 1;
                word[start] = table[entry].last;
                entry = usize::from(table[entry].prefix);
            }
            start -= 1;
            word[start] = first;
            out.write_all(&word[start..])?;
            if extra {
                out.write_all(&[first])?;
            }
        }
        if let Some(old) = previous
            && next < CODES
        {
            let (old_first, old_len) = if old < FIRST {
                (old as u8, 1)
            } else {
                (table[old].first, table[old].len)
            };
            table[next] = Entry {
                prefix: old as u16,
                len: old_len + 1,
                first: old_first,
                last: first,
            };
            next += 1;
            // The pinned scanner uses EarlyChange=1 even when the dictionary requests zero.
            if width < 12 && next + 1 == 1 << width {
                width += 1;
            }
        }
        previous = Some(code);
    }
    Ok(if size == 0 {
        Output::UseInput
    } else if size > limit {
        Output::TooLarge(size)
    } else if let Some(out) = out {
        Output::Decoded(out.into_inner().map_err(|e| e.into_error())?)
    } else {
        Output::Counted(size)
    })
}
