//! Passive pictures in BIFF8 drawing groups and inline OfficeArt file BLIP store entries.
use super::{ChildSink, Handling, Input};
use crate::objects::Snapshot;
use std::io::{self, Read, Seek, SeekFrom, Write};

const GROUP: u16 = 0x00eb;
const CONTINUE: u16 = 0x003c;
const MAX_RECORD: usize = 8228;
const REPORT_HEADER: &[u8] = b"-- BIFF content extracted and disassembled from CL_TYPE_MSXL .xls file because a XLM macro was found in the document\n";

// Stock matches its report before flushing the final 4096-byte stdio block. Bound the
// length of its ordinary record lines to establish when only its preamble is visible.
fn report_line_bound(opcode: u16) -> Option<usize> {
    Some(match opcode {
        0x0018 | 0x0207 => return None, // Name and String have variable listings.
        0x0031 => 24,                   // FONT has no label in the reference listing.
        0x000a => 32,                   // EOF
        0x00e0 => 35,                   // XF
        0x0809 | 0x0022 | 0x00a1 | 0x00fc | 0x0293 => 40,
        0x0042 | 0x003d | 0x008d | 0x0200 | 0x005d | 0x001d => 48,
        0x00eb => 63,  // MSODRAWINGGROUP
        0x0085 => 110, // BOUNDSHEET appends its sheet kind and visibility.
        _ => 74, // The longest static opcode description uses 59 bytes, plus 15 bytes of formatting.
    })
}

fn formula_bound(data: &[u8]) -> Option<usize> {
    let count = u16::from_le_bytes(data.get(20..22)?.try_into().ok()?) as usize;
    let mut tokens = data.get(22..)?;
    if tokens.len() != count {
        return None;
    }
    // Fixed record/coordinate text, the final token boundary, and the terminating newline.
    let mut bound = 96;
    while let Some(&code) = tokens.first() {
        // Each bound includes the token label and all printed operands. The scanner only
        // describes these BIFF tokens. Their formulas and functions are never evaluated.
        let (width, printed) = match code {
            0x03..=0x16 => (1, 16), // arithmetic, comparisons, and range operators
            0x1c | 0x1d => (2, 24), // error or Boolean
            0x1e => (3, 16),        // unsigned 16-bit integer
            0x1f => (9, 336), // a finite double has at most 309 digits before the decimal point
            0x01 | 0x24 | 0x44 | 0x64 => (5, 40), // cell references
            0x25 | 0x45 | 0x65 => (9, 64), // cell ranges
            0x21 | 0x41 | 0x61 => (3, 64), // fixed-arity function
            0x22 | 0x42 | 0x62 if *tokens.get(3)? < 0x80 => (4, 80), // worksheet function
            0x19 if *tokens.get(1)? == 0x10 => (4, 24), // optimized SUM
            _ => return None,
        };
        tokens = tokens.get(width..)?;
        bound += printed;
    }
    Some(bound)
}

pub(super) fn scan(mut input: Input<'_>, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut group = sink
        .child_limit()
        .is_none()
        .then(|| Snapshot::new(sink.temporary_directory()));
    let mut previous_group = false;
    let report_can_fit = REPORT_HEADER.len() as u64 <= sink.remaining();
    let mut report_bound = 0u64;
    let mut group_len = 0u64;
    let mut remaining = input.len();
    let mut buf = [0; MAX_RECORD];
    while remaining >= 4 {
        sink.check()?;
        let mut header = [0; 4];
        input.read_exact(&mut header)?;
        let opcode = u16::from_le_bytes([header[0], header[1]]);
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if size > MAX_RECORD || size as u64 > remaining - 4 {
            return Ok(Handling::Incomplete);
        }
        if report_can_fit {
            let line = if opcode == 0x0006 {
                input.read_exact(&mut buf[..size])?;
                formula_bound(&buf[..size])
            } else {
                report_line_bound(opcode)
            };
            let bound = match line {
                Some(bound) => bound,
                // Bound variable report text when only its admission can affect the verdict.
                // A formula token can print a decimal double. Its 22-byte header is fixed.
                None if group.is_none() && opcode == 0x0006 => 128 + 1024 * size.saturating_sub(22),
                None if group.is_none() => 128 + size * 4, // Name and String
                None => return Ok(Handling::Incomplete),
            };
            report_bound = report_bound.saturating_add(bound as u64);
            if group.is_some() && report_bound >= 4096 {
                return Ok(Handling::Incomplete);
            }
        }
        if opcode != CONTINUE {
            previous_group = opcode == GROUP;
        }
        if previous_group && let Some(group) = &mut group {
            group_len += size as u64;
            if group_len >= 1 << 30 {
                return Ok(Handling::Incomplete);
            }
            input.read_exact(&mut buf[..size])?;
            group.write_all(&buf[..size])?;
        } else if !report_can_fit || opcode != 0x0006 {
            input.seek(SeekFrom::Current(size as i64))?;
        }
        remaining -= size as u64 + 4;
    }
    let Some(group) = group else {
        let preamble = REPORT_HEADER.len() as u64;
        if sink.skip_declared_size(preamble) {
            return Ok(Handling::Complete);
        }
        let maximum = preamble.saturating_add(report_bound / 4096 * 4096);
        if maximum > sink.remaining() {
            return Ok(Handling::Incomplete);
        }
        sink.can_enter_child();
        return Ok(Handling::Complete);
    };
    if !sink.skip_declared_size(REPORT_HEADER.len() as u64)
        && sink.match_generic_view(REPORT_HEADER)?
    {
        return Ok(Handling::Stopped);
    }
    group.with_bytes(|data| pictures(data, sink))
}

struct Record<'a> {
    version: u16,
    instance: u16,
    kind: u16,
    body: &'a [u8],
}

fn record<'a>(data: &mut &'a [u8]) -> Option<Record<'a>> {
    let (head, tail) = data.split_at_checked(8)?;
    let flags = u16::from_le_bytes([head[0], head[1]]);
    let len = u32::from_le_bytes(head[4..8].try_into().ok()?) as usize;
    let (body, rest) = tail.split_at_checked(len)?;
    *data = rest;
    Some(Record {
        version: flags & 15,
        instance: flags >> 4,
        kind: u16::from_le_bytes([head[2], head[3]]),
        body,
    })
}

fn pictures(mut data: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(group) = record(&mut data) else {
        return Ok(Handling::Incomplete);
    };
    if group.kind != 0xf000 || group.version != 15 || group.instance != 0 || !data.is_empty() {
        return Ok(Handling::Incomplete);
    }
    let mut children = group.body;
    while !children.is_empty() {
        sink.check()?;
        let Some(container) = record(&mut children) else {
            return Ok(Handling::Incomplete);
        };
        if container.kind != 0xf001 {
            continue;
        }
        if container.version != 15 {
            return Ok(Handling::Incomplete);
        }
        let mut files = container.body;
        while !files.is_empty() {
            sink.check()?;
            let block = files;
            let Some(entry) = record(&mut files) else {
                return Ok(Handling::Incomplete);
            };
            let image = match entry.kind {
                0xf007 => inline(entry),
                // For a bare BLIP stock bounds its image by the entire remaining store.
                _ => image(entry, &block[8..]),
            };
            let Some(image) = image else {
                return Ok(Handling::Incomplete);
            };
            if sink.skip_declared_size(image.len() as u64) {
                return Ok(Handling::Complete);
            }
            if sink.child_bytes(image, None)? {
                return Ok(Handling::Stopped);
            }
        }
    }
    Ok(Handling::Complete)
}

fn inline(entry: Record<'_>) -> Option<&[u8]> {
    if entry.version != 2 {
        return None;
    }
    let header = entry.body.get(..36)?;
    let size = u32::from_le_bytes(header[20..24].try_into().ok()?) as usize;
    let name_len = usize::from(header[33]);
    let mut data = entry.body.get(36 + name_len..)?;
    if data.len() != size {
        return None;
    }
    let blip = record(&mut data)?;
    if !data.is_empty() {
        return None;
    }
    let storage = blip.body;
    image(blip, storage)
}

fn image<'a>(record: Record<'a>, storage: &'a [u8]) -> Option<&'a [u8]> {
    if record.version != 0 {
        return None;
    }
    let first = match (record.kind, record.instance) {
        (0xf01d | 0xf02a, 0x46a | 0x46b) => 0x46a, // JPEG
        (0xf01d | 0xf02a, 0x6e2 | 0x6e3) => 0x6e2, // CMYK JPEG
        (0xf01e, _) => 0x6e0,                      // PNG
        (0xf01f, _) => 0x7a8,                      // DIB
        (0xf029, _) => 0x6e4,                      // TIFF
        _ => return None,
    };
    let offset = match record.instance.checked_sub(first)? {
        0 => 17, // One identifier and one tag byte
        1 => 33, // Two identifiers and one tag byte
        _ => return None,
    };
    let bytes = storage.get(offset..)?;
    Some(&bytes[..record.body.len().min(bytes.len())])
}
