use super::{ChildSink, Handling, decoded};
use flate2::read::DeflateDecoder;
use std::io::{self, Cursor, Read};

const LOCAL: &[u8; 4] = b"PK\x03\x04";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";
const END: &[u8; 4] = b"PK\x05\x06";

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(data[at..at + 2].try_into().unwrap())
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

struct Entry<'a> {
    method: u16,
    flags: u16,
    name: &'a [u8],
    compressed: &'a [u8],
    expanded_len: u32,
    consumed: usize,
}

impl<'a> Entry<'a> {
    fn parse(bytes: &'a [u8], sizes: (u32, u32)) -> Option<Self> {
        let (head, rest) = bytes.split_at_checked(30)?;
        if &head[..4] != LOCAL {
            return None;
        }
        let flags = u16_at(head, 6);
        let (compressed_len, expanded_len) = if flags & 8 != 0 {
            sizes
        } else {
            (u32_at(head, 18), u32_at(head, 22))
        };
        if compressed_len == u32::MAX || expanded_len == u32::MAX {
            return None;
        }
        let (name, rest) = rest.split_at_checked(usize::from(u16_at(head, 26)))?;
        let data = rest.get(usize::from(u16_at(head, 28))..)?;
        let (compressed, rest) = data.split_at_checked(compressed_len as usize)?;
        let rest = if flags & 8 != 0 {
            let descriptor = rest.strip_prefix(b"PK\x07\x08").unwrap_or(rest);
            descriptor.get(12..)?
        } else {
            rest
        };
        Some(Self {
            method: u16_at(head, 8),
            flags,
            // The reference supplies the last filename component to its child scanner.
            name: name.rsplit(|&b| b == b'/' || b == b'\\').next()?,
            compressed,
            expanded_len,
            consumed: bytes.len() - rest.len(),
        })
    }

    fn visit(&self, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        if self.flags & (1 | 0x2000) != 0 {
            return Ok(Handling::Incomplete);
        }
        if self.compressed.is_empty() {
            return Ok(Handling::Complete);
        }
        let max_file_size = sink.max_file_size();
        match self.method {
            0 if self.compressed.len() >= self.expanded_len as usize => {
                self.scan(self.compressed.take(max_file_size), sink)
            }
            8 => self.scan(
                ZipOutput::new(DeflateDecoder::new(self.compressed), max_file_size),
                sink,
            ),
            12 => self.scan(
                ZipOutput::new(bzip2::read::BzDecoder::new(self.compressed), max_file_size),
                sink,
            ),
            _ => Ok(Handling::Incomplete),
        }
    }

    fn scan(&self, reader: impl Read, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let remaining = sink.remaining();
        let probe = remaining.saturating_add(1);
        let mut stream = reader.take(probe);
        let result = decoded(&mut stream, Some(self.name), false, sink)?;
        // Stock leaves the ZIP member loop when its child scanner exceeds MaxScanSize.
        if probe - stream.limit() > remaining {
            Ok(Handling::Stopped)
        } else {
            Ok(result)
        }
    }
}

// The reference writes compressed members in 8192-byte batches. When the final
// batch exceeds MaxFileSize, it retains only the preceding complete batches.
struct ZipOutput<R> {
    reader: R,
    full: u64,
    tail_limit: usize,
    tail: Cursor<Vec<u8>>,
}

impl<R: Read> ZipOutput<R> {
    fn new(reader: R, limit: u64) -> Self {
        Self {
            reader,
            full: limit - limit % 8192,
            tail_limit: (limit % 8192) as usize,
            tail: Cursor::default(),
        }
    }
}

impl<R: Read> Read for ZipOutput<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.full > 0 {
            let len = self.full.min(out.len() as u64) as usize;
            let n = self.reader.read(&mut out[..len])?;
            self.full -= n as u64;
            return Ok(n);
        }
        if self.tail_limit > 0 {
            let n = self.tail_limit;
            self.tail_limit = 0;
            (&mut self.reader)
                .take(n as u64 + 1)
                .read_to_end(self.tail.get_mut())?;
            if self.tail.get_ref().len() > n {
                self.tail.get_mut().clear();
            }
        }
        self.tail.read(out)
    }
}

// Scan backward without allocating a list of possible end records. A long trailer
// must still give the caller opportunities to check its time and connection limits.
pub(in crate::objects) fn directory(
    bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Option<(usize, usize)>> {
    if bytes.len() < 22 {
        return Ok(None);
    }
    let mut limit = bytes.len() - 21;
    while limit != 0 {
        sink.check()?;
        let begin = limit.saturating_sub(8192);
        for at in (begin..limit).rev() {
            if &bytes[at..at + 4] == END {
                let record = &bytes[at..at + 22];
                let offset = u32_at(record, 16) as usize;
                if offset != 0 && bytes.get(offset..).is_some_and(|b| b.starts_with(CENTRAL)) {
                    return Ok(Some((offset, usize::from(u16_at(record, 10)))));
                }
            }
        }
        limit = begin;
    }
    Ok(None)
}

pub(in crate::objects) fn single(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if bytes.len() < 30 || u16_at(bytes, 6) & 8 != 0 {
        // The embedded reader has no central directory for data-descriptor sizes.
        return Ok(Handling::Complete);
    }
    match Entry::parse(bytes, (0, 0)) {
        Some(member) => member.visit(sink),
        None => Ok(Handling::Incomplete),
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if let Some((directory_offset, count)) = directory(bytes, sink)? {
        let mut directory = &bytes[directory_offset..];
        // A classic directory contains at most 65535 records. Store only offsets
        // and sizes so each filename and member body still borrows the source object.
        let mut records = Vec::new();
        let max_files = sink.max_files();
        let limit = if max_files == 0 {
            count
        } else {
            count.min(max_files)
        };
        for _ in 0..limit {
            sink.check()?;
            let Some((head, rest)) = directory.split_at_checked(46) else {
                return Ok(Handling::Incomplete);
            };
            if &head[..4] != CENTRAL || u16_at(head, 34) != 0 {
                return Ok(Handling::Incomplete);
            }
            let fields: usize = [28, 30, 32]
                .into_iter()
                .map(|at| usize::from(u16_at(head, at)))
                .sum();
            let Some(next) = rest.get(fields..) else {
                return Ok(Handling::Incomplete);
            };
            records.push((u32_at(head, 42), (u32_at(head, 20), u32_at(head, 24))));
            directory = next;
        }
        if limit == count && !directory.starts_with(END) {
            return Ok(Handling::Incomplete);
        }
        records.sort_unstable();
        records.dedup();
        let mut last_end = 0;
        for (offset, sizes) in records {
            sink.check()?;
            let offset = offset as usize;
            let Some(data) = bytes.get(offset..directory_offset) else {
                return Ok(Handling::Incomplete);
            };
            let Some(entry) = Entry::parse(data, sizes) else {
                return Ok(Handling::Incomplete);
            };
            if offset < last_end {
                return Ok(Handling::Incomplete);
            }
            last_end = offset + entry.consumed;
            match entry.visit(sink)? {
                Handling::Complete => {}
                Handling::Stopped => break,
                other => return Ok(other),
            }
        }
    }
    // In 1.4.3 the local-header retry requires a previously extracted directory entry.
    // An archive missing its entire directory therefore produces no child.
    Ok(Handling::Complete)
}
