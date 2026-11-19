//! Typed streams produced by the stock HTML, script, and mail parsers.
use super::{ChildSink, Handling, classify::Parser};
use crate::body::Target;
use std::io::{self, Read, Write};

mod attachments;
mod html;
mod mail;
pub(super) use mail::{base64_reader, valid_base64};

fn text_byte(b: u8) -> bool {
    matches!(b, 7..=10 | 12 | 13 | 27 | 0x20..=0x7e | 0x80..=0xff)
}

pub(super) fn file_type(bytes: &[u8]) -> &'static str {
    let head = &bytes[..bytes.len().min(1024)];
    if head.iter().copied().all(text_byte) {
        // Stock includes extended single-byte text and UTF-8 in this class.
        return "CL_TYPE_TEXT_ASCII";
    }
    let (pairs, _) = head.as_chunks::<2>();
    let Some((prefix, rest)) = pairs.split_first() else {
        return "CL_TYPE_BINARY_DATA";
    };
    let little = *prefix == [0xff, 0xfe];
    let marked = little || *prefix == [0xfe, 0xff];
    for &pair in rest {
        let point = if little {
            u16::from_le_bytes(pair)
        } else {
            u16::from_be_bytes(pair)
        };
        if point == 0xfffe || (!marked && point < 128 && !text_byte(point as u8)) {
            return "CL_TYPE_BINARY_DATA";
        }
    }
    if little {
        "CL_TYPE_TEXT_UTF16LE"
    } else {
        "CL_TYPE_TEXT_UTF16BE"
    }
}

pub(super) fn plain(bytes: &[u8]) -> bool {
    file_type(bytes) != "CL_TYPE_BINARY_DATA"
}

pub(super) fn parser(bytes: &[u8]) -> Option<Parser> {
    let head = &bytes[..bytes.len().min(1024)];
    if mail::recognizes(head) {
        return Some(Parser::Mail);
    }
    if plain(head) && html::recognizes(head) {
        return Some(Parser::Html { big_endian: false });
    }
    if !head.contains(&0) {
        return None;
    }
    let pairs = head.as_chunks::<2>().0;
    let mut projected = [0; 512];
    let sample = &mut projected[..pairs.len()];
    if pairs.contains(&[b'<', 0]) {
        for (dst, &pair) in sample.iter_mut().zip(pairs) {
            *dst = html_byte(pair);
        }
        if html::recognizes(sample) {
            return Some(Parser::Utf16Html);
        }
    }
    if head.starts_with(&[0xfe, 0xff]) {
        for (dst, &pair) in sample.iter_mut().zip(pairs) {
            *dst = if pair[0] == 0 { pair[1] } else { 0xff };
        }
        if html::recognizes(sample) {
            return Some(Parser::Html { big_endian: true });
        }
    }
    None
}

pub(super) fn container_type(bytes: &[u8]) -> Option<&'static str> {
    attachments::file_type(bytes)
}

pub(super) fn before_raw(
    parser: Parser,
    bytes: &[u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    match parser {
        Parser::Tnef => attachments::tnef(bytes, sink),
        Parser::Uuencoded => attachments::uu(bytes, sink),
        Parser::Utf16Html => sink.utf16_html(bytes),
        Parser::Html { big_endian: true } => unicode_html(bytes, false, sink),
        Parser::Html { big_endian: false } => html::extract(bytes, sink, bytes.len(), true),
        Parser::Mail => mail::extract(bytes, sink),
        _ => Ok(Handling::Unrecognized),
    }
}

// ClamAV's little-endian HTML projection combines the upper byte at bit four.
fn html_byte(pair: [u8; 2]) -> u8 {
    pair[0].wrapping_add(pair[1] << 4)
}

pub(super) fn unicode_html(
    bytes: &[u8],
    little: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let size = if little { bytes.len() / 2 } else { bytes.len() };
    if size as u64 > sink.text_limits().0 {
        return Ok(Handling::Complete);
    }
    let mut spool = super::Snapshot::new(sink.temporary_directory());
    // The reference fills 8,191 nonzero bytes, then rewinds the source by the
    // number of output bytes after the last space. These units differ for UTF-16BE.
    const BLOCK: usize = 8191;
    let byte = |at: usize| {
        if little {
            html_byte([bytes[2 * at], bytes[2 * at + 1]])
        } else {
            bytes[at]
        }
    };
    let mut buffer = Vec::with_capacity(BLOCK);
    let mut at = 0;
    while at < size {
        buffer.clear();
        while at < size && buffer.len() < BLOCK {
            sink.check()?;
            let end = (at + BLOCK).min(size);
            while at < end && buffer.len() < BLOCK {
                let b = byte(at);
                if b != 0 {
                    buffer.push(b);
                }
                at += 1;
            }
        }
        if at < size
            && !byte(at).is_ascii_whitespace()
            && let Some(space) = buffer.iter().rposition(u8::is_ascii_whitespace)
            && space > 0
        {
            at -= buffer.len() - space - 1;
            buffer.truncate(space + 1);
        }
        buffer.retain(|b| *b != b'\r');
        spool.write_all(buffer.trim_ascii_start())?;
    }
    spool.with_bytes(|data| html::extract(data, sink, size, false))
}

struct NormalizedText<'a> {
    bytes: &'a [u8],
    space: bool,
}

impl Read for NormalizedText<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        // Printable text with single spaces keeps its length. Lowercase it in bulk.
        let n = self.bytes.len().min(output.len());
        let input = &self.bytes[..n];
        if n >= 64
            && !(self.space && input[0] == b' ')
            && input.iter().all(|b| (0x20..=0x7f).contains(b))
            && memchr::memmem::find(input, b"  ").is_none()
        {
            output[..n].copy_from_slice(input);
            output[..n].make_ascii_lowercase();
            self.bytes = &self.bytes[n..];
            self.space = input[n - 1] == b' ';
            return Ok(n);
        }
        let mut written = 0;
        while written < output.len() {
            let Some((&b, rest)) = self.bytes.split_first() else {
                break;
            };
            self.bytes = rest;
            let b = match b {
                9..=13 | b' ' if !self.space => b' ',
                0x21..=0x7f => b.to_ascii_lowercase(),
                _ => continue,
            };
            self.space = b == b' ';
            output[written] = b;
            written += 1;
        }
        Ok(written)
    }
}

pub(super) fn after_raw(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if !plain(bytes) || parser(bytes).is_some() {
        return Ok(Handling::Unrecognized);
    }
    let mut reader = NormalizedText {
        bytes,
        space: false,
    };
    Ok(
        if bytes.len() as u64 <= sink.text_limits().2 && sink.view(&mut reader, Target::Ascii)? {
            Handling::Stopped
        } else {
            Handling::Complete
        },
    )
}

#[cfg(test)]
mod normalized_text_tests {
    use super::*;

    #[test]
    fn bulk_reads_keep_scalar_whitespace_state() -> io::Result<()> {
        let mut source = b"MiXeD-bOX ".repeat(900);
        source[8191..8193].fill(b' ');
        source.extend(0..=u8::MAX);
        source.extend(b" Warehouse note.".repeat(900));
        source.extend(b"\r\n  Tail\x7f  ");
        let mut expected = Vec::new();
        for &byte in &source {
            match byte {
                9..=13 | b' ' if expected.last() != Some(&b' ') => expected.push(b' '),
                0x21..=0x7f => expected.push(byte.to_ascii_lowercase()),
                _ => (),
            }
        }
        for size in [1, 2, 63, 64, 65, 257, 8191, 8192] {
            let mut reader = NormalizedText {
                bytes: &source,
                space: false,
            };
            let mut actual = Vec::new();
            let mut buf = vec![0; size];
            loop {
                assert_eq!(reader.read(&mut [])?, 0);
                let n = reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                actual.extend_from_slice(&buf[..n]);
            }
            assert_eq!(actual, expected, "read size {size}");
        }
        Ok(())
    }
}
