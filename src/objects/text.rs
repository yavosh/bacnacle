//! Typed streams produced by the stock HTML, script, and mail parsers.
use super::{ChildSink, Handling};
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

// The reference recognizes BOM-marked text, and unmarked little-endian ASCII HTML.
fn utf16(bytes: &[u8]) -> Option<(bool, bool)> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return Some((true, true));
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return Some((false, true));
    }
    if bytes.len() >= 6
        && bytes
            .as_chunks::<2>()
            .0
            .iter()
            .all(|p| p[0].is_ascii() && p[0] != 0 && p[1] == 0)
    {
        return Some((true, false));
    }
    None
}

pub(super) fn raw_target(bytes: &[u8]) -> Option<Target> {
    let head = &bytes[..bytes.len().min(1024)];
    if mail::recognizes(head) {
        return Some(Target::Mail);
    }
    if let Some((little, bom)) = utf16(head) {
        let decoded: Vec<_> = head[if bom { 2 } else { 0 }..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair[usize::from(!little)])
            .collect();
        return html::recognizes(&decoded).then_some(Target::Html);
    }
    if plain(head) && html::recognizes(head) {
        return Some(Target::Html);
    }
    None
}

// Call after raw_target identified HTML. The pinned engine calls the separately
// decoded little-endian form HTML_UTF16 and still scans its generic outer bytes.
pub(super) fn little_endian_html(bytes: &[u8]) -> bool {
    matches!(utf16(&bytes[..bytes.len().min(1024)]), Some((true, _)))
}

pub(super) fn container_type(bytes: &[u8]) -> Option<&'static str> {
    attachments::file_type(bytes)
}

pub(super) fn before_raw(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match container_type(bytes) {
        Some("CL_TYPE_TNEF") => return attachments::tnef(bytes, sink),
        Some("CL_TYPE_UUENCODED") => return attachments::uu(bytes, sink),
        _ => (),
    }
    match raw_target(bytes) {
        Some(Target::Html) => {
            if let Some((little, bom)) = utf16(&bytes[..bytes.len().min(1024)]) {
                let content = if bom { &bytes[2..] } else { bytes };
                let mut spool = super::Snapshot::new(sink.temporary_directory());
                {
                    let mut output = io::BufWriter::new(&mut spool);
                    for block in content.chunks(8192) {
                        sink.check()?;
                        let (pairs, remainder) = block.as_chunks::<2>();
                        if !remainder.is_empty() {
                            return Ok(Handling::Incomplete);
                        }
                        for pair in pairs {
                            if pair[usize::from(little)] != 0 {
                                return Ok(Handling::Incomplete);
                            }
                            output.write_all(&[pair[usize::from(!little)]])?;
                        }
                    }
                    output.flush()?;
                }
                return spool.with_bytes(|ascii| html::extract(ascii, sink, bom.then_some(little)));
            }
            html::extract(bytes, sink, None)
        }
        Some(Target::Mail) => mail::extract(bytes, sink),
        _ => Ok(Handling::Unrecognized),
    }
}

struct NormalizedText<'a> {
    bytes: &'a [u8],
    space: bool,
}

impl Read for NormalizedText<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
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
    if !plain(bytes) || raw_target(bytes).is_some() {
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
