//! Scan the catalog, subdocuments and heap extents in the order used by XAR.
use super::{ChildSink, Handling, decoded};
use crate::objects::Snapshot;
use flate2::read::ZlibDecoder;
use lzma_rust2::LzmaReader;
use quick_xml::{
    Reader,
    events::{BytesStart, Event},
};
use std::io::{self, Read, Write};

// The pinned allocator bounds the declared catalog plus its terminating NUL to one GiB.
const MAX_TOC: u64 = (1 << 30) - 1;
const MAX_DEPTH: usize = 256;

#[derive(Clone, Copy, Default)]
enum Codec {
    #[default]
    Stored,
    Zlib,
    Lzma,
}

#[derive(Default)]
struct Extent {
    offset: Option<usize>,
    length: Option<usize>,
    size: Option<usize>,
    codec: Codec,
}

impl Extent {
    fn scan(&self, heap: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let (Some(offset), Some(len), Some(_)) = (self.offset, self.length, self.size) else {
            return Ok(Handling::Incomplete);
        };
        let Some(rest) = heap.get(offset..) else {
            return Ok(Handling::Incomplete);
        };
        let bytes = &rest[..len.min(rest.len())];
        match self.codec {
            Codec::Stored => {
                let n = usize::try_from(sink.max_file_size())
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                Ok(if sink.child_bytes(&bytes[..n], None)? {
                    Handling::Stopped
                } else {
                    Handling::Complete
                })
            }
            Codec::Zlib => match decoded(ZlibDecoder::new(bytes), None, false, sink)? {
                // Stock discards a stream with an inflate error and visits the next extent.
                Handling::Incomplete => Ok(Handling::Complete),
                result => Ok(result),
            },
            Codec::Lzma => match LzmaReader::new_mem_limit(bytes, 64 * 1024, None) {
                Ok(reader) => decoded(reader, None, false, sink),
                Err(_) => Ok(Handling::Incomplete),
            },
        }
    }
}

fn encoding(start: &BytesStart<'_>) -> Option<Codec> {
    let mut codec = Codec::Stored;
    for attr in start.attributes() {
        let attr = attr.ok()?;
        if attr.key.as_ref() == "style" {
            codec = match attr.value.as_ref() {
                "application/x-gzip" => Codec::Zlib,
                "application/x-lzma" => Codec::Lzma,
                _ => Codec::Stored,
            };
        }
    }
    Some(codec)
}

fn integer(text: &str) -> Option<usize> {
    let text = text.trim_start();
    let text = text.strip_prefix('+').unwrap_or(text);
    let n = text.bytes().take_while(u8::is_ascii_digit).count();
    text.get(..n)?.parse::<isize>().ok()?.try_into().ok()
}

// libxml serializes the subdocument's inner XML before scanning it. Normalize empty
// elements and attribute quotes without expanding DTDs, namespaces or external entities.
fn subdoc(reader: &mut Reader<&[u8]>, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut spool = Snapshot::new(sink.temporary_directory());
    let mut depth = 0usize;
    let mut open = false;
    {
        let mut out = io::BufWriter::new(&mut spool);
        loop {
            sink.check()?;
            let Ok(event) = reader.read_event() else {
                return Ok(Handling::Incomplete);
            };
            if let Event::End(end) = &event
                && depth == 0
                && end.local_name().as_ref() == "subdoc"
            {
                break;
            }
            if depth > MAX_DEPTH {
                return Ok(Handling::Incomplete);
            }
            if open && !matches!(event, Event::End(_)) {
                out.write_all(b">")?;
                open = false;
            }
            match event {
                Event::Start(ref tag) | Event::Empty(ref tag) => {
                    let name = tag.name();
                    if name.as_ref().contains(':') {
                        return Ok(Handling::Incomplete);
                    }
                    out.write_all(b"<")?;
                    out.write_all(name.as_ref().as_bytes())?;
                    for attribute in tag.attributes() {
                        let Ok(a) = attribute else {
                            return Ok(Handling::Incomplete);
                        };
                        if a.key.as_ref().starts_with("xmlns")
                            || a.key.as_ref().contains(':')
                            || a.value
                                .bytes()
                                .any(|b| matches!(b, b'&' | b'<' | b'"' | b'\r' | b'\n' | b'\t'))
                        {
                            return Ok(Handling::Incomplete);
                        }
                        out.write_all(b" ")?;
                        out.write_all(a.key.as_ref().as_bytes())?;
                        out.write_all(b"=\"")?;
                        out.write_all(a.value.as_bytes())?;
                        out.write_all(b"\"")?;
                    }
                    if matches!(event, Event::Empty(_)) {
                        out.write_all(b"/>")?;
                    } else {
                        open = true;
                        depth += 1;
                    }
                }
                Event::End(ref tag) => {
                    let Some(d) = depth.checked_sub(1) else {
                        return Ok(Handling::Incomplete);
                    };
                    depth = d;
                    if open {
                        out.write_all(b"/>")?;
                        open = false;
                    } else {
                        out.write_all(b"</")?;
                        out.write_all(tag.name().as_ref().as_bytes())?;
                        out.write_all(b">")?;
                    }
                }
                Event::Text(text) if !text.contains('\r') && !text.contains('>') => {
                    out.write_all(text.as_ref().as_bytes())?;
                }
                Event::GeneralRef(entity) if matches!(entity.as_ref(), "amp" | "lt" | "gt") => {
                    out.write_all(b"&")?;
                    out.write_all(entity.as_ref().as_bytes())?;
                    out.write_all(b";")?;
                }
                _ => return Ok(Handling::Incomplete),
            }
        }
        out.flush()?;
    }
    spool.with_bytes(|bytes| {
        Ok(if sink.child_bytes(bytes, None)? {
            Handling::Stopped
        } else {
            Handling::Complete
        })
    })
}

fn parse(toc: &[u8], heap: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if sink.child_bytes(toc, None)? {
        return Ok(Handling::Stopped);
    }
    let mut reader = Reader::from_reader(toc);
    let mut depth = 0usize;
    let mut in_toc = false;
    let mut namespace_depth = None;
    let mut skip_next = false;
    let mut active = None::<(usize, Extent)>;
    let mut number = None;
    loop {
        sink.check()?;
        let Ok(event) = reader.read_event() else {
            return Ok(Handling::Incomplete);
        };
        let skip = std::mem::take(&mut skip_next);
        match event {
            Event::Start(ref start) | Event::Empty(ref start) => {
                let empty = matches!(event, Event::Empty(_));
                if !empty {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Ok(Handling::Incomplete);
                    }
                }
                if skip {
                    continue;
                }
                let name = start.local_name();
                if !in_toc {
                    let namespaced = start.attributes().any(|a| {
                        a.is_ok_and(|a| {
                            a.key.as_ref() == "xmlns" || a.key.as_ref().starts_with("xmlns:")
                        })
                    });
                    if namespaced && !empty {
                        namespace_depth.get_or_insert(depth);
                    }
                    if name.as_ref() == "subdoc" {
                        if namespace_depth.is_some() {
                            return Ok(Handling::Incomplete);
                        }
                        if !empty {
                            let outcome = subdoc(&mut reader, sink)?;
                            if outcome != Handling::Complete {
                                return Ok(outcome);
                            }
                            depth -= 1;
                        }
                        // xmlTextReaderNext moves to the next sibling before the reference read loop resumes.
                        skip_next = true;
                    } else if name.as_ref() == "toc" {
                        in_toc = true;
                    }
                } else if let Some((_, item)) = &mut active {
                    match name.as_ref() {
                        "offset" | "size" | "length" if !empty => {
                            number = Some((depth, name.as_ref().to_owned()))
                        }
                        "encoding" => {
                            let Some(codec) = encoding(start) else {
                                return Ok(Handling::Incomplete);
                            };
                            item.codec = codec;
                        }
                        _ => {}
                    }
                } else if matches!(name.as_ref(), "ea" | "data") {
                    if empty {
                        return Ok(Handling::Complete);
                    }
                    active = Some((depth, Extent::default()));
                }
            }
            Event::Text(text) => {
                if let Some((d, field)) = number.take()
                    && d == depth
                    && let Some((_, item)) = &mut active
                {
                    let n = integer(text.as_ref());
                    match field.as_str() {
                        "offset" => item.offset = n,
                        "length" => item.length = n,
                        _ => item.size = n,
                    }
                }
            }
            Event::End(end) => {
                number = None;
                if active.as_ref().is_some_and(|(d, _)| *d == depth) {
                    let (_, item) = active.take().unwrap();
                    if item.offset.is_none() && item.length.is_none() && item.size.is_none() {
                        return Ok(Handling::Complete);
                    }
                    let result = item.scan(heap, sink)?;
                    if result != Handling::Complete {
                        return Ok(result);
                    }
                }
                if namespace_depth == Some(depth) {
                    namespace_depth = None;
                }
                if end.local_name().as_ref() == "xar" {
                    return Ok(Handling::Complete);
                }
                let Some(d) = depth.checked_sub(1) else {
                    return Ok(Handling::Incomplete);
                };
                depth = d;
            }
            Event::Decl(decl)
                if decl.encoding().is_some_and(|e| {
                    !e.is_ok_and(|e| {
                        e.eq_ignore_ascii_case("UTF-8") || e.eq_ignore_ascii_case("US-ASCII")
                    })
                }) =>
            {
                return Ok(Handling::Incomplete);
            }
            Event::DocType(_) => return Ok(Handling::Incomplete),
            Event::Eof => {
                return Ok(if depth == 0 {
                    Handling::Complete
                } else {
                    Handling::Incomplete
                });
            }
            _ => {}
        }
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(header) = bytes.get(..28) else {
        return Ok(Handling::Complete);
    };
    let start = u16::from_be_bytes(header[4..6].try_into().unwrap()) as usize;
    let packed = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let declared = u64::from_be_bytes(header[16..24].try_into().unwrap());
    let Some((toc, heap)) = usize::try_from(packed)
        .ok()
        .and_then(|n| bytes.get(start..)?.split_at_checked(n))
    else {
        return Ok(Handling::Complete);
    };
    let mut spool = Snapshot::new(sink.temporary_directory());
    if declared > MAX_TOC {
        return Ok(Handling::Complete);
    }
    let mut z = ZlibDecoder::new(toc).take(declared);
    let mut total = 0u64;
    let mut buf = [0; 8192];
    loop {
        sink.check()?;
        let Ok(n) = z.read(&mut buf) else {
            return Ok(Handling::Incomplete);
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        if sink.skip_declared_size(total) {
            return Ok(Handling::Complete);
        }
        spool.write_all(&buf[..n])?;
    }
    spool.with_bytes(|xml| parse(xml, heap, sink))
}
