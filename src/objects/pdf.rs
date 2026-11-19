//! Scan PDF streams after the raw PDF matcher, in physical indirect-object order.
use super::{ChildSink, Handling, Limit, Snapshot};
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

mod filters;
mod object_stream;
use filters::{Filter, Output};

type Id = (usize, usize);
const MAX_OBJECTS: usize = 65_536;
const MAX_FILTERS: usize = 64;

#[derive(Clone)]
struct Tokens<'a> {
    data: &'a [u8],
    pos: usize,
}

fn white(b: u8) -> bool {
    b == 0 || b.is_ascii_whitespace()
}

fn delimiter(b: u8) -> bool {
    white(b) || b"()<>[]{}/%".contains(&b)
}

impl<'a> Tokens<'a> {
    fn next(&mut self) -> Option<&'a [u8]> {
        while let Some(&b) = self.data.get(self.pos) {
            if b == b'%' {
                self.pos += self.data[self.pos..]
                    .iter()
                    .position(|b| matches!(b, b'\n' | b'\r'))
                    .unwrap_or(self.data.len() - self.pos);
            } else if white(b) {
                self.pos += 1;
            } else {
                break;
            }
        }
        let at = self.pos;
        let b = *self.data.get(at)?;
        self.pos += 1;
        match b {
            b'(' => {
                let mut depth = 1;
                while let Some(&c) = self.data.get(self.pos) {
                    self.pos += 1;
                    match c {
                        b'\\' => self.pos = (self.pos + 1).min(self.data.len()),
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => (),
                    }
                }
            }
            b'<' | b'>' if self.data.get(self.pos) == Some(&b) => self.pos += 1,
            b'<' => {
                self.pos += self.data[self.pos..]
                    .iter()
                    .position(|&c| c == b'>')
                    .map_or(self.data.len() - self.pos, |n| n + 1);
            }
            b'>' | b'[' | b']' | b'{' | b'}' | b')' => (),
            _ => {
                while self.data.get(self.pos).is_some_and(|&c| !delimiter(c)) {
                    self.pos += 1;
                }
            }
        }
        Some(&self.data[at..self.pos])
    }

    fn reference(&self) -> Option<Id> {
        let mut input = self.clone();
        let id = (number(input.next()?)?, number(input.next()?)?);
        (input.next()? == b"R").then_some(id)
    }

    fn skip_value(&mut self) -> bool {
        let Some(token) = self.next() else {
            return false;
        };
        let mut depth = usize::from(matches!(token, b"[" | b"<<"));
        while depth != 0 {
            match self.next() {
                Some(b"[" | b"<<") => depth += 1,
                Some(b"]" | b">>") => depth -= 1,
                Some(_) => (),
                None => return false,
            }
        }
        true
    }
}

fn number(token: &[u8]) -> Option<usize> {
    if token.is_empty() || !token.iter().all(u8::is_ascii_digit) {
        return None;
    }
    token.iter().try_fold(0usize, |v, &b| {
        v.checked_mul(10)?.checked_add((b - b'0') as usize)
    })
}

#[derive(Default)]
struct Object<'a> {
    id: Id,
    start: usize,
    length: Option<usize>,
    length_ref: Option<Id>,
    encoded: Option<&'a [u8]>,
    filters: Vec<Filter>,
    image: bool,
    embedded: bool,
    object_stream: bool,
    directory: Option<object_stream::Directory>,
    unsupported: bool,
}

struct Pdf<'a> {
    objects: Vec<Object<'a>>,
    count: usize,
    lengths: HashMap<Id, usize>,
    contents: HashSet<Id>,
}

fn stream_start(input: &mut Tokens<'_>) -> Option<usize> {
    while matches!(input.data.get(input.pos), Some(b' ' | b'\t')) {
        input.pos += 1;
    }
    match input.data.get(input.pos..)? {
        [b'\r', b'\n', ..] => Some(input.pos + 2),
        [b'\n' | b'\r', ..] => Some(input.pos + 1),
        _ => None,
    }
}

fn read_stream<'a>(input: &mut Tokens<'a>) -> Option<&'a [u8]> {
    let start = stream_start(input)?;
    let rest = &input.data[start..];
    let size = rest.windows(9).position(|word| word == b"endstream")?;
    input.pos = start + size + 9;
    Some(&rest[..size])
}

fn trim_eol(bytes: &[u8]) -> &[u8] {
    bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .or_else(|| bytes.strip_suffix(b"\r"))
        .unwrap_or(bytes)
}

fn parse<'a>(data: &'a [u8], sink: &mut dyn ChildSink) -> io::Result<Option<Pdf<'a>>> {
    let mut input = Tokens { data, pos: 0 };
    let mut pdf = Pdf {
        objects: Vec::new(),
        count: 0,
        lengths: HashMap::new(),
        contents: HashSet::new(),
    };
    let mut count = 0usize;
    let mut last = [None, None];
    while let Some(tok) = input.next() {
        if tok == b"/Encrypt" {
            return Ok(None);
        }
        if tok != b"obj" {
            last = [last[1], number(tok)];
            continue;
        }
        sink.check()?;
        count += 1;
        if count > MAX_OBJECTS {
            return Ok(None);
        }
        let [Some(id), Some(gen_id)] = last else {
            return Ok(None);
        };
        let mut obj = Object {
            id: (id, gen_id),
            start: input.pos,
            ..Object::default()
        };
        let mut copy = input.clone();
        if let Some(n) = copy.next().and_then(number)
            && copy.next() == Some(b"endobj".as_slice())
        {
            pdf.lengths.insert(obj.id, n);
        }
        loop {
            let Some(tok) = input.next() else {
                return Ok(None);
            };
            match tok {
                b"endobj" => break,
                b"stream" => {
                    obj.directory = object_stream::Directory::read(&data[obj.start..input.pos]);
                    let Some(encoded) = read_stream(&mut input) else {
                        return Ok(None);
                    };
                    obj.encoded = Some(encoded);
                }
                b"/Contents" => {
                    if let Some(id) = input.reference() {
                        pdf.contents.insert(id);
                        if pdf.contents.len() > MAX_OBJECTS {
                            return Ok(None);
                        }
                    }
                }
                b"/Length" => {
                    obj.length_ref = input.reference();
                    let mut look = input.clone();
                    let candidate = look.next().and_then(number);
                    if input.data.get(look.pos) != Some(&b' ') {
                        obj.length = candidate;
                    }
                }
                b"/Filter" => {
                    if !obj.filters.is_empty() {
                        return Ok(None);
                    }
                    let Some(first) = input.next() else {
                        return Ok(None);
                    };
                    if first == b"[" {
                        loop {
                            let Some(name) = input.next() else {
                                return Ok(None);
                            };
                            if name == b"]" {
                                break;
                            }
                            if obj.filters.len() >= MAX_FILTERS {
                                return Ok(None);
                            }
                            obj.filters.push(Filter::parse(name));
                        }
                    } else {
                        obj.filters.push(Filter::parse(first));
                    }
                }
                b"/Image" => obj.image = true,
                b"/EmbeddedFile" => obj.embedded = true,
                b"/ObjStm" => obj.object_stream = true,
                b"/JS" | b"/JavaScript" | b"/OpenAction" | b"/Launch" => obj.unsupported = true,
                // The sampled filters use their defaults even with explicit decode parameters.
                b"/DecodeParms" | b"/DP" => {
                    if !input.skip_value() {
                        return Ok(None);
                    }
                }
                b"/Encrypt" => return Ok(None),
                n if n.first() == Some(&b'/') && n.contains(&b'#') => obj.unsupported = true,
                _ => (),
            }
        }
        if obj.encoded.is_some() || obj.unsupported {
            pdf.objects.push(obj);
        }
        last = [None, None];
    }
    pdf.count = count;
    Ok(Some(pdf))
}

pub(super) fn header_type(data: &[u8]) -> bool {
    data[..data.len().min(1024)]
        .windows(7)
        .any(|w| (w.starts_with(b"%PDF-") || w.starts_with(b"%pdf-")) && w[6] == b'.')
}

pub(super) fn extract(data: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(start) = data[..data.len().min(1032)]
        .windows(5)
        .position(|w| w == b"%PDF-")
    else {
        return Ok(Handling::Complete);
    };
    let data = &data[start..];
    let Some(mut pdf) = parse(data, sink)? else {
        return Ok(Handling::Incomplete);
    };
    sink.check()?;
    let mut packed = pdf
        .objects
        .iter()
        .any(|obj| obj.directory.is_some())
        .then(|| {
            object_stream::Packed::new(
                sink.temporary_directory(),
                sink.remaining(),
                pdf.count,
                pdf.objects.iter().map(|obj| obj.id),
            )
        });
    'objects: for obj in pdf.objects {
        sink.check()?;
        if obj.unsupported {
            return Ok(Handling::Incomplete);
        }
        let Some(bytes) = obj.encoded else { continue };
        let content = pdf.contents.contains(&obj.id);
        if obj.image && !obj.filters.contains(&Filter::Jpeg) {
            continue;
        }
        if !obj.filters.is_empty()
            && !obj.embedded
            && !content
            && !obj.filters.iter().any(Filter::dumped)
        {
            continue;
        }
        if obj.filters.contains(&Filter::Unsupported) {
            return Ok(Handling::Incomplete);
        }
        let length = obj
            .length_ref
            .and_then(|id| pdf.lengths.get(&id).copied())
            .or(obj.length)
            .unwrap_or(0)
            .min(bytes.len());
        // The pinned fallback determines EOL width relative to the indirect object header.
        let end = if length == 0 && !obj.filters.contains(&Filter::Flate) {
            trim_eol(&data[obj.start..obj.start + bytes.len()]).len()
        } else if bytes.len().saturating_sub(length) > 2 {
            bytes.len()
        } else {
            length
        };
        let bytes = &bytes[..end];
        let mut decoded: Option<Snapshot> = None;
        let mut directory = obj.directory;
        let mut filters = obj
            .filters
            .into_iter()
            .take_while(|f| *f != Filter::Jpeg)
            .peekable();
        while let Some(filter) = filters.next() {
            let retain =
                filters.peek().is_some() || directory.is_some() || sink.child_limit().is_none();
            let first_stage = decoded.is_none();
            let limit = if obj.object_stream && filter == Filter::Flate {
                // Stock inflates the first 256 KiB before checking its next allocation.
                (sink.remaining() / (256 << 10)).max(1) * (256 << 10)
            } else {
                sink.remaining()
            };
            let mut input_verdict = None;
            let mut next = |data: &[u8]| {
                let result = filter.decode(data, limit, retain, sink)?;
                if let Output::UseInput = result {
                    // The current stage still owns this borrowed input, including earlier filters' output.
                    input_verdict = Some(visit_stream(data, content, sink)?);
                }
                Ok(result)
            };
            let result = match decoded.take() {
                Some(last) => last.with_bytes(next),
                None => next(bytes),
            };
            match result? {
                Output::Counted(size) => {
                    record_child_limit(size, sink);
                    continue 'objects;
                }
                Output::Malformed => return Ok(Handling::Incomplete),
                Output::Decoded(output) => decoded = Some(output),
                Output::UseInput => {
                    if input_verdict.expect("fallback visited the input") {
                        return Ok(Handling::Stopped);
                    }
                    continue 'objects;
                }
                Output::TooLarge(required) => {
                    sink.skip_declared_size(required);
                    if obj.object_stream && filter == Filter::Flate && first_stage {
                        directory = None;
                        break;
                    }
                    continue 'objects;
                }
            }
        }
        let mut visit = |data: &[u8]| -> io::Result<bool> {
            if let (Some(directory), Some(packed)) = (directory, packed.as_mut()) {
                packed.inspect(directory, data, &mut pdf.lengths, &mut pdf.contents, sink)?;
                if sink.skip_declared_size(data.len() as u64) {
                    return Ok(false);
                }
            }
            visit_stream(data, content, sink)
        };
        let stopped = match decoded {
            Some(s) => s.with_bytes(visit)?,
            None => visit(bytes)?,
        };
        if stopped {
            return Ok(Handling::Stopped);
        }
    }
    packed.map_or(Ok(Handling::Complete), |packed| packed.finish(sink))
}

fn record_child_limit(size: u64, sink: &mut dyn ChildSink) {
    if size > 5 || sink.child_limit() == Some(Limit::MaxFiles) {
        sink.can_enter_child();
    }
}

fn visit_stream(data: &[u8], content: bool, sink: &mut dyn ChildSink) -> io::Result<bool> {
    if sink.child_limit().is_some() {
        record_child_limit(data.len() as u64, sink);
        return Ok(false);
    }
    if sink.child_bytes(data, None)? {
        return Ok(true);
    }
    if content {
        return scan_page_text(data, sink);
    }
    Ok(false)
}

// The normalized text cannot be longer than its source. When that bound fits,
// an admitted child needs only one pass. Otherwise count before opening a spool.
fn scan_page_text(data: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    let remaining = sink.remaining();
    let denied = sink.child_limit().is_some();
    let may_exceed_size = data.len() as u64 > remaining;
    if denied || may_exceed_size {
        let stop_after = if may_exceed_size { remaining.max(5) } else { 5 };
        let size = page_text(data, sink, None, stop_after)?;
        if size <= 5 || sink.skip_declared_size(size) || !sink.can_enter_child() {
            return Ok(false);
        }
    }
    let mut snapshot = Snapshot::new(sink.temporary_directory());
    let size = page_text(data, sink, Some(&mut snapshot), u64::MAX)?;
    if size <= 5 {
        return Ok(false);
    }
    sink.visit_snapshot(snapshot, None, None)
}

// The pinned contents pass reads parenthesized strings from arrays starting a line.
fn page_text(
    data: &[u8],
    sink: &mut dyn ChildSink,
    mut snapshot: Option<&mut Snapshot>,
    stop_after: u64,
) -> io::Result<u64> {
    let mut written = 0u64;
    let mut at_line_start = true;
    let mut array = false;
    let mut literal = false;
    let mut space = false;
    let mut out = [0; 8192];
    let mut used = 0;
    for chunk in data.chunks(out.len()) {
        sink.check()?;
        for &b in chunk {
            if !array {
                array = at_line_start && b == b'[';
                at_line_start = b == b'\n';
            } else if !literal {
                literal = b == b'(';
            } else if b == b')' {
                literal = false;
            } else if used == out.len() {
                // Stock consumes this literal byte while flushing the full block.
                // Whitespace state starts fresh in the next output block.
                if let Some(file) = &mut snapshot {
                    file.write_all(&out)?;
                }
                written += used as u64;
                used = 0;
                space = false;
            } else {
                let normalized = match b {
                    9..=13 | b' ' if !space => b' ',
                    0x21..=0x7f => b.to_ascii_lowercase(),
                    _ => continue,
                };
                space = normalized == b' ';
                out[used] = normalized;
                used += 1;
            }
        }
        if written + used as u64 > stop_after {
            return Ok(written + used as u64);
        }
    }
    if let Some(file) = snapshot {
        file.write_all(&out[..used])?;
    }
    Ok(written + used as u64)
}
