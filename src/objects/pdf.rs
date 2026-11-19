//! Scan PDF streams after the raw PDF matcher, in physical indirect-object order.
use super::{ChildSink, Handling, Snapshot};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};

mod filters;
mod object_stream;
use filters::Filter;

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
                // The pinned Flate, ASCII and run-length decoders ignore filter parameters.
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
        for filter in obj.filters {
            if filter == Filter::Jpeg {
                break;
            }
            let first_stage = decoded.is_none();
            let limit = if obj.object_stream && filter == Filter::Flate {
                // Stock inflates the first 256 KiB before checking its next allocation.
                (sink.remaining() / (256 << 10)).max(1) * (256 << 10)
            } else {
                sink.remaining()
            };
            let mut next = |data: &[u8]| -> io::Result<Option<Snapshot>> {
                let dir = sink.temporary_directory().to_owned();
                let mut source = filter.reader(data)?;
                Snapshot::read_bounded(&mut *source, &dir, limit, || sink.check())
            };
            let result = match decoded.take() {
                Some(last) => last.with_bytes(next),
                None => next(bytes),
            };
            match result {
                Ok(Some(output)) => decoded = Some(output),
                Ok(None) => {
                    sink.skip_declared_size(sink.remaining().saturating_add(1));
                    if obj.object_stream && filter == Filter::Flate && first_stage {
                        directory = None;
                        break;
                    }
                    continue 'objects;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::InvalidData
                            | io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::InvalidInput
                    ) =>
                {
                    return Ok(Handling::Incomplete);
                }
                Err(e) => return Err(e),
            }
        }
        let mut visit = |data: &[u8]| -> io::Result<bool> {
            if let (Some(directory), Some(packed)) = (directory, packed.as_mut()) {
                packed.inspect(directory, data, &mut pdf.lengths, &mut pdf.contents, sink)?;
                if sink.skip_declared_size(data.len() as u64) {
                    return Ok(false);
                }
            }
            if sink.child_bytes(data, None)? {
                return Ok(true);
            }
            if content {
                let mut text = ContentsText::new(data);
                if sink.child(&mut text, None, None)? {
                    return Ok(true);
                }
            }
            Ok(false)
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

// The pinned contents pass reads parenthesized strings from text arrays starting a line.
struct ContentsText<'a> {
    input: &'a [u8],
    at_line_start: bool,
    array: bool,
    literal: bool,
    space: bool,
}
impl<'a> ContentsText<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            at_line_start: true,
            array: false,
            literal: false,
            space: false,
        }
    }
}
impl Read for ContentsText<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut used = 0;
        while used < out.len() {
            let Some((&b, rest)) = self.input.split_first() else {
                break;
            };
            self.input = rest;
            if !self.array {
                self.array = self.at_line_start && b == b'[';
                self.at_line_start = b == b'\n';
            } else if !self.literal {
                self.literal = b == b'(';
            } else if b == b')' {
                self.literal = false;
            } else {
                let normalized = match b {
                    9..=13 | b' ' if !self.space => b' ',
                    0x21..=0x7f => b.to_ascii_lowercase(),
                    _ => continue,
                };
                self.space = normalized == b' ';
                out[used] = normalized;
                used += 1;
            }
        }
        Ok(used)
    }
}
