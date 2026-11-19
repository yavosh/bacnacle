use super::{ChildSink, Handling};
use std::io::{self, Read};

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    const START: &[&[u8]] = &[
        b"From: ",
        b"From ",
        b">From ",
        b"Received: ",
        b"Subject: ",
        b"Date: ",
        b"To: ",
        b"Message-ID: ",
        b"Message-Id: ",
        b"Return-Path: ",
        b"Return-path: ",
        b"Delivered-To: ",
        b"Delivery-date: ",
        b"Envelope-to: ",
        b"Received-SPF: ",
        b"X-Original-To: ",
    ];
    START.iter().any(|s| bytes.starts_with(s))
        || (bytes
            .get(..13)
            .is_some_and(|s| s.eq_ignore_ascii_case(b"MIME-Version:"))
            && bytes
                .windows(14)
                .any(|s| s.eq_ignore_ascii_case(b"\nContent-Type:")))
}

struct Part<'a> {
    kind: Vec<u8>,
    disposition: Vec<u8>,
    encoding: Vec<u8>,
    body: &'a [u8],
}

fn line(input: &[u8]) -> (&[u8], &[u8]) {
    let (text, rest) = input
        .iter()
        .position(|&b| b == b'\n')
        .map_or((input, &[][..]), |i| (&input[..i], &input[i + 1..]));
    (text.strip_suffix(b"\r").unwrap_or(text), rest)
}

fn headers(mut input: &[u8]) -> Option<Part<'_>> {
    let mut part = Part {
        kind: vec![],
        disposition: vec![],
        encoding: vec![],
        body: &[],
    };
    let mut last = None;
    let original_len = input.len();
    while !input.is_empty() && original_len - input.len() <= 64 * 1024 {
        let (row, rest) = line(input);
        input = rest;
        if row.is_empty() {
            part.body = input;
            return Some(part);
        }
        let continuation = row.starts_with(b" ") || row.starts_with(b"\t");
        let value = if continuation {
            row.trim_ascii()
        } else {
            let colon = row.iter().position(|b| *b == b':')?;
            let name = &row[..colon];
            last = if name.eq_ignore_ascii_case(b"Content-Type") {
                Some(0)
            } else if name.eq_ignore_ascii_case(b"Content-Disposition") {
                Some(1)
            } else if name.eq_ignore_ascii_case(b"Content-Transfer-Encoding") {
                Some(2)
            } else {
                None
            };
            row[colon + 1..].trim_ascii()
        };
        if value.len() > 8192 {
            return None;
        }
        let field = match last {
            Some(0) => &mut part.kind,
            Some(1) => &mut part.disposition,
            Some(2) => &mut part.encoding,
            _ => continue,
        };
        if !field.is_empty() {
            if !continuation {
                return None;
            }
            field.push(b' ');
        }
        field.extend_from_slice(value);
    }
    None
}

fn parameter<'a>(value: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    value.split(|c| *c == b';').skip(1).find_map(|field| {
        let eq = field.iter().position(|&c| c == b'=')?;
        if !field[..eq].trim_ascii().eq_ignore_ascii_case(name) {
            return None;
        }
        let v = field[eq + 1..].trim_ascii();
        Some(
            v.strip_prefix(b"\"")
                .and_then(|s| s.strip_suffix(b"\""))
                .unwrap_or(v),
        )
    })
}

fn b64(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum Encoding {
    Plain,
    Base64,
    Quoted,
}

struct Body<'a> {
    data: &'a [u8],
    mode: Encoding,
    code: u16,
    bits: u8,
    final_lf: bool,
}

pub(in crate::objects) fn valid_base64(data: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    let mut digits = 0;
    let mut pads = 0;
    for block in data.chunks(8192) {
        sink.check()?;
        for &b in block {
            if b.is_ascii_whitespace() {
                continue;
            }
            if b == b'=' && pads < 2 {
                pads += 1;
            } else if pads == 0 && b64(b).is_some() {
                digits += 1;
            } else {
                return Ok(false);
            }
        }
    }
    if digits % 4 == 1 || (pads != 0 && (digits + pads) % 4 != 0) {
        return Ok(false);
    }
    Ok(true)
}

pub(in crate::objects) fn base64_reader(data: &[u8]) -> impl Read + '_ {
    Body::new(data, Encoding::Base64)
}

impl<'a> Body<'a> {
    fn new(data: &'a [u8], mode: Encoding) -> Self {
        Self {
            data,
            mode,
            code: 0,
            bits: 0,
            final_lf: !data.is_empty()
                && !data.ends_with(b"\n")
                && !matches!(mode, Encoding::Base64),
        }
    }

    fn next_byte(&mut self) -> io::Result<Option<u8>> {
        while let Some((&b, rest)) = self.data.split_first() {
            self.data = rest;
            match self.mode {
                Encoding::Base64 => {
                    if b.is_ascii_whitespace() || b == b'=' {
                        continue;
                    }
                    let six = b64(b).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid base64 mail part")
                    })?;
                    self.code = (self.code << 6) | u16::from(six);
                    self.bits += 6;
                    if self.bits < 8 {
                        continue;
                    }
                    self.bits -= 8;
                    return Ok(Some((self.code >> self.bits) as u8));
                }
                Encoding::Quoted if b == b'=' => {
                    if let Some(next) = rest
                        .strip_prefix(b"\r\n")
                        .or_else(|| rest.strip_prefix(b"\n"))
                    {
                        self.data = next;
                        continue;
                    }
                    if let Some(hex) = rest
                        .get(..2)
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .and_then(|s| u8::from_str_radix(s, 16).ok())
                    {
                        self.data = &rest[2..];
                        return Ok(Some(hex));
                    }
                }
                _ => (),
            }
            if b == b'\r' && rest.starts_with(b"\n") {
                continue;
            }
            return Ok(Some(b));
        }
        Ok(std::mem::take(&mut self.final_lf).then_some(b'\n'))
    }
}

impl Read for Body<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        for (i, dest) in output.iter_mut().enumerate() {
            let Some(b) = self.next_byte()? else {
                return Ok(i);
            };
            *dest = b;
        }
        Ok(output.len())
    }
}

fn submit(
    bytes: &[u8],
    mode: Encoding,
    filename: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    submit_parts(&[], bytes, mode, filename, sink)
}

fn submit_parts(
    prefix: &[u8],
    bytes: &[u8],
    mode: Encoding,
    filename: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let body = Body::new(bytes, mode);
    let bound = (prefix.len() + bytes.len()) as u64 + u64::from(body.final_lf);
    // A nonempty prefix ends on the LF immediately before the removed begin line.
    let mut data = Body::new(prefix, Encoding::Plain).chain(body);
    if sink.child_limit().is_some() {
        // Stock checks the decoded byte count before the file and map limits.
        if bound > sink.remaining() {
            let mut total = 0;
            let mut block = [0; 8192];
            loop {
                sink.check()?;
                let n = data.read(&mut block)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
            }
            if sink.skip_declared_size(total) {
                return Ok(Handling::Complete);
            }
        }
        sink.can_enter_child();
        return Ok(Handling::Complete);
    }
    Ok(if sink.child(&mut data, None, filename)? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}

#[derive(Default)]
struct ForwardFiles<'a> {
    transfer: bool,
    note: Option<&'a [u8]>,
    multiple_notes: bool,
}

fn forward_files<'a>(mut body: &'a [u8], sink: &mut dyn ChildSink) -> io::Result<ForwardFiles<'a>> {
    const MARKER: &[u8] = b"Content-Transfer-Encoding";
    let mut files = ForwardFiles::default();
    while !body.is_empty() {
        sink.check()?;
        let (row, next) = line(body);
        // Stock checks this case-insensitive prefix even in prose, without a colon.
        if let Some((name, rest)) = row.split_at_checked(MARKER.len())
            && name.eq_ignore_ascii_case(MARKER)
            && !rest.windows(4).any(|w| w == b"7bit")
        {
            files.transfer = true;
        }
        if row.starts_with(b"b")
            && row
                .get(..6)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"begin "))
            && row
                .get(6..9)
                .is_some_and(|p| p.iter().all(u8::is_ascii_digit))
            && row.get(9) == Some(&b' ')
        {
            files.multiple_notes |= files.note.is_some();
            files.note.get_or_insert(body);
        }
        body = next;
    }
    Ok(files)
}

enum Saved<'a> {
    Forward(&'a [u8]),
    Uuencoded(Option<super::attachments::RecoveredNote<'a>>),
}

#[derive(Default)]
struct Deferred<'a> {
    first: Option<Saved<'a>>,
    uncertain: bool,
    max_bytes: u64,
    prior_limit: bool,
    has_uu: bool,
}

impl<'a> Deferred<'a> {
    fn add(&mut self, file: Saved<'a>, bound: u64, uncertain: bool) {
        self.uncertain |= self.first.is_some() || uncertain;
        self.has_uu |= matches!(file, Saved::Uuencoded(_));
        self.max_bytes = self.max_bytes.max(bound);
        self.first.get_or_insert(file);
    }
}

fn part<'a>(
    input: &'a [u8],
    sink: &mut dyn ChildSink,
    depth: usize,
    multipart_member: bool,
    deferred: &mut Deferred<'a>,
) -> io::Result<Handling> {
    if depth >= 16 {
        return Ok(Handling::Incomplete);
    }
    let Some(p) = headers(input) else {
        return Ok(Handling::Incomplete);
    };
    let mime = p
        .kind
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    if mime
        .get(..10)
        .is_some_and(|v| v.eq_ignore_ascii_case(b"multipart/"))
    {
        let Some(boundary) = parameter(&p.kind, b"boundary") else {
            return Ok(Handling::Incomplete);
        };
        if boundary.is_empty() || boundary.len() > 200 {
            return Ok(Handling::Incomplete);
        }
        let mut data = p.body;
        let mut start = None;
        while !data.is_empty() {
            sink.check()?;
            let (row, next) = line(data);
            let offset = p.body.len() - data.len();
            let ending = row
                .strip_prefix(b"--")
                .and_then(|s| s.strip_prefix(boundary))
                .map(<[u8]>::trim_ascii_end);
            if let Some(suffix @ (b"" | b"--")) = ending {
                if let Some(at) = start {
                    let result = part(&p.body[at..offset], sink, depth + 1, true, deferred)?;
                    if result != Handling::Complete {
                        return Ok(result);
                    }
                }
                if suffix == b"--" {
                    return Ok(Handling::Complete);
                }
                start = Some(p.body.len() - next.len());
            }
            data = next;
        }
        return Ok(Handling::Incomplete);
    }
    if mime.eq_ignore_ascii_case(b"message/partial") {
        return Ok(Handling::Incomplete);
    }
    let enc = p.encoding.trim_ascii();
    if [b"x-uuencode".as_slice(), b"uuencode", b"uue"]
        .iter()
        .any(|e| enc.eq_ignore_ascii_case(e))
    {
        return super::attachments::uu(p.body, sink);
    }
    let mode = if enc.eq_ignore_ascii_case(b"base64") {
        Encoding::Base64
    } else if enc.eq_ignore_ascii_case(b"quoted-printable") {
        Encoding::Quoted
    } else if enc.is_empty()
        || [b"7bit".as_slice(), b"8bit", b"binary"]
            .iter()
            .any(|s| enc.eq_ignore_ascii_case(s))
    {
        Encoding::Plain
    } else {
        return Ok(Handling::Incomplete);
    };
    let forwarded = mime.eq_ignore_ascii_case(b"message/rfc822");
    if forwarded && !multipart_member {
        return match mode {
            Encoding::Plain => part(p.body, sink, depth + 1, false, deferred),
            // A standalone message is parsed for literal message headers. Its wrapping
            // transport declaration does not decode a fresh child as it does in multipart.
            Encoding::Base64 if valid_base64(p.body, sink)? => Ok(Handling::Complete),
            Encoding::Quoted => {
                let Some(inner) = headers(p.body) else {
                    return Ok(Handling::Incomplete);
                };
                let kind = inner.kind.strip_prefix(b"=20").unwrap_or(&inner.kind);
                if inner.encoding.is_empty()
                    && inner.disposition.is_empty()
                    && kind.eq_ignore_ascii_case(b"text/plain")
                {
                    submit(inner.body, Encoding::Plain, None, sink)
                } else {
                    Ok(Handling::Incomplete)
                }
            }
            _ => Ok(Handling::Incomplete),
        };
    }
    let mut prefix = &[][..];
    let mut body = p.body;
    if forwarded && matches!(mode, Encoding::Plain) {
        let files = forward_files(p.body, sink)?;
        if let Some(encoded) = files.note {
            let delayed = enc.is_empty() || enc.eq_ignore_ascii_case(b"7bit");
            let note = super::attachments::recovered_note(encoded, sink)?;
            if files.transfer && !delayed {
                let Some(note) = note.filter(|_| !files.multiple_notes) else {
                    return Ok(Handling::Incomplete);
                };
                // The reference removes the begin line, data and zero line. The end
                // line stays in the forward that it submits before direct siblings.
                prefix = &p.body[..p.body.len() - encoded.len()];
                body = note.tail;
                deferred.add(Saved::Uuencoded(Some(note)), encoded.len() as u64, false);
            } else {
                deferred.add(
                    Saved::Uuencoded(note),
                    encoded.len() as u64,
                    files.multiple_notes || files.transfer,
                );
                return Ok(Handling::Complete);
            }
        }
        if !files.transfer {
            return Ok(Handling::Complete);
        }
        if enc.is_empty() || enc.eq_ignore_ascii_case(b"7bit") {
            // These saved messages follow directly scanned attachments. With explicit
            // 7bit the reference also writes a second transfer-decoding recovery file.
            let bound = p.body.len() as u64 + u64::from(!p.body.ends_with(b"\n"));
            deferred.add(
                Saved::Forward(p.body),
                bound,
                enc.eq_ignore_ascii_case(b"7bit"),
            );
            return Ok(Handling::Complete);
        }
    }
    if matches!(mode, Encoding::Base64) && !valid_base64(p.body, sink)? {
        return Ok(Handling::Incomplete);
    }
    let filename = parameter(&p.disposition, b"filename")
        .or_else(|| parameter(&p.kind, b"name"))
        .or(forwarded.then_some(b"textportion".as_slice()));
    deferred.prior_limit |= sink.child_limit().is_some();
    submit_parts(prefix, body, mode, filename, sink)
}

fn parse_message(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let mut deferred = Deferred::default();
    let result = part(bytes, sink, 0, false, &mut deferred)?;
    if result != Handling::Complete {
        return Ok(result);
    }
    let Some(bytes) = deferred.first else {
        return Ok(Handling::Complete);
    };
    if deferred.uncertain {
        // A recovered note may be too short to consume any file or scan budget.
        if deferred.has_uu {
            return Ok(Handling::Incomplete);
        }
        if sink.child_limit().is_some() {
            // The reference scans these generated files in filesystem order.
            // Return a limit only when it was recorded earlier or every possible file fits.
            if deferred.prior_limit || deferred.max_bytes <= sink.remaining() {
                sink.can_enter_child();
                return Ok(Handling::Complete);
            }
            if sink.remaining() == 0 {
                sink.skip_declared_size(1);
                return Ok(Handling::Complete);
            }
        }
        return Ok(Handling::Incomplete);
    }
    match bytes {
        Saved::Forward(body) => submit(body, Encoding::Plain, None, sink),
        Saved::Uuencoded(Some(note)) => note.submit(sink),
        Saved::Uuencoded(None) => Ok(Handling::Incomplete),
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if bytes.starts_with(b">From ") {
        return Ok(Handling::Incomplete);
    }
    if bytes.starts_with(b"From ") {
        let (_, mut rest) = line(bytes);
        let mut message = rest;
        let mut empty = true;
        while !rest.is_empty() {
            let (row, next) = line(rest);
            sink.check()?;
            if empty && row.starts_with(b"From ") {
                let previous = &message[..message.len() - rest.len()];
                let result = parse_message(previous, sink)?;
                if result != Handling::Complete {
                    return Ok(result);
                }
                message = next;
            }
            empty = row.is_empty();
            rest = next;
        }
        return parse_message(message, sink);
    }
    parse_message(bytes, sink)
}
