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

impl Body<'_> {
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

fn part(input: &[u8], sink: &mut dyn ChildSink, depth: usize) -> io::Result<Handling> {
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
                    let result = part(&p.body[at..offset], sink, depth + 1)?;
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
    if mime.eq_ignore_ascii_case(b"message/rfc822") {
        return if matches!(mode, Encoding::Plain) {
            part(p.body, sink, depth + 1)
        } else {
            Ok(Handling::Incomplete)
        };
    }
    if matches!(mode, Encoding::Base64) {
        let mut digits = 0;
        let mut pads = 0;
        for block in p.body.chunks(8192) {
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
                    return Ok(Handling::Incomplete);
                }
            }
        }
        if digits % 4 == 1 || (pads != 0 && (digits + pads) % 4 != 0) {
            return Ok(Handling::Incomplete);
        }
    }
    let filename = parameter(&p.disposition, b"filename").or_else(|| parameter(&p.kind, b"name"));
    let mut data = Body {
        data: p.body,
        mode,
        bits: 0,
        code: 0,
        final_lf: !p.body.is_empty()
            && !p.body.ends_with(b"\n")
            && !matches!(mode, Encoding::Base64),
    };
    Ok(if sink.child(&mut data, None, filename)? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
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
                let result = part(previous, sink, 0)?;
                if result != Handling::Complete {
                    return Ok(result);
                }
                message = next;
            }
            empty = row.is_empty();
            rest = next;
        }
        return part(message, sink, 0);
    }
    part(bytes, sink, 0)
}
