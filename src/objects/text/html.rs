mod data;
mod script;
use super::{ChildSink, Handling, Target};
use std::io::{self, BufWriter, Seek, Write};
use tempfile::SpooledTempFile;

// Only the spellings recognized by the pinned stock magic database select target 3.
pub(super) fn recognizes(head: &[u8]) -> bool {
    const MAGIC: &[&[u8]] = &[
        b"<HTML>", b"<Html>", b"<html>", b"<HEAD>", b"<Head>", b"<head>", b"<IFRAME", b"<iframe",
        b"<IMG", b"<Img", b"<img", b"<OBJECT", b"<Object", b"<object", b"<SCRIPT", b"<Script",
        b"<script", b"<TABLE", b"<table",
    ];
    head.iter()
        .enumerate()
        .filter(|(_, b)| **b == b'<')
        .any(|(i, _)| {
            let tag = &head[i..];
            MAGIC.iter().any(|magic| tag.starts_with(magic))
                || ((tag.starts_with(b"<a ") || tag.starts_with(b"<A "))
                    && tag[3..].windows(4).any(|attr| {
                        attr[..2].eq_ignore_ascii_case(b"hr") && matches!(&attr[2..], b"ef" | b"EF")
                    }))
        })
}

struct View {
    out: BufWriter<SpooledTempFile>,
    limit: u64,
    count: u64,
    last_space: bool,
}

impl View {
    fn new(sink: &dyn ChildSink) -> Self {
        Self {
            out: BufWriter::new(tempfile::spooled_tempfile_in(
                64 * 1024,
                sink.temporary_directory(),
            )),
            limit: if sink.child_limit().is_none() {
                sink.remaining()
            } else {
                0
            },
            count: 0,
            last_space: false,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let left = self.limit.saturating_sub(self.count);
        let keep = left.min(bytes.len() as u64) as usize;
        self.out.write_all(&bytes[..keep])?;
        self.count = self.count.saturating_add(bytes.len() as u64);
        if let Some(&b) = bytes.last() {
            self.last_space = b == b' ';
        }
        Ok(())
    }

    fn separate(&mut self) -> io::Result<()> {
        if !self.last_space {
            self.write(b" ")?;
        }
        Ok(())
    }

    fn submit(self, sink: &mut dyn ChildSink, name: &[u8], targets: &[Target]) -> io::Result<bool> {
        let mut file = self.out.into_inner().map_err(|e| e.into_error())?;
        for &target in targets {
            // Stock checks the normalized size before file count and recursion.
            if sink.skip_declared_size(self.count) || !sink.can_enter_child() {
                break;
            }
            file.rewind()?;
            if sink.child(&mut file, Some(target), Some(name))? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn entity(bytes: &[u8]) -> Option<(u16, usize)> {
    let end = bytes.iter().take(16).position(|&b| b == b';')?;
    let name = &bytes[1..end];
    let b = match name {
        b"amp" => u16::from(b'&'),
        b"lt" => u16::from(b'<'),
        b"gt" => u16::from(b'>'),
        b"quot" => u16::from(b'"'),
        b"apos" => u16::from(b'\''),
        b"nbsp" => 0xa0,
        b"copy" => 0xa9,
        b"reg" => 0xae,
        b"pound" => 0xa3,
        b"euro" => 0x20ac,
        b"lambda" => 0x03bb,
        b"ndash" => 0x2013,
        b"mdash" => 0x2014,
        b"hellip" => 0x2026,
        _ => {
            let n = name.strip_prefix(b"#")?;
            let (n, base) = n
                .strip_prefix(b"x")
                .or_else(|| n.strip_prefix(b"X"))
                .map_or((n, 10), |n| (n, 16));
            u16::from_str_radix(std::str::from_utf8(n).ok()?, base).ok()?
        }
    };
    Some((b, end + 1))
}

fn ws(bytes: &[u8]) -> &[u8] {
    bytes.trim_ascii_start()
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
}

// Keep each quoted attribute within its tag and release it as soon as the tag ends.
fn tag(
    input: &[u8],
    full: &mut View,
    text: &mut View,
    urls: &mut data::DataUrls,
) -> io::Result<Option<(usize, bool, bool)>> {
    let mut bytes = ws(&input[1..]);
    let close = bytes.starts_with(b"/");
    if close {
        bytes = &bytes[1..];
    }
    let len = bytes
        .iter()
        .take_while(|b| !b.is_ascii_whitespace() && **b != b'>')
        .count();
    if len == 0 {
        return Ok(None);
    }
    let name = &bytes[..len];
    let script = name.eq_ignore_ascii_case(b"script");
    full.write(if close { b"</" } else { b"<" })?;
    for &b in name {
        full.write(&[b.to_ascii_lowercase()])?;
    }
    bytes = &bytes[len..];
    text.separate()?;
    loop {
        bytes = ws(bytes);
        if let Some(rest) = bytes.strip_prefix(b">") {
            full.write(b">")?;
            return Ok(Some((input.len() - rest.len(), script, close)));
        }
        if let Some(rest) = bytes.strip_prefix(b"/>") {
            full.write(b"/>")?;
            return Ok(Some((input.len() - rest.len(), false, close)));
        }
        let len = bytes.iter().take_while(|b| name_byte(**b)).count();
        if close || len == 0 || input.len() - bytes.len() > 8192 {
            return Ok(None);
        }
        let attr = &bytes[..len];
        full.write(b" ")?;
        for &b in attr {
            full.write(&[b.to_ascii_lowercase()])?;
        }
        bytes = ws(&bytes[len..]);
        if !bytes.starts_with(b"=") {
            continue;
        }
        bytes = ws(&bytes[1..]);
        let Some(&first) = bytes.first() else {
            return Ok(None);
        };
        let quoted = matches!(first, b'"' | b'\'');
        if quoted {
            bytes = &bytes[1..];
        }
        let is_data = bytes
            .get(..5)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"data:"));
        let max = if is_data { bytes.len() } else { 8193 };
        let end = bytes.iter().take(max).position(|&b| {
            if quoted {
                b == first
            } else {
                b.is_ascii_whitespace() || b == b'>'
            }
        });
        let Some(end) = end else { return Ok(None) };
        let mut val = &bytes[..end];
        bytes = &bytes[end + usize::from(quoted)..];
        let url = (name.eq_ignore_ascii_case(b"a") && attr.eq_ignore_ascii_case(b"href"))
            || (name.eq_ignore_ascii_case(b"img") && attr.eq_ignore_ascii_case(b"src"));
        if is_data {
            urls.push(bytes.len() + usize::from(quoted), val.len())?;
            full.write(if quoted { b"=\"data\"" } else { b"=data" })?;
            continue;
        }
        full.write(if quoted { b"=\"" } else { b"=" })?;
        let has_url = url && !val.is_empty();
        while let Some((&b, rest)) = val.split_first() {
            let c = if b == b'&' {
                let Some((c, n)) = entity(val) else {
                    return Ok(None);
                };
                val = &val[n..];
                let Ok(c) = u8::try_from(c) else {
                    return Ok(None);
                };
                c
            } else {
                val = rest;
                b
            };
            if c.is_ascii_control() {
                return Ok(None);
            }
            full.write(&[c.to_ascii_lowercase()])?;
            if url {
                text.write(&[c])?;
            }
        }
        if quoted {
            full.write(b"\"")?;
        }
        if has_url {
            text.write(b" ")?;
        }
    }
}

pub(super) fn extract(
    bytes: &[u8],
    sink: &mut dyn ChildSink,
    input_size: usize,
) -> io::Result<Handling> {
    let (max_html, max_notags, _) = sink.text_limits();
    if input_size as u64 > max_html {
        return Ok(Handling::Complete);
    }
    let mut full = View::new(sink);
    let mut text = View::new(sink);
    let mut pending = false;
    let mut skip_space = true;
    let mut script = false;
    let mut javascript = View::new(sink);
    let mut urls = data::DataUrls::new(bytes.len(), sink);
    let mut script_start = None;
    let mut unknown_script = false;
    let mut pos = 0;
    let mut next_check = 0;
    while pos < bytes.len() {
        if pos >= next_check {
            sink.check()?;
            next_check = pos.saturating_add(8192);
        }
        let tail = &bytes[pos..];
        let b = tail[0];
        if b == b'\r' {
            pos += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            if !script {
                pending = !skip_space;
                text.separate()?;
            }
            pos += 1;
            continue;
        }
        if pending {
            full.write(b" ")?;
            pending = false;
        }
        if b == b'<' {
            if tail.starts_with(b"<!--")
                || tail
                    .get(..9)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"<!doctype"))
            {
                if script {
                    return Ok(Handling::Incomplete);
                }
                let terminator: &[u8] = if tail.starts_with(b"<!--") {
                    b"-->"
                } else {
                    b">"
                };
                let Some(end) = tail.windows(terminator.len()).position(|w| w == terminator) else {
                    return Ok(Handling::Incomplete);
                };
                pos += end + terminator.len();
                text.separate()?;
            } else {
                let Some((used, is_script, close)) = tag(tail, &mut full, &mut text, &mut urls)?
                else {
                    return Ok(Handling::Incomplete);
                };
                if is_script {
                    script = !close;
                    if close {
                        if let Some(start) = script_start.take()
                            && !script::normalize(&bytes[start..pos], &mut javascript, sink)?
                        {
                            unknown_script = true;
                        }
                    } else if tail[..used].eq_ignore_ascii_case(b"<script>") {
                        script_start = Some(pos + used);
                    } else {
                        unknown_script = true;
                    }
                }
                pos += used;
            }
            skip_space = true;
            continue;
        }
        if !b.is_ascii() {
            let n = tail.iter().take(3).take_while(|b| !b.is_ascii()).count();
            let group = &tail[..n];
            // The HTML text extractor groups at most three high bytes. Its text
            // view ends each group with the preceding byte, or zero for a singleton.
            if matches!(
                group,
                [0xe3, 0x80, 0x82] | [0xef, 0xbc, 0x8e] | [0xef, 0xb9, 0x92]
            ) {
                full.write(b".")?;
                text.write(b".")?;
            } else {
                full.write(group)?;
                let space = text.last_space;
                text.write(&group[..n - 1])?;
                text.write(&[if n == 1 { 0 } else { group[n - 2] }])?;
                text.last_space = space;
            }
            skip_space = false;
            pos += n;
            continue;
        }
        if b == 0 {
            return Ok(Handling::Incomplete);
        }
        skip_space = false;
        if b == b'&' {
            let Some((c, n)) = entity(tail) else {
                return Ok(Handling::Incomplete);
            };
            if let Ok(byte) = u8::try_from(c) {
                full.write(&[byte.to_ascii_lowercase()])?;
            } else {
                full.write(format!("&#x{c:04x};").as_bytes())?;
            }
            if !script {
                text.separate()?;
            }
            pos += n;
        } else {
            let c = if script && b == b'\'' {
                b'"'
            } else {
                b.to_ascii_lowercase()
            };
            full.write(&[c])?;
            if !script {
                if b < 0x20 {
                    text.separate()?;
                } else {
                    text.write(&[c])?;
                }
            }
            pos += 1;
        }
    }
    if full.submit(sink, b"nocomment.html", &[Target::Html])?
        || (input_size as u64 <= max_notags
            && text.submit(sink, b"notags.html", &[Target::Html])?)
    {
        return Ok(Handling::Stopped);
    }
    if unknown_script || script_start.is_some() {
        return Ok(Handling::Incomplete);
    }
    if javascript.count > 0
        && javascript.submit(sink, b"javascript", &[Target::Html, Target::Ascii])?
    {
        return Ok(Handling::Stopped);
    }
    urls.scan(bytes, sink)
}
