//! Passive local destinations in PDF 1.7, sections 12.3.2 and 12.6.4.2.
use super::{ChildSink, Id, Object, Tokens, number, stream_start};
use std::{collections::HashMap, io};

#[derive(Clone, Copy)]
pub(super) enum Destination {
    Inline,
    Page(Id),
    Indirect(Id),
}

fn coordinate(value: &[u8]) -> bool {
    let value = value
        .strip_prefix(b"-")
        .or_else(|| value.strip_prefix(b"+"))
        .unwrap_or(value);
    let mut digits = false;
    let mut dot = false;
    for &c in value {
        if c.is_ascii_digit() {
            digits = true;
        } else if c == b'.' && !dot {
            dot = true;
        } else {
            return false;
        }
    }
    digits
}

fn array(input: &mut Tokens<'_>) -> Option<Id> {
    let id = (number(input.next()?)?, number(input.next()?)?);
    if input.next()? != b"R" {
        return None;
    }
    let kind = input.next()?;
    let count = match kind {
        b"/Fit" | b"/FitB" => 0,
        b"/FitH" | b"/FitBH" | b"/FitV" | b"/FitBV" => 1,
        b"/XYZ" => 3,
        b"/FitR" => 4,
        _ => return None,
    };
    for _ in 0..count {
        let value = input.next()?;
        if !(coordinate(value) || value == b"null" && kind != b"/FitR") {
            return None;
        }
    }
    (input.next()? == b"]").then_some(id)
}

fn goto(input: &mut Tokens<'_>) -> Option<()> {
    let (mut subtype, mut dest, mut typed) = (false, false, false);
    loop {
        match input.next()? {
            b"/S" if !subtype && input.next()? == b"/GoTo" => subtype = true,
            b"/Type" if !typed && input.next()? == b"/Action" => typed = true,
            b"/D" if !dest => {
                match input.next()? {
                    b"[" => {
                        array(input)?;
                    }
                    v if v.starts_with(b"/") && v.len() > 1 && !v.contains(&b'#') => {}
                    v if v.starts_with(b"(") && v.ends_with(b")") => {}
                    _ => return None,
                }
                dest = true;
            }
            b">>" => return (subtype && dest).then_some(()),
            _ => return None,
        }
    }
}

// Only fields in the outer dictionary identify catalogs and pages. Ignore names
// inside strings, arrays and nested dictionaries. Duplicate fields are ambiguous.
fn field<'a>(body: &'a [u8], name: &[u8]) -> Option<Tokens<'a>> {
    let mut input = Tokens { data: body, pos: 0 };
    if input.next()? != b"<<" {
        return None;
    }
    let mut found = None;
    loop {
        let key = input.next()?;
        if key == b">>" {
            return if input.next().is_none() { found } else { None };
        }
        if !key.starts_with(b"/") {
            return None;
        }
        if key == name && found.replace(input.clone()).is_some() {
            return None;
        }
        if input.reference().is_some() {
            input.next();
            input.next();
            input.next();
        } else if !input.skip_value() {
            return None;
        }
    }
}

pub(super) fn catalog(body: &[u8]) -> Option<Destination> {
    if field(body, b"/Type")?.next()? != b"/Catalog" {
        return None;
    }
    let mut input = field(body, b"/OpenAction")?;
    if let Some(id) = input.reference() {
        return Some(Destination::Indirect(id));
    }
    match input.next()? {
        b"[" => array(&mut input).map(Destination::Page),
        b"<<" => goto(&mut input).map(|()| Destination::Inline),
        _ => None,
    }
}

#[derive(Default)]
enum Definition<'a> {
    #[default]
    Missing,
    Unique {
        start: usize,
        body: &'a [u8],
        page: bool,
        action: bool,
        selected: bool,
    },
    Ambiguous,
}

fn passive_body(body: &[u8]) -> bool {
    let mut input = Tokens { data: body, pos: 0 };
    let valid = match input.next() {
        Some(b"[") => array(&mut input).is_some(),
        Some(b"<<") => goto(&mut input).is_some(),
        _ => false,
    };
    valid && input.next().is_none()
}

// Only referenced IDs occupy the lookup table. A single pass finds forward and
// backward references, and never interprets a token inside a physical stream.
pub(super) fn resolve<'a>(
    data: &'a [u8],
    objects: &mut Vec<Object<'a>>,
    requests: &[(usize, Destination)],
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let mut definitions = HashMap::new();
    for &(_, request) in requests {
        if let Destination::Page(id) | Destination::Indirect(id) = request {
            definitions.insert(id, Definition::Missing);
        }
    }
    if definitions.is_empty() {
        return Ok(true);
    }
    // The first pass already located every stream payload. Advance over those
    // spans directly so large attachments are read only once.
    let mut streams = objects
        .iter()
        .filter(|o| !o.raw_destination)
        .filter_map(|o| o.encoded.map(|bytes| (o.start, bytes)));
    let mut input = Tokens { data, pos: 0 };
    let mut last = [None, None];
    while let Some(token) = input.next() {
        if token != b"obj" {
            last = [last[1], number(token)];
            continue;
        }
        sink.check()?;
        let start = input.pos;
        let mut stream = false;
        let [Some(id), Some(generation)] = last else {
            return Ok(false);
        };
        let definition = definitions.get_mut(&(id, generation));
        let mut next_check = start.saturating_add(64 * 1024);
        let end = loop {
            if input.pos >= next_check {
                sink.check()?;
                next_check = input.pos.saturating_add(64 * 1024);
            }
            match input.next() {
                Some(b"endobj") => break input.pos - 6,
                Some(b"stream") => {
                    stream = true;
                    let Some((owner, bytes)) = streams.next() else {
                        return Ok(false);
                    };
                    let Some(at) = stream_start(&mut input) else {
                        return Ok(false);
                    };
                    if owner != start || data[at..].as_ptr() != bytes.as_ptr() {
                        return Ok(false);
                    }
                    input.pos = at + bytes.len() + b"endstream".len();
                }
                None => return Ok(false),
                _ => {}
            }
        };
        if let Some(definition) = definition {
            *definition = if matches!(definition, Definition::Missing) && !stream {
                let body = &data[start..end];
                Definition::Unique {
                    start,
                    body,
                    page: field(body, b"/Type").and_then(|mut t| t.next()) == Some(b"/Page"),
                    action: passive_body(body),
                    selected: false,
                }
            } else {
                Definition::Ambiguous
            };
        }
        last = [None, None];
    }
    for &(owner, request) in requests {
        let (Destination::Page(id) | Destination::Indirect(id)) = request else {
            continue;
        };
        if let Some(Definition::Unique {
            page,
            action,
            selected,
            ..
        }) = definitions.get_mut(&id)
            && match request {
                Destination::Page(_) => *page,
                _ => *action,
            }
        {
            *selected = true;
        } else {
            objects[owner].unsupported = true;
        }
    }
    for (id, definition) in definitions {
        if let Definition::Unique {
            start,
            body,
            selected: true,
            ..
        } = definition
        {
            objects.push(Object {
                id,
                start,
                raw_destination: true,
                encoded: Some(body),
                ..Object::default()
            });
        }
    }
    objects.sort_unstable_by_key(|obj| (obj.start, obj.raw_destination));
    Ok(true)
}
