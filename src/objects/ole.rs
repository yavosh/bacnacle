//! Extract ordinary compound-file streams and native Package attachments.
use super::{ChildSink, Handling};
use cfb::CompoundFile;
use directory::{Inventory, Stream};
use md5::{Digest, Md5};
use std::io::{self, BufRead, BufReader, Cursor, Read};

mod directory;
mod hwp;
mod office;
mod temporary;
type Document<'a> = CompoundFile<Cursor<&'a [u8]>>;

fn native(name: &str) -> bool {
    name.eq_ignore_ascii_case("\x01Ole10Native") || name.eq_ignore_ascii_case("_1_ole10native")
}

fn named(entry: &Stream, names: &[&str]) -> bool {
    names.iter().any(|n| entry.name.eq_ignore_ascii_case(n))
}

fn size(input: &mut dyn Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn skip_name(input: &mut dyn BufRead, sink: &mut dyn ChildSink) -> io::Result<bool> {
    loop {
        sink.check()?;
        let buf = input.fill_buf()?;
        if buf.is_empty() {
            return Ok(false);
        }
        if let Some(pos) = buf.iter().position(|&b| b == 0) {
            input.consume(pos + 1);
            return Ok(true);
        }
        let n = buf.len();
        input.consume(n);
    }
}

fn payload(stream: cfb::Stream<Cursor<&[u8]>>, sink: &mut dyn ChildSink) -> io::Result<bool> {
    let total = stream.len();
    let mut input = BufReader::new(stream);
    if total < 4 {
        return Ok(false);
    }
    let mut n = size(&mut input)?;
    if u64::from(n) <= total - 4 {
        let mut scratch = [0; 8];
        input.read_exact(&mut scratch[..2])?;
        if !skip_name(&mut input, sink)? || !skip_name(&mut input, sink)? {
            return Ok(false);
        }
        input.read_exact(&mut scratch)?;
        if !skip_name(&mut input, sink)? {
            return Ok(false);
        }
        n = size(&mut input)?;
    }
    sink.child(&mut input.take(n.into()), None, None)
}

fn raw(
    doc: &mut Document,
    directory: &Inventory,
    entry: &Stream,
    filename: Option<&[u8]>,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let mut stream = doc.open_stream(directory.path(entry))?;
    sink.child(&mut stream, None, filename)
}

// Stock scans the temporary stream files under their hashed names on the Package path.
fn normalized_name(name: &str) -> Option<String> {
    let mut result = String::new();
    for b in name.bytes() {
        match b {
            1..=9 => result.push_str(&format!("_{b}_")),
            32..=126 => result.push(char::from(b.to_ascii_lowercase())),
            _ => return None,
        }
    }
    Some(result)
}

fn temp_name(normalized: &str, count: usize) -> String {
    let mut digest: String = Md5::digest(normalized)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    digest.push_str(&format!("_{count}"));
    digest
}

fn native_payload(
    doc: &mut Document,
    directory: &Inventory,
    entry: &Stream,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    match payload(doc.open_stream(directory.path(entry))?, sink) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        result => result,
    }
}

fn visit(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(directory) = Inventory::read(bytes, sink)? else {
        return Ok(Handling::Incomplete);
    };
    sink.check()?;
    let mut doc = cfb::OpenOptions::new()
        .strict()
        .max_buffer_size(8192)
        .open_with(Cursor::new(bytes))?;
    sink.check()?;
    if directory
        .streams
        .iter()
        .any(|e| named(e, &["encryptioninfo", "encryptedpackage"]))
    {
        return Ok(Handling::Incomplete);
    }
    let temporary_pass = directory.streams.iter().any(|e| {
        native(&e.name) || named(e, &["_vba_project", "worddocument", "powerpoint document"])
    });
    if let Some(flags) = hwp::header(&mut doc, &directory, sink)? {
        if temporary_pass {
            return Ok(Handling::Incomplete);
        }
        return hwp::scan(&mut doc, &directory, flags, sink);
    }
    if !temporary_pass {
        for entry in &directory.streams {
            if !office::ordinary(&mut doc, &directory, entry, sink)? {
                return Ok(Handling::Incomplete);
            }
        }
        for (preceding, entry) in directory.streams.iter().enumerate() {
            sink.check()?;
            if sink.ole_directory_limit(entry.depth, preceding) {
                break;
            }
            if raw(&mut doc, &directory, entry, None, sink)? {
                return Ok(Handling::Stopped);
            }
        }
        return Ok(Handling::Complete);
    }
    // Root Package attachments precede the Office-specific passes.
    for entry in directory
        .streams
        .iter()
        .rev()
        .filter(|e| e.depth == 1 && native(&e.name))
    {
        if native_payload(&mut doc, &directory, entry, sink)? {
            return Ok(Handling::Stopped);
        }
    }
    for entry in &directory.streams {
        if named(entry, &["_vba_project", "dir"])
            || !office::ordinary(&mut doc, &directory, entry, sink)?
        {
            return Ok(Handling::Incomplete);
        }
    }
    let mut candidates = directory
        .streams
        .iter()
        .enumerate()
        .filter(|(_, e)| e.size > 5);
    let Some((index, entry)) = candidates.next() else {
        return Ok(Handling::Complete);
    };
    if candidates.next().is_some() {
        return temporary::scan(&mut doc, &directory, sink);
    }
    let Some(normalized) = normalized_name(&entry.name) else {
        return Ok(Handling::Incomplete);
    };
    let count = directory.streams[..index]
        .iter()
        .filter(|e| normalized_name(&e.name).as_ref() == Some(&normalized))
        .count()
        + 1;
    let name = temp_name(&normalized, count);
    // Each enclosing storage performs a recursive raw pass before descending into its children.
    for level in 1..=entry.depth {
        sink.check()?;
        if level > 1
            && level == entry.depth
            && native(&entry.name)
            && native_payload(&mut doc, &directory, entry, sink)?
        {
            return Ok(Handling::Stopped);
        }
        if raw(&mut doc, &directory, entry, Some(name.as_bytes()), sink)? {
            return Ok(Handling::Stopped);
        }
    }
    Ok(Handling::Complete)
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match visit(bytes, sink) {
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::NotFound
            ) =>
        {
            Ok(Handling::Incomplete)
        }
        result => result,
    }
}

pub(super) fn wrapped(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let Some(cfb) = bytes.get(4..) else {
        return Ok(Handling::Complete);
    };
    Ok(if sink.child_bytes(cfb, None)? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}
