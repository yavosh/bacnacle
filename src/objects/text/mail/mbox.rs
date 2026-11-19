//! Direct MIME members precede the stock mailbox's shared recovery directory.
use super::{ChildSink, Deferred, Handling, forward_files, headers, mailbox_media, part};
use crate::objects::Limit;
use crate::objects::{ObjectBytes, Snapshot};
use std::io::{self, Write};

fn next<'a>(
    message: &'a [u8],
    sink: &mut dyn ChildSink,
) -> io::Result<(&'a [u8], Option<&'a [u8]>)> {
    let mut rest = message;
    let mut empty = false;
    while !rest.is_empty() {
        sink.check()?;
        let (_, row, next) = physical_row(rest);
        if empty && row.starts_with(b"From ") {
            return Ok((&message[..message.len() - rest.len()], Some(next)));
        }
        empty = row.is_empty();
        rest = next;
    }
    Ok((message, None))
}

#[derive(Default)]
pub(in crate::objects) struct SavedLetters<'a> {
    rest: Option<&'a [u8]>,
    pub count: usize,
    pub total: u64,
    pub largest: u64,
    pub largest_script: u64,
    smallest: u64,
}

fn message_headers<'a>(
    bytes: &'a [u8],
    sink: &mut dyn ChildSink,
) -> io::Result<Option<super::Part<'a>>> {
    let mut rest = bytes;
    while !rest.is_empty() && bytes.len() - rest.len() <= 64 * 1024 {
        sink.check()?;
        let (wire, row, tail) = physical_row(rest);
        if wire.contains(&0) || !wire.ends_with(b"\n") {
            return Ok(None);
        }
        if row.is_empty() {
            return Ok(headers(bytes));
        }
        rest = tail;
    }
    Ok(None)
}

fn plain_letter(p: &super::Part<'_>) -> bool {
    let kind = p.media_type();
    p.encoding.is_empty()
        && (kind.is_empty()
            || kind.eq_ignore_ascii_case(b"text/plain")
            || mailbox_media(kind) && p.named_attachment())
}

impl SavedLetters<'_> {
    // The first pass has validated these immutable messages. Revisit their spans
    // instead of retaining one allocation or decoded snapshot per letter.
    pub(in crate::objects) fn read(
        &mut self,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<ObjectBytes<'_>>> {
        while let Some(rest) = self.rest.take() {
            let (message, next_message) = next(rest, sink)?;
            self.rest = next_message;
            if let Some(p) = headers(message)
                && plain_letter(&p)
            {
                let Some(body) = canonical(p.body, true, sink)? else {
                    return Ok(None);
                };
                if body.as_ref().len() > 5 {
                    return Ok(Some(body));
                }
            }
        }
        Ok(None)
    }
}

#[derive(Default)]
struct Directory<'a> {
    first: Option<&'a [u8]>,
    letters: SavedLetters<'a>,
    members: usize,
    uncertain_size: bool,
    rejected_direct: bool,
}

impl<'a> Directory<'a> {
    fn message(&mut self, bytes: &'a [u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
        let Some(p) = message_headers(bytes, sink)? else {
            return Ok(Handling::Incomplete);
        };
        let kind = p.media_type();
        let text = kind.is_empty() || kind.eq_ignore_ascii_case(b"text/plain");
        if !kind.eq_ignore_ascii_case(b"multipart/mixed") {
            let files = forward_files(p.body, || sink.check(), mailbox_line)?;
            if files.transfer || files.note.is_some() {
                return Ok(Handling::Incomplete);
            }
        }
        if plain_letter(&p) {
            let Some(size) = canonical_size(p.body, sink)? else {
                self.uncertain_size = true;
                return Ok(Handling::Complete);
            };
            // Empty bodies produce no directory entry. Tiny entries count as MIME output
            // but never enter the ordinary file scanner.
            self.members += usize::from(size != 0);
            if size <= 5 {
                return Ok(Handling::Complete);
            }
            self.first.get_or_insert(p.body);
            if size <= sink.text_limits().2 {
                self.letters.largest_script = self.letters.largest_script.max(size);
            }
            if self.letters.count == 0 {
                self.letters.smallest = size
            } else {
                self.letters.smallest = self.letters.smallest.min(size)
            }
            self.letters.count += 1;
            self.letters.total += size;
            self.letters.largest = self.letters.largest.max(size);
            return Ok(Handling::Complete);
        }
        // Explicit 7bit can create an additional decoded recovery file.
        let mixed = kind.eq_ignore_ascii_case(b"multipart/mixed") && p.encoding.is_empty();
        if !(mixed || p.direct_encoding() && (text || mailbox_media(kind))) {
            return Ok(Handling::Incomplete);
        }
        let Some(bytes) = canonical(bytes, false, sink)? else {
            return Ok(Handling::Incomplete);
        };
        let mut state = Deferred {
            mbox: true,
            ..Deferred::default()
        };
        let result = part(bytes.as_ref(), sink, 0, false, &mut state)?;
        self.members += state.direct_members;
        self.rejected_direct |= state.rejected_direct;
        Ok(result)
    }

    fn finish(mut self, mailbox: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
        if self.uncertain_size {
            return Ok(Handling::Incomplete);
        }
        let Some(first) = self.first else {
            return Ok(Handling::Complete);
        };
        if sink.child_limit() == Some(Limit::MaxFiles) {
            sink.can_enter_child();
            return Ok(Handling::Complete);
        }
        let first_limit = sink.size_limit(self.letters.smallest);
        if sink.size_limit(self.letters.largest) != first_limit {
            return Ok(Handling::Incomplete);
        }
        if first_limit.is_some() {
            sink.skip_declared_size(self.letters.smallest);
            return Ok(Handling::Complete);
        }
        if !sink.can_enter_child() {
            return Ok(Handling::Complete);
        }
        // An oversized directly submitted file remains in the directory. If it is first,
        // stock can stop before the otherwise affordable saved letter.
        if self.rejected_direct && !(sink.at_root() && super::printable(mailbox, sink)?) {
            return Ok(Handling::Incomplete);
        }
        let result = if self.letters.count > 1 {
            sink.mailbox_letters(&mut self.letters)?
        } else {
            let Some(first) = canonical(first, true, sink)? else {
                return Ok(Handling::Incomplete);
            };
            if sink.child_bytes(first.as_ref(), None)? {
                Handling::Stopped
            } else {
                Handling::Complete
            }
        };
        Ok(if self.rejected_direct && result == Handling::Stopped {
            Handling::Incomplete
        } else {
            result
        })
    }
}

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    let (_, _, rest) = physical_row(bytes);
    let (first, second) = next(rest, sink)?;
    let Some(second) = second else {
        return super::parse_message(first, false, sink);
    };
    let mut dir = Directory::default();
    dir.letters.rest = Some(rest);
    let mut message = first;
    let mut following = Some(second);
    loop {
        let max = sink.max_files();
        if max != 0 && dir.members >= max {
            // Intermediate MIME count errors can be discarded. A nonempty final message
            // reports the count limit before the recovery directory is opened.
            if following.is_none() {
                let Some(p) = message_headers(message, sink)? else {
                    return Ok(Handling::Incomplete);
                };
                match canonical_size(p.body, sink)? {
                    None => return Ok(Handling::Incomplete),
                    Some(0) => break,
                    Some(_) => sink.record_file_limit(),
                }
                return Ok(Handling::Complete);
            }
        } else {
            let result = dir.message(message, sink)?;
            if result != Handling::Complete {
                return Ok(result);
            }
        }
        let Some(rest) = following else { break };
        (message, following) = next(rest, sink)?;
    }
    dir.finish(bytes, sink)
}

fn mailbox_line(bytes: &[u8]) -> (&[u8], &[u8]) {
    let (_, row, rest) = physical_row(bytes);
    (row, rest)
}

fn physical_row(bytes: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let window = &bytes[..bytes.len().min(999)];
    let consumed = window
        .iter()
        .position(|b| *b == b'\n')
        .map_or(window.len(), |i| i + 1);
    let (wire, rest) = bytes.split_at(consumed);
    let end = wire
        .iter()
        .rposition(|b| !matches!(b, b'\r' | b'\n'))
        .map_or(0, |i| i + 1);
    (wire, &wire[..end], rest)
}

// The mbox reader takes at most 999 physical bytes per read. Each saved message
// collapses consecutive empty rows and preserves a whitespace-only row as one space.
fn rows(mut bytes: &[u8], mut empty: bool) -> impl Iterator<Item = (&[u8], Option<&[u8]>)> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let (wire, row, rest) = physical_row(bytes);
        bytes = rest;
        let keep = !empty || !row.is_empty();
        empty = row.is_empty();
        let row = if !row.is_empty() && row.iter().all(u8::is_ascii_whitespace) {
            b" ".as_slice()
        } else {
            row
        };
        Some((wire, keep.then_some(row)))
    })
}

fn canonical_size(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Option<u64>> {
    let mut size = 0;
    for (wire, row) in rows(bytes, true) {
        sink.check()?;
        if wire.contains(&0) {
            return Ok(None);
        }
        if let Some(row) = row {
            size += row.len() as u64 + 1;
        }
    }
    Ok(Some(size))
}

fn canonical<'a>(
    bytes: &'a [u8],
    after_blank: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Option<ObjectBytes<'a>>> {
    let mut spool = None;
    let mut consumed = 0;
    for (wire, row) in rows(bytes, after_blank) {
        sink.check()?;
        if wire.contains(&0) {
            return Ok(None);
        }
        if spool.is_none() && (row.is_none() || wire.strip_suffix(b"\n") != row) {
            let mut snapshot = std::io::BufWriter::new(Snapshot::new(sink.temporary_directory()));
            for prefix in bytes[..consumed].chunks(65536) {
                sink.check()?;
                snapshot.write_all(prefix)?;
            }
            spool = Some(snapshot);
        }
        if let (Some(output), Some(row)) = (spool.as_mut(), row) {
            output.write_all(row)?;
            output.write_all(b"\n")?;
        }
        consumed += wire.len();
    }
    match spool {
        Some(snapshot) => Ok(Some(
            snapshot
                .into_inner()
                .map_err(|e| e.into_error())?
                .into_bytes()?,
        )),
        None => Ok(Some(ObjectBytes::Borrowed(bytes))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_scan_checks_long_physical_lines() {
        let source = [b'X'; 4096];
        let mut calls = 0;
        let result = forward_files(
            &source,
            || {
                calls += 1;
                if calls == 3 {
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    Ok(())
                }
            },
            mailbox_line,
        );
        assert!(matches!(result,Err(e) if e.kind()==io::ErrorKind::Interrupted));
        assert_eq!(calls, 3);
    }
}
