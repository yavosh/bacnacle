//! PDF 1.5 compressed indirect objects. Their offsets are relative to /First.
use super::{ChildSink, ContentsText, Handling, Id, MAX_OBJECTS, Snapshot, Tokens, number, white};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::Path,
};

#[derive(Clone, Copy)]
pub(super) struct Directory {
    first: usize,
    members: usize,
}

impl Directory {
    pub(super) fn read(dictionary: &[u8]) -> Option<Self> {
        // The pinned reader requires this contiguous spelling when interpreting the directory.
        if !dictionary.windows(12).any(|s| s == b"/Type/ObjStm") {
            return None;
        }
        let mut input = Tokens {
            data: dictionary,
            pos: 0,
        };
        let (mut first, mut members) = (None, None);
        while let Some(token) = input.next() {
            match token {
                b"/First" => first = input.next().and_then(number),
                b"/N" => members = input.next().and_then(number),
                _ => {}
            }
        }
        Some(Self {
            first: first?,
            members: members?,
        })
    }
}

enum Deferred {
    Array { contents: bool },
    Contents,
    Raw,
    Unsupported,
}
struct Item {
    offset: Option<usize>,
    size: usize,
    kind: Deferred,
}

pub(super) struct Packed {
    /// Array objects may become page contents when a later packed dictionary references them.
    arrays: HashMap<Id, usize>,
    physical: HashSet<Id>,
    deferred: Vec<Item>,
    file: Snapshot,
    length: usize,
    spool_limit: u64,
    count: usize,
}

impl Packed {
    pub(super) fn new(
        directory: &Path,
        spool_limit: u64,
        count: usize,
        physical: impl Iterator<Item = Id>,
    ) -> Self {
        Self {
            arrays: HashMap::new(),
            physical: physical.collect(),
            deferred: Vec::new(),
            file: Snapshot::new(directory),
            length: 0,
            spool_limit,
            count,
        }
    }

    pub(super) fn inspect(
        &mut self,
        directory: Directory,
        data: &[u8],
        lengths: &mut HashMap<Id, usize>,
        contents: &mut HashSet<Id>,
        sink: &mut dyn ChildSink,
    ) -> io::Result<()> {
        let Some((index, body)) = data.split_at_checked(directory.first) else {
            return Ok(());
        };
        let mut index = Tokens {
            data: index,
            pos: 0,
        };
        let mut pair =
            || -> Option<(usize, usize)> { Some((number(index.next()?)?, number(index.next()?)?)) };
        let mut here = pair();
        for n in 0..directory.members {
            sink.check()?;
            if self.count >= MAX_OBJECTS {
                self.defer(&[], Deferred::Unsupported)?;
                break;
            }
            let Some((id, start)) = here else {
                break;
            };
            here = if n + 1 == directory.members {
                None
            } else {
                pair()
            };
            let end = here.map_or(body.len(), |(_, p)| p);
            let Some(bytes) = body.get(start..end) else {
                break;
            };
            self.count += 1;
            let mut input = Tokens {
                data: bytes,
                pos: 0,
            };
            let first = input.next();
            if first == Some(b"[") {
                let entry = self.deferred.len();
                self.defer(bytes, Deferred::Array { contents: false })?;
                self.arrays.insert((id, 0), entry);
                continue;
            }
            if first.and_then(number).is_some() {
                // The pinned indirect-length cursor advances to the next token boundary.
                let mut value = Tokens {
                    data: &body[start..],
                    pos: 0,
                };
                if !bytes.first().is_some_and(|b| white(*b)) {
                    value.next();
                }
                if let Some(size) = value.next().and_then(number) {
                    lengths.entry((id, 0)).or_insert(size);
                }
                continue;
            }
            if first != Some(b"<<") {
                continue;
            }
            let mut dump = None;
            while let Some(token) = input.next() {
                match token {
                    b"/Contents" => {
                        let mut value = input.clone();
                        if value.clone().next() == Some(b"[") {
                            value.next();
                        }
                        match value.reference() {
                            Some(id) if self.physical.contains(&id) => {
                                contents.insert(id);
                            }
                            Some(id) if self.arrays.contains_key(&id) => {
                                let item = &mut self.deferred[self.arrays[&id]];
                                item.kind = Deferred::Array { contents: true };
                            }
                            _ => dump = Some(Deferred::Contents),
                        }
                    }
                    b"/EmbeddedFile" => {
                        dump.get_or_insert(Deferred::Raw);
                    }
                    b"/JS" | b"/JavaScript" | b"/OpenAction" | b"/Launch" | b"stream" => {
                        dump = Some(Deferred::Unsupported);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(kind) = dump {
                self.defer(bytes, kind)?;
            }
        }
        Ok(())
    }

    fn defer(&mut self, bytes: &[u8], kind: Deferred) -> io::Result<()> {
        let end = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("PDF object size overflow"))?;
        let offset = if end as u64 <= self.spool_limit && !matches!(kind, Deferred::Unsupported) {
            self.file.write_all(bytes)?;
            Some(std::mem::replace(&mut self.length, end))
        } else {
            None
        };
        self.deferred.push(Item {
            offset,
            size: bytes.len(),
            kind,
        });
        Ok(())
    }

    pub(super) fn finish(self, sink: &mut dyn ChildSink) -> io::Result<Handling> {
        if self.deferred.is_empty() {
            return Ok(Handling::Complete);
        }
        self.file.with_bytes(|data| {
            for item in self.deferred {
                sink.check()?;
                match item.kind {
                    Deferred::Array { contents: false } => continue,
                    Deferred::Unsupported => return Ok(Handling::Incomplete),
                    _ => {}
                }
                let Some(start) = item.offset else {
                    if sink.skip_declared_size(item.size as u64) {
                        continue;
                    }
                    return Ok(Handling::Incomplete);
                };
                let bytes = &data[start..start + item.size];
                if sink.child_bytes(bytes, None)? {
                    return Ok(Handling::Stopped);
                }
                if !matches!(item.kind, Deferred::Raw)
                    && sink.child(&mut ContentsText::new(bytes), None, None)?
                {
                    return Ok(Handling::Stopped);
                }
            }
            Ok(Handling::Complete)
        })
    }
}
