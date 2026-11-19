//! PDF 1.5 compressed indirect objects. Their offsets are relative to /First.
use super::{
    ChildSink, Handling, Id, MAX_OBJECTS, Snapshot, Tokens, destination, number, scan_page_text,
    white,
};
use aho_corasick::AhoCorasick;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    path::Path,
    sync::LazyLock,
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

    fn entries<'a>(&self, index: &'a [u8], body: &'a [u8]) -> Entries<'a> {
        Entries {
            index: Tokens {
                data: index,
                pos: 0,
            },
            body,
            remaining: self.members,
            next: None,
            budget: super::TokenBudget::default(),
            ordinal: 0,
        }
    }

    // In compact directories, a forward reference selects the catalog. A backward
    // reference selects the earlier member. Only the measured single-catalog,
    // same-directory forms are resolved. Object numbers need no lookup table.
    fn opening(
        &self,
        index: &[u8],
        body: &[u8],
        available: usize,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<(usize, usize)>> {
        const NAME: &[u8] = b"/OpenAction";
        static SEARCH: LazyLock<AhoCorasick> =
            LazyLock::new(|| AhoCorasick::new([NAME]).expect("static PDF name"));
        if self.members > available {
            return Ok(None);
        }
        let mut present = false;
        for start in (0..body.len()).step_by(64 * 1024) {
            sink.check()?;
            let end = body
                .len()
                .min(start.saturating_add(64 * 1024 + NAME.len() - 1));
            if SEARCH.is_match(&body[start..end]) {
                present = true;
                break;
            }
        }
        if !present {
            return Ok(None);
        }
        let mut catalog = None;
        let mut entries = self.entries(index, body);
        while let Some(entry) = entries.next(sink)? {
            sink.check()?;
            if let Some(dest) = destination::catalog(entry.bytes, &mut || sink.check())?
                && catalog.replace((entry.ordinal, dest)).is_some()
            {
                return Ok(None);
            }
        }
        let Some((owner, dest)) = catalog else {
            return Ok(None);
        };
        let id = match dest {
            destination::Destination::Inline => return Ok(Some((owner, owner))),
            destination::Destination::Page((id, 0))
            | destination::Destination::Indirect((id, 0)) => id,
            _ => return Ok(None),
        };
        let mut selected = None;
        let mut entries = self.entries(index, body);
        while let Some(entry) = entries.next(sink)? {
            sink.check()?;
            if id != entry.id {
                continue;
            }
            let valid = match dest {
                destination::Destination::Page(_) => {
                    destination::page(entry.bytes, &mut || sink.check())?
                }
                _ => destination::passive_body(entry.bytes, &mut || sink.check())?,
            };
            if !valid || selected.replace(entry.ordinal.min(owner)).is_some() {
                return Ok(None);
            }
        }
        Ok(selected.map(|child| (owner, child)))
    }
}

struct Entry<'a> {
    ordinal: usize,
    id: usize,
    start: usize,
    bytes: &'a [u8],
}

struct Entries<'a> {
    index: Tokens<'a>,
    body: &'a [u8],
    remaining: usize,
    ordinal: usize,
    next: Option<(usize, usize)>,
    budget: super::TokenBudget,
}

impl<'a> Entries<'a> {
    fn pair(&mut self, sink: &mut dyn ChildSink) -> io::Result<Option<(usize, usize)>> {
        let Some(id) = self.index.integer_checked(&mut self.budget, sink)? else {
            return Ok(None);
        };
        Ok(self
            .index
            .integer_checked(&mut self.budget, sink)?
            .map(|start| (id, start)))
    }

    fn next(&mut self, sink: &mut dyn ChildSink) -> io::Result<Option<Entry<'a>>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let here = if self.ordinal == 0 {
            self.pair(sink)?
        } else {
            self.next.take()
        };
        let Some((id, start)) = here else {
            return Ok(None);
        };
        self.remaining -= 1;
        self.next = if self.remaining > 0 {
            self.pair(sink)?
        } else {
            None
        };
        let end = self.next.map_or(self.body.len(), |(_, p)| p);
        let ordinal = self.ordinal;
        self.ordinal += 1;
        Ok(self.body.get(start..end).map(|bytes| Entry {
            ordinal,
            id,
            start,
            bytes,
        }))
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
        let available = MAX_OBJECTS - self.count;
        let opening = directory.opening(index, body, available, sink)?;
        let mut entries = directory.entries(index, body);
        while let Some(Entry {
            ordinal: n,
            id,
            start,
            bytes,
        }) = entries.next(sink)?
        {
            sink.check()?;
            if n >= available {
                self.defer(&[], Deferred::Unsupported, sink)?;
                break;
            }
            let selected = opening.is_some_and(|(_, child)| child == n);
            self.count += 1;
            let mut input = Tokens {
                data: bytes,
                pos: 0,
            };
            let mut budget = super::TokenBudget::default();
            let first = input.next_checked(&mut budget, sink)?;
            if first == Some(b"[") {
                let entry = self.deferred.len();
                self.defer(
                    bytes,
                    if selected {
                        Deferred::Raw
                    } else {
                        Deferred::Array { contents: false }
                    },
                    sink,
                )?;
                self.arrays.insert((id, 0), entry);
                continue;
            }
            if let Some(token) = first
                && super::number_with(token, &mut |n| budget.charge(n, &mut || sink.check()))?
                    .is_some()
            {
                // The pinned indirect-length cursor advances to the next token boundary.
                let mut value = Tokens {
                    data: &body[start..],
                    pos: 0,
                };
                if !bytes.first().is_some_and(|b| white(*b)) {
                    value.next_checked(&mut budget, sink)?;
                }
                if let Some(size) = value.integer_checked(&mut budget, sink)? {
                    lengths.entry((id, 0)).or_insert(size);
                }
                continue;
            }
            if first != Some(b"<<") {
                continue;
            }
            let mut dump = selected.then_some(Deferred::Raw);
            let mut seen_opening = false;
            while let Some(token) = input.next_checked(&mut budget, sink)? {
                match token {
                    b"/Contents" => {
                        let mut value = input.clone();
                        if value.clone().next_checked(&mut budget, sink)? == Some(b"[") {
                            value.next_checked(&mut budget, sink)?;
                        }
                        match value.reference_checked(&mut budget, sink)? {
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
                    b"/OpenAction"
                        if !seen_opening && opening.is_some_and(|(owner, _)| owner == n) =>
                    {
                        seen_opening = true
                    }
                    b"/JS" | b"/JavaScript" | b"/OpenAction" | b"/Launch" | b"stream" => {
                        dump = Some(Deferred::Unsupported);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(kind) = dump {
                self.defer(bytes, kind, sink)?;
            }
        }
        Ok(())
    }

    fn defer(&mut self, bytes: &[u8], kind: Deferred, sink: &mut dyn ChildSink) -> io::Result<()> {
        let end = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("PDF object size overflow"))?;
        let offset = if end as u64 <= self.spool_limit && !matches!(kind, Deferred::Unsupported) {
            for chunk in bytes.chunks(super::TOKEN_BLOCK) {
                sink.check()?;
                self.file.write_all(chunk)?;
            }
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
                if !matches!(item.kind, Deferred::Raw) && scan_page_text(bytes, sink)? {
                    return Ok(Handling::Stopped);
                }
            }
            Ok(Handling::Complete)
        })
    }
}
