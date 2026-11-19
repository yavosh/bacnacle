//! Object traversal for one scan against one immutable database generation.
use crate::body::{ObjectContext, Target};
use std::io::{self, Read, Write};
use std::path::Path;

mod archive;
mod classify;
mod dmg;
mod embedded;
mod hfs;
mod hwp3;
mod installer;
mod iso;
mod macho;
mod office;
mod ole;
mod onenote;
mod partition;
mod pdf;
mod rtf;
mod swf;
mod text;
mod udf;
mod xdp;
mod xml;

/// A handler can recognize a format without proving that it visited every object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Handling {
    Unrecognized,
    Complete,
    Incomplete,
    Stopped,
}

trait ChildSink {
    /// Visit one child synchronously. A true return stops traversal in this handler.
    fn child(
        &mut self,
        data: &mut dyn Read,
        target: Option<Target>,
        name: Option<&[u8]>,
    ) -> io::Result<bool> {
        match self.read_child(data)? {
            Some(snapshot) => self.visit_snapshot(snapshot, target, name),
            None => Ok(false),
        }
    }
    fn read_child(&mut self, data: &mut dyn Read) -> io::Result<Option<Snapshot>>;
    fn visit_snapshot(
        &mut self,
        snapshot: Snapshot,
        target: Option<Target>,
        name: Option<&[u8]>,
    ) -> io::Result<bool>;
    fn child_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool>;
    fn embedded_archive(&mut self, kind: &'static str, bytes: &[u8]) -> io::Result<Handling>;
    fn embedded_xdp(&mut self, bytes: &[u8]) -> io::Result<Handling>;
    fn installer_header(&mut self, bytes: &[u8]) -> io::Result<bool>;
    fn partition(&mut self, snapshot: Snapshot) -> io::Result<bool> {
        snapshot.with_bytes(|bytes| self.partition_bytes(bytes, None))
    }
    fn partition_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool>;
    fn view(&mut self, data: &mut dyn Read, target: Target) -> io::Result<bool>;

    fn check(&mut self) -> io::Result<()>;
    fn remaining(&self) -> u64;
    fn max_file_size(&self) -> u64;
    fn max_files(&self) -> usize;
    fn max_partitions(&self) -> usize;
    fn ole_directory_limit(&mut self, depth: usize, preceding_streams: usize) -> bool;
    fn skip_declared_size(&mut self, size: u64) -> bool;
    fn text_limits(&self) -> (u64, u64, u64);
    fn temporary_directory(&self) -> &Path;
}

#[derive(Clone, Debug)]
pub struct Options {
    pub max_file_size: u64,
    pub max_scan_size: u64,
    pub max_files: usize,
    pub max_partitions: usize,
    pub max_recursion: usize,
    pub max_rec_hwp3: usize,
    pub alert_exceeds_max: bool,
    pub scan_archive: bool,
    pub scan_pe: bool,
    pub max_embedded_pe: u64,
    pub scan_elf: bool,
    pub scan_pdf: bool,
    pub scan_ole2: bool,
    pub scan_hwp3: bool,
    pub scan_xml_docs: bool,
    pub scan_swf: bool,
    pub scan_onenote: bool,
    pub scan_image: bool,
    pub alert_broken_media: bool,
    pub scan_html: bool,
    pub scan_mail: bool,
    pub max_html_normalize: u64,
    pub max_html_no_tags: u64,
    pub max_script_normalize: u64,
    pub map_normalized_script: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_file_size: 100 << 20,
            max_scan_size: 400 << 20,
            max_files: 10_000,
            max_partitions: 50,
            max_recursion: 17,
            max_rec_hwp3: 16,
            alert_exceeds_max: false,
            scan_archive: true,
            scan_pe: true,
            max_embedded_pe: 40 << 20,
            scan_elf: true,
            scan_pdf: true,
            scan_ole2: true,
            scan_hwp3: true,
            scan_xml_docs: true,
            scan_swf: true,
            scan_onenote: true,
            scan_image: true,
            alert_broken_media: false,
            scan_html: true,
            scan_mail: true,
            max_html_normalize: 40 << 20,
            max_html_no_tags: 8 << 20,
            max_script_normalize: 20 << 20,
            map_normalized_script: false,
        }
    }
}

pub struct Layer {
    pub file_type: &'static str,
    pub target: Target,
    pub name: Option<Box<[u8]>>,
    pub size: usize,
}

pub struct Object<'a> {
    pub bytes: &'a [u8],
    pub context: &'a ObjectContext,
    pub parents: &'a [Layer],
    pub layer: &'a Layer,
    pub normalized: bool,
    pub body_only: bool,
    pub handled_format: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Verdict {
    Found(String),
    Miss,
    Incomplete,
    /// The pinned engine omits this entire top-level object.
    Skipped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
    MaxFileSize,
    MaxScanSize,
    MaxFiles,
    MaxRecursion,
    MaxScanTime,
}

impl Limit {
    pub fn signature(self) -> String {
        format!("Heuristics.Limits.Exceeded.{self:?}")
    }
}

fn unlimited_if_zero(n: u64) -> u64 {
    if n == 0 { u64::MAX } else { n }
}

/// Keep small objects in memory. Map larger private snapshots only while visiting them.
pub struct Snapshot(tempfile::SpooledTempFile);

impl Write for Snapshot {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Snapshot {
    pub fn new(directory: &Path) -> Self {
        Self(tempfile::spooled_tempfile_in(64 * 1024, directory))
    }

    fn read_bounded(
        input: &mut dyn Read,
        directory: &Path,
        limit: u64,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<Self>> {
        let mut spool = Self::new(directory);
        let mut input = input.take(limit.saturating_add(1));
        let mut size = 0u64;
        let mut buf = [0u8; 8192];
        loop {
            check()?;
            let n = match input.read(&mut buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if n == 0 {
                return Ok(Some(spool));
            }
            size += n as u64;
            if size > limit {
                return Ok(None);
            }
            spool.write_all(&buf[..n])?;
        }
    }
    pub fn with_bytes<T>(self, visit: impl FnOnce(&[u8]) -> io::Result<T>) -> io::Result<T> {
        match self.0.into_inner() {
            tempfile::SpooledData::InMemory(data) => visit(data.get_ref()),
            tempfile::SpooledData::OnDisk(file) => {
                // SAFETY: the spool owns this unlinked file. Writers have finished and
                // the immutable mapping and file both outlive the callback.
                let bytes = unsafe { memmap2::Mmap::map(&file)? };
                visit(&bytes)
            }
        }
    }
}

type Matcher<'a> =
    dyn FnMut(Object<'_>, &mut dyn FnMut() -> io::Result<()>) -> io::Result<Verdict> + 'a;

struct Traversal<'a> {
    options: &'a Options,
    temporary_directory: &'a Path,
    parents: Vec<Layer>,
    bytes_scanned: u64,
    files_scanned: usize,
    stopped: Option<Verdict>,
    first_limit: Option<Limit>,
    matcher: &'a mut Matcher<'a>,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}

#[derive(Clone, Copy, PartialEq)]
enum InputKind {
    File,
    Normalized(Target),
    Partition,
}

pub fn scan(
    bytes: &[u8],
    options: &Options,
    temporary_directory: &Path,
    mut matcher: impl FnMut(Object<'_>, &mut dyn FnMut() -> io::Result<()>) -> io::Result<Verdict>,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<Verdict> {
    let mut walk = Traversal {
        options,
        temporary_directory,
        parents: Vec::new(),
        bytes_scanned: 0,
        files_scanned: 0,
        stopped: None,
        first_limit: None,
        matcher: &mut matcher,
        check: &mut check,
    };
    walk.visit(bytes, InputKind::File, None)?;
    Ok(walk.stopped.unwrap_or_else(|| match walk.first_limit {
        Some(limit) if options.alert_exceeds_max => Verdict::Found(limit.signature()),
        _ => Verdict::Miss,
    }))
}

impl Traversal<'_> {
    fn recursion_limit(&self) -> usize {
        match self.options.max_recursion {
            0 => 17,
            value => value,
        }
    }

    fn visit(&mut self, bytes: &[u8], kind: InputKind, name: Option<&[u8]>) -> io::Result<()> {
        self.check()?;
        if bytes.len() <= 5 {
            return Ok(());
        }
        if self.options.max_files != 0 && self.files_scanned >= self.options.max_files {
            self.first_limit.get_or_insert(Limit::MaxFiles);
            return Ok(());
        }
        if bytes.len() as u64 > self.remaining() {
            self.record_size_limit(bytes.len() as u64);
            return Ok(());
        }
        self.files_scanned += 1;
        self.bytes_scanned += bytes.len() as u64;
        if kind == InputKind::File && classify::ignored(bytes) {
            if self.parents.is_empty() {
                self.stopped = Some(Verdict::Skipped);
            }
            return Ok(());
        }
        let file_type = classify::FileType::classify(bytes, kind, self)?;
        self.parents.push(Layer {
            target: file_type.context.target(),
            file_type: file_type.name,
            size: bytes.len(),
            name: name.map(Into::into),
        });
        let handling = file_type.parser.before_raw(bytes, self.options, self)?;
        if handling == Handling::Incomplete {
            self.stopped = Some(Verdict::Incomplete);
        }
        if self.stopped.is_none()
            && (file_type.parser != classify::Parser::Html || !self.options.scan_html)
        {
            let (layer, parents) = self.parents.split_last().expect("current layer");
            let object = Object {
                bytes,
                context: &file_type.context,
                layer,
                parents,
                normalized: matches!(kind, InputKind::Normalized(_)),
                body_only: false,
                handled_format: handling == Handling::Complete,
            };
            let verdict = (self.matcher)(object, self.check)?;
            if verdict != Verdict::Miss {
                self.stopped = Some(verdict);
            }
        }
        if self.stopped.is_none() {
            let recognize = kind == InputKind::File
                && (self.options.scan_archive
                    || self.options.scan_pe && embedded::pe_carrier(file_type.name)
                    || self.options.scan_pdf && xdp::can_retype(file_type.name))
                && (file_type.parser != classify::Parser::Html || !self.options.scan_html);
            if self.after_raw(bytes, &file_type, recognize)? == Handling::Incomplete {
                self.stopped = Some(Verdict::Incomplete);
            }
        }
        self.parents.pop();
        Ok(())
    }

    fn after_raw(
        &mut self,
        bytes: &[u8],
        file_type: &classify::FileType,
        recognize: bool,
    ) -> io::Result<Handling> {
        if recognize && embedded::enabled(file_type.name) {
            let mut count = 0;
            let mut start = 0;
            let mut disks = if self.options.scan_archive {
                [
                    file_type.parser.disk_descriptor(),
                    if matches!(file_type.parser, classify::Parser::PartitionMap(_)) {
                        None
                    } else {
                        partition::from_mbr(bytes)
                            .map(|name| (510, classify::Disk::PartitionMap(name)))
                    },
                    dmg::recognized(bytes).then(|| (bytes.len() - 512, classify::Disk::Dmg)),
                ]
            } else {
                [None; 3]
            };
            disks.sort_by_key(|disk| disk.map_or(usize::MAX, |(offset, _)| offset));
            for (offset, disk) in disks.into_iter().flatten() {
                let before = embedded::extract(
                    bytes,
                    file_type.name,
                    start..offset,
                    &mut count,
                    self.options,
                    self,
                )?;
                if matches!(before, Handling::Incomplete | Handling::Stopped)
                    || self.stopped.is_some()
                {
                    return Ok(before);
                }
                self.parents.last_mut().expect("current image").file_type = disk.name();
                let result = disk.extract(bytes, self)?;
                if result == Handling::Incomplete || self.stopped.is_some() {
                    return Ok(result);
                }
                start = offset;
            }
            let result = embedded::extract(
                bytes,
                file_type.name,
                start..bytes.len(),
                &mut count,
                self.options,
                self,
            )?;
            if result == Handling::Incomplete || self.stopped.is_some() {
                return Ok(result);
            }
        }
        file_type.parser.after_raw(bytes, self.options, self)
    }

    fn record_size_limit(&mut self, size: u64) {
        let reason = if size
            > unlimited_if_zero(self.options.max_scan_size).saturating_sub(self.bytes_scanned)
        {
            Limit::MaxScanSize
        } else {
            Limit::MaxFileSize
        };
        self.first_limit.get_or_insert(reason);
    }
    fn can_enter_child(&mut self) -> bool {
        if self.options.max_files != 0 && self.files_scanned >= self.options.max_files {
            self.first_limit.get_or_insert(Limit::MaxFiles);
            return false;
        }
        if self.parents.len() >= self.recursion_limit() {
            self.first_limit.get_or_insert(Limit::MaxRecursion);
            return false;
        }
        true
    }
}

impl ChildSink for Traversal<'_> {
    fn installer_header(&mut self, bytes: &[u8]) -> io::Result<bool> {
        if !self.can_enter_child() || self.skip_declared_size(bytes.len() as u64) {
            return Ok(false);
        }
        self.check()?;
        let context = ObjectContext::typed(Target::Generic, bytes);
        let layer = Layer {
            file_type: "CL_TYPE_ANY",
            target: Target::Generic,
            name: None,
            size: bytes.len(),
        };
        let object = Object {
            bytes,
            context: &context,
            parents: &self.parents,
            layer: &layer,
            normalized: false,
            body_only: false,
            handled_format: true,
        };
        let verdict = (self.matcher)(object, self.check)?;
        if verdict != Verdict::Miss {
            self.stopped = Some(verdict);
        }
        Ok(self.stopped.is_some())
    }

    fn embedded_xdp(&mut self, bytes: &[u8]) -> io::Result<Handling> {
        let layer = self.parents.last_mut().expect("XDP has an owning object");
        if !xdp::can_retype(layer.file_type) {
            return Ok(Handling::Unrecognized);
        }
        layer.file_type = "CL_TYPE_XDP";
        xdp::extract(bytes, self)
    }

    fn partition_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool> {
        if self.skip_declared_size(bytes.len() as u64) || !self.can_enter_child() {
            return Ok(false);
        }
        self.visit(bytes, InputKind::Partition, name)?;
        Ok(self.stopped.is_some())
    }

    fn max_partitions(&self) -> usize {
        self.options.max_partitions
    }

    fn embedded_archive(&mut self, kind: &'static str, bytes: &[u8]) -> io::Result<Handling> {
        if self.skip_declared_size(bytes.len() as u64) || !self.can_enter_child() {
            return Ok(Handling::Complete);
        }
        // A suffix is another map of the same input. Stock checks its size
        // and pushes its type, then charges only the newly extracted children.
        self.parents.push(Layer {
            file_type: kind,
            target: if kind == "CL_TYPE_MSEXE" {
                Target::Pe
            } else {
                Target::Generic
            },
            name: None,
            size: bytes.len(),
        });
        let result = embedded::contents(bytes, kind, self);
        self.parents.pop();
        result
    }

    fn read_child(&mut self, data: &mut dyn Read) -> io::Result<Option<Snapshot>> {
        if !self.can_enter_child() {
            return Ok(None);
        }
        let limit = self.remaining();
        let snapshot =
            Snapshot::read_bounded(data, self.temporary_directory, limit, &mut *self.check)?;
        if snapshot.is_none() {
            self.record_size_limit(limit.saturating_add(1));
        }
        Ok(snapshot)
    }

    fn visit_snapshot(
        &mut self,
        snapshot: Snapshot,
        target: Option<Target>,
        name: Option<&[u8]>,
    ) -> io::Result<bool> {
        let kind = target.map_or(InputKind::File, InputKind::Normalized);
        snapshot.with_bytes(|bytes| self.visit(bytes, kind, name))?;
        Ok(self.stopped.is_some())
    }

    fn child_bytes(&mut self, bytes: &[u8], name: Option<&[u8]>) -> io::Result<bool> {
        if !self.can_enter_child() {
            return Ok(false);
        }
        self.check()?;
        let limit = self.remaining();
        if bytes.len() as u64 > limit {
            self.record_size_limit(limit.saturating_add(1));
            return Ok(false);
        }
        self.visit(bytes, InputKind::File, name)?;
        Ok(self.stopped.is_some())
    }

    fn view(&mut self, data: &mut dyn Read, target: Target) -> io::Result<bool> {
        let layer = self.parents.last().expect("view has an owning object");
        let mapped = target == Target::Ascii && self.options.map_normalized_script;
        // Text normalization contracts the input. The mail view preserves its length.
        let snapshot = Snapshot::read_bounded(
            data,
            self.temporary_directory,
            layer.size as u64,
            &mut *self.check,
        )?
        .ok_or_else(|| io::Error::other("normalized view exceeds its source size"))?;
        snapshot.with_bytes(|bytes| {
            if mapped {
                if bytes.len() as u64 > self.remaining() {
                    self.record_size_limit(bytes.len() as u64);
                    return Ok(false);
                }
                if self.options.max_files != 0 && self.files_scanned >= self.options.max_files {
                    self.first_limit.get_or_insert(Limit::MaxFiles);
                    return Ok(false);
                }
                if self.parents.len() >= self.recursion_limit() {
                    self.first_limit.get_or_insert(Limit::MaxRecursion);
                    return Ok(false);
                }
            }
            let (owner, parents) = self
                .parents
                .split_last()
                .expect("view has an owning object");
            let context = ObjectContext::typed(target, bytes);
            let layer = Layer {
                target,
                file_type: if target == Target::Ascii {
                    "CL_TYPE_TEXT_ASCII"
                } else {
                    "CL_TYPE_MAIL"
                },
                size: bytes.len(),
                name: owner.name.clone(),
            };
            let object = Object {
                bytes,
                context: &context,
                layer: &layer,
                parents: if mapped { &self.parents } else { parents },
                normalized: true,
                body_only: target == Target::Ascii && !mapped,
                handled_format: true,
            };
            let verdict = (self.matcher)(object, self.check)?;
            if verdict != Verdict::Miss {
                self.stopped = Some(verdict);
            }
            Ok(self.stopped.is_some())
        })
    }

    fn check(&mut self) -> io::Result<()> {
        (self.check)()
    }

    fn remaining(&self) -> u64 {
        unlimited_if_zero(self.options.max_file_size)
            .min(unlimited_if_zero(self.options.max_scan_size).saturating_sub(self.bytes_scanned))
    }

    fn max_file_size(&self) -> u64 {
        unlimited_if_zero(self.options.max_file_size)
    }
    fn max_files(&self) -> usize {
        self.options.max_files
    }

    fn ole_directory_limit(&mut self, depth: usize, preceding_streams: usize) -> bool {
        let limit = if depth > self.recursion_limit() {
            Limit::MaxRecursion
        } else if self.options.max_files != 0
            && self.files_scanned.saturating_add(preceding_streams) > self.options.max_files
        {
            Limit::MaxFiles
        } else {
            return false;
        };
        self.first_limit.get_or_insert(limit);
        true
    }
    fn skip_declared_size(&mut self, size: u64) -> bool {
        if size <= self.remaining() {
            return false;
        }
        self.record_size_limit(size);
        true
    }

    fn text_limits(&self) -> (u64, u64, u64) {
        (
            self.options.max_html_normalize,
            self.options.max_html_no_tags,
            self.options.max_script_normalize,
        )
    }
    fn temporary_directory(&self) -> &Path {
        self.temporary_directory
    }
}
