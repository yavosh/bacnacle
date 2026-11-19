use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use rustix::fs::{self, AtFlags, Dir, DirEntry, FileType};

const BATCH: usize = 2048;

pub(super) struct Order(Entries);

enum Entries {
    Native,
    Unsorted,
    Memory(std::vec::IntoIter<Entry>),
    SortedFile {
        input: BufReader<File>,
        remaining: usize,
    },
}

// Stock sorts files before directories, then by directory-entry inode.
// The stable batch sort and left-first merge preserve readdir order on ties.
struct Entry {
    key: (bool, u64),
    name: OsString,
}

impl Entry {
    fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        let bytes = self.name.as_bytes();
        let length = u16::try_from(bytes.len()).map_err(io::Error::other)?;
        writer.write_all(&[self.key.0.into()])?;
        writer.write_all(&self.key.1.to_le_bytes())?;
        writer.write_all(&length.to_le_bytes())?;
        writer.write_all(bytes)
    }

    fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut header = [0; 11];
        reader.read_exact(&mut header)?;
        let ino = u64::from_le_bytes(header[1..9].try_into().unwrap());
        let length = u16::from_le_bytes([header[9], header[10]]);
        let mut name = vec![0; usize::from(length)];
        reader.read_exact(&mut name)?;
        if header[0] > 1
            || name.is_empty()
            || name.contains(&b'/')
            || name.contains(&0)
            || name == b"."
            || name == b".."
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid directory sort record",
            ));
        }
        Ok(Self {
            key: (header[0] == 1, ino),
            name: OsString::from_vec(name),
        })
    }
}

fn name(entry: &DirEntry) -> &OsStr {
    OsStr::from_bytes(entry.file_name().to_bytes())
}

fn is_dir(dir: &Dir, entry: &DirEntry, follow_links: bool) -> io::Result<bool> {
    let kind = match entry.file_type() {
        FileType::Unknown => fs::statat(dir.fd()?, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .map(|s| FileType::from_raw_mode(s.st_mode))
            .unwrap_or(FileType::Unknown),
        kind => kind,
    };
    if kind == FileType::Symlink && follow_links {
        return Ok(fs::statat(dir.fd()?, entry.file_name(), AtFlags::empty())
            .is_ok_and(|s| FileType::from_raw_mode(s.st_mode) == FileType::Directory));
    }
    Ok(kind == FileType::Directory)
}

// Alternate runs across two anonymous files. Each merge reads those files
// sequentially into another pair. At most four sort files are open per merge.
fn outputs(tmp: &Path) -> io::Result<[BufWriter<File>; 2]> {
    Ok([
        BufWriter::new(tempfile::tempfile_in(tmp)?),
        BufWriter::new(tempfile::tempfile_in(tmp)?),
    ])
}

fn reader(writer: BufWriter<File>) -> io::Result<BufReader<File>> {
    let mut file = writer.into_inner().map_err(|e| e.into_error())?;
    file.rewind()?;
    Ok(BufReader::new(file))
}

fn write_batch(batch: &mut Vec<Entry>, out: &mut BufWriter<File>) -> io::Result<()> {
    batch.sort_by_key(|row| row.key);
    for row in batch.drain(..) {
        row.write(out)?;
    }
    Ok(())
}

fn next_record(input: &mut BufReader<File>, remaining: &mut usize) -> io::Result<Option<Entry>> {
    if *remaining == 0 {
        return Ok(None);
    }
    *remaining -= 1;
    Entry::read(input).map(Some)
}

fn merge(
    inputs: &mut [BufReader<File>; 2],
    mut counts: [usize; 2],
    output: &mut BufWriter<File>,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    let mut heads = [
        next_record(&mut inputs[0], &mut counts[0])?,
        next_record(&mut inputs[1], &mut counts[1])?,
    ];
    let mut emitted = 0usize;
    loop {
        let side = match (&heads[0], &heads[1]) {
            (Some(a), Some(b)) => usize::from(a.key > b.key),
            (Some(_), None) => 0,
            (None, Some(_)) => 1,
            (None, None) => return Ok(()),
        };
        if emitted.is_multiple_of(256) {
            check()?;
        }
        heads[side].as_ref().unwrap().write(output)?;
        heads[side] = next_record(&mut inputs[side], &mut counts[side])?;
        emitted += 1;
    }
}

fn sorted(
    dir: &mut Dir,
    follow_links: bool,
    tmp: &Path,
    batch_size: usize,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<Entries> {
    let mut batch = Vec::new();
    let mut spill = None;
    let mut total = 0usize;
    let mut dest = 0;
    while let Some(entry) = dir.read().transpose()? {
        if total.is_multiple_of(256) {
            check()?;
        }
        let filename = name(&entry);
        if filename == "." || filename == ".." {
            continue;
        }
        if batch.len() == batch_size {
            if spill.is_none() {
                spill = Some(outputs(tmp)?);
            }
            write_batch(&mut batch, &mut spill.as_mut().unwrap()[dest])?;
            dest ^= 1;
        }
        batch.push(Entry {
            key: (is_dir(dir, &entry, follow_links)?, entry.ino()),
            name: filename.to_owned(),
        });
        total += 1;
    }
    let Some(mut files) = spill else {
        batch.sort_by_key(|row| row.key);
        return Ok(Entries::Memory(batch.into_iter()));
    };
    write_batch(&mut batch, &mut files[dest])?;
    drop(batch);
    let mut width = batch_size;
    while width < total {
        let [left, right] = files;
        let mut inputs = [reader(left)?, reader(right)?];
        files = outputs(tmp)?;
        let mut remaining = total;
        let mut dest = 0;
        while remaining > 0 {
            let left = width.min(remaining);
            let right = width.min(remaining - left);
            merge(&mut inputs, [left, right], &mut files[dest], check)?;
            remaining -= left + right;
            dest ^= 1;
        }
        width = width.saturating_mul(2);
    }
    let [result, _empty] = files;
    Ok(Entries::SortedFile {
        input: reader(result)?,
        remaining: total,
    })
}

impl Order {
    pub(super) fn new(first_match: bool) -> Self {
        Self(if first_match {
            Entries::Unsorted
        } else {
            Entries::Native
        })
    }

    pub(super) fn next(
        &mut self,
        dir: &mut Dir,
        follow_links: bool,
        tmp: &Path,
        mut check: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Option<OsString>> {
        if matches!(self.0, Entries::Unsorted) {
            self.0 = sorted(dir, follow_links, tmp, BATCH, &mut check)
                .map_err(|error| io::Error::other(format!("directory sort failed: {error}")))?;
        }
        match &mut self.0 {
            Entries::Native => loop {
                let Some(entry) = dir.read().transpose()? else {
                    return Ok(None);
                };
                let name = name(&entry);
                if name != "." && name != ".." {
                    return Ok(Some(name.to_owned()));
                }
            },
            Entries::Memory(rows) => Ok(rows.next().map(|row| row.name)),
            Entries::SortedFile { input, remaining } => {
                Ok(next_record(input, remaining)?.map(|row| row.name))
            }
            Entries::Unsorted => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_merge_preserves_equal_inodes_and_cleans_up() -> io::Result<()> {
        let data = tempfile::tempdir()?;
        let spill = tempfile::tempdir()?;
        let invalid_spill = data.path().join("original");
        File::create(&invalid_spill)?;
        for index in 0..29 {
            std::fs::hard_link(&invalid_spill, data.path().join(index.to_string()))?;
        }
        #[cfg(target_os = "linux")]
        std::fs::hard_link(
            &invalid_spill,
            data.path().join(OsString::from_vec(vec![0xfe])),
        )?;
        std::fs::create_dir(data.path().join("directory"))?;
        let open = || Dir::new(File::open(data.path())?).map_err(io::Error::from);
        let mut dir = open()?;
        let mut order = Order::new(true);
        let mut expected = Vec::new();
        // Small directories never touch TemporaryDirectory.
        while let Some(name) = order.next(&mut dir, false, &invalid_spill, || Ok(()))? {
            expected.push(name);
        }
        let mut native = open()?;
        let mut tied = Vec::new();
        while let Some(entry) = native.read().transpose()? {
            let n = name(&entry);
            if n != "." && n != ".." && n != "directory" {
                tied.push(n.to_owned());
            }
        }
        tied.push(OsString::from("directory"));
        assert_eq!(expected, tied);
        dir = open()?;
        let mut order = Order(sorted(&mut dir, false, spill.path(), 3, &mut || Ok(()))?);
        assert!(matches!(order.0, Entries::SortedFile { .. }));
        let mut actual = Vec::new();
        while let Some(name) = order.next(&mut dir, false, spill.path(), || Ok(()))? {
            actual.push(name);
        }
        assert_eq!(actual, expected);
        drop(order);
        assert!(spill.path().read_dir()?.next().is_none());

        assert!(sorted(&mut open()?, false, &invalid_spill, 3, &mut || Ok(())).is_err());
        let mut checks = 0;
        let canceled = sorted(&mut open()?, false, spill.path(), 3, &mut || {
            checks += 1;
            if checks > 4 {
                Err(io::Error::other("cancel"))
            } else {
                Ok(())
            }
        });
        assert!(canceled.is_err());
        assert!(spill.path().read_dir()?.next().is_none());
        Ok(())
    }
}
