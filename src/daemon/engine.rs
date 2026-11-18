//! One immutable database generation, shared by all commands in an active scan.
mod cvd;
mod raw;

use super::Config;
use barnacle::index::{self, Index};
use barnacle::{Feed, PINNED_FLEVEL, hash_reader};
use nix::libc;
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn open_database(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid(format!(
            "expected a regular database: {}",
            path.display()
        )));
    }
    Ok(file)
}

#[derive(Eq, PartialEq)]
struct Source {
    path: PathBuf,
    inode: u64,
    device: u64,
    length: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}

impl Source {
    fn new(path: PathBuf, m: &fs::Metadata) -> Self {
        Self {
            path,
            inode: m.ino(),
            device: m.dev(),
            length: m.len(),
            changed: (m.ctime(), m.ctime_nsec()),
            modified: (m.mtime(), m.mtime_nsec()),
        }
    }

    fn copy_to(&self, destination: &Path) -> io::Result<()> {
        let mut input = open_database(&self.path)?;
        let mut output = File::create_new(destination)?;
        let consistent = |m: fs::Metadata| Self::new(self.path.clone(), &m) == *self;
        if !consistent(input.metadata()?)
            || io::copy(
                &mut (&mut input).take(self.length.saturating_add(1)),
                &mut output,
            )? != self.length
            || !consistent(input.metadata()?)
        {
            return Err(invalid(format!(
                "{} changed while loading",
                self.path.display()
            )));
        }
        Ok(())
    }
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn sources(config: &Config) -> io::Result<Vec<Source>> {
    let mut inputs = Vec::new();
    for item in fs::read_dir(&config.database_directory)? {
        let path = item?.path();
        let ext = extension(&path);
        if !matches!(
            ext.as_str(),
            "db" | "hdb"
                | "hsb"
                | "hdu"
                | "hsu"
                | "fp"
                | "sfp"
                | "ign"
                | "ign2"
                | "cvd"
                | "cld"
                | "cud"
                | "crb"
                | "mdb"
                | "msb"
                | "imp"
                | "mdu"
                | "msu"
                | "ndb"
                | "ndu"
                | "ldb"
                | "ldu"
                | "cbc"
                | "sdb"
                | "zmd"
                | "rmd"
                | "cfg"
                | "info"
                | "wdb"
                | "pdb"
                | "gdb"
                | "ftm"
                | "idb"
                | "cdb"
                | "cat"
                | "ioc"
                | "yar"
                | "yara"
                | "pwdb"
        ) {
            continue;
        }
        if config.official_database_only
            && !matches!(ext.as_str(), "cvd" | "cld" | "ign" | "ign2")
            && !path.ends_with("daily.cfg")
            && !path.ends_with("local.gdb")
        {
            continue;
        }
        let m = fs::metadata(&path)?;
        if !m.is_file() {
            return Err(invalid(format!(
                "expected a regular database: {}",
                path.display()
            )));
        }
        inputs.push(Source::new(path, &m));
    }
    // clamd retains readdir order among databases with the same load priority.
    inputs.sort_by_key(|s| match extension(&s.path).as_str() {
        "ign" | "ign2" => 0,
        _ if s.path.ends_with("daily.cvd") => 1,
        _ => 2,
    });
    Ok(inputs)
}

pub(super) struct Generation {
    sources: Vec<Source>,
    index: Index,
    version: String,
    scan_limit: u64,
    scan_time: Duration,
    partial_only: bool,
}

fn daily_version() -> io::Result<String> {
    let stamp: libc::time_t = cvd::DAILY_TIMESTAMP as _;
    let mut local = std::mem::MaybeUninit::uninit();
    let mut output = [0 as libc::c_char; 64];
    // SAFETY: the two writable buffers belong to this call. localtime_r initializes
    // local on success, and strftime writes a NUL-terminated string on success.
    unsafe {
        if libc::localtime_r(&stamp, local.as_mut_ptr()).is_null()
            || libc::strftime(
                output.as_mut_ptr(),
                output.len(),
                c"%a %b %e %T %Y".as_ptr(),
                local.as_ptr(),
            ) == 0
        {
            return Err(invalid("cannot format daily database time"));
        }
        Ok(format!(
            "ClamAV 1.4.3/28187/{}",
            CStr::from_ptr(output.as_ptr()).to_string_lossy()
        ))
    }
}

impl Generation {
    pub(super) fn load(config: &Config) -> io::Result<Self> {
        let inputs = sources(config)?;
        let has_cvd = inputs.iter().any(|s| extension(&s.path) == "cvd");
        if has_cvd
            && !cvd::PINNED
                .iter()
                .all(|(name, _, _)| inputs.iter().any(|s| s.path.ends_with(name)))
        {
            return Err(invalid(
                "expected verified daily.cvd, main.cvd and bytecode.cvd together",
            ));
        }
        if let Some(days) = config.fail_if_cvd_older_than {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs();
            if !has_cvd || now.saturating_sub(cvd::DAILY_TIMESTAMP) > days.saturating_mul(86_400) {
                return Err(invalid("database exceeds FailIfCvdOlderThan"));
            }
        }
        if config.detect_pua && has_cvd {
            return Err(invalid("PUA database matching is unsupported"));
        }
        let temp = tempfile::tempdir_in(&config.temporary_directory)?;
        let local_dir = temp.path().join("local");
        fs::create_dir(&local_dir)?;
        let mut paths = Vec::new();
        for source in &inputs {
            let path = &source.path;
            let ext = extension(path);
            match ext.as_str() {
                "cvd" => cvd::extract(path, temp.path(), &mut paths)?,
                "hdu" | "hsu" | "mdu" | "msu" | "ndu" | "ldu" if !config.detect_pua => continue,
                "hdb" | "hsb" | "ign" | "ign2" | "fp" | "sfp" => {
                    let output =
                        local_dir.join(path.file_name().expect("directory entry has a name"));
                    source.copy_to(&output)?;
                    paths.push((output, false));
                }
                _ => return Err(invalid(format!("unsupported database: {}", path.display()))),
            }
        }
        let paths: Vec<_> = paths
            .iter()
            .map(|(p, official)| (p.as_path(), *official))
            .collect();
        let mut feed = Feed::load_sources(&paths, PINNED_FLEVEL)?;
        let partial_only = has_cvd || feed.inventory.iter().any(|i| i.outside_matcher > 0);
        let db = temp.path().join("index.bhi");
        index::build(&db, &mut feed.rules)?;
        drop(feed);
        let index = Index::open_pread(&db)?;
        if inputs != sources(config)? {
            return Err(invalid("database changed while loading"));
        }
        let scan_limit = [config.max_file_size, config.max_scan_size]
            .into_iter()
            .filter(|&n| n != 0)
            .min()
            .unwrap_or(u64::MAX);
        Ok(Self {
            sources: inputs,
            index,
            scan_limit,
            scan_time: config.max_scan_time,
            partial_only,
            version: if has_cvd {
                daily_version()?
            } else {
                "ClamAV 1.4.3".into()
            },
        })
    }

    pub(super) fn version(&self) -> &str {
        &self.version
    }

    pub(super) fn changed(&self, config: &Config) -> io::Result<bool> {
        Ok(self.sources != sources(config)?)
    }

    pub(super) fn scan(&self, reader: impl Read) -> io::Result<Option<String>> {
        let mut input = ScanInput {
            reader: reader.take(self.scan_limit.saturating_add(1)),
            header: Vec::with_capacity(raw::HEADER_SIZE),
            deadline: (!self.scan_time.is_zero())
                .then(|| Instant::now().checked_add(self.scan_time))
                .flatten(),
        };
        let hashes = hash_reader(&mut input)?;
        if hashes.size > self.scan_limit {
            return Err(invalid("scan size limit exceeded"));
        }
        // The pinned engine skips files of five bytes or less. Unimplemented
        // allowlists and other official matchers can suppress or supersede a hash.
        if self.partial_only || hashes.size > i32::MAX as u64 {
            return Ok(None);
        }
        let result =
            hashes.lookup(|algorithm, digest, size| self.index.lookup(algorithm, digest, size))?;
        if result.is_some() && raw::eligible(&input.header) {
            Ok(result)
        } else {
            Ok(None)
        }
    }
}

struct ScanInput<R> {
    reader: R,
    header: Vec<u8>,
    deadline: Option<Instant>,
}

impl<R: Read> Read for ScanInput<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.deadline.is_some_and(|t| Instant::now() >= t) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MaxScanTime exceeded",
            ));
        }
        let n = self.reader.read(buffer)?;
        let keep = n.min(raw::HEADER_SIZE - self.header.len());
        self.header.extend_from_slice(&buffer[..keep]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    struct Fixture {
        root: tempfile::TempDir,
        config: Config,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("db");
            fs::create_dir(&dir).unwrap();
            let config = Config {
                database_directory: dir,
                temporary_directory: root.path().to_owned(),
                ..Config::default()
            };
            Self { root, config }
        }

        fn write(&self, name: &str, value: impl AsRef<[u8]>) {
            fs::write(self.config.database_directory.join(name), value).unwrap();
        }
    }

    fn rule(payload: &[u8], name: &str) -> String {
        let digest: String = Md5::digest(payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{digest}:{}:{name}\n", payload.len())
    }

    #[test]
    fn reload_preserves_old_generation_and_applies_ignores_and_limits() {
        let mut f = Fixture::new();
        let bytes = b"raw binary payload";
        f.write("fixture.hdb", rule(bytes, "First"));
        let old = Generation::load(&f.config).unwrap();
        assert_eq!(old.version(), "ClamAV 1.4.3");
        assert_eq!(
            old.scan(&bytes[..]).unwrap().as_deref(),
            Some("First.UNOFFICIAL")
        );
        assert!(!old.changed(&f.config).unwrap());
        f.write("fixture.ign2", "First\n");
        f.write("freshclam.dat", "metadata");
        assert!(old.changed(&f.config).unwrap());
        assert_eq!(
            old.scan(&bytes[..]).unwrap().as_deref(),
            Some("First.UNOFFICIAL")
        );
        let new = Generation::load(&f.config).unwrap();
        assert!(new.scan(&bytes[..]).unwrap().is_none());
        assert!(new.scan(&b"unknown content"[..]).unwrap().is_none());
        fs::remove_file(f.config.database_directory.join("fixture.ign2")).unwrap();
        f.config.max_file_size = bytes.len() as u64 - 1;
        assert!(
            Generation::load(&f.config)
                .unwrap()
                .scan(&bytes[..])
                .is_err()
        );
        f.config.max_file_size = bytes.len() as u64;
        assert!(
            Generation::load(&f.config)
                .unwrap()
                .scan(&bytes[..])
                .unwrap()
                .is_some()
        );
        assert_eq!(f.root.path().read_dir().unwrap().count(), 1);
    }

    #[test]
    fn competing_and_unsupported_results_remain_incomplete() {
        let f = Fixture::new();
        let raw = b"abcdef";
        let ignored = b"OggS harmless bytes";
        let archive = b"\x1f\x8b\x08 fake gzip fixture";
        f.write(
            "local.hdb",
            [
                rule(raw, "Local"),
                rule(ignored, "Ogg"),
                rule(archive, "Outer"),
                rule(b"short", "Tiny"),
            ]
            .concat(),
        );
        let db = Generation::load(&f.config).unwrap();
        assert_eq!(
            db.scan(&raw[..]).unwrap().as_deref(),
            Some("Local.UNOFFICIAL")
        );
        assert!(db.scan(&ignored[..]).unwrap().is_none());
        assert!(db.scan(&archive[..]).unwrap().is_none());
        assert!(db.scan(&b"short"[..]).unwrap().is_none());
        f.write("suppress.fp", rule(raw, "Suppressed"));
        assert!(
            Generation::load(&f.config)
                .unwrap()
                .scan(&raw[..])
                .unwrap()
                .is_none()
        );
        f.write("suppress.fp", "invalid allowlist record");
        assert!(Generation::load(&f.config).is_err());
        f.write("suppress.fp", rule(raw, "Suppressed"));
        f.write("extra.ldb", "different matcher");
        assert!(db.changed(&f.config).unwrap());
        assert!(Generation::load(&f.config).is_err());
    }

    #[test]
    fn archives_fail_closed_before_activation() {
        let f = Fixture::new();
        for (name, _, _) in cvd::PINNED {
            f.write(name, b"tampered archive");
        }
        assert!(
            Generation::load(&f.config)
                .err()
                .unwrap()
                .to_string()
                .contains("SHA-256")
        );
        let local = Fixture::new();
        local.write("daily.cld", b"unverified replacement");
        assert!(Generation::load(&local.config).is_err());
    }

    #[test]
    #[ignore = "set BARNACLE_CVD_DIR to the verified FreshClam snapshot"]
    fn verified_archives_coexist_with_local_sources() {
        let snapshot = PathBuf::from(std::env::var_os("BARNACLE_CVD_DIR").unwrap());
        let f = Fixture::new();
        for (name, _, _) in cvd::PINNED {
            std::os::unix::fs::symlink(snapshot.join(name), f.config.database_directory.join(name))
                .unwrap();
        }
        let bytes = b"local mixed generation";
        f.write("local.hdb", rule(bytes, "Mixed"));
        let db = Generation::load(&f.config).unwrap();
        assert!(db.version().starts_with("ClamAV 1.4.3/28187/"));
        let local = hash_reader(&bytes[..])
            .unwrap()
            .lookup(|a, d, s| db.index.lookup(a, d, s))
            .unwrap();
        assert_eq!(local.as_deref(), Some("Mixed.UNOFFICIAL"));
        assert!(db.scan(&bytes[..]).unwrap().is_none());
    }
}
