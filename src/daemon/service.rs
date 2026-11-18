use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::{User, geteuid, setgid, setuid};

use super::config::{Config, invalid};
use super::listeners::OwnedPath;

pub(super) fn drop_privileges(name: Option<&str>) -> io::Result<()> {
    let Some(name) = name else {
        return Ok(());
    };
    let user = User::from_name(name)?.ok_or_else(|| invalid("unknown service User"))?;
    if geteuid().is_root() {
        let name = CString::new(name).map_err(|_| invalid("invalid User"))?;
        // SAFETY: name is a valid C string and the service has not spawned threads.
        if unsafe { nix::libc::initgroups(name.as_ptr(), user.gid.as_raw() as _) } != 0 {
            return Err(io::Error::last_os_error());
        }
        setgid(user.gid)?;
        setuid(user.uid)?;
    } else if geteuid() != user.uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot switch to configured User",
        ));
    }
    Ok(())
}

pub(super) struct PidFile {
    file: File,
    _path: OwnedPath,
}

impl PidFile {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o640)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(invalid("PidFile must name a regular, unlinked-to file"));
        }
        file.try_lock().map_err(io::Error::from)?;
        if metadata.len() != 0 {
            let mut old = String::new();
            (&file).take(32).read_to_string(&mut old)?;
            let pid: i32 = old
                .trim()
                .parse()
                .map_err(|_| invalid("invalid existing PidFile"))?;
            if pid <= 0 || metadata.len() > 32 {
                return Err(invalid("invalid existing PidFile"));
            }
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None)
                != Err(nix::errno::Errno::ESRCH)
            {
                return Err(invalid("PidFile belongs to a running process"));
            }
        }
        use std::io::Seek;
        file.rewind()?;
        Ok(Self {
            file,
            _path: OwnedPath::new(path, &metadata),
        })
    }

    pub(super) fn publish(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        writeln!(self.file, "{}", std::process::id())
    }
}

pub(super) struct Log {
    file: Option<File>,
}

impl Log {
    pub(super) fn open(config: &Config) -> io::Result<Self> {
        let file = config
            .log_file
            .as_ref()
            .map(|path| -> io::Result<File> {
                let file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o640)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                    .open(path)?;
                if !file.metadata()?.is_file() {
                    return Err(invalid("LogFile must name a regular file"));
                }
                if !config.log_unlock {
                    file.try_lock().map_err(io::Error::from)?;
                }
                Ok(file)
            })
            .transpose()?;
        Ok(Self { file })
    }

    pub(super) fn reopen(&mut self, config: &Config) -> io::Result<()> {
        if let (Some(path), Some(file)) = (&config.log_file, &self.file) {
            let current = file.metadata()?;
            if fs::symlink_metadata(path)
                .is_ok_and(|m| m.ino() == current.ino() && m.dev() == current.dev())
            {
                return Ok(());
            }
        }
        *self = Self::open(config)?;
        Ok(())
    }

    pub(super) fn write(&mut self, config: &Config, message: &str) -> io::Result<()> {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        if let (Some(file), Some(path)) = (&self.file, &config.log_file) {
            let current = file.metadata()?;
            if config.log_max_size != 0 && current.len() >= config.log_max_size {
                if !config.log_rotate {
                    return Ok(());
                }
                let live = fs::symlink_metadata(path)?;
                if live.dev() == current.dev() && live.ino() == current.ino() {
                    let mut rotated = path.as_os_str().to_owned();
                    rotated.push(format!(".{}", time.as_nanos()));
                    fs::hard_link(path, &rotated)?;
                    fs::remove_file(path)?;
                }
                self.reopen(config)?;
            }
        }
        let Some(file) = &mut self.file else {
            if config.foreground {
                eprintln!("{message}");
            }
            return Ok(());
        };
        if config.log_time {
            write!(file, "{} ", time.as_secs())?;
        }
        writeln!(file, "{message}")
    }
}

pub(super) fn detach() -> io::Result<()> {
    // Darwin still exports daemon(3), although its SDK deprecates it for launchd jobs.
    // SAFETY: startup is single-threaded. No mutex, signal callback, or worker spans fork.
    unsafe extern "C" {
        fn daemon(nochdir: nix::libc::c_int, noclose: nix::libc::c_int) -> nix::libc::c_int;
    }
    if unsafe { daemon(1, 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn reopen_switches_log_files_and_preserves_external_rotation() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("log");
        let rotated = dir.path().join("previous");
        let config = Config {
            log_file: Some(path.clone()),
            ..Config::default()
        };
        let mut log = Log::open(&config)?;
        log.write(&config, "before")?;
        fs::rename(&path, &rotated)?;
        log.reopen(&config)?;
        log.write(&config, "after")?;
        assert_eq!(fs::read_to_string(&rotated)?, "before\n");
        assert_eq!(fs::read_to_string(&path)?, "after\n");
        assert!(Log::open(&config).is_err());
        Ok(())
    }

    #[test]
    fn pidfile_rejects_symlinks_and_a_live_owner() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("pid");
        let target = dir.path().join("target");
        fs::write(&target, "keep")?;
        symlink(&target, &path)?;
        assert!(PidFile::open(&path).is_err());
        assert_eq!(fs::read(&target)?, b"keep");
        fs::remove_file(&path)?;
        let mut first = PidFile::open(&path)?;
        first.publish()?;
        assert!(PidFile::open(&path).is_err());
        assert_eq!(
            fs::read_to_string(&path)?.trim(),
            std::process::id().to_string()
        );
        drop(first);
        assert!(!path.exists());
        Ok(())
    }
}
