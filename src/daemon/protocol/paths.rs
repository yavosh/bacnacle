use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use rustix::fs::{self, AtFlags, CWD, Dir, FileType, Mode, OFlags};

use super::{INCOMPLETE, Jobs, Reply, State};
use crate::daemon::Generation;
use crate::daemon::config::Config;
use std::sync::Arc;

struct Directory {
    entries: Dir,
    path: PathBuf,
    identity: (u64, u64),
}

enum Target {
    Skip(&'static str),
    Open(File),
}

fn open_target(parent: BorrowedFd<'_>, name: &Path, config: &Config) -> io::Result<Target> {
    let mut stat = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    let link = FileType::from_raw_mode(stat.st_mode) == FileType::Symlink;
    if link {
        if !config.follow_directory_symlinks && !config.follow_file_symlinks {
            return Ok(Target::Skip("Excluded (symbolic link). ERROR"));
        }
        stat = fs::statat(parent, name, AtFlags::empty())?;
    }
    let kind = FileType::from_raw_mode(stat.st_mode);
    if link
        && ((kind == FileType::Directory && !config.follow_directory_symlinks)
            || (kind != FileType::Directory && !config.follow_file_symlinks))
    {
        return Ok(Target::Skip("Excluded (symbolic link). ERROR"));
    }
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY;
    if !link {
        flags |= OFlags::NOFOLLOW;
    }
    match kind {
        FileType::Directory => flags |= OFlags::DIRECTORY,
        FileType::RegularFile => (),
        _ => return Ok(Target::Skip("Not supported file type ERROR")),
    }
    let file = File::from(fs::openat(parent, name, flags, Mode::empty())?);
    let opened = fs::fstat(&file)?;
    if opened.st_dev != stat.st_dev || opened.st_ino != stat.st_ino {
        return Err(io::Error::other("Path changed during scan"));
    }
    Ok(Target::Open(file))
}

fn path_error(reply: &Reply<'_>, path: &Path, err: &io::Error) -> io::Result<()> {
    if err.kind() == io::ErrorKind::PermissionDenied {
        return reply.line(Some(path.as_os_str()), "Access denied. ERROR");
    }
    let message = match err.raw_os_error() {
        Some(code) => nix::errno::Errno::from_raw(code).desc().to_owned(),
        None => err.to_string(),
    };
    reply.line(
        Some(path.as_os_str()),
        &format!("File path check failure: {message}. ERROR"),
    )
}

pub(super) fn scan<'a>(
    state: &State,
    reply: Reply<'a>,
    cmd: &[u8],
    root: &Path,
    generation: Arc<Generation>,
    jobs: Option<&Jobs<'a, '_>>,
) -> io::Result<()> {
    let config = &state.config;
    if cmd == b"ALLMATCHSCAN" && !config.allow_all_match_scan {
        return reply.line(
            Some(root.as_os_str()),
            "ALLMATCHSCAN command disabled by clamd configuration. ERROR",
        );
    }
    let start = Instant::now();
    let mut stack = Vec::<Directory>::new();
    let mut root_dev = None;
    let mut first = true;
    let mut reported = false;
    loop {
        if state.stopping()
            || (!config.max_scan_time.is_zero() && start.elapsed() >= config.max_scan_time)
        {
            return reply.line(Some(root.as_os_str()), "Directory scan interrupted. ERROR");
        }
        let (parent, name, path) = if first {
            first = false;
            (CWD, root.to_owned(), root.to_owned())
        } else if let Some(dir) = stack.last_mut() {
            match dir.entries.read() {
                None => {
                    stack.pop();
                    continue;
                }
                Some(Err(error)) => {
                    path_error(&reply, &dir.path, &error.into())?;
                    reported = true;
                    stack.pop();
                    continue;
                }
                Some(Ok(entry)) => {
                    let name = OsStr::from_bytes(entry.file_name().to_bytes());
                    if name == "." || name == ".." {
                        continue;
                    }
                    (dir.entries.fd()?, PathBuf::from(name), dir.path.join(name))
                }
            }
        } else {
            break;
        };
        if config
            .exclude_paths
            .iter()
            .any(|pattern| pattern.is_match(&path.to_string_lossy()))
        {
            reply.line(Some(path.as_os_str()), "Excluded. ERROR")?;
            reported = true;
            continue;
        }
        let file = match open_target(parent, &name, config) {
            Ok(Target::Open(file)) => file,
            Ok(Target::Skip(reason)) => {
                reply.line(Some(path.as_os_str()), reason)?;
                reported = true;
                continue;
            }
            Err(error) => {
                path_error(&reply, &path, &error)?;
                // Stock reports both realpath and stat failures for a missing input.
                if error.kind() == io::ErrorKind::NotFound {
                    path_error(&reply, &path, &error)?;
                }
                reported = true;
                continue;
            }
        };
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(error) => {
                path_error(&reply, &path, &error)?;
                reported = true;
                continue;
            }
        };
        let device = meta.dev();
        if device != *root_dev.get_or_insert(device) && !config.cross_filesystems {
            reply.line(
                Some(path.as_os_str()),
                "Excluded (another filesystem). ERROR",
            )?;
            reported = true;
        } else if meta.is_dir() {
            if (config.max_directory_recursion != 0 && stack.len() > config.max_directory_recursion)
                || stack.iter().any(|dir| dir.identity == (device, meta.ino()))
            {
                reply.line(
                    Some(path.as_os_str()),
                    "Directory recursion limit or cycle. ERROR",
                )?;
                reported = true;
                continue;
            }
            match Dir::new(file) {
                Ok(entries) => stack.push(Directory {
                    entries,
                    path,
                    identity: (device, meta.ino()),
                }),
                Err(error) => {
                    path_error(&reply, &path, &error.into())?;
                    reported = true;
                }
            }
        } else {
            let label = std::fs::canonicalize(&path).unwrap_or(path);
            reported = true;
            if cmd == b"ALLMATCHSCAN" {
                reply.line(Some(label.as_os_str()), INCOMPLETE)?;
                continue;
            }
            if let Some(jobs) = jobs {
                let generation = generation.clone();
                jobs.submit(move || {
                    reply
                        .result(label.as_os_str(), reply.scan(&generation, file))
                        .map(|_| ())
                })?;
                continue;
            }
            let detected = reply.result(label.as_os_str(), reply.scan(&generation, file))?;
            if detected && cmd == b"SCAN" {
                break;
            }
        }
    }
    if !reported {
        reply.line(Some(root.as_os_str()), INCOMPLETE)?;
    }
    Ok(())
}
