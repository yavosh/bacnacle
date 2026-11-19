use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::unistd::{Group, chown};
use socket2::{Domain, SockAddr, Socket, Type};

use super::config::{Config, invalid};
use super::protocol::Connection;

pub(super) struct OwnedPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl OwnedPath {
    pub(super) fn new(path: &Path, metadata: &fs::Metadata) -> Self {
        Self {
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn remove(&self) -> io::Result<()> {
        let current = fs::symlink_metadata(&self.path)?;
        if current.dev() == self.device && current.ino() == self.inode {
            fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

impl Drop for OwnedPath {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

pub(super) struct Listener {
    socket: Socket,
    unix: bool,
    _cleanup: Option<OwnedPath>,
}

impl AsFd for Listener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl Listener {
    fn new(socket: Socket, cleanup: Option<OwnedPath>) -> io::Result<Self> {
        let family = socket.local_addr()?.domain();
        if !matches!(family, Domain::UNIX | Domain::IPV4 | Domain::IPV6)
            || socket.r#type()? != Type::STREAM
        {
            return Err(invalid("expected Unix or TCP listening socket"));
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            unix: family == Domain::UNIX,
            _cleanup: cleanup,
        })
    }

    pub(super) fn accept(&self) -> io::Result<Connection> {
        let (socket, _) = self.socket.accept()?;
        socket.set_nonblocking(false)?;
        if self.unix {
            Ok(Connection::Unix(UnixStream::from(socket)))
        } else {
            Ok(Connection::Tcp(TcpStream::from(socket)))
        }
    }
}

#[cfg(target_os = "linux")]
fn activated() -> io::Result<Vec<Listener>> {
    // systemd passes listening sockets in contiguous descriptors beginning at 3.
    if std::env::var("LISTEN_PID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        != Some(std::process::id())
    {
        return Ok(Vec::new());
    }
    let Some(count) = std::env::var_os("LISTEN_FDS") else {
        return Ok(Vec::new());
    };
    let count: i32 = count
        .to_str()
        .and_then(|s| s.parse().ok())
        .filter(|n| (0..=i32::MAX - 3).contains(n))
        .ok_or_else(|| invalid("invalid LISTEN_FDS"))?;
    let mut listeners = Vec::new();
    for fd in 3..3 + count {
        // Probe the descriptor without assuming it is valid. Only adopt a fresh duplicate.
        let duplicate = unsafe { nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, 3 + count) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl returned an exclusively owned, successfully duplicated descriptor.
        let socket = unsafe { Socket::from_raw_fd(duplicate) };
        if !socket.is_listener()? {
            return Err(invalid("activated descriptor is not a listening socket"));
        }
        if unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        listeners.push(Listener::new(socket, None)?);
    }
    Ok(listeners)
}

#[cfg(not(target_os = "linux"))]
fn activated() -> io::Result<Vec<Listener>> {
    Ok(Vec::new())
}

pub(super) fn open(config: &Config) -> io::Result<Vec<Listener>> {
    let mut listeners = activated()?;
    if !listeners.is_empty() {
        return Ok(listeners);
    }
    if let Some(path) = &config.local_socket {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        let addr = SockAddr::unix(path)?;
        socket.bind(&addr).or_else(|error| {
            if error.kind() != io::ErrorKind::AddrInUse || !config.fix_stale_socket {
                return Err(error);
            }
            let existing = fs::symlink_metadata(path)?;
            if !existing.file_type().is_socket() {
                return Err(error);
            }
            let probe = Socket::new(Domain::UNIX, Type::STREAM, None)?;
            probe.set_nonblocking(true)?;
            match probe.connect(&addr) {
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    OwnedPath::new(path, &existing).remove()?;
                    socket.bind(&addr)
                }
                _ => Err(error),
            }
        })?;
        let cleanup = OwnedPath::new(path, &fs::symlink_metadata(path)?);
        if let Some(name) = &config.local_socket_group {
            let group =
                Group::from_name(name)?.ok_or_else(|| invalid("unknown LocalSocketGroup"))?;
            chown(path, None, Some(group.gid))?;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(config.local_socket_mode))?;
        socket.listen(config.backlog)?;
        listeners.push(Listener::new(socket, Some(cleanup))?);
    }
    if let Some(port) = config.tcp_port {
        let defaults = ["0.0.0.0".to_owned(), "::".to_owned()];
        let hosts = if config.tcp_addresses.is_empty() {
            &defaults[..]
        } else {
            &config.tcp_addresses
        };
        let mut bound = HashSet::new();
        for host in hosts {
            for addr in (host.as_str(), port).to_socket_addrs()? {
                if !bound.insert(addr) {
                    continue;
                }
                let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
                socket.set_reuse_address(true)?;
                if addr.is_ipv6() {
                    socket.set_only_v6(true)?;
                }
                socket.bind(&addr.into())?;
                socket.listen(config.backlog)?;
                listeners.push(Listener::new(socket, None)?);
            }
        }
    }
    if listeners.is_empty() {
        return Err(invalid(
            "configure LocalSocket or TCPSocket, or supply a systemd listening socket",
        ));
    }
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn stale_socket_recovery_preserves_other_entries() -> io::Result<()> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let path = dir.path().join("socket");
        let mut config = Config {
            local_socket: Some(path.clone()),
            fix_stale_socket: false,
            ..Default::default()
        };
        drop(UnixListener::bind(&path)?);
        assert!(open(&config).is_err());
        config.fix_stale_socket = true;
        let listeners = open(&config)?;
        assert!(open(&config).is_err());
        drop(listeners);
        assert!(!path.exists());
        fs::write(&path, "keep")?;
        assert!(open(&config).is_err());
        assert_eq!(fs::read(&path)?, b"keep");
        Ok(())
    }

    #[test]
    fn shutdown_preserves_a_replaced_socket_path() -> io::Result<()> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let path = dir.path().join("socket");
        let config = Config {
            local_socket: Some(path.clone()),
            ..Default::default()
        };
        let listeners = open(&config)?;
        fs::rename(&path, dir.path().join("original"))?;
        fs::write(&path, "replacement")?;
        drop(listeners);
        assert_eq!(fs::read(&path)?, b"replacement");
        Ok(())
    }
}
