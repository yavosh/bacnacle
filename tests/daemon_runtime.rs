#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use client::{Daemon, stream_frame, unix_request};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "daemon did not publish the expected state"
        );
        thread::sleep(Duration::from_millis(30));
    }
}

#[test]
fn invalid_reload_preserves_generation_then_self_check_applies_repair() -> io::Result<()> {
    let directory = tempfile::tempdir_in("/tmp")?;
    let root = directory.path();
    let db = root.join("db");
    let socket = root.join("socket");
    let pid = root.join("pid");
    let log = root.join("service.log");
    let config = root.join("clamd.conf");
    let rule = db.join("test.hdb");
    fs::create_dir(&db)?;
    let original = "e80b5017098950fc58aad83c8c14978e:6:Before\n";
    fs::write(&rule, original)?;
    fs::write(
        &config,
        format!(
            "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nPidFile {}\nLogFile {}\nSelfCheck 1\nConcurrentDatabaseReload no\n",
            socket.display(),
            db.display(),
            pid.display(),
            log.display()
        ),
    )?;
    let _child = Daemon::start(Path::new(env!("CARGO_BIN_EXE_barnacle")), &config, &socket)?;
    let process = Pid::from_raw(
        fs::read_to_string(&pid)?
            .trim()
            .parse()
            .map_err(io::Error::other)?,
    );
    let scan = stream_frame(b"abcdef")?;
    assert_eq!(
        unix_request(&socket, &scan)?,
        "stream: Before.UNOFFICIAL FOUND\0"
    );
    fs::write(&rule, "invalid hash database\n")?;
    kill(process, Signal::SIGUSR2)?;
    until(|| fs::read_to_string(&log).is_ok_and(|s| s.contains("Database reload failed")));
    assert_eq!(
        unix_request(&socket, &scan)?,
        "stream: Before.UNOFFICIAL FOUND\0"
    );
    fs::write(&rule, original.replace("Before", "After"))?;
    until(|| unix_request(&socket, &scan).is_ok_and(|s| s == "stream: After.UNOFFICIAL FOUND\0"));
    kill(process, Signal::SIGTERM)?;
    until(|| !socket.exists() && !pid.exists());
    Ok(())
}

fn idle_session_with_one_worker(exe: &Path) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let dir = tempfile::tempdir_in("/tmp")?;
    let root = dir.path();
    let socket = root.join("socket");
    let config = root.join("config");
    fs::write(
        root.join("test.hdb"),
        "e80b5017098950fc58aad83c8c14978e:6:Test\n",
    )?;
    fs::write(
        &config,
        format!(
            "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nMaxThreads 1\nMaxQueue 1\n",
            socket.display(),
            root.display()
        ),
    )?;
    let _child = Daemon::start(exe, &config, &socket)?;
    let mut session = UnixStream::connect(&socket)?;
    session.set_read_timeout(Some(Duration::from_secs(5)))?;
    session.write_all(b"zIDSESSION\0zPING\0")?;
    let mut frame = [0; 8];
    session.read_exact(&mut frame)?;
    assert_eq!(&frame, b"1: PONG\0");
    let mut queued = UnixStream::connect(&socket)?;
    queued.set_read_timeout(Some(Duration::from_secs(3)))?;
    queued.write_all(b"zPING\0")?;
    let mut pong = [0; 5];
    queued.read_exact(&mut pong)?;
    assert_eq!(&pong, b"PONG\0");
    session.write_all(b"zPING\0zEND\0")?;
    session.read_exact(&mut frame)?;
    assert_eq!(&frame, b"2: PONG\0");
    Ok(())
}

#[test]
fn idle_session_leaves_one_worker_available() -> io::Result<()> {
    idle_session_with_one_worker(Path::new(env!("CARGO_BIN_EXE_barnacle")))
}

#[test]
#[ignore = "requires pinned Debian clamd 1.4.3"]
fn stock_idle_session_leaves_one_worker_available() -> io::Result<()> {
    idle_session_with_one_worker(Path::new("/usr/sbin/clamd"))
}

struct ActiveScanFixture {
    _daemon: Daemon,
    _directory: tempfile::TempDir,
    socket: std::path::PathBuf,
    rule: std::path::PathBuf,
    pidfile: std::path::PathBuf,
    log: std::path::PathBuf,
}

impl ActiveScanFixture {
    fn start() -> io::Result<Self> {
        let directory = tempfile::tempdir_in("/tmp")?;
        let root = directory.path();
        let socket = root.join("socket");
        let config = root.join("config");
        let pidfile = root.join("pid");
        let log = root.join("log");
        let db = root.join("db");
        fs::create_dir(&db)?;
        let rule = db.join("test.hdb");
        fs::write(&rule, "e80b5017098950fc58aad83c8c14978e:6:First\n")?;
        fs::write(
            &config,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nPidFile {}\nLogFile {}\nConcurrentDatabaseReload no\nSelfCheck 0\nReadTimeout 120\n",
                socket.display(),
                db.display(),
                root.display(),
                pidfile.display(),
                log.display()
            ),
        )?;
        let daemon = Daemon::start(Path::new(env!("CARGO_BIN_EXE_barnacle")), &config, &socket)?;
        Ok(Self {
            _daemon: daemon,
            _directory: directory,
            socket,
            rule,
            pidfile,
            log,
        })
    }

    fn upload(&self, session: bool) -> io::Result<std::os::unix::net::UnixStream> {
        use std::io::{Read, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        if session {
            socket2::SockRef::from(&stream).set_send_buffer_size(4096)?;
            stream.write_all(b"zIDSESSION\0zPING\0zINSTREAM\0")?;
            // Exceed the send buffer before opening the next connection. This makes
            // the session start its scan worker while capacity is available.
            let chunk = [0_u8; 16384];
            stream.write_all(&((chunk.len() * 8 + 1) as u32).to_be_bytes())?;
            for _ in 0..8 {
                stream.write_all(&chunk)?;
            }
            let mut pong = [0; 8];
            stream.read_exact(&mut pong)?;
            assert_eq!(&pong, b"1: PONG\0");
        } else {
            stream.write_all(b"zINSTREAM\0\0\0\0\x06abc")?;
        }
        Ok(stream)
    }

    fn wait_for_uploads(&self, count: usize, scoped: bool) {
        until(|| {
            unix_request(&self.socket, b"zSTATS\0").is_ok_and(|s| {
                s.matches("\tINSTREAM ").count() == count && (!scoped || s.contains("\tSCAN "))
            })
        });
    }
}

#[test]
fn signal_shutdown_interrupts_uploads_and_session_workers() -> io::Result<()> {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    for signal in [Signal::SIGTERM, Signal::SIGINT] {
        let service = ActiveScanFixture::start()?;
        let session = service.upload(true)?;
        let upload = service.upload(false)?;
        let idle = UnixStream::connect(&service.socket)?;
        idle.set_read_timeout(Some(Duration::from_secs(3)))?;
        service.wait_for_uploads(2, true);
        let pid = fs::read_to_string(&service.pidfile)?
            .trim()
            .parse()
            .map_err(io::Error::other)?;
        kill(Pid::from_raw(pid), signal)?;
        for mut client in [upload, session, idle] {
            let mut reply = Vec::new();
            match client.read_to_end(&mut reply) {
                Ok(_) => (),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => (),
                Err(e) => return Err(e),
            }
            assert!(!reply.ends_with(b"FOUND\0") && !reply.ends_with(b"OK\0"));
        }
        until(|| !service.pidfile.exists() && !service.socket.exists());
    }
    Ok(())
}

#[test]
fn nonconcurrent_reload_waits_for_inflight_scan_and_blocks_new_snapshots() -> io::Result<()> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let service = ActiveScanFixture::start()?;
    let mut old = service.upload(false)?;
    service.wait_for_uploads(1, false);
    fs::write(&service.rule, "e80b5017098950fc58aad83c8c14978e:6:Second\n")?;
    assert_eq!(unix_request(&service.socket, b"zRELOAD\0")?, "RELOADING\0");
    until(|| {
        fs::read_to_string(&service.log)
            .is_ok_and(|s| s.contains("Waiting for active scans before database reload"))
    });
    let mut next = UnixStream::connect(&service.socket)?;
    next.write_all(&stream_frame(b"abcdef")?)?;
    service.wait_for_uploads(2, false);
    next.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut byte = [0];
    let error = next.read(&mut byte).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    old.write_all(b"def\0\0\0\0")?;
    let mut reply = String::new();
    old.read_to_string(&mut reply)?;
    assert_eq!(reply, "stream: First.UNOFFICIAL FOUND\0");
    next.set_read_timeout(Some(Duration::from_secs(3)))?;
    reply.clear();
    next.read_to_string(&mut reply)?;
    assert_eq!(reply, "stream: Second.UNOFFICIAL FOUND\0");
    Ok(())
}
