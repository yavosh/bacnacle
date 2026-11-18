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
