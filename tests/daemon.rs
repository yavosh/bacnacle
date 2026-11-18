//! Exercise the public clamd entry point. The ignored test runs the same requests against stock.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use client::{Daemon, exchange, stream_frame, unix_request};
use md5::{Digest, Md5};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use std::fs;
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_barnacle");
const DATA: &[u8] = b"Barnacle local daemon test fixture\n";

fn write_rule(path: &Path, name: &str) -> io::Result<()> {
    let digest: String = Md5::digest(DATA)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    fs::write(path, format!("{digest}:{}:{name}\n", DATA.len()))
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "daemon state did not change in time"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn lifecycle(exe: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let root = temp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let rule = db.join("local.hdb");
    write_rule(&rule, "Barnacle.First")?;
    let sample = root.canonicalize()?.join("fixture");
    fs::write(&sample, DATA)?;
    let socket = root.join("socket");
    let pidfile = root.join("pid");
    let config = root.join("config");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nLocalSocketMode 660\nPidFile {}\nTemporaryDirectory {}\nTCPAddr 127.0.0.1\nTCPSocket {}\nSelfCheck 0\nCommandReadTimeout 1\nReadTimeout 2\n",
            db.display(),
            socket.display(),
            pidfile.display(),
            root.display(),
            addr.port()
        ),
    )?;
    drop(listener);
    let _daemon = Daemon::start(exe, &config, &socket)?;
    wait_until(|| pidfile.is_file());
    let pid = fs::read_to_string(&pidfile)?
        .trim()
        .parse::<i32>()
        .map_err(io::Error::other)?;
    assert_eq!(fs::metadata(&socket)?.permissions().mode() & 0o777, 0o660);
    let tcp_request = |bytes: &[u8]| -> io::Result<String> {
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
        tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        exchange(tcp, bytes)
    };
    assert_eq!(
        tcp_request(&stream_frame(DATA)?)?,
        "stream: Barnacle.First.UNOFFICIAL FOUND\0"
    );
    assert_eq!(
        tcp_request(format!("zSCAN {}\0", sample.display()).as_bytes())?,
        format!("{}: Barnacle.First.UNOFFICIAL FOUND\0", sample.display())
    );
    assert_eq!(
        tcp_request(b"zFILDES\0\0")?,
        "No file descriptor received. ERROR\0"
    );
    for op in ["SCAN", "CONTSCAN", "MULTISCAN"] {
        let command = format!("z{op} {}\0", sample.display());
        assert_eq!(
            unix_request(&socket, command.as_bytes())?,
            format!("{}: Barnacle.First.UNOFFICIAL FOUND\0", sample.display())
        );
    }
    let directory = root.canonicalize()?.join("objects");
    fs::create_dir(&directory)?;
    let mut hits = Vec::new();
    for name in ["first", "second"] {
        let path = directory.join(name);
        fs::write(&path, DATA)?;
        hits.push(format!(
            "{}: Barnacle.First.UNOFFICIAL FOUND",
            path.display()
        ));
    }
    hits.sort_unstable();
    for op in ["SCAN", "CONTSCAN", "MULTISCAN"] {
        let command = format!("z{op} {}\0", directory.display());
        let replies = unix_request(&socket, command.as_bytes())?;
        let mut frames: Vec<_> = replies.strip_suffix('\0').unwrap().split('\0').collect();
        frames.sort_unstable();
        if op == "SCAN" {
            assert_eq!(frames.len(), 1);
            assert!(hits.iter().any(|hit| hit == frames[0]));
        } else {
            assert_eq!(frames, hits);
        }
    }
    let all = format!("zALLMATCHSCAN {}\0", sample.display());
    let message = if stock {
        "Barnacle.First.UNOFFICIAL FOUND"
    } else {
        "Incomplete scan: unsupported detection coverage. ERROR"
    };
    assert_eq!(
        unix_request(&socket, all.as_bytes())?,
        format!("{}: {message}\0", sample.display())
    );
    let missing = directory.join("missing");
    let error = format!(
        "{}: File path check failure: No such file or directory. ERROR\0",
        missing.display()
    );
    for op in ["SCAN", "CONTSCAN", "MULTISCAN", "ALLMATCHSCAN"] {
        let command = format!("z{op} {}\0", missing.display());
        assert_eq!(unix_request(&socket, command.as_bytes())?, error.repeat(2));
    }
    if !nix::unistd::geteuid().is_root() {
        let locked = directory.join("unreadable");
        fs::write(&locked, DATA)?;
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))?;
        let command = format!("zSCAN {}\0", locked.display());
        assert_eq!(
            unix_request(&socket, command.as_bytes())?,
            format!("{}: Access denied. ERROR\0", locked.display())
        );
    }
    let link = directory.join("link");
    std::os::unix::fs::symlink(&sample, &link)?;
    let empty = directory.join("empty");
    fs::create_dir(&empty)?;
    for (path, partial) in [
        (&link, "Excluded (symbolic link). ERROR"),
        (
            &empty,
            "Incomplete scan: unsupported detection coverage. ERROR",
        ),
    ] {
        let command = format!("zSCAN {}\0", path.display());
        let verdict = if stock { "OK" } else { partial };
        assert_eq!(
            unix_request(&socket, command.as_bytes())?,
            format!("{}: {verdict}\0", path.display())
        );
    }

    let replies = unix_request(&socket, b"zIDSESSION\0zPING\0zPING\0zEND\0")?;
    let mut frames: Vec<_> = replies.strip_suffix('\0').unwrap().split('\0').collect();
    frames.sort_unstable();
    assert_eq!(frames, ["1: PONG", "2: PONG"]);
    assert_eq!(unix_request(&socket, b"nPING\n")?, "PONG\n");
    assert_eq!(unix_request(&socket, b"PING\n")?, "PONG\n");
    assert_eq!(unix_request(&socket, b"zDETSTATS\0")?, "");
    assert_eq!(unix_request(&socket, b"zDETSTATSCLEAR\0")?, "");
    assert_eq!(
        unix_request(&socket, b"zIDSESSION\0zRELOAD\0")?,
        "1: Command invalid inside IDSESSION. ERROR\0"
    );
    let stats = unix_request(&socket, b"zSTATS\0")?;
    for field in [
        "POOLS: 1\n",
        "STATE: VALID PRIMARY\n",
        "THREADS: live ",
        "idle-timeout ",
        "QUEUE: ",
        "MEMSTATS: ",
        "pools_total ",
    ] {
        assert!(stats.contains(field), "missing {field:?} in {stats:?}");
    }
    assert!(stats.ends_with("\nEND\0"), "{stats:?}");

    // A client can cancel a partial upload and reconnect immediately.
    let mut canceled = UnixStream::connect(&socket)?;
    canceled.write_all(b"zINSTREAM\0\0\0\0\x10half")?;
    drop(canceled);
    assert_eq!(unix_request(&socket, b"zPING\0")?, "PONG\0");
    let idle = UnixStream::connect(&socket)?;
    idle.set_read_timeout(Some(Duration::from_secs(6)))?;
    assert_eq!(exchange(idle, b"")?, "COMMAND READ TIMED OUT\n");

    let raw = stream_frame(b"ordinary file without a matching signature")?;
    let expected = if stock {
        "stream: OK\0"
    } else {
        "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
    };
    assert_eq!(unix_request(&socket, &raw)?, expected);

    write_rule(&rule, "Barnacle.Second")?;
    assert_eq!(unix_request(&socket, b"zRELOAD\0")?, "RELOADING\0");
    let scan = stream_frame(DATA)?;
    wait_until(|| {
        unix_request(&socket, &scan)
            .is_ok_and(|s| s == "stream: Barnacle.Second.UNOFFICIAL FOUND\0")
    });
    kill(Pid::from_raw(pid), Signal::SIGHUP)?;
    assert_eq!(unix_request(&socket, b"zPING\0")?, "PONG\0");
    assert_eq!(unix_request(&socket, b"zSHUTDOWN\0")?, "");
    wait_until(|| !socket.exists() && !pidfile.exists());
    Ok(())
}

#[test]
fn barnacle_lifecycle() -> io::Result<()> {
    lifecycle(Path::new(BIN), false)
}

#[test]
#[ignore = "requires pinned Debian clamd 1.4.3"]
fn stock_lifecycle() -> io::Result<()> {
    lifecycle(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn build_and_validate_with_the_shipped_binary() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let rule = temp.path().join("local.hdb");
    write_rule(&rule, "Barnacle.Test")?;
    let index = temp.path().join("index");
    let build = Command::new(BIN)
        .arg("build")
        .arg(&index)
        .arg(rule)
        .output()?;
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let validate = |path: &Path| Command::new(BIN).arg("validate").arg(path).output();
    let result = validate(&index)?;
    assert!(result.status.success());
    assert_eq!(result.stdout, b"valid\n");
    let mut data = fs::read(&index)?;
    data.pop();
    let damaged = temp.path().join("incomplete");
    fs::write(&damaged, data)?;
    let result = validate(&damaged)?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty() && !result.stderr.is_empty());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires systemd-socket-activate and the pinned Debian daemon"]
fn systemd_inherited_socket() -> io::Result<()> {
    for exe in ["/usr/sbin/clamd", BIN] {
        let temp = tempfile::tempdir_in("/tmp")?;
        let root = temp.path();
        let db = root.join("db");
        fs::create_dir(&db)?;
        write_rule(&db.join("fixture.hdb"), "Barnacle.Service")?;
        let config = root.join("service.conf");
        let socket = root.join("systemd.sock");
        let pidfile = root.join("pid");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nPidFile {}\nSelfCheck 0\n",
                db.display(),
                socket.display(),
                pidfile.display()
            ),
        )?;
        let mut activate = Command::new("systemd-socket-activate");
        activate
            .arg("--listen")
            .arg(&socket)
            .arg(exe)
            .arg("--foreground=true")
            .arg("--config-file")
            .arg(&config);
        let _daemon = Daemon::start_command(&mut activate, &config, &socket)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(DATA)?)?,
            "stream: Barnacle.Service.UNOFFICIAL FOUND\0"
        );
        assert_eq!(unix_request(&socket, b"zQUIT\0")?, "");
        wait_until(|| !pidfile.exists());
        assert!(socket.exists(), "the launcher owns the inherited socket");
    }
    Ok(())
}

#[test]
fn background_entry_point() -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let root = temp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    write_rule(&db.join("fixture.hdb"), "Barnacle.Service")?;
    let socket = root.join("socket");
    let config = root.join("background.conf");
    let pidfile = root.join("pid");
    fs::write(
        &config,
        format!(
            "DatabaseDirectory {}\nLocalSocket {}\nPidFile {}\nSelfCheck 0\n",
            db.display(),
            socket.display(),
            pidfile.display()
        ),
    )?;
    let mut parent = Command::new(BIN).arg("-c").arg(&config).spawn()?;
    struct Stop<'a>(&'a Path);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            let _ = unix_request(self.0, b"zSHUTDOWN\0");
        }
    }
    let _stop = Stop(&socket);
    let original = parent.id();
    assert!(parent.wait()?.success());
    wait_until(|| {
        pidfile.is_file() && unix_request(&socket, b"zPING\0").is_ok_and(|s| s == "PONG\0")
    });
    let serving: u32 = fs::read_to_string(&pidfile)?
        .trim()
        .parse()
        .map_err(io::Error::other)?;
    assert_ne!(serving, original);
    assert_eq!(unix_request(&socket, b"zQUIT\0")?, "");
    wait_until(|| !pidfile.exists() && !socket.exists());
    Ok(())
}
