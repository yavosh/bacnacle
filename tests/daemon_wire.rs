#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use client::{Daemon, stream_frame, unix_request};
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

#[test]
fn directories_session_and_skipped_objects() -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path().canonicalize()?;
    let socket = root.join("socket");
    let scratch = root.join("scratch");
    fs::create_dir(&scratch)?;
    let db = root.join("db");
    let tree = root.join("objects");
    fs::create_dir(&db)?;
    fs::create_dir(&tree)?;
    let data = b"abcdefgh";
    fs::write(
        db.join("fixture.hdb"),
        "e8dc4081b13434b45189a720b77b6818:8:Fixture\n",
    )?;
    let hit = tree.join("hit");
    fs::write(&hit, data)?;
    let second = tree.join("second");
    fs::write(&second, data)?;
    let skip = tree.join("omit-path");
    fs::write(&skip, data)?;
    let link = tree.join("link");
    symlink(&hit, &link)?;
    let deep = tree.join("one/two");
    fs::create_dir_all(&deep)?;
    fs::write(deep.join("deep-hit"), data)?;
    let config = root.join("clamd.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nTemporaryDirectory {}\nSelfCheck 0\nMaxThreads 4\nMaxQueue 4\nMaxDirectoryRecursion 1\nExcludePath omit-path$\n",
            socket.display(),
            db.display(),
            scratch.display()
        ),
    )?;
    let _daemon = Daemon::start(Path::new(env!("CARGO_BIN_EXE_barnacle")), &config, &socket)?;
    let ordered = root.join("ordered");
    fs::create_dir_all(ordered.join("00-subdirectory"))?;
    fs::write(ordered.join("00-subdirectory/nested-hit"), data)?;
    let early = ordered.join("99-earlier-inode");
    let late = ordered.join("01-later-inode");
    fs::write(&early, data)?;
    fs::write(&late, data)?;
    use std::os::unix::fs::MetadataExt;
    let first = if early.metadata()?.ino() < late.metadata()?.ino() {
        early
    } else {
        late
    };
    assert_eq!(
        unix_request(&socket, format!("zSCAN {}\0", ordered.display()).as_bytes())?,
        format!("{}: Fixture.UNOFFICIAL FOUND\0", first.display())
    );
    for (frame, expected) in [
        (&b"zFILDES\0\0"[..], "No file descriptor received. ERROR\0"),
        (&b"nFILDES\nx"[..], "No file descriptor received. ERROR\n"),
        (
            &b"zIDSESSION\0zFILDES\0\0"[..],
            "1: No file descriptor received. ERROR\0",
        ),
    ] {
        assert_eq!(unix_request(&socket, frame)?, expected);
    }
    let mut incomplete = std::os::unix::net::UnixStream::connect(&socket)?;
    std::io::Write::write_all(&mut incomplete, b"zFILDES\0")?;
    incomplete.shutdown(std::net::Shutdown::Write)?;
    let mut result = Vec::new();
    std::io::Read::read_to_end(&mut incomplete, &mut result)?;
    assert!(result.is_empty());
    for cmd in ["CONTSCAN", "MULTISCAN"] {
        let frames = unix_request(&socket, format!("z{cmd} {}\0", tree.display()).as_bytes())?;
        let mut actual = frames
            .split_terminator('\0')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut expected = vec![
            format!("{}: Fixture.UNOFFICIAL FOUND", hit.display()),
            format!("{}: Fixture.UNOFFICIAL FOUND", second.display()),
            format!("{}: Excluded. ERROR", skip.display()),
            format!("{}: Excluded (symbolic link). ERROR", link.display()),
            format!(
                "{}: Directory recursion limit or cycle. ERROR",
                deep.display()
            ),
        ];
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected, "{cmd}");
    }
    let mut commands = b"zIDSESSION\0".to_vec();
    let mut expected = Vec::new();
    for i in 1..=24 {
        match i % 3 {
            0 => {
                commands.extend_from_slice(b"zPING\0");
                expected.push(format!("{i}: PONG"));
            }
            1 => {
                commands.extend(format!("zSCAN {}\0", hit.display()).bytes());
                expected.push(format!("{i}: {}: Fixture.UNOFFICIAL FOUND", hit.display()));
            }
            _ => {
                commands.extend(stream_frame(data)?);
                expected.push(format!("{i}: stream: Fixture.UNOFFICIAL FOUND"));
            }
        }
    }
    commands.extend_from_slice(b"zEND\0");
    let frames = unix_request(&socket, &commands)?;
    let mut actual = frames
        .split_terminator('\0')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
    let large = root.join("large");
    fs::create_dir(&large)?;
    for index in 0..2050 {
        fs::hard_link(&hit, large.join(index.to_string()))?;
    }
    let first = large.read_dir()?.next().unwrap()?.path();
    let scan = format!("zSCAN {}\0", large.display());
    assert_eq!(
        unix_request(&socket, scan.as_bytes())?,
        format!("{}: Fixture.UNOFFICIAL FOUND\0", first.display())
    );
    // A regular file at TemporaryDirectory makes spilling fail, even when
    // tests run as root. The running daemon already owns its active index.
    fs::rename(&scratch, root.join("previous-scratch"))?;
    fs::write(&scratch, b"unavailable directory")?;
    let failure = unix_request(&socket, scan.as_bytes())?;
    assert!(failure.contains("directory sort failed"));
    assert!(failure.ends_with(". ERROR\0"));
    assert_eq!(failure.matches('\0').count(), 1);
    Ok(())
}
