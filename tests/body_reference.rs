//! The same harmless files and NDB records run on Barnacle and the pinned Debian daemon.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/pe.rs"]
mod pe;

use client::{Daemon, stream_frame, unix_request};
use md5::{Digest, Md5};
use std::fs;
use std::io;
use std::path::Path;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let root = temp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let rules = [
        ("Exact", 0, "*", hex(b"BarnacleExact")),
        ("Floating", 0, "3,2", hex(b"OnlyHere")),
        ("End", 0, "EOF-7", hex(b"EndMark")),
        (
            "Masked",
            0,
            "*",
            format!("{}4??242{}", hex(b"Nibble"), hex(b"Tail")),
        ),
        (
            "Alt",
            0,
            "*",
            format!("{}(4142|434445){}", hex(b"Choose"), hex(b"Done")),
        ),
        (
            "Gap",
            0,
            "*",
            format!("{}{{2-4}}{}", hex(b"PartOne"), hex(b"PartTwo")),
        ),
        (
            "Star",
            0,
            "*",
            format!("{}*{}", hex(b"FirstMarker"), hex(b"LastMarker")),
        ),
        (
            "ShortRange",
            0,
            "*",
            format!("5a[1-3]{}", hex(b"RightFlank")),
        ),
        ("Boundary", 0, "*", hex(b"AcrossTheReadBoundary")),
        (
            "WideGap",
            0,
            "*",
            format!("{}{{40-}}{}", hex(b"WideStart"), hex(b"WideFinish")),
        ),
        ("Section", 1, "S0+24", hex(b"SectionMarker")),
        ("Suppressed", 0, "*", hex(b"IgnoredMarker")),
    ];
    let mut ndb = String::new();
    for (name, target, offset, pattern) in rules {
        ndb.push_str(&format!("Barnacle.{name}:{target}:{offset}:{pattern}\n"));
    }
    fs::write(db.join("rules.ndb"), ndb)?;
    fs::write(db.join("rules.ign2"), "Barnacle.Suppressed\n")?;
    let mixed = b"ordinary BarnacleExact record";
    fs::write(
        db.join("rules.hdb"),
        format!(
            "{}:{}:Barnacle.Whole\n",
            hex(&Md5::digest(mixed)),
            mixed.len()
        ),
    )?;
    let config = root.join("clamd.conf");
    let socket = root.join("socket");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n",
            db.display(),
            root.display(),
            socket.display()
        ),
    )?;
    let _daemon = Daemon::start(exe, &config, &socket)?;
    let mut boundary = vec![b'x'; 32 * 1024 - 7];
    boundary.extend_from_slice(b"AcrossTheReadBoundary");
    let mut wide = b"WideStart".to_vec();
    wide.extend(std::iter::repeat_n(b'X', 100_000));
    wide.extend_from_slice(b"WideFinish");
    let mut image = pe::benign_pe();
    image[536..549].copy_from_slice(b"SectionMarker");
    let cases: &[(&[u8], Option<&str>)] = &[
        (mixed, Some("Exact")),
        (b"000OnlyHere", Some("Floating")),
        (b"00000OnlyHere", Some("Floating")),
        (b"00OnlyHere", None),
        (b"000000OnlyHere", None),
        (b"before-EndMark", Some("End")),
        (b"before-EndMark!", None),
        (b"ordinary NibbleAbBTail", Some("Masked")),
        (b"ordinary ChooseABDone", Some("Alt")),
        (b"ordinary ChooseCDEDone", Some("Alt")),
        (b"ordinary PartOne===PartTwo", Some("Gap")),
        (b"ordinary PartOne=====PartTwo", None),
        (b"normal FirstMarker and then LastMarker", Some("Star")),
        (b"normal ZQQRightFlank", Some("ShortRange")),
        (&boundary, Some("Boundary")),
        (&wide, Some("WideGap")),
        (&image, Some("Section")),
        (b"SectionMarker only in an ordinary text object", None),
        (b"ordinary IgnoredMarker", None),
    ];
    for (i, &(bytes, name)) in cases.iter().enumerate() {
        let expected = match name {
            Some(name) => format!("stream: Barnacle.{name}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(
            unix_request(&socket, &stream_frame(bytes)?)?,
            expected,
            "fixture {i}"
        );
    }
    Ok(())
}

#[test]
fn body_patterns_in_daemon() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_body_patterns() -> io::Result<()> {
    compare(Path::new("/usr/sbin/clamd"), true)
}
