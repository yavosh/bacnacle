//! Exercise body-only precedence across targets, matcher algorithms and scan windows.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
#[path = "common/pe.rs"]
mod pe;

use barnacle::body::{BodyIndex, BodyMatch, ObjectContext};
use barnacle::{IgnoreSet, PINNED_FLEVEL};
use client::{Daemon, stream_frame, unix_request};
use std::fs;
use std::io;
use std::path::Path;

const RULES: &str = concat!(
    "Scan.Early:0:*:45524c59??3031\n",
    "Scan.Late:0:*:4c415445\n",
    "Scan.Three1:0:*:717172\n",
    "Scan.Three2:0:*:717172\n",
    "Scan.Long1:0:*:53616d654c69746572616c\n",
    "Scan.Long2:0:*:53616d654c69746572616c\n",
    "Scan.Target:1:*:54797065644d61726b\n",
    "Scan.Generic:0:*:47656e657269634d61726b\n",
    "Scan.AC1:0:*:555657??3132\n",
    "Scan.AC2:0:*:555657??3132\n",
    "Scan.Unique:0:*:4d4e4f??4142\n",
    "Scan.Group1:0:*:4d4e4f??41??\n",
    "Scan.Group2:0:*:4d4e4f??41??\n",
    "Scan.Deferred:0:*:5061645374617274*7a7a7a7a\n",
    "Scan.Single:0:*:61616161\n",
);

fn cases() -> Vec<(Vec<u8>, &'static str)> {
    let mut cross = b"ERLYX01 ".to_vec();
    cross.resize(131_072 + 31, b' ');
    cross.extend_from_slice(b"LATE");
    let mut deferred = b"PadStart".to_vec();
    deferred.resize(131_072 + 32, b' ');
    deferred.extend_from_slice(b"zzzz");
    let mut image = pe::benign_pe();
    image[520..531].copy_from_slice(b"GenericMark");
    image[600..609].copy_from_slice(b"TypedMark");
    vec![
        (b"an ERLYX01 and a LATE match".to_vec(), "Scan.Late"),
        (cross, "Scan.Early"),
        (b"contains qqr here".to_vec(), "Scan.Three2"),
        (b"contains SameLiteral here".to_vec(), "Scan.Long1"),
        (image, "Scan.Target"),
        (b"contains UVWQ12 here".to_vec(), "Scan.AC1"),
        (b"contains MNO#AB here".to_vec(), "Scan.Group1"),
        (b"PadStart zzzz".to_vec(), "Scan.Deferred"),
        (deferred, "Scan.Deferred"),
    ]
}

fn index(dir: &Path) -> io::Result<BodyIndex> {
    let file = dir.join("content.ndb");
    fs::write(&file, RULES)?;
    BodyIndex::load_sources(&[(&file, false)], PINNED_FLEVEL, &IgnoreSet::default())
}

#[test]
fn static_prefix_ties_and_target_priority() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let index = index(dir.path())?;
    for (bytes, expected) in cases() {
        assert_eq!(
            index.first_match(&bytes, &ObjectContext::raw(&bytes))?,
            Some(format!("{expected}.UNOFFICIAL").as_str())
        );
    }
    Ok(())
}

#[test]
fn overlapping_positions_appear_once_when_the_reference_windows_overlap() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let index = index(dir.path())?;
    let mut input = vec![0; 131_072 + 7];
    input[131_067..131_074].copy_from_slice(b"aaaaaaa");
    let mut positions = Vec::new();
    index.scan(
        &input,
        &ObjectContext::raw(&input),
        |BodyMatch {
             rule_id,
             start,
             end,
         }| {
            if index.name(rule_id) == "Scan.Single.UNOFFICIAL" {
                positions.push((start, end));
            }
        },
    )?;
    positions.sort_unstable();
    assert_eq!(
        positions,
        [
            (131067, 131071),
            (131068, 131072),
            (131069, 131073),
            (131070, 131074)
        ]
    );
    Ok(())
}

#[test]
fn malformed_active_rule_reports_its_source_line() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("fixtures.ndb");
    fs::write(&path, "Future:0:*:oops:999\nInvalid:0:*:oops\n")?;
    let error = BodyIndex::load_sources(&[(&path, false)], PINNED_FLEVEL, &IgnoreSet::default())
        .err()
        .expect("active invalid rule should fail");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("fixtures.ndb:2:"));
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn compare_real_daemon_winners() -> io::Result<()> {
    let dir = tempfile::tempdir_in("/tmp")?;
    let root = dir.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let index = index(&db)?;
    let config = root.join("clamd.conf");
    let sock = root.join("socket");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _daemon = Daemon::start(Path::new("/usr/sbin/clamd"), &config, &sock)?;
    for (bytes, _) in cases() {
        let winner = index
            .first_match(&bytes, &ObjectContext::raw(&bytes))?
            .unwrap();
        assert_eq!(
            unix_request(&sock, &stream_frame(&bytes)?)?,
            format!("stream: {winner} FOUND\0")
        );
    }
    Ok(())
}
