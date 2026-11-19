//! Compare the occurrence evidence consumed by a stock logical signature.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;

use barnacle::body::{BodyIndex, ObjectContext};
use barnacle::{IgnoreSet, PINNED_FLEVEL};
use std::fs;
use std::io;
use std::path::Path;

const PATTERN: &str = "4142??4445";

fn samples() -> Vec<(Vec<u8>, Vec<usize>)> {
    let mut samples = Vec::new();
    for offsets in [
        vec![],
        vec![13],
        vec![13, 32_766],
        vec![13, 131_070, 131_100],
    ] {
        let mut bytes = vec![b'x'; offsets.last().copied().unwrap_or(9) + 12];
        for &at in &offsets {
            bytes[at..at + 5].copy_from_slice(b"ABxDE");
        }
        samples.push((bytes, offsets));
    }
    samples
}

#[test]
fn occurrences_report_object_positions_once_across_windows() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tag.ndb");
    fs::write(&path, format!("Tag:0:*:{PATTERN}\n"))?;
    let idx = BodyIndex::load_sources(&[(&path, false)], PINNED_FLEVEL, &IgnoreSet::default())?;
    for (data, expected) in samples() {
        let mut positions = vec![];
        idx.scan(&data, &ObjectContext::raw(&data), |hit| {
            assert_eq!(idx.name(hit.rule_id), "Tag.UNOFFICIAL");
            assert_eq!(hit.end, hit.start + 5);
            positions.push(hit.start);
        })?;
        assert_eq!(positions, expected);
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_logical_signature_observes_the_same_counts() -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("database");
    fs::create_dir(&db)?;
    let rules: String = (1..=3)
        .map(|n| format!("Barnacle.Count{n};Target:0;0={n};{PATTERN}\n"))
        .collect();
    fs::write(db.join("counts.ldb"), rules)?;
    let socket = root.path().join("socket");
    let conf = root.path().join("clamd.conf");
    fs::write(
        &conf,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nSelfCheck 0\nDisableCache yes\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _daemon = client::Daemon::start(Path::new("/usr/sbin/clamd"), &conf, &socket)?;
    for (data, positions) in samples() {
        let n = positions.len();
        let expected = if n == 0 {
            "stream: OK\0".into()
        } else {
            format!("stream: Barnacle.Count{n}.UNOFFICIAL FOUND\0")
        };
        assert_eq!(
            client::unix_request(&socket, &client::stream_frame(&data)?)?,
            expected
        );
    }
    Ok(())
}
