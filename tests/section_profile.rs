//! Check the section-table experiment's fixture against the stock PE parser and both index backends.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "../examples/section_prepare/fields.rs"]
mod fields;

use barnacle::{
    Feed, PINNED_FLEVEL, hash_reader,
    index::{self, Index},
};
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

const DIGEST: &str = "f7ee145f039055a238206abf1e95355f";
const WINNER: &str = "Barnacle.Section.Third.UNOFFICIAL";

fn rules() -> String {
    ["First", "Second", "Third"]
        .iter()
        .map(|name| format!("512:{DIGEST}:Barnacle.Section.{name}\n"))
        .collect()
}

#[path = "common/pe.rs"]
mod pe;
use pe::benign_pe;

#[test]
fn compact_section_tables_match_the_stock_winner() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let mut normalized = Vec::new();
    for rule in rules().split_inclusive('\n') {
        fields::transpose(rule, &mut normalized)?;
    }
    let source = tmp.path().join("section.hsb");
    fs::write(&source, normalized)?;
    let mut feed = Feed::load(&[source], false, PINNED_FLEVEL)?;
    assert_eq!(feed.duplicate_keys, 2);
    let table = tmp.path().join("section.bhi");
    index::build(&table, &mut feed.rules)?;
    let image = benign_pe();
    // SAFETY: the builder's inode stays immutable in this private directory until both indexes close.
    for index in [Index::open_memory(&table)?, unsafe {
        Index::open_mapped(&table)?
    }] {
        let lookup = |bytes: &[u8]| hash_reader(bytes)?.lookup(|a, d, s| index.lookup(a, d, s));
        assert_eq!(lookup(&image[512..])?.as_deref(), Some(WINNER));
        assert_eq!(lookup(&image)?, None);
    }
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd 1.4.3+dfsg-1"]
fn live_clamd_finds_the_signature_only_in_the_pe_section() -> io::Result<()> {
    let package = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert!(package.status.success());
    assert_eq!(package.stdout, b"1.4.3+dfsg-1");
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    fs::write(db.join("fixture.mdb"), rules())?;
    let socket = root.path().join("socket");
    let config = root.path().join("clamd.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _daemon = daemon::Daemon::start(Path::new("/usr/sbin/clamd"), &config, &socket)?;
    let image = benign_pe();
    assert_eq!(
        daemon::unix_request(&socket, &daemon::stream_frame(&image)?)?,
        format!("stream: {WINNER} FOUND\0")
    );
    assert_eq!(
        daemon::unix_request(&socket, &daemon::stream_frame(&image[512..])?)?,
        "stream: OK\0"
    );
    Ok(())
}
