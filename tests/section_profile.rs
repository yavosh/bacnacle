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

fn benign_pe() -> Vec<u8> {
    // A PE32 header and one read-only, non-executable .data section. The image has no entry point.
    let mut image = vec![0u8; 1024];
    image[..2].copy_from_slice(b"MZ");
    image[60] = 128;
    image[128..132].copy_from_slice(b"PE\0\0");
    let coff = &mut image[132..152];
    coff[..2].copy_from_slice(&0x014cu16.to_le_bytes());
    coff[2] = 1; // sections
    coff[16] = 224; // size of optional header
    coff[18] = 2; // image
    let optional = &mut image[152..376];
    optional[..2].copy_from_slice(&0x010bu16.to_le_bytes());
    for (offset, value) in [
        (8, 512u32),
        (28, 0x00400000),
        (32, 4096),
        (36, 512),
        (56, 8192),
        (60, 512),
        (92, 16),
    ] {
        optional[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    optional[68] = 3; // console subsystem
    let section = &mut image[376..416];
    section[..5].copy_from_slice(b".data");
    for (offset, value) in [
        (8, 512u32),
        (12, 4096),
        (16, 512),
        (20, 512),
        (36, 0x40000040),
    ] {
        section[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in image[512..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    image
}

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
