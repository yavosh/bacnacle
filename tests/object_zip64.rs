//! Compare ZIP64 archives containing two benign members from independent writers.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const LEDGER: &[u8] = include_bytes!("fixtures/zip64/authored.zip");
const IMAGE: &[u8] = include_bytes!("fixtures/images/blue.png");
const CASES: &[(&str, &[u8], &str, bool)] = &[
    // Archive, bytes, first scanned member, and whether the image can match.
    ("libarchive", LEDGER, "Note", true),
    (
        "libarchive stored",
        include_bytes!("fixtures/zip64/stored.zip"),
        "Note",
        true,
    ),
    (
        "libarchive reversed",
        include_bytes!("fixtures/zip64/reversed.zip"),
        "Image",
        true,
    ),
    (
        "classic control",
        include_bytes!("fixtures/zip64/control.zip"),
        "Note",
        true,
    ),
    (
        "Perl stream",
        include_bytes!("fixtures/zip64/streamed.zip"),
        "",
        false,
    ),
    (
        "Apache Always",
        include_bytes!("fixtures/zip64/Always.zip"),
        "",
        false,
    ),
    (
        "Apache compatible",
        include_bytes!("fixtures/zip64/AlwaysWithCompatibility.zip"),
        "",
        false,
    ),
    (
        "Apache ZIP64 note",
        include_bytes!("fixtures/zip64/mixed-true.zip"),
        "Image",
        true,
    ),
    (
        "Apache ZIP64 image",
        include_bytes!("fixtures/zip64/mixed-false.zip"),
        "Note",
        false,
    ),
];
fn note() -> Vec<u8> {
    b"The warehouse received four folders.\n".repeat(256)
}
fn hdb(label: &str, b: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Zip64.{label}\n",
        barnacle::hash_reader(b)?.md5_hex(),
        b.len()
    ))
}
struct Server {
    _service: daemon::Daemon,
    dir: tempfile::TempDir,
    socket: PathBuf,
}
impl Server {
    fn start(stock: bool, rules: &str, option: &str) -> io::Result<Self> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        fs::write(db.join("local.hdb"), rules)?;
        let socket = dir.path().join("socket");
        let cfg = dir.path().join("conf");
        fs::write(
            &cfg,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\n{option}\n",
                db.display(),
                dir.path().display(),
                socket.display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let service = daemon::Daemon::start(Path::new(exe), &cfg, &socket)?;
        Ok(Self {
            _service: service,
            dir,
            socket,
        })
    }
    fn check(&self, label: &str, bytes: &[u8], name: &str, stock: bool) -> io::Result<()> {
        let want = match name {
            "" if stock => "stream: OK\0".into(),
            "" => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
            s if s.starts_with("Max") => format!("stream: Heuristics.Limits.Exceeded.{s} FOUND\0"),
            s => format!("stream: Zip64.{s}.UNOFFICIAL FOUND\0"),
        };
        assert_eq!(
            daemon::unix_request(&self.socket, &daemon::stream_frame(bytes)?)?,
            want,
            "{label}"
        );
        Ok(())
    }
}

fn compare(stock: bool) -> io::Result<()> {
    let note = note();
    let text = hdb("Note", &note)?;
    let image = hdb("Image", IMAGE)?;
    let members = text.clone() + &image;
    let mut outside = String::new();
    for &(_, bytes, _, _) in CASES {
        outside += &hdb("Outer", bytes)?;
    }
    let both = Server::start(stock, &(members.clone() + &outside), "")?;
    let later = Server::start(stock, &(image.clone() + &outside), "")?;
    let off = Server::start(stock, &(members.clone() + &outside), "ScanArchive no")?;
    let count = Server::start(stock, &members, "MaxFiles 2\nAlertExceedsMax yes")?;
    let blocked = Server::start(stock, &members, "MaxFiles 1\nAlertExceedsMax yes")?;
    for &(label, bytes, first, has_image) in CASES {
        both.check(
            label,
            bytes,
            if first.is_empty() { "Outer" } else { first },
            stock,
        )?;
        later.check(
            label,
            bytes,
            if has_image { "Image" } else { "Outer" },
            stock,
        )?;
        off.check(label, bytes, "Outer", stock)?;
        count.check(label, bytes, first, stock)?;
        blocked.check(
            label,
            bytes,
            if first.is_empty() { "" } else { "MaxFiles" },
            stock,
        )?;
    }
    let rules = members + &hdb("Clipped", &note[..8192])?;
    for (option, result) in [
        ("MaxFileSize 8191".into(), "Image"),
        ("MaxFileSize 8192".into(), "Clipped"),
        ("MaxRecursion 1".into(), "MaxRecursion"),
        (
            format!("MaxScanSize {}", LEDGER.len() + note.len() - 1),
            "MaxScanSize",
        ),
        (format!("MaxScanSize {}", LEDGER.len() + note.len()), "Note"),
    ] {
        Server::start(stock, &rules, &format!("{option}\nAlertExceedsMax yes"))?
            .check(&option, LEDGER, result, stock)?;
    }
    Ok(())
}

#[test]
fn authored_zip64_archives() -> io::Result<()> {
    compare(false)
}
#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_authored_zip64_archives() -> io::Result<()> {
    compare(true)
}

#[test]
fn zip64_member_names_and_parent() -> io::Result<()> {
    use barnacle::objects::{self, Options, Verdict};
    let dir = tempfile::tempdir()?;
    let note = note();
    let mut seen = Vec::new();
    objects::scan(
        LEDGER,
        &Options::default(),
        dir.path(),
        |obj, _| {
            if !obj.normalized && (obj.bytes == note || obj.bytes == IMAGE) {
                assert_eq!(obj.parents.len(), 1);
                assert_eq!(obj.parents[0].file_type, "CL_TYPE_ZIP");
                seen.push(obj.layer.name.as_deref().unwrap().to_vec());
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(seen, [b"receipt.txt".to_vec(), b"blue.png".to_vec()]);
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_zip64_metadata() -> io::Result<()> {
    let s = Server::start(
        true,
        &hdb("Unused", b"unrelated note")?,
        "GenerateMetadataJson yes\nLeaveTemporaryFiles yes",
    )?;
    s.check("metadata", LEDGER, "", true)?;
    let mut dirs = vec![s.dir.path().to_owned()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            } else if entry.file_name() == "metadata.json" {
                let value: serde_json::Value = serde_json::from_slice(&fs::read(entry.path())?)?;
                if value["FileType"] == "CL_TYPE_ZIP" {
                    let children = value["ContainedObjects"].as_array().unwrap();
                    assert_eq!(children[0]["FileName"], "receipt.txt");
                    assert_eq!(children[1]["FileName"], "blue.png");
                    assert_eq!(children[0]["FileSize"], note().len());
                    assert_eq!(children[1]["FileSize"], IMAGE.len());
                    return Ok(());
                }
            }
        }
    }
    panic!("missing stock ZIP metadata");
}

fn sentinel_archive(mask: u8, reverse_catalog: bool) -> Vec<u8> {
    let mut bytes = LEDGER.to_vec();
    let end = bytes.len() - 22;
    if reverse_catalog {
        let first = u32::from_le_bytes(bytes[end + 16..end + 20].try_into().unwrap()) as usize;
        let tail = end - 76;
        let second = first
            + 46
            + [28, 30, 32]
                .into_iter()
                .map(|n| {
                    u16::from_le_bytes(bytes[first + n..first + n + 2].try_into().unwrap()) as usize
                })
                .sum::<usize>();
        bytes[first..tail].rotate_left(second - first);
    }
    for (bit, from, to) in [(1, 8, 10), (2, 10, 12), (4, 12, 16), (8, 16, 20)] {
        if mask & bit != 0 {
            bytes[end + from..end + to].fill(0xff);
        }
    }
    bytes
}

fn compare_sentinels(stock: bool) -> io::Result<()> {
    let both = hdb("Note", &note())? + &hdb("Image", IMAGE)?;
    let by_order = Server::start(stock, &both, "")?;
    let later = Server::start(stock, &hdb("Image", IMAGE)?, "")?;
    let count = Server::start(stock, &both, "MaxFiles 2\nAlertExceedsMax yes")?;
    let blocked = Server::start(stock, &both, "MaxFiles 1\nAlertExceedsMax yes")?;
    let shallow = Server::start(stock, &both, "MaxRecursion 1\nAlertExceedsMax yes")?;
    for mask in 0..16 {
        for reverse_catalog in [false, true] {
            let archive = sentinel_archive(mask, reverse_catalog);
            let label =
                format!("classic sentinel fields {mask:04b}, reversed directory {reverse_catalog}");
            for (server, winner) in [
                (&by_order, "Note"),
                (&later, "Image"),
                (&count, "Note"),
                (&blocked, "MaxFiles"),
                (&shallow, "MaxRecursion"),
            ] {
                server.check(
                    &label,
                    &archive,
                    if mask & 8 == 0 { winner } else { "" },
                    stock,
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn zip64_directory_sentinels() -> io::Result<()> {
    compare_sentinels(false)
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_zip64_directory_sentinels() -> io::Result<()> {
    compare_sentinels(true)
}
