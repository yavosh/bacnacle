//! Compare benign XAR heap members, XML and limits against the pinned daemon.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use daemon::{Daemon, stream_frame, unix_request};
use flate2::{Compression, write::ZlibEncoder};
use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const FIRST: &[u8] = b"an ordinary guide stored in the XAR heap";
const SECOND: &[u8] = b"ordinary notes in the second XAR member";
fn deflate(d: &[u8]) -> io::Result<Vec<u8>> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(d)?;
    z.finish()
}
fn build(toc: &str, heap: &[u8]) -> io::Result<Vec<u8>> {
    let z = deflate(toc.as_bytes())?;
    let mut out = b"xar!\0\x1c\0\x01".to_vec();
    out.extend((z.len() as u64).to_be_bytes());
    out.extend((toc.len() as u64).to_be_bytes());
    out.extend([0; 4]);
    out.extend(z);
    out.extend(heap);
    Ok(out)
}
fn extent(tag: &str, offset: usize, len: usize, size: usize, codec: &str) -> String {
    format!(
        "<{tag}><length>{len}</length><offset>{offset}</offset><size>{size}</size><encoding style=\"{codec}\"/></{tag}>"
    )
}
fn toc(subdocs: &str, properties: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n{subdocs}\n<toc><file id=\"1\"><name>notes.txt</name><type>file</type>{properties}</file></toc>\n</xar>\n"
    )
}
fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let plain = "application/octet-stream";
    let zlib = "application/x-gzip";
    let note = extent("data", 0, FIRST.len(), FIRST.len(), plain);
    let compressed = deflate(SECOND)?;
    let z = extent("data", 0, compressed.len(), SECOND.len(), zlib);
    let short_heap = [FIRST, SECOND].concat();
    let later = extent("data", FIRST.len(), SECOND.len(), SECOND.len(), plain);
    let ea = extent("ea", 0, FIRST.len(), FIRST.len(), plain);
    let doc = "<meta>ordinary subdocument</meta>";
    let packed_toc = toc("", &z);
    let packed = build(&packed_toc, &compressed)?;
    let hash_toc = toc("", &format!("<note>whole table marker</note>{note}"));
    let hash_outer = build(
        &toc("", &format!("<note>whole XAR marker</note>{note}")),
        FIRST,
    )?;
    let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    bz.write_all(SECOND)?;
    let bz = bz.finish()?;
    let sub = toc(
        &format!("<subdoc subdoc_name=\"extra\">{doc}</subdoc>"),
        &note,
    );
    let options = lzma_rust2::LzmaOptions {
        dict_size: 8192,
        ..Default::default()
    };
    let mut lz =
        lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &options, Some(SECOND.len() as u64))?;
    lz.write_all(SECOND)?;
    let lz = lz.finish()?;
    let mut xz = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))?;
    xz.write_all(SECOND)?;
    let xz = xz.finish()?;
    let canonical = "<metadata id=\"x\"><empty/></metadata>";
    let mut rules = String::new();
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("Toc", hash_toc.as_bytes()),
        ("Outer", &hash_outer),
        ("Subdoc", doc.as_bytes()),
        ("BzipWrapper", &bz),
        ("Canonical", canonical.as_bytes()),
    ] {
        let digest: String = Md5::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        rules.push_str(&format!("{digest}:{}:Xar.{name}\n", data.len()));
    }
    fs::write(db.join("local.hdb"), rules)?;
    let start = |id: &str, opts: &str| -> io::Result<_> {
        let conf = root.join(format!("{id}.conf"));
        let socket = root.join(format!("{id}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\n{opts}\n",
                db.display(),
                root.display(),
                socket.display()
            ),
        )?;
        Ok((Daemon::start(exe, &conf, &socket)?, socket))
    };
    let check = |socket: &Path, label: &str, bytes: &[u8], name: Option<&str>| -> io::Result<()> {
        let expected = match name {
            Some(s) if s.starts_with("Heuristics.") => format!("stream: {s} FOUND\0"),
            Some(s) => format!("stream: Xar.{s}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        let actual = unix_request(socket, &stream_frame(bytes)?)?;
        assert_eq!(actual, expected, "{label}");
        Ok(())
    };
    let (daemon, sock) = start("default", "")?;
    let checked = note.replace("</data>","<archived-checksum style=\"md5\">00000000000000000000000000000000</archived-checksum></data>");
    let separated = toc("<subdoc>harmless notes</subdoc>", &note);
    let canonical_subdoc = toc(
        "<subdoc><metadata id='x'><empty></empty></metadata></subdoc>",
        &note,
    );
    let bad_member = [b"ordinary invalid compressed data".as_slice(), FIRST].concat();
    let bad_len = bad_member.len() - FIRST.len();
    let mixed = toc(
        "",
        &format!(
            "{}{}",
            extent("data", 0, bad_len, 48, zlib),
            extent("data", bad_len, FIRST.len(), FIRST.len(), plain)
        ),
    );
    let mut long_toc = toc("", &note);
    long_toc = long_toc.replace(
        "<file id",
        &format!("<!--{}--><file id", "ordinary text ".repeat(100)),
    );
    let over_catalog = build(&long_toc, FIRST)?;
    let larger = b"ordinary long document section ".repeat(200);
    let zlarge = deflate(&larger)?;
    let over_member = build(
        &toc("", &extent("data", 0, zlarge.len(), larger.len(), zlib)),
        &zlarge,
    )?;
    let valid_toc = toc(
        "",
        &format!(
            "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>{}",
            extent("data", 20, FIRST.len(), FIRST.len(), plain)
        ),
    );
    let mut valid = build(&valid_toc, &[])?;
    valid[24..28].copy_from_slice(&1u32.to_be_bytes());
    let sum = sha1::Sha1::digest(&valid[28..]);
    valid.extend_from_slice(&sum);
    valid.extend_from_slice(FIRST);
    let nested_zip = zip::zip(&[("plain.xar", &packed)], true, false, false)?;
    let heap = |bytes: &[u8], size, codec| {
        build(
            &toc("", &extent("data", 0, bytes.len(), size, codec)),
            bytes,
        )
    };
    let cases = [
        ("checksummed archive", valid, Some("First")),
        (
            "damaged member before good extent",
            build(&mixed, &bad_member)?,
            Some("First"),
        ),
        ("stored", build(&toc("", &note), FIRST)?, Some("First")),
        ("deflated", packed.clone(), Some("Second")),
        ("whole table wins", build(&hash_toc, FIRST)?, Some("Toc")),
        ("child beats outer", hash_outer.clone(), Some("First")),
        ("subdoc first", build(&sub, FIRST)?, Some("Subdoc")),
        (
            "subdoc serialization",
            build(&canonical_subdoc, FIRST)?,
            Some("Canonical"),
        ),
        (
            "subdoc preceding heap",
            build(&separated, FIRST)?,
            Some("First"),
        ),
        (
            "adjacent subdoc and toc",
            build(
                &separated.replace("</subdoc>\n<toc>", "</subdoc><toc>"),
                FIRST,
            )?,
            None,
        ),
        (
            "EA before data",
            build(&toc("", &format!("{ea}{later}")), &short_heap)?,
            Some("First"),
        ),
        (
            "table order vs offset",
            build(&toc("", &format!("{later}{note}")), &short_heap)?,
            Some("Second"),
        ),
        (
            "wrong checksum",
            build(&toc("", &checked), FIRST)?,
            Some("First"),
        ),
        (
            "bzip wrapper",
            heap(&bz, SECOND.len(), "application/x-bzip2")?,
            Some("Second"),
        ),
        (
            "XZ wrapper",
            heap(&xz, SECOND.len(), "application/x-xz")?,
            Some("Second"),
        ),
        (
            "LZMA direct decode",
            heap(&lz, SECOND.len(), "application/x-lzma")?,
            Some("Second"),
        ),
        (
            "unknown encoding",
            heap(FIRST, FIRST.len(), "text/plain")?,
            Some("First"),
        ),
        (
            "truncated heap",
            build(
                &toc(
                    "",
                    &extent("data", FIRST.len(), SECOND.len() + 20, SECOND.len(), plain),
                ),
                &short_heap,
            )?,
            Some("Second"),
        ),
        ("ZIP containing XAR", nested_zip, Some("Second")),
        ("short header", b"xar!ordinary".to_vec(), None),
        ("truncated TOC", packed[..40].to_vec(), None),
        (
            "truncated XML",
            build(&packed_toc[..packed_toc.len() - 12], &compressed)?,
            Some("Second"),
        ),
    ];
    for (label, file, expected) in cases {
        check(&sock, label, &file, expected)?;
    }
    drop(daemon);
    for (id, config, bytes, name) in [
        (
            "disabled",
            "ScanArchive no".to_string(),
            &hash_outer,
            Some("Outer"),
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes".into(),
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "count",
            "MaxFiles 2\nAlertExceedsMax yes".into(),
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            "byte",
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                packed.len() + packed_toc.len() + 7
            ),
            &packed,
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            "catalog-size",
            "MaxFileSize 512\nAlertExceedsMax yes".into(),
            &over_catalog,
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
        (
            "catalog-no-alert",
            "MaxFileSize 512\nAlertExceedsMax no".into(),
            &over_catalog,
            None,
        ),
        (
            "expanded-size",
            "MaxFileSize 512\nAlertExceedsMax yes".into(),
            &over_member,
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
    ] {
        let (_service, sock) = start(id, &config)?;
        check(&sock, id, bytes, name)?;
    }
    Ok(())
}
#[test]
fn barnacle_xar_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_xar_objects() -> io::Result<()> {
    let pkg = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pkg.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn catalog_and_extent_receive_fresh_unnamed_contexts() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    let catalog = toc(
        "",
        &extent(
            "data",
            0,
            FIRST.len(),
            FIRST.len(),
            "application/octet-stream",
        ),
    );
    let xar = build(&catalog, FIRST)?;
    let archive = zip::zip(&[("ordinary.xar", &xar)], true, false, false)?;
    let mut objects = Vec::new();
    scan(
        &archive,
        &Options::default(),
        tmp.path(),
        |object, _| {
            if !object.normalized && (object.bytes == catalog.as_bytes() || object.bytes == FIRST) {
                assert_eq!(
                    object
                        .parents
                        .iter()
                        .map(|e| e.file_type)
                        .collect::<Vec<_>>(),
                    ["CL_TYPE_ZIP", "CL_TYPE_XAR"]
                );
                assert_eq!(
                    object.parents[1].name.as_deref(),
                    Some(b"ordinary.xar".as_slice())
                );
                assert!(object.layer.name.is_none());
                objects.push(object.bytes == FIRST);
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(objects, [false, true]);
    Ok(())
}
