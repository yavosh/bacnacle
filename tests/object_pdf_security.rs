//! Compare qpdf standard-security attachments with pinned Debian clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod client;
use client::{Daemon, stream_frame, unix_request};
use std::{fs, io, path::Path};

const NOTE: &[u8] = b"Quarterly statement from accounting.";
const DISPATCH: &[u8] = b"Dispatch note for seven boxes of stationery.\n";
const FILES: &[(&str, &[u8])] = &[
    ("plain", include_bytes!("fixtures/pdf/open/ordinary.pdf")),
    ("r4", include_bytes!("fixtures/pdf/open/r4.pdf")),
    ("r5", include_bytes!("fixtures/pdf/open/r5.pdf")),
    ("r6", include_bytes!("fixtures/pdf/open/r6.pdf")),
];

fn shipment_table() -> String {
    use std::fmt::Write;
    let mut text = String::from("Shipment,BoxCount,Receipt\n");
    let mut state = 1_285_u32;
    for row in 0..13_000 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        writeln!(text, "{row},{},{state:08X}", 1 + state % 100).unwrap();
    }
    text
}

fn hash(data: &[u8], name: &str) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Pdf.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}

fn check(exe: &Path, stock: bool) -> io::Result<()> {
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let check = |bytes: &[u8],
                 rules: &str,
                 logical: &str,
                 extra: &str,
                 want: &str|
     -> io::Result<()> {
        fs::write(db.join("stock.hdb"), rules)?;
        if !logical.is_empty() {
            fs::write(db.join("context.ldb"), logical)?;
        }
        let config = root.path().join("conf");
        let sock = root.path().join("s");
        fs::write(
            &config,
            format!(
                "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n{extra}\n",
                db.display(),
                sock.display()
            ),
        )?;
        let daemon = Daemon::start(exe, &config, &sock)?;
        let reply = unix_request(&sock, &stream_frame(bytes)?)?;
        drop(daemon);
        if !logical.is_empty() {
            fs::remove_file(db.join("context.ldb"))?;
        }
        let expected = if want == "Miss" {
            if stock {
                "stream: OK\0".into()
            } else {
                "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into()
            }
        } else if want.starts_with("Heuristics.") {
            format!("stream: {want} FOUND\0")
        } else {
            format!("stream: Pdf.{want}.UNOFFICIAL FOUND\0")
        };
        assert_eq!(reply, expected, "{extra}, {want}, {} bytes", bytes.len());
        Ok(())
    };
    let note = hash(NOTE, "Note")?;
    let unrelated = hash(b"Unrelated stationery", "Other")?;
    let sig = NOTE.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let parent = format!("Pdf.Parent;Engine:81-255,Target:0,Container:CL_TYPE_PDF;0;{sig}\n");
    for &(_, bytes) in FILES {
        check(bytes, &note, "", "", "Note")?;
        check(
            bytes,
            &(note.clone() + &hash(bytes, "Outer")?),
            "",
            "",
            "Outer",
        )?;
        if stock {
            check(bytes, &unrelated, &parent, "", "Parent")?;
        }
        check(bytes, &note, "", "ScanPDF no", "Miss")?;
        check(
            bytes,
            &note,
            "",
            "MaxRecursion 1\nAlertExceedsMax yes",
            "Heuristics.Limits.Exceeded.MaxRecursion",
        )?;
        check(
            bytes,
            &note,
            "",
            "MaxFiles 1\nAlertExceedsMax yes",
            "Heuristics.Limits.Exceeded.MaxFiles",
        )?;
        check(
            bytes,
            &note,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                bytes.len() + NOTE.len()
            ),
            "Note",
        )?;
        check(
            bytes,
            &note,
            "",
            &format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                bytes.len() + NOTE.len() - 1
            ),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        )?;
    }
    let two = include_bytes!("fixtures/pdf/open/two.pdf");
    check(
        two,
        &(note.clone() + &hash(DISPATCH, "Dispatch")?),
        "",
        "",
        "Dispatch",
    )?;
    check(two, &note, "", "", "Note")?;
    let stored = include_bytes!("fixtures/pdf/open/stored.pdf");
    let at = memchr::memmem::find(stored, b"stream\n").unwrap() + 7;
    let cipher = &stored[at..at + 64];
    let stored_rule = hash(cipher, "Stored")?;
    check(stored, &note, "", "", "Miss")?;
    check(stored, &(stored_rule.clone() + &note), "", "", "Stored")?;
    check(
        stored,
        &stored_rule,
        "",
        &format!("MaxScanSize {}\nAlertExceedsMax yes", stored.len() + 64),
        "Stored",
    )?;
    check(
        stored,
        &stored_rule,
        "",
        &format!("MaxScanSize {}\nAlertExceedsMax yes", stored.len() + 63),
        "Heuristics.Limits.Exceeded.MaxScanSize",
    )?;
    let manifest = include_bytes!("fixtures/pdf/open/manifest.pdf");
    let table = b"shipment,quantity\n1024,12\n1025,16\n";
    let start = memchr::memmem::find(manifest, b"stream\n").unwrap() + 7;
    let size = memchr::memmem::find(&manifest[start..], b"endstream").unwrap() / 16 * 16;
    let cipher_rule = hash(&manifest[start..start + size], "ManifestCipher")?;
    check(manifest, &hash(table, "Table")?, "", "", "Miss")?;
    check(
        manifest,
        &(hash(table, "Table")? + &cipher_rule),
        "",
        "",
        "ManifestCipher",
    )?;
    let mime = include_bytes!("fixtures/pdf/open/mime.pdf");
    check(mime, &note, "", "", "Note")?;
    check(mime, &(hash(mime, "Outer")? + &note), "", "", "Outer")?;
    let shipments = include_bytes!("fixtures/pdf/open/shipments.pdf");
    let table = shipment_table();
    let rows = hash(table.as_bytes(), "Shipments")?;
    check(shipments, &rows, "", "", "Shipments")?;
    check(
        shipments,
        &(rows.clone() + &hash(shipments, "Outer")?),
        "",
        "",
        "Outer",
    )?;
    check(
        shipments,
        &rows,
        "",
        &format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            shipments.len() + table.len()
        ),
        "Shipments",
    )?;
    check(
        shipments,
        &rows,
        "",
        &format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            shipments.len() + table.len() - 1
        ),
        "Heuristics.Limits.Exceeded.MaxScanSize",
    )?;
    check(
        shipments,
        &rows,
        "",
        "MaxFiles 1\nAlertExceedsMax yes",
        "Heuristics.Limits.Exceeded.MaxFiles",
    )?;
    let restricted = include_bytes!("fixtures/pdf/open/restricted.pdf");
    check(
        restricted,
        &note,
        "",
        "",
        if stock { "Note" } else { "Miss" },
    )?;
    let locked = include_bytes!("fixtures/pdf/open/locked.pdf");
    check(locked, &note, "", "", "Miss")?;
    check(locked, &(note + &hash(locked, "Outer")?), "", "", "Outer")?;
    Ok(())
}
#[test]
fn openable_pdf_streams() -> io::Result<()> {
    check(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}
#[test]
fn decrypted_attachment_metadata() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for &(_, bytes) in FILES {
        let mut count = 0;
        scan(
            bytes,
            &Options::default(),
            tmp.path(),
            |object, _| {
                if object.bytes == NOTE && !object.normalized {
                    assert_eq!(
                        object.parents.last().map(|p| p.file_type),
                        Some("CL_TYPE_PDF")
                    );
                    assert_eq!(object.layer.file_type, "CL_TYPE_TEXT_ASCII");
                    assert!(object.layer.name.is_none());
                    count += 1;
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(count, 1);
    }
    Ok(())
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_openable_pdf_streams() -> io::Result<()> {
    check(Path::new("/usr/sbin/clamd"), true)
}

#[test]
fn denied_large_attachment_counts_without_creating_scratch() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    let bytes = include_bytes!("fixtures/pdf/open/shipments.pdf");
    let denied = Options {
        max_files: 1,
        alert_exceeds_max: true,
        ..Options::default()
    };
    let result = scan(
        bytes,
        &denied,
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )?;
    assert_eq!(
        result,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxFiles".into())
    );
    let error = scan(
        bytes,
        &Options::default(),
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    Ok(())
}
