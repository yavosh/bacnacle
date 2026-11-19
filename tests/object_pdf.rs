//! Compare the order and bytes of benign PDF objects with the pinned daemon.
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

const FIRST: &[u8] = b"ordinary first PDF document stream";
const SECOND: &[u8] = b"an ordinary second PDF attachment";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn deflate(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
    z.write_all(data)?;
    z.finish()
}

fn ascii85(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut padded = [0; 4];
        padded[..chunk.len()].copy_from_slice(chunk);
        let mut value = u32::from_be_bytes(padded);
        let mut digits = [0; 5];
        for digit in digits.iter_mut().rev() {
            *digit = b'!' + (value % 85) as u8;
            value /= 85;
        }
        out.extend_from_slice(&digits[..chunk.len() + 1]);
    }
    out.extend_from_slice(b"~>");
    out
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} {dict} >>\nstream\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    out
}

// Use a real indirect-object table, xref, trailer and byte offsets.
fn pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.5\n".to_vec();
    let mut offsets = vec![];
    for (i, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        writeln!(out, "{} 0 obj", i + 1).unwrap();
        out.extend_from_slice(object);
        out.extend_from_slice(b"\nendobj\n");
    }
    let index = out.len();
    writeln!(out, "xref\n0 {}\n0000000000 65535 f ", objects.len() + 1).unwrap();
    for offset in offsets {
        writeln!(out, "{offset:010} 00000 n ").unwrap();
    }
    writeln!(
        out,
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{index}\n%%EOF",
        objects.len() + 1
    )
    .unwrap();
    out
}

fn document(catalog_note: &str, first: Vec<u8>, attachment: Vec<u8>) -> Vec<u8> {
    pdf(&[
        format!("<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 5 0 R] >> >> /Note ({catalog_note}) >>").into_bytes(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>".to_vec(),
        first,
        b"<< /Type /Filespec /F (notes.txt) /EF << /F 6 0 R >> >>".to_vec(),
        attachment,
    ])
}

fn compare(exe: &Path, stock: bool) -> io::Result<()> {
    let tmp = tempfile::tempdir_in("/tmp")?;
    let root = tmp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let mut rules = String::new();
    let first_line = [FIRST, b"\n"].concat();
    for (name, data) in [
        ("First", FIRST),
        ("Second", SECOND),
        ("FirstLine", first_line.as_slice()),
        ("Text", b"ordinary page text"),
    ] {
        rules.push_str(&format!(
            "{}:{}:Pdf.{name}\n",
            hex(&Md5::digest(data)),
            data.len()
        ));
    }
    fs::write(db.join("local.hdb"), rules)?;
    fs::write(
        db.join("local.ndb"),
        format!("Pdf.Outer:10:*:{}\n", hex(b"OuterPdfMark")),
    )?;
    let start = |profile: &str, options: &str| -> io::Result<_> {
        let conf = root.join(format!("{profile}.conf"));
        let socket = root.join(format!("{profile}.sock"));
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDisableCache yes\nSelfCheck 0\nDatabaseDirectory {}\nTemporaryDirectory {}\nLocalSocket {}\n{options}\n",
                db.display(),
                root.display(),
                socket.display()
            ),
        )?;
        Ok((Daemon::start(exe, &conf, &socket)?, socket))
    };
    let (daemon, socket) = start("base", "")?;
    let text = b"BT (ordinary page contents) Tj ET";
    let quiet = || stream("", text);
    let bare = document(
        "notes",
        stream("", FIRST),
        stream("/Type /EmbeddedFile", SECOND),
    );
    let flate = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /FlateDecode",
            &deflate(SECOND)?,
        ),
    );
    let ah = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /ASCIIHexDecode",
            format!("{}>", hex(SECOND)).as_bytes(),
        ),
    );
    let combined = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter [/ASCIIHexDecode /FlateDecode]",
            format!("{}>", hex(&deflate(SECOND)?)).as_bytes(),
        ),
    );
    let flate_params = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /Fl /DecodeParms << /Predictor 1 >>",
            &deflate(SECOND)?,
        ),
    );
    let a85 = document(
        "notes",
        quiet(),
        stream(
            "/Type /EmbeddedFile /Filter /ASCII85Decode",
            &ascii85(SECOND),
        ),
    );
    let mut run = vec![(SECOND.len() - 1) as u8];
    run.extend_from_slice(SECOND);
    run.push(128);
    let run_length = document(
        "notes",
        quiet(),
        stream("/Type /EmbeddedFile /Filter /RunLengthDecode", &run),
    );
    let normalized = document(
        "notes",
        stream(
            "/Filter /FlateDecode",
            &deflate(b"BT\n[(Ordinary )(PAGE TEXT)] TJ\nET")?,
        ),
        stream("/Type /EmbeddedFile", SECOND),
    );
    let outer = document(
        "OuterPdfMark",
        stream("/Filter /FlateDecode", &deflate(FIRST)?),
        stream("/Type /EmbeddedFile", SECOND),
    );
    let mut truncated = flate.clone();
    truncated.truncate(truncated.len() - 20);
    let mut cut_stream = flate.clone();
    let endstream = flate.windows(9).rposition(|w| w == b"endstream").unwrap();
    cut_stream.truncate(endstream - 12);
    let cases = [
        ("page then attachment", bare, Some("FirstLine")),
        ("compressed attachment", flate.clone(), Some("Second")),
        ("Flate parameters", flate_params, Some("Second")),
        ("ASCIIHex attachment", ah, Some("Second")),
        ("two filters", combined, Some("Second")),
        ("ASCII85 attachment", a85, Some("Second")),
        ("run length attachment", run_length, Some("Second")),
        ("normalized page text", normalized, Some("Text")),
        ("outer vs child", outer, Some("Outer")),
        (
            "ZIP containing PDF",
            zip::zip(&[("ordinary.pdf", &flate)], true, false, false)?,
            Some("Second"),
        ),
        ("missing final trailer", truncated, Some("Second")),
        ("incomplete attachment stream", cut_stream, None),
        (
            "clean",
            document("notes", quiet(), stream("/Type /EmbeddedFile", text)),
            None,
        ),
    ];
    for (label, bytes, name) in cases {
        let expected = match name {
            Some(name) => format!("stream: Pdf.{name}.UNOFFICIAL FOUND\0"),
            None if stock => "stream: OK\0".to_owned(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".to_owned(),
        };
        assert_eq!(
            unix_request(&socket, &stream_frame(&bytes)?)?,
            expected,
            "{label}"
        );
    }
    drop(daemon);
    let larger = b"ordinary expanded document page.\n".repeat(256);
    let compressed = document(
        "notes",
        stream("/Filter /FlateDecode", &deflate(&larger)?),
        quiet(),
    );
    assert!(compressed.len() < 2048 && larger.len() > 2048);
    for (profile, options, sample, name) in [
        (
            "bytes",
            "MaxFileSize 2048\nAlertExceedsMax yes",
            &compressed,
            "Heuristics.Limits.Exceeded.MaxFileSize",
        ),
        (
            "depth",
            "MaxRecursion 1\nAlertExceedsMax yes",
            &flate,
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
    ] {
        let (_service, socket) = start(profile, options)?;
        assert_eq!(
            unix_request(&socket, &stream_frame(sample)?)?,
            format!("stream: {name} FOUND\0"),
            "{profile}"
        );
    }
    let (_service, socket) = start("disabled", "ScanPDF no")?;
    let reply = unix_request(&socket, &stream_frame(&flate)?)?;
    assert_eq!(
        reply,
        if stock {
            "stream: OK\0"
        } else {
            "stream: Incomplete scan: unsupported detection coverage. ERROR\0"
        }
    );
    Ok(())
}

#[test]
fn barnacle_pdf_objects() -> io::Result<()> {
    compare(Path::new(env!("CARGO_BIN_EXE_barnacle")), false)
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn stock_pdf_objects() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(Path::new("/usr/sbin/clamd"), true)
}
