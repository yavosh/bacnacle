//! Ordinary Office 2003 and HWPML XML against the pinned reference daemon.
#[path = "common/base64.rs"]
mod base64;
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;
use md5::{Digest, Md5};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const FIRST: &[u8] = b"ordinary XML attachment";
const SECOND: &[u8] = b"a second XML attachment";
const A: &str = "b3JkaW5hcnkgWE1MIGF0dGFjaG1lbnQ=";
const B: &str = "YSBzZWNvbmQgWE1MIGF0dGFjaG1lbnQ=";
const WORD: &str = "w:wordDocument";
const EXCEL: &str = "Workbook";
const HWP: &str = "HWPML";

fn doc(root: &str, content: &str, offset: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if root == HWP {
        out.extend([0xef, 0xbb, 0xbf]);
    }
    out.extend(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.resize(offset.max(out.len()), b' ');
    out.extend(format!("<{root} xmlns:w=\"http://schemas.microsoft.com/office/word/2003/wordml\">{content}</{root}>").bytes());
    out
}

fn hash(bytes: &[u8], name: &str) -> String {
    let hex: String = Md5::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{hex}:{}:Local.{name}\n", bytes.len())
}

fn hwp_compressed(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes)?;
    let compressed = base64::encode(&encoder.finish()?);
    let compressed = doc(
        HWP,
        &format!(
            "<TAIL><BINDATA Compress=\"true\" Encoding=\"Base64\">{compressed}\n</BINDATA></TAIL>"
        ),
        0,
    );
    Ok(compressed)
}

struct Server {
    _dir: tempfile::TempDir,
    _process: daemon::Daemon,
    sock: std::path::PathBuf,
    stock: bool,
}

impl Server {
    fn start(stock: bool, config: &str, rules: &str, logical: &str) -> io::Result<Self> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        if !rules.is_empty() {
            fs::write(db.join("samples.hdb"), rules)?;
        }
        if !logical.is_empty() {
            fs::write(db.join("samples.ldb"), logical)?;
        }
        let sock = dir.path().join("sock");
        let conf = dir.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nLocalSocket {}\nDatabaseDirectory {}\nSelfCheck 0\nDisableCache yes\n{config}\n",
                sock.display(),
                db.display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let process = daemon::Daemon::start(Path::new(exe), &conf, &sock)?;
        Ok(Self {
            _dir: dir,
            _process: process,
            sock,
            stock,
        })
    }

    fn check(&self, label: &str, data: &[u8], name: Option<&str>) -> io::Result<()> {
        let reply = daemon::unix_request(&self.sock, &daemon::stream_frame(data)?)?;
        let expected = match name {
            Some(n) if n.starts_with("Heuristics.") => format!("stream: {n} FOUND\0"),
            Some(n) => format!("stream: Local.{n}.UNOFFICIAL FOUND\0"),
            None if self.stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(reply, expected, "{label}");
        Ok(())
    }
}

fn compare(stock: bool) -> io::Result<()> {
    let files = hash(FIRST, "First") + &hash(SECOND, "Second");
    let first = format!("<w:binData w:name=\"ordinary.txt\">\n{A}\n</w:binData>");
    let second = format!("<binData>{B}\n</binData>");
    let word = doc(
        WORD,
        &format!("<w:docOleData>{first}{second}</w:docOleData>"),
        0,
    );
    let excel = doc(EXCEL, &format!("<Worksheet>{second}{first}</Worksheet>"), 0);
    let hwp = doc(
        HWP,
        &format!(
            "<TAIL><BINDATASTORAGE><BINDATA Id=\"1\" Compress=\"false\" Encoding=\"Base64\">\n{A}\n</BINDATA></BINDATASTORAGE></TAIL>"
        ),
        0,
    );
    let hashes = files.clone() + &hash(&word, "Word") + &hash(&excel, "Excel") + &hash(&hwp, "Hwp");
    let daemon = Server::start(stock, "", &hashes, "")?;
    daemon.check("Word child before document", &word, Some("First"))?;
    daemon.check("Excel reversed children", &excel, Some("Second"))?;
    daemon.check("HWP base64", &hwp, Some("First"))?;
    let compressed = hwp_compressed(FIRST)?;
    daemon.check("HWP deflate attachment", &compressed, Some("First"))?;
    daemon.check(
        "Unknown HWP encoding retains text",
        &doc(
            HWP,
            "<TAIL><BINDATA Encoding=\"Text\">ordinary XML attachment</BINDATA></TAIL>",
            0,
        ),
        Some("First"),
    )?;
    daemon.check(
        "Word processing instruction",
        &doc(
            "document",
            &format!("<?mso-application progid=\"Word.Document\"?>{first}"),
            0,
        ),
        Some("First"),
    )?;
    daemon.check("HWP script plain",&doc(HWP,"<TAIL><SCRIPTCODE><SCRIPTSOURCE>ordinary XML attachment</SCRIPTSOURCE></SCRIPTCODE></TAIL>",0),Some("First"))?;
    daemon.check(
        "HWP body skip",
        &doc(
            HWP,
            "<BODY><SCRIPTSOURCE>ordinary XML attachment</SCRIPTSOURCE></BODY>",
            0,
        ),
        None,
    )?;
    daemon.check(
        "Office style skip",
        &doc(WORD, &format!("<w:styles>{first}</w:styles>"), 0),
        None,
    )?;
    daemon.check(
        "CDATA skip",
        &doc(EXCEL, &format!("<binData><![CDATA[{A}\n]]></binData>"), 0),
        None,
    )?;
    daemon.check(
        "One-line Base64",
        &doc(WORD, &format!("<binData>{A}</binData>"), 0),
        None,
    )?;
    daemon.check(
        "XML numeric newline",
        &doc(EXCEL, &format!("<binData>{A}&#10;</binData>"), 0),
        Some("First"),
    )?;
    daemon.check(
        "XML CRLF",
        &doc(EXCEL, &format!("<binData>{A}\r\n</binData>"), 0),
        Some("First"),
    )?;
    daemon.check(
        "Alternate case and namespace",
        &doc(EXCEL, &format!("<w:bInDaTa>{A}\n</w:bInDaTa>"), 0),
        Some("First"),
    )?;
    daemon.check("Excel boundary", &doc(EXCEL, &first, 1015), Some("First"))?;
    daemon.check("Excel later offset", &doc(EXCEL, &first, 1016), None)?;
    daemon.check(
        "Deep attachment",
        &doc(
            WORD,
            &format!("{}{}{}", "<g>".repeat(18), first, "</g>".repeat(18)),
            0,
        ),
        Some("First"),
    )?;
    daemon.check(
        "XML nesting limit",
        &doc(
            WORD,
            &format!("{}{}{}", "<g>".repeat(19), first, "</g>".repeat(19)),
            0,
        ),
        None,
    )?;
    daemon.check(
        "Word inside ZIP",
        &zip::zip(&[("document.xml", &word)], true, false, false)?,
        Some("First"),
    )?;
    for (size, expected) in [(10_000_000, Some("First")), (10_000_001, None)] {
        let long = doc(
            EXCEL,
            &format!("<Note>{}</Note>{first}", "x".repeat(size)),
            0,
        );
        daemon.check("XML text node size limit", &long, expected)?;
    }
    drop(daemon);
    let disabled = Server::start(stock, "ScanXMLDOCS no", &hashes, "")?;
    for (doc, name) in [(&word, "Word"), (&excel, "Excel"), (&hwp, "Hwp")] {
        disabled.check("ScanXMLDOCS no", doc, Some(name))?;
    }
    drop(disabled);
    let no_archives = Server::start(stock, "ScanArchive no", &files, "")?;
    no_archives.check("ScanArchive no", &word, Some("First"))?;
    drop(no_archives);
    let hex: String = FIRST.iter().map(|b| format!("{b:02x}")).collect();
    let mut logical = String::new();
    for (t, n) in [("WORD", "Word"), ("XL", "Excel"), ("HWP", "Hwp")] {
        logical.push_str(&format!(
            "Local.{n};Engine:81-255,Target:0,Container:CL_TYPE_XML_{t};0;{hex}\n"
        ));
    }
    if stock {
        let parents = Server::start(true, "", "", &logical)?;
        for (doc, name) in [(&word, "Word"), (&excel, "Excel"), (&hwp, "Hwp")] {
            parents.check("Typed parent", doc, Some(name))?;
        }
    }
    let large = vec![b'x'; 100_000];
    let large_hwp = hwp_compressed(&large)?;
    let encoded = base64::encode(&large);
    let lines = encoded
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let large_word = doc(WORD, &format!("<binData>{lines}\n</binData>"), 0);
    let big_hashes = hash(&large, "Large") + &hash(&large[..8192], "Prefix");
    let regular = Server::start(stock, "", &big_hashes, "")?;
    regular.check("Large Word XML attachment", &large_word, Some("Large"))?;
    regular.check(
        "Large compressed HWPML attachment",
        &large_hwp,
        Some("Large"),
    )?;
    drop(regular);
    let clipped = Server::start(
        stock,
        "MaxFileSize 12000\nAlertExceedsMax yes",
        &big_hashes,
        "",
    )?;
    clipped.check("HWP expansion limit", &large_hwp, Some("Prefix"))?;
    drop(clipped);
    let tiny = doc(WORD, "<binData>YQ==\n</binData>", 0);
    let small = Server::start(stock, "MaxFiles 1\nAlertExceedsMax yes", &files, "")?;
    small.check("Tiny decoded attachment", &tiny, None)?;
    drop(small);
    let first_size = word.len() + FIRST.len();
    for (cfg, expected) in [
        (
            "MaxRecursion 1".to_string(),
            "Heuristics.Limits.Exceeded.MaxRecursion",
        ),
        ("MaxFiles 1".into(), "Heuristics.Limits.Exceeded.MaxFiles"),
        ("MaxFiles 2".into(), "First"),
        (format!("MaxScanSize {first_size}"), "First"),
        (
            format!("MaxScanSize {}", first_size - 1),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
    ] {
        let limits = Server::start(stock, &format!("{cfg}\nAlertExceedsMax yes"), &files, "")?;
        limits.check(&cfg, &word, Some(expected))?;
    }
    Ok(())
}

#[test]
fn barnacle_xml_documents() -> io::Result<()> {
    compare(false)
}

#[test]
fn decoded_attachments_keep_the_xml_parent() -> io::Result<()> {
    use barnacle::objects::{Options, Verdict, scan};
    let tmp = tempfile::tempdir()?;
    for (root, tag, kind) in [
        (WORD, "w:binData", "CL_TYPE_XML_WORD"),
        (EXCEL, "binData", "CL_TYPE_XML_XL"),
        (HWP, "BINDATA", "CL_TYPE_XML_HWP"),
    ] {
        let document = doc(
            root,
            &format!("<{tag} Encoding=\"Base64\" name=\"note.txt\">{A}\n</{tag}>"),
            0,
        );
        let zipped = zip::zip(&[("member.xml", &document)], true, false, false)?;
        let verdict = scan(
            &zipped,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                if !obj.normalized && obj.bytes == FIRST {
                    assert_eq!(
                        obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                        ["CL_TYPE_ZIP", kind]
                    );
                    assert_eq!(
                        obj.parents[1].name.as_deref(),
                        Some(b"member.xml".as_slice())
                    );
                    assert_eq!(obj.layer.name, None);
                    return Ok(Verdict::Found("attachment".into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Found("attachment".into()));
    }
    Ok(())
}
#[test]
#[ignore = "requires Debian clamd 1.4.3+dfsg-1"]
fn stock_xml_documents() -> io::Result<()> {
    let version = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(version.stdout, b"1.4.3+dfsg-1");
    compare(true)
}
