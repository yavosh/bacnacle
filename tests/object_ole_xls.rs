//! Passive BIFF8 workbook drawings against the pinned Debian scanner.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
use barnacle::objects::{Options, Verdict, scan};
use daemon::{Daemon, stream_frame, unix_request};
use std::{
    fs,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};

const EXCEL: &[u8] = include_bytes!("fixtures/xls/dots.xls");
const CALC: &[u8] = include_bytes!("fixtures/xls/arithmetic.xls");
const DOTS: &[u8] = include_bytes!("fixtures/xls/dots.png");
const JPEG: &[u8] = include_bytes!("fixtures/images/blue.jpg");
const TIFF: &[u8] = include_bytes!("fixtures/images/blue.tiff");
const REPORT: &[u8] = b"-- BIFF content extracted and disassembled from CL_TYPE_MSXL .xls file because a XLM macro was found in the document\n";

fn art(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut data = flags.to_le_bytes().to_vec();
    data.extend(kind.to_le_bytes());
    data.extend((payload.len() as u32).to_le_bytes());
    data.extend(payload);
    data
}
fn picture(kind: u16, instance: u16, data: &[u8], wrapped: bool) -> Vec<u8> {
    let mut blob = vec![0; if instance & 1 == 0 { 16 } else { 32 }];
    blob.push(255);
    blob.extend(data);
    let blip = art(kind, instance << 4, &blob);
    if !wrapped {
        return blip;
    }
    let typ = match kind {
        0xf01e => 6,
        0xf01d => 5,
        0xf029 => 17,
        _ => 0,
    };
    let mut entry = vec![0; 36];
    entry[0] = typ;
    entry[1] = typ;
    entry[20..24].copy_from_slice(&(blip.len() as u32).to_le_bytes());
    entry[24] = 1;
    entry.extend(blip);
    art(0xf007, u16::from(typ) << 4 | 2, &entry)
}
fn biff(code: u16, data: &[u8]) -> Vec<u8> {
    let mut out = code.to_le_bytes().to_vec();
    out.extend((data.len() as u16).to_le_bytes());
    out.extend(data);
    out
}

fn bitmap() -> Vec<u8> {
    // A 208-pixel 24-bit row is already DWORD aligned. The first 40 bytes are BITMAPINFOHEADER.
    let mut bytes = vec![0; 40 + 208 * 130 * 3];
    bytes[..4].copy_from_slice(&40u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&208u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&130u32.to_le_bytes());
    bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&24u16.to_le_bytes());
    bytes
}
fn workbook(images: &[Vec<u8>], fences: &[usize], continuation: u16) -> Vec<u8> {
    let store = art(0xf001, (images.len() as u16) << 4 | 15, &images.concat());
    let group = art(0xf000, 15, &store);
    let mut raw = Vec::new();
    let mut at = 0;
    let mut code = 0xeb;
    for end in fences.iter().copied().chain([group.len()]) {
        raw.extend(biff(code, &group[at..end]));
        at = end;
        code = continuation;
    }
    raw.extend(biff(0xa, &[]));
    raw
}
fn compound(entries: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    let mut doc =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new()))?;
    for (name, data) in entries {
        doc.create_stream(name)?.write_all(data)?;
    }
    Ok(doc.into_inner().into_inner())
}
fn single(raw: &[u8]) -> io::Result<Vec<u8>> {
    compound(&[("Workbook", raw)])
}
fn hash(name: &str, data: &[u8]) -> io::Result<String> {
    Ok(format!(
        "{}:{}:Xls.{name}\n",
        barnacle::hash_reader(data)?.md5_hex(),
        data.len()
    ))
}
struct Server {
    _process: Daemon,
    _dir: tempfile::TempDir,
    sock: PathBuf,
    stock: bool,
}
impl Server {
    fn start(stock: bool, opts: &str, hdb: &str, ndb: &str, ldb: &str) -> io::Result<Self> {
        let dir = tempfile::tempdir_in("/tmp")?;
        let db = dir.path().join("db");
        fs::create_dir(&db)?;
        for (filename, text) in [("local.hdb", hdb), ("local.ndb", ndb), ("local.ldb", ldb)] {
            if !text.is_empty() {
                fs::write(db.join(filename), text)?;
            }
        }
        let sock = dir.path().join("sock");
        let conf = dir.path().join("clamd.conf");
        fs::write(
            &conf,
            format!(
                "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nTemporaryDirectory {}\nDisableCache yes\nSelfCheck 0\n{opts}\n",
                db.display(),
                sock.display(),
                dir.path().display()
            ),
        )?;
        let exe = if stock {
            "/usr/sbin/clamd"
        } else {
            env!("CARGO_BIN_EXE_barnacle")
        };
        let process = Daemon::start(Path::new(exe), &conf, &sock)?;
        Ok(Self {
            _process: process,
            _dir: dir,
            sock,
            stock,
        })
    }
    fn check(&self, name: &str, bytes: &[u8], expected: Option<&str>) -> io::Result<()> {
        let result = unix_request(&self.sock, &stream_frame(bytes)?)?;
        let expected = match expected {
            Some(limit) if limit.starts_with("Heuristics.") => format!("stream: {limit} FOUND\0"),
            Some(s) => format!("stream: Xls.{s}.UNOFFICIAL FOUND\0"),
            None if self.stock => "stream: OK\0".into(),
            None => "stream: Incomplete scan: unsupported detection coverage. ERROR\0".into(),
        };
        assert_eq!(result, expected, "{name}");
        Ok(())
    }
}
fn compare(stock: bool) -> io::Result<()> {
    let mut wb = Vec::new();
    cfb::CompoundFile::open(Cursor::new(EXCEL))?
        .open_stream("Workbook")?
        .read_to_end(&mut wb)?;
    let dots = picture(0xf01e, 0x6e0, DOTS, true);
    let jpg = picture(0xf01d, 0x46b, JPEG, true);
    let dual = workbook(&[dots.clone(), jpg.clone()], &[3, 40, 2100], 0x3c);
    let rev = workbook(&[jpg.clone(), dots.clone()], &[4, 53, 103], 0xeb);
    let dib = bitmap();
    let files =
        hash("Dots", DOTS)? + &hash("Jpeg", JPEG)? + &hash("Tiff", TIFF)? + &hash("Dib", &dib)?;
    let daemon = Server::start(
        stock,
        "",
        &(files.clone() + &hash("Workbook", &wb)? + &hash("Outer", EXCEL)?),
        "",
        "",
    )?;
    daemon.check("authored PNG before outer", EXCEL, Some("Dots"))?;
    let bare_and_inline = single(&workbook(
        &[picture(0xf01d, 0x46a, JPEG, false), dots.clone()],
        &[],
        0x3c,
    ))?;
    daemon.check(
        "nonfinal bare JPEG passes through to the inline PNG",
        &bare_and_inline,
        Some("Dots"),
    )?;
    let exact_jpeg = [JPEG, &dots[..17]].concat();
    Server::start(stock, "", &(hash("Bare", &exact_jpeg)? + &files), "", "")?.check(
        "stock includes the following 17 bytes in the bare JPEG",
        &bare_and_inline,
        Some("Bare"),
    )?;
    daemon.check(
        "CONTINUE segments including split headers",
        &single(&dual)?,
        Some("Dots"),
    )?;
    daemon.check(
        "multiple drawing-group segments",
        &single(&rev)?,
        Some("Jpeg"),
    )?;
    daemon.check(
        "direct TIFF record",
        &single(&workbook(&[picture(0xf029, 0x6e4, TIFF, false)], &[], 0x3c))?,
        Some("Tiff"),
    )?;
    let book = compound(&[("Book", &dual)])?;
    daemon.check("Book skips picture scan", &book, None)?;
    let book_hash = Server::start(
        stock,
        "",
        &(hash("Book", &book)? + &hash("RawBook", &dual)?),
        "",
        "",
    )?;
    book_hash.check("Book outer remains eligible", &book, Some("Book"))?;
    let breaks = (8192..dib.len()).step_by(8192).collect::<Vec<_>>();
    let large = single(&workbook(
        &[picture(0xf01f, 0x7a8, &dib, true)],
        &breaks,
        0x3c,
    ))?;
    daemon.check(
        "DIB with multiple continuations and disk spool",
        &large,
        Some("Dib"),
    )?;
    let only = Server::start(stock, "", &hash("Workbook", &wb)?, "", "")?;
    only.check("raw Workbook skipped", EXCEL, None)?;
    only.check("direct Workbook hash", &wb, Some("Workbook"))?;
    let outer = Server::start(
        stock,
        "",
        &(hash("Workbook", &wb)? + &hash("Outer", EXCEL)?),
        "",
        "",
    )?;
    outer.check("outer hash after pictures", EXCEL, Some("Outer"))?;
    let siblings = Server::start(stock, "", &hash("Jpeg", JPEG)?, "", "")?;
    let one = workbook(&[dots], &[], 0x3c);
    siblings.check(
        "unrelated OLE sibling omitted",
        &compound(&[("Workbook", &one), ("Sibling", JPEG)])?,
        None,
    )?;
    let mixed = single(&dual)?;
    for (options, expected) in [
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                mixed.len() + JPEG.len()
            ),
            "Heuristics.Limits.Exceeded.MaxScanSize",
        ),
        (
            "MaxFiles 2\nAlertExceedsMax yes".into(),
            "Heuristics.Limits.Exceeded.MaxFiles",
        ),
    ] {
        Server::start(stock, &options, &hash("Jpeg", JPEG)?, "", "")?.check(
            "later picture after a limit",
            &mixed,
            Some(expected),
        )?;
    }
    let report = Server::start(
        stock,
        "",
        &(files.clone() + &hash("Report", REPORT)?),
        "",
        "",
    )?;
    report.check("report hash before PNG", EXCEL, Some("Report"))?;
    report.check(
        "authored ordinary formulas preserve the short report",
        CALC,
        Some("Report"),
    )?;
    daemon.check(
        "authored arithmetic and square root formulas before picture",
        CALC,
        Some("Dots"),
    )?;
    let integer = [0x1e, 2, 0];
    for tokens in [
        [integer.as_slice(), &[0x1e, 3, 0, 0x03]].concat(), // 2+3
        vec![0x44, 4, 0, 1, 0xc0, 0x1e, 2, 0, 0x05, 0x41, 0x14, 0], // SQRT(B5*2)
        vec![0x25, 0, 0, 3, 0, 0, 0, 0, 0, 0x19, 0x10, 0, 0], // SUM(A1:A4)
        [vec![0x1f], f64::MAX.to_le_bytes().to_vec()].concat(),
    ] {
        let mut cell = vec![0; 22];
        cell[20..22].copy_from_slice(&(tokens.len() as u16).to_le_bytes());
        cell.extend(tokens);
        let doc = single(&[biff(6, &cell), one.clone()].concat())?;
        report.check("short formula report before image", &doc, Some("Report"))?;
        daemon.check("image after short formula report", &doc, Some("Dots"))?;
    }
    // A long sum of ordinary integer literals fills the stock report buffer.
    let mut tokens = integer.to_vec();
    for _ in 0..350 {
        tokens.extend(integer);
        tokens.push(3);
    }
    let mut cell = vec![0; 22];
    cell[20..22].copy_from_slice(&(tokens.len() as u16).to_le_bytes());
    cell.extend(tokens);
    let long = single(&[biff(6, &cell), one.clone()].concat())?;
    report.check(
        "multi-block formula report cannot match its preamble hash",
        &long,
        Some("Dots"),
    )?;
    let needle = b"BIFF content extracted"
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    for (target, expected) in [(0, "ReportBody"), (7, "Dots")] {
        let rules = format!("Xls.ReportBody:{target}:*:{needle}\n");
        Server::start(stock, "", &files, &rules, "")?.check(
            "report target",
            EXCEL,
            Some(expected),
        )?;
    }
    let options = [
        ("ScanOLE2 no".into(), None),
        ("ScanImage no".into(), Some("Dots")),
        (
            "MaxRecursion 1\nAlertExceedsMax yes".into(),
            Some("Heuristics.Limits.Exceeded.MaxRecursion"),
        ),
        (
            "MaxFiles 1\nAlertExceedsMax yes".into(),
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        ("MaxFiles 2\nAlertExceedsMax yes".into(), Some("Dots")),
        (
            format!(
                "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + REPORT.len() - 1
            ),
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            format!(
                "MaxFiles 1\nMaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + REPORT.len()
            ),
            Some("Heuristics.Limits.Exceeded.MaxFiles"),
        ),
        (
            format!("MaxFileSize {}\nAlertExceedsMax yes", EXCEL.len() - 1),
            Some("Heuristics.Limits.Exceeded.MaxFileSize"),
        ),
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + DOTS.len() - 1
            ),
            Some("Heuristics.Limits.Exceeded.MaxScanSize"),
        ),
        (
            format!(
                "MaxScanSize {}\nAlertExceedsMax yes",
                EXCEL.len() + DOTS.len()
            ),
            Some("Dots"),
        ),
    ];
    for (opts, expected) in options {
        Server::start(stock, &opts, &files, "", "")?.check(&opts, EXCEL, expected)?;
    }
    let mut formula = vec![0; 22];
    formula[6..14].copy_from_slice(&3f64.to_le_bytes());
    formula[20] = 3;
    formula.extend([0x1e, 3, 0]); // An ordinary numeric formula with a cached result of three.
    let formula = biff(6, &formula);
    let small_png = include_bytes!("fixtures/images/blue.png");
    let small = picture(0xf01e, 0x6e0, small_png, true);
    let large = picture(0xf01e, 0x6e0, DOTS, true);
    for (pictures, winner, with_outer) in [
        (
            vec![large.clone()],
            "Heuristics.Limits.Exceeded.MaxScanSize",
            "Outer",
        ),
        (
            vec![large.clone(), small.clone()],
            "Heuristics.Limits.Exceeded.MaxScanSize",
            "Outer",
        ),
        (vec![small, large], "Small", "Small"),
    ] {
        let bytes = single(&[formula.as_slice(), &workbook(&pictures, &[], 0x3c)].concat())?;
        let config = format!(
            "MaxScanSize {}\nAlertExceedsMax yes",
            bytes.len() + REPORT.len() - 1
        );
        let pictures = files.clone() + &hash("Small", small_png)?;
        Server::start(stock, &config, &pictures, "", "")?.check(
            "size-only limit before formula listing",
            &bytes,
            Some(winner),
        )?;
        Server::start(
            stock,
            &config,
            &(pictures + &hash("Outer", &bytes)?),
            "",
            "",
        )?
        .check(
            "outer hash after size-limited report and pictures",
            &bytes,
            Some(with_outer),
        )?;
    }
    for prefix in [formula, biff(0xe0, &[0; 20]).repeat(113)] {
        let bytes = single(&[prefix.as_slice(), &one].concat())?;
        for (key, limit) in [
            ("MaxFiles", "Heuristics.Limits.Exceeded.MaxFiles"),
            ("MaxRecursion", "Heuristics.Limits.Exceeded.MaxRecursion"),
        ] {
            for (budget, expected) in [
                (100_000usize, limit),
                (REPORT.len(), limit),
                (REPORT.len() - 1, "Heuristics.Limits.Exceeded.MaxScanSize"),
            ] {
                let config = format!(
                    "{key} 1\nMaxScanSize {}\nAlertExceedsMax yes",
                    bytes.len() + budget
                );
                Server::start(stock, &config, &files, "", "")?.check(
                    "blocked formula or format list",
                    &bytes,
                    Some(expected),
                )?;
            }
        }
    }
    Ok(())
}

#[test]
fn barnacle_excel_pictures() -> io::Result<()> {
    compare(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_excel_pictures() -> io::Result<()> {
    let pin = std::process::Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(pin.stdout, b"1.4.3+dfsg-1");
    compare(true)
}

#[test]
fn picture_parent_and_filename() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut count = 0;
    scan(
        EXCEL,
        &Options::default(),
        temp.path(),
        |obj, _| {
            if obj.bytes == DOTS {
                assert_eq!(
                    obj.parents.iter().map(|p| p.file_type).collect::<Vec<_>>(),
                    ["CL_TYPE_MSOLE2"]
                );
                assert_eq!(obj.layer.file_type, "CL_TYPE_PNG");
                assert!(obj.layer.name.is_none());
                count += 1;
            }
            Ok(Verdict::Miss)
        },
        || Ok(()),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_picture_parent_and_filename() -> io::Result<()> {
    let needle = DOTS[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    for (parent, expected) in [("CL_TYPE_MSOLE2", Some("Parent")), ("CL_TYPE_MSXL", None)] {
        let rules = format!(
            "Xls.Parent;Engine:81-255,Target:0,Container:{parent},FileSize:{0}-{0};0;{needle}\n",
            DOTS.len()
        );
        let s = Server::start(true, "", "", "", &rules)?;
        s.check(parent, EXCEL, expected)?;
        s.check("direct PNG", DOTS, None)?;
    }
    let s = Server::start(
        true,
        "GenerateMetadataJson yes\nLeaveTemporaryFiles yes",
        &hash("Unrelated", JPEG)?,
        "",
        "",
    )?;
    s.check("metadata", EXCEL, None)?;
    let mut dirs = vec![s._dir.path().to_path_buf()];
    let mut found = false;
    while let Some(d) = dirs.pop() {
        for f in fs::read_dir(d)? {
            let f = f?;
            if f.file_type()?.is_dir() {
                dirs.push(f.path());
            } else if f.file_name() == "metadata.json" {
                let info: serde_json::Value = serde_json::from_slice(&fs::read(f.path())?)?;
                if info["FileType"] == "CL_TYPE_MSXL" {
                    let image = &info["ContainedObjects"][0];
                    assert_eq!(image["FileType"], "CL_TYPE_PNG");
                    assert_eq!(image["FileSize"], DOTS.len());
                    assert!(image["FileName"].is_null());
                    found = true;
                }
            }
        }
    }
    assert!(found);
    Ok(())
}

#[test]
fn unsupported_drawings_and_report_layouts_are_incomplete() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let png = picture(0xf01e, 0x6e0, DOTS, true);
    let ordinary = workbook(std::slice::from_ref(&png), &[], 0x3c);
    let mut long = biff(0x7777, &[]).repeat(300);
    long.extend_from_slice(&ordinary);
    let both = compound(&[("Workbook", &ordinary), ("Book", &ordinary)])?;
    let mut delayed_header = vec![0; 36];
    delayed_header[0] = 6;
    delayed_header[28..32].copy_from_slice(&500u32.to_le_bytes());
    let delayed = workbook(&[art(0xf007, 0x62, &delayed_header)], &[], 0x3c);
    for image in [single(&long)?, both, single(&delayed)?] {
        let verdict = scan(
            &image,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                Ok(if obj.bytes == DOTS {
                    Verdict::Found("early picture".into())
                } else {
                    Verdict::Miss
                })
            },
            || Ok(()),
        )?;
        assert_eq!(verdict, Verdict::Incomplete);
    }
    Ok(())
}

#[test]
fn blocked_drawings_avoid_scratch_and_io_errors_propagate() -> io::Result<()> {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");
    let dib = bitmap();
    let breaks = (8192..dib.len()).step_by(8192).collect::<Vec<_>>();
    let file = single(&workbook(
        &[picture(0xf01f, 0x7a8, &dib, true)],
        &breaks,
        0x3c,
    ))?;
    let blocked = Options {
        max_files: 1,
        alert_exceeds_max: true,
        ..Options::default()
    };
    assert_eq!(
        scan(
            &file,
            &blocked,
            &missing,
            |_, _| Ok(Verdict::Miss),
            || Ok(())
        )?,
        Verdict::Found("Heuristics.Limits.Exceeded.MaxFiles".into())
    );
    let err = scan(
        &file,
        &Options::default(),
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    Ok(())
}

const LEDGER: &[u8] = include_bytes!("fixtures/xls/ledger-summary.xls");

fn authored_drawing() -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    cfb::CompoundFile::open(Cursor::new(CALC))?
        .open_stream("Workbook")?
        .read_to_end(&mut raw)?;
    let mut records = raw.as_slice();
    while let Some((header, rest)) = records.split_at_checked(4) {
        let n = u16::from_le_bytes([header[2], header[3]]) as usize;
        let (payload, tail) = rest.split_at(n);
        if header[..2] == [0xeb, 0] {
            return Ok([biff(0xeb, payload), biff(10, &[])].concat());
        }
        records = tail;
    }
    Err(io::Error::other("authored fixture has no drawing group"))
}

fn compare_large_reports(stock: bool) -> io::Result<()> {
    // The pinned daemon accepted each exact hash with the picture HDB loaded at the same time.
    let rules = hash("Dots", DOTS)?
        + &hash("Preamble", REPORT)?
        + "7471d03533bdbc5afcf0628e340bbb07:4213:Xls.Sum\n6d6770fb32f9b3c0931eb6efcc1b7359:16501:Xls.Ledger\n74d3a2f47bf4f858f6abc8e065e8b55e:4213:Xls.Next\n274ef05da79cc224b17913cadb9c17a4:4213:Xls.Exact\n";
    let drawing = authored_drawing()?;
    let stream = |prefix: &[u8]| single(&[prefix, drawing.as_slice()].concat());
    let scan = Server::start(stock, "", &rules, "", "")?;
    scan.check(
        "120-row worksheet with a final SUM and a picture",
        LEDGER,
        Some("Ledger"),
    )?;
    Server::start(stock, "", &hash("Dots", DOTS)?, "", "")?.check(
        "picture after ledger report miss",
        LEDGER,
        Some("Dots"),
    )?;
    for (formats, ends, expected) in [
        (0, 125, "Preamble"),
        (11, 113, "Preamble"),
        (22, 101, "Next"),
        (75, 171, "Exact"),
    ] {
        let doc = stream(
            &[
                biff(224, &[0; 20]).repeat(formats),
                biff(10, &[]).repeat(ends),
            ]
            .concat(),
        )?;
        scan.check(
            "4095, 4096, 4097, and 8192 formatted bytes",
            &doc,
            Some(expected),
        )?;
    }
    let mut ints = vec![30, 2, 0];
    for _ in 0..350 {
        ints.extend([30, 2, 0, 3]);
    }
    let mut cell = vec![0; 22];
    cell[20..22].copy_from_slice(&(ints.len() as u16).to_le_bytes());
    cell.extend(ints);
    scan.check(
        "350-term sum report before PNG",
        &stream(&biff(6, &cell))?,
        Some("Sum"),
    )?;

    let xf = b"00e0     20   XF : Extended Format\n";
    let data = [REPORT, &xf.repeat(300)[..8192]].concat();
    let repeated = stream(&biff(224, &[0; 20]).repeat(300))?;
    let mut small_formula = vec![0; 22];
    small_formula[20] = 3;
    small_formula.extend([30, 2, 0]);
    let uncertain = stream(&[biff(6, &small_formula), biff(224, &[0; 20]).repeat(300)].concat())?;
    scan.check(
        "an uncertain formula suffix inside a flushed block",
        &uncertain,
        stock.then_some("Dots"),
    )?;
    let small_budget = format!(
        "MaxScanSize {}\nAlertExceedsMax yes",
        uncertain.len() + DOTS.len()
    );
    Server::start(stock, &small_budget, &rules, "", "")?.check(
        "known oversize report permits the picture",
        &uncertain,
        Some("Dots"),
    )?;
    let hashes = hash("Format", &data)? + &hash("Dots", DOTS)? + &hash("Outer", &repeated)?;
    let needle = xf.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let body = format!("Xls.Line:0:*:{needle}\n");
    Server::start(stock, "", &hashes, &body, "")?.check(
        "body before format report hash",
        &repeated,
        Some("Line"),
    )?;
    Server::start(stock, "", &hashes, "", "")?.check(
        "format report wins against PNG and outer hash",
        &repeated,
        Some("Format"),
    )?;
    for (files, delta, expected) in [
        (10, 0, "Format"),
        (10, -1, "Dots"),
        (1, 0, "Outer"),
        (1, -1, "Outer"),
    ] {
        let budget = (repeated.len() + data.len())
            .checked_add_signed(delta)
            .unwrap();
        let config = format!("MaxFiles {files}\nMaxScanSize {budget}\nAlertExceedsMax yes");
        Server::start(stock, &config, &hashes, "", "")?.check(
            "exact report byte budget",
            &repeated,
            Some(expected),
        )?;
        if files == 1 {
            let limit = if delta == 0 {
                "Heuristics.Limits.Exceeded.MaxFiles"
            } else {
                "Heuristics.Limits.Exceeded.MaxScanSize"
            };
            Server::start(stock, &config, &rules, "", "")?.check(
                "report size before count",
                &repeated,
                Some(limit),
            )?;
        }
    }
    for (offset, limit) in [
        (0, "Heuristics.Limits.Exceeded.MaxRecursion"),
        (-1, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        let budget = (repeated.len() + data.len())
            .checked_add_signed(offset)
            .unwrap();
        let config = format!("MaxRecursion 1\nMaxScanSize {budget}\nAlertExceedsMax yes");
        Server::start(stock, &config, &rules, "", "")?.check(
            "report size before depth",
            &repeated,
            Some(limit),
        )?;
    }
    Server::start(
        stock,
        "MaxFiles 2\nAlertExceedsMax yes",
        &hash("Dots", DOTS)?,
        "",
        "",
    )?
    .check(
        "large report miss leaves a slot for the picture",
        &repeated,
        Some("Dots"),
    )?;
    let many = stream(&biff(10, &[]).repeat(4000))?;
    let file_limit = format!("MaxFileSize {}\nAlertExceedsMax yes", many.len());
    Server::start(stock, &file_limit, &hash("Other", JPEG)?, "", "")?.check(
        "report exceeds the per-file ceiling",
        &many,
        Some("Heuristics.Limits.Exceeded.MaxFileSize"),
    )?;
    Ok(())
}

#[test]
fn barnacle_large_biff_reports() -> io::Result<()> {
    compare_large_reports(false)?;
    compare_unknown_report_limits(false)
}
#[test]
#[ignore = "requires pinned Debian clamd"]
fn stock_large_biff_reports() -> io::Result<()> {
    compare_large_reports(true)?;
    compare_unknown_report_limits(true)
}

fn compare_unknown_report_limits(stock: bool) -> io::Result<()> {
    let mut records = biff(0xe0, &[0; 20]).repeat(1400);
    for row in 0..128u16 {
        let mut data = [0; 16];
        data[..2].copy_from_slice(&row.to_le_bytes());
        data[4..6].copy_from_slice(&1u16.to_le_bytes());
        data[6..8].copy_from_slice(&255u16.to_le_bytes());
        records.extend(biff(0x0208, &data));
    }
    records.extend(authored_drawing()?);
    let doc = single(&records)?;
    assert_eq!(doc.len(), 42496);
    let lower = REPORT.len() + 12 * 4096;
    let upper = REPORT.len() + 14 * 4096;
    let file_limit = "Heuristics.Limits.Exceeded.MaxFileSize";
    let scan_limit = "Heuristics.Limits.Exceeded.MaxScanSize";
    let miss = hash("Other", JPEG)?;
    let picture = hash("Dots", DOTS)?;
    let outer = hash("Outer", &doc)?;
    for (file, scan, reason) in [
        (doc.len(), 1 << 20, Some(file_limit)),
        (doc.len(), doc.len() + upper, Some(file_limit)),
        (doc.len(), doc.len() + lower - 1, Some(scan_limit)),
        // One endpoint crosses the scan budget. Stock's actual report fits that budget.
        (
            doc.len(),
            doc.len() + upper - 1,
            stock.then_some(file_limit),
        ),
        // The lower endpoint can enter and the upper one exceeds the per-file limit.
        (lower, 1 << 20, stock.then_some(file_limit)),
    ] {
        let opts = format!("MaxFileSize {file}\nMaxScanSize {scan}\nAlertExceedsMax yes");
        for (name, rules, result) in [
            ("limit", &miss, reason),
            ("picture", &picture, reason.map(|_| "Dots")),
            ("outer", &outer, reason.map(|_| "Outer")),
        ] {
            Server::start(stock, &opts, rules, "", "")?.check(
                &format!("{name} file={file} scan={scan}"),
                &doc,
                result,
            )?;
        }
    }
    Ok(())
}

#[test]
fn large_report_scratch_respects_admission() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    let missing = tmp.path().join("missing");
    let data = single(&[biff(10, &[]).repeat(4000), authored_drawing()?].concat())?;
    for (files, budget, expected) in [
        (1, 200000, "Heuristics.Limits.Exceeded.MaxFiles"),
        (1, 66000, "Heuristics.Limits.Exceeded.MaxScanSize"),
        (10, 66000, "Heuristics.Limits.Exceeded.MaxScanSize"),
    ] {
        let o = Options {
            max_files: files,
            max_scan_size: (data.len() + budget) as u64,
            alert_exceeds_max: true,
            ..Default::default()
        };
        let v = scan(&data, &o, &missing, |_, _| Ok(Verdict::Miss), || Ok(()))?;
        assert_eq!(v, Verdict::Found(expected.into()));
    }
    let error = scan(
        &data,
        &Options::default(),
        &missing,
        |_, _| Ok(Verdict::Miss),
        || Ok(()),
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    Ok(())
}
