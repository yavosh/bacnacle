#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/zip.rs"]
mod zip;

use barnacle::objects::{self, Options, Verdict};
use std::{fs, io, path::Path};

const MARKER: &[u8] = b"Quarterly reference document";
const TYPES: [&str; 5] = [
    "CL_TYPE_ZIP",
    "CL_TYPE_OOXML_WORD",
    "CL_TYPE_OOXML_XL",
    "CL_TYPE_OOXML_PPT",
    "CL_TYPE_OOXML_HWP",
];

fn samples() -> io::Result<Vec<(Vec<u8>, &'static str)>> {
    let mut out = Vec::new();
    for (path, ty) in [
        ("notes/report.txt", TYPES[0]),
        ("word/document.xml", TYPES[1]),
        ("xl/workbook.xml", TYPES[2]),
        ("ppt/slides/a.xml", TYPES[3]),
        ("Contents/content.hpf", TYPES[4]),
    ] {
        out.push((zip::zip(&[(path, MARKER)], true, false, false)?, ty));
    }
    // A package hint among the first three entries triggers full directory inspection.
    for (first, ty) in [("[Content_Types].xml", TYPES[2]), ("note.txt", TYPES[0])] {
        out.push((
            zip::zip(
                &[
                    (first, b"ordinary package contents"),
                    ("b.txt", b"second ordinary note"),
                    ("c.txt", b"third ordinary note"),
                    ("xl/workbook.xml", MARKER),
                ],
                true,
                false,
                true,
            )?,
            ty,
        ));
    }
    Ok(out)
}

#[test]
fn member_type_and_parent_context() -> io::Result<()> {
    let tmp = tempfile::tempdir()?;
    for (data, ty) in samples()? {
        let result = objects::scan(
            &data,
            &Options::default(),
            tmp.path(),
            |obj, _| {
                if obj.bytes == MARKER {
                    assert_eq!(obj.parents.len(), 1);
                    assert_eq!(obj.parents[0].file_type, ty);
                    assert_eq!(obj.parents[0].size, data.len());
                    assert_eq!(obj.layer.file_type, "CL_TYPE_TEXT_ASCII");
                    assert!(obj.layer.name.is_some());
                    return Ok(Verdict::Found(ty.into()));
                }
                Ok(Verdict::Miss)
            },
            || Ok(()),
        )?;
        assert_eq!(result, Verdict::Found(ty.into()));
    }
    Ok(())
}

#[test]
#[ignore = "requires the pinned Debian clamd"]
fn stock_parent_type_selects_the_same_member() -> io::Result<()> {
    let temp = tempfile::tempdir_in("/tmp")?;
    let root = temp.path();
    let db = root.join("db");
    fs::create_dir(&db)?;
    let hex: String = MARKER.iter().map(|byte| format!("{byte:02x}")).collect();
    let rules: String = TYPES
        .iter()
        .map(|t| format!("Parent.{t};Engine:81-255,Target:0,Container:{t};0;{hex}\n"))
        .collect();
    fs::write(db.join("parents.ldb"), rules)?;
    let sock = root.join("sock");
    let config = root.join("clamd.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDisableCache yes\nDatabaseDirectory {}\nLocalSocket {}\n",
            db.display(),
            sock.display()
        ),
    )?;
    let _clamd = daemon::Daemon::start(Path::new("/usr/sbin/clamd"), &config, &sock)?;
    for (bytes, ty) in samples()? {
        assert_eq!(
            daemon::unix_request(&sock, &daemon::stream_frame(&bytes)?)?,
            format!("stream: Parent.{ty}.UNOFFICIAL FOUND\0"),
            "{ty}"
        );
    }
    Ok(())
}
