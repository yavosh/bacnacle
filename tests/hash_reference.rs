//! Replay the nine pinned whole-file hash cases through the Barnacle CLI and stock clamd.

#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DATABASES: [(&str, &[u8]); 2] = [
    (
        "fixture.hdb",
        include_bytes!("fixtures/hash-reference/fixture.hdb"),
    ),
    (
        "fixture.hsb",
        include_bytes!("fixtures/hash-reference/fixture.hsb"),
    ),
];

fn sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn reference() -> Value {
    serde_json::from_str(include_str!("../docs/hash-reference-debian13.json")).unwrap()
}

fn write_databases(root: &Path, reference: &Value) -> Vec<PathBuf> {
    let db = root.join("db");
    fs::create_dir(&db).unwrap();
    DATABASES
        .iter()
        .map(|&(name, contents)| {
            assert_eq!(sha256(contents), reference["database_sha256"][name]);
            let path = db.join(name);
            fs::write(&path, contents).unwrap();
            path
        })
        .collect()
}

fn cases(reference: &Value) -> &[Value] {
    let entries = reference["cases"].as_array().unwrap();
    assert_eq!(entries.len(), 9);
    entries
}

fn fixture(case: &Value) -> Vec<u8> {
    let mut data: Vec<_> = (0..=255).collect();
    data.extend_from_slice(case["case"].as_str().unwrap().as_bytes());
    assert_eq!(case["bytes"], data.len());
    assert_eq!(case["sha256"], sha256(&data));
    data
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn backends_match_the_recorded_stock_daemon() {
    let reference = reference();
    let root = tempfile::tempdir().unwrap();
    let databases = write_databases(root.path(), &reference);
    let index = root.path().join("fixture.bhi");
    let file = root.path().join("sample");
    let binary = env!("CARGO_BIN_EXE_barnacle");
    success(
        Command::new(binary)
            .arg("build")
            .arg(&index)
            .args(databases)
            .output()
            .unwrap(),
    );

    for case in cases(&reference) {
        fs::write(&file, fixture(case)).unwrap();
        let expected = match case["result"].as_str().unwrap() {
            "matched" => format!("matched\t{}\n", case["signature"].as_str().unwrap()),
            "unmatched" => "unmatched\n".to_owned(),
            other => panic!("unexpected reference verdict {other}"),
        };
        for backend in ["memory", "pread", "mmap"] {
            let reply = success(
                Command::new(binary)
                    .args(["scan", backend])
                    .arg(&index)
                    .arg(&file)
                    .output()
                    .unwrap(),
            );
            assert_eq!(reply, expected, "{} ({backend})", case["case"]);
        }
    }
}

#[test]
#[ignore = "requires the pinned Debian clamd package"]
fn live_stock_daemon_matches_every_recorded_reply() {
    let reference = reference();
    let package = success(
        Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "clamav-daemon"])
            .output()
            .unwrap(),
    );
    assert_eq!(reference["clamav-daemon"], package);

    let root = tempfile::tempdir_in("/tmp").unwrap();
    write_databases(root.path(), &reference);
    let config = root.path().join("clamd.conf");
    let template = reference["config_template"].as_str().unwrap();
    fs::write(
        &config,
        template.replace("{root}", root.path().to_str().unwrap()),
    )
    .unwrap();
    let socket = root.path().join("socket");
    let _daemon = daemon::Daemon::start(Path::new("/usr/sbin/clamd"), &config, &socket).unwrap();
    let version = daemon::unix_request(&socket, b"zVERSION\0").unwrap();
    assert_eq!(
        version,
        format!("{}\0", reference["version_reply"].as_str().unwrap())
    );

    for case in cases(&reference) {
        let frame = daemon::stream_frame(&fixture(case)).unwrap();
        let actual = daemon::unix_request(&socket, &frame).unwrap();
        let expected = format!("{}\0", case["reply"].as_str().unwrap());
        assert_eq!(actual, expected, "{}", case["case"]);
    }
}
