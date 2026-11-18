use flate2::{Compression, write::GzEncoder};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sample(label: &str) -> Vec<u8> {
    let mut bytes: Vec<_> = (0..=255).collect();
    bytes.extend_from_slice(label.as_bytes());
    bytes
}

pub fn corpus() -> io::Result<BTreeMap<&'static str, Vec<u8>>> {
    let detected = sample("barnacle-detected");
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(&detected)?;
    Ok(BTreeMap::from([
        ("clean", sample("barnacle-clean")),
        ("detected", detected),
        ("nested", gzip.finish()?),
        ("competing", sample("barnacle-competing")),
        ("limit", vec![b'a'; 1025]),
    ]))
}

pub fn write_rules(db: &Path) -> io::Result<()> {
    let detected = sample("barnacle-detected");
    let competing = sample("barnacle-competing");
    let first = hex(&Md5::digest(&detected));
    let other = hex(&Sha256::digest(&competing));
    fs::write(
        db.join("fixture.hdb"),
        format!("{first}:{}:Barnacle.Oracle.Detected\n", detected.len()),
    )?;
    fs::write(
        db.join("fixture.hsb"),
        format!(
            "{other}:*:Barnacle.Oracle.Wildcard:73\n{other}:{}:Barnacle.Oracle.Exact\n",
            competing.len()
        ),
    )
}

pub fn file_hash(path: &Path) -> io::Result<String> {
    let mut input = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = [0; 64 * 1024];
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        digest.update(&buf[..count]);
    }
    Ok(hex(&digest.finalize()))
}
