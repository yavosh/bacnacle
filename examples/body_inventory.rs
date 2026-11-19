//! Inventory active body patterns from the extracted, verified reference generation.
use barnacle::body::{BodyIndex, ObjectContext};
use barnacle::{Feed, PINNED_FLEVEL};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

fn digest(path: &Path) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut file = fs::File::open(path)?;
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn main() -> io::Result<()> {
    let mut args = env::args_os().skip(1);
    let dir = PathBuf::from(args.next().ok_or_else(|| {
        io::Error::other("usage: body_inventory EXTRACTED_REFERENCE_DIR [SAMPLE ...]")
    })?);
    let ignore_paths = [dir.join("daily.ign"), dir.join("daily.ign2")];
    let (_, ignores) = Feed::load_sources_with_ignores(
        &ignore_paths.each_ref().map(|p| (p.as_path(), true)),
        PINNED_FLEVEL,
    )?;
    let databases = [dir.join("daily.ndb"), dir.join("main.ndb")];
    let index = BodyIndex::load_sources(
        &databases.each_ref().map(|p| (p.as_path(), true)),
        PINNED_FLEVEL,
        &ignores,
    )?;
    let mut sources = Vec::new();
    for source in &index.inventory {
        sources.push(json!({
            "file": source.path.file_name().and_then(|name| name.to_str()),
            "sha256": digest(&source.path)?,
            "records": source.records, "active": source.active,
            "skipped_flevel": source.skipped_flevel, "skipped_ignored": source.skipped_ignored,
            "targets": source.targets, "offsets": source.offsets, "features": source.features,
        }));
    }
    let mut samples = Vec::new();
    for arg in args {
        let path = PathBuf::from(arg);
        let bytes = fs::read(&path)?;
        let mut matches = 0u64;
        index.scan(&bytes, &ObjectContext::raw(&bytes), |_| matches += 1)?;
        samples.push(json!({"path": path, "bytes": bytes.len(), "body_matches": matches}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "flevel": PINNED_FLEVEL, "active": index.rule_count(), "sources": sources, "samples": samples
        }))?
    );
    Ok(())
}
