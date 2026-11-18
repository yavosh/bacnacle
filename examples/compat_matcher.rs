//! Observe Barnacle's offline CLI on the same objects used by the daemon oracle.
#[path = "compat_oracle/fixtures.rs"]
mod fixtures;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const INDEX_SHA256: &str = "f6ab2fe6c2e908d4cc0961554e6f71b38c7db643f28eb000c191a65e5e2140bb";

fn observation(stock: &Value, output: Output, direct_hit: bool) -> Result<Value> {
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    let signature = stdout
        .strip_suffix('\n')
        .and_then(|s| s.strip_prefix("matched\t"));
    let consistent = if direct_hit {
        stock["verdict"] == "detected"
            && signature.is_some()
            && signature == stock["signature"].as_str()
    } else {
        stdout == "unmatched\n"
    };
    Ok(json!({
        "stdout": stdout, "stderr": stderr, "exit_code": output.status.code(),
        "matcher_signature": signature, "stock_instream": stock,
        "agrees_with_fixture": consistent && output.status.success() && stderr.is_empty(),
    }))
}

fn run(binary: &Path, official: &Path) -> Result<()> {
    if fixtures::file_hash(official)? != INDEX_SHA256 {
        return Err("official index differs from the verified generation".into());
    }
    let stock: Value = serde_json::from_str(include_str!("../docs/compat-reference.json"))?;
    let tmp = tempfile::tempdir()?;
    let path = tmp.path();
    fixtures::write_rules(path)?;
    for name in ["fixture.hdb", "fixture.hsb"] {
        if stock["profiles"]["local"]["database_sha256"][name]
            != fixtures::file_hash(&path.join(name))?
        {
            return Err(format!("local signature database differs from stock: {name}").into());
        }
    }
    let local = path.join("local.bhi");
    let build = Command::new(binary)
        .arg("build")
        .args([&local, &path.join("fixture.hdb"), &path.join("fixture.hsb")])
        .output()?;
    if !build.status.success() {
        return Err(format!(
            "fixture build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        )
        .into());
    }
    let corpus = fixtures::corpus()?;
    let mut rows = Map::new();
    let mut success = true;
    for (profile, index) in [("local", local.as_path()), ("official", official)] {
        let mut cases = Map::new();
        for (&name, bytes) in &corpus {
            let baseline = &stock["profiles"][profile]["scans"][name];
            let sha = fixtures::hex(&Sha256::digest(bytes));
            if baseline["sha256"] != sha || !baseline["instream"]["reply"].is_string() {
                return Err(format!("missing or stale reference for {profile}/{name}").into());
            }
            let body = path.join("object");
            fs::write(&body, bytes)?;
            let output = Command::new(binary)
                .args(["scan", "memory"])
                .arg(index)
                .arg(body)
                .output()?;
            let direct_hit = profile == "local" && matches!(name, "detected" | "competing");
            let row = observation(&baseline["instream"], output, direct_hit)?;
            success &= row["agrees_with_fixture"] == true;
            cases.insert(name.into(), row);
        }
        rows.insert(profile.into(), Value::Object(cases));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "scope": "whole-file matcher", "backend": "memory", "profiles": rows,
            "gaps": ["daemon protocol", "complete clean verdict", "extracted objects", "daemon scan limits"],
        }))?
    );
    if !success {
        return Err("unexpected offline matcher result".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [binary, official] = args.as_slice() else {
        return Err("usage: compat_matcher BARNACLE OFFICIAL_INDEX".into());
    };
    run(Path::new(binary), Path::new(official))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn changed_cli_signature_or_exit_status_fails_a_direct_match() {
        let stock = json!({"verdict": "detected", "signature": "Fixture.Exact"});
        for (line, exit) in [
            ("matched\tFixture.Other\n", 0),
            ("matched\tFixture.Exact\n", 1),
            ("unmatched\n", 0),
        ] {
            let output = Output {
                status: ExitStatus::from_raw(exit << 8),
                stdout: line.into(),
                stderr: Vec::new(),
            };
            assert_eq!(
                observation(&stock, output, true).unwrap()["agrees_with_fixture"],
                false
            );
        }
    }
}
