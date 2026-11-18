//! Measure two passes over PE section payloads or known section digest keys in a fresh Linux guest.
#[path = "stock_profile/cgroup.rs"]
mod cgroup;

use cgroup::Counters;
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn reply(output: &mut impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    if output.read_line(&mut line)? == 0 {
        return Err(invalid("benchmark exited before replying"));
    }
    Ok(line)
}

fn pass(line: &str, trace: &str) -> io::Result<Value> {
    let fields: Vec<_> = line.split_whitespace().collect();
    let [count, elapsed, p95, hits, hash] = fields.as_slice() else {
        return Err(invalid("invalid hash benchmark report"));
    };
    let number = |s: &str| s.parse::<u64>().map_err(io::Error::other);
    let (count, elapsed, p95, hits) = (
        number(count)?,
        number(elapsed)?,
        number(p95)?,
        number(hits)?,
    );
    let (expected_count, expected_hits) = match trace {
        "file" => (4096, 0),
        "digest" => (65536, 32768),
        _ => return Err(invalid("unknown trace")),
    };
    if elapsed == 0
        || p95 == 0
        || count != expected_count
        || hits != expected_hits
        || hash.len() != 64
        || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("unexpected result count, hits, timing or checksum"));
    }
    Ok(
        json!({"requests":count,"hits":hits,"checksum":hash,"elapsed_ns":elapsed,"p95_ns":p95,"per_second":count as f64*1e9/elapsed as f64}),
    )
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [
        backend,
        index,
        queries,
        corpus,
        trace,
        concurrency,
        group,
        bench,
    ] = args.as_slice()
    else {
        return Err(invalid(
            "usage: section_profile memory|mmap INDEX QUERIES CORPUS file|digest 1|4 SCANNER_CGROUP HASH_BENCH",
        ));
    };
    if !matches!(backend.as_str(), "memory" | "mmap") || !matches!(concurrency.as_str(), "1" | "4")
    {
        return Err(invalid("unsupported backend or concurrency"));
    }
    let input = match trace.as_str() {
        "file" => corpus,
        "digest" => queries,
        _ => return Err(invalid("unsupported trace")),
    };
    // Charge the active trace's input pages to the separate driver cgroup before the scan.
    io::copy(&mut File::open(input)?, &mut io::sink())?;
    let group = Path::new(group);
    let start = Instant::now();
    let mut child = Command::new("/bin/sh")
        .args([
            "-ec",
            "echo $$ > \"$1/cgroup.procs\"; shift; exec \"$@\"",
            "section-profile",
        ])
        .arg(group)
        .args([bench, backend, index, trace, input, concurrency])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let measured = (|| {
        let mut stdin = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        if reply(&mut output)?.trim_end() != "READY" {
            return Err(invalid("hash benchmark failed to become ready"));
        }
        let startup_ns = start.elapsed().as_nanos() as u64;
        let ready = Counters::read(group)?.json();
        let mut results = serde_json::Map::new();
        let mut checksum = Value::Null;
        for phase in ["cold", "warm"] {
            writeln!(stdin, "run")?;
            stdin.flush()?;
            let mut result = pass(&reply(&mut output)?, trace)?;
            if phase == "warm" && result["checksum"] != checksum {
                return Err(invalid("cold and warm lookup results differ"));
            }
            checksum = result["checksum"].clone();
            result["cgroup"] = Counters::read(group)?.json();
            results.insert(phase.into(), result);
        }
        std::thread::sleep(Duration::from_secs(10));
        let idle = Counters::read(group)?.json();
        Ok(
            json!({"backend":backend, "trace":trace, "concurrency":concurrency.parse::<u8>().unwrap(), "startup_ns":startup_ns, "ready":ready, "passes":results, "idle":idle}),
        )
    })();
    if measured.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    let report = measured?;
    if !status.success() {
        return Err(io::Error::other(format!("hash benchmark exited {status}")));
    }
    println!("{report}");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn detects_changed_counts_and_empty_timing() {
        let checksum = "f".repeat(64);
        assert!(super::pass(&format!("65536 100 1 32768 {checksum}"), "digest").is_ok());
        assert!(super::pass(&format!("65536 100 1 0 {checksum}"), "digest").is_err());
        assert!(super::pass(&format!("4096 0 0 0 {checksum}"), "file").is_err());
    }
}
