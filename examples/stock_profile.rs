//! Profile the pinned Debian clamd in a fresh Linux cgroup v2 on an isolated guest.
#[path = "stock_profile/cgroup.rs"]
mod cgroup;
#[path = "bench/corpus.rs"]
mod corpus;

use cgroup::Counters;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;

const POLL: Duration = Duration::from_millis(20);
const TIMEOUT: Duration = Duration::from_secs(90);

fn request(socket: &Path, command: &[u8], payload: Option<&[u8]>) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(command)?;
    if let Some(data) = payload {
        stream.write_all(&(data.len() as u32).to_be_bytes())?;
        stream.write_all(data)?;
        stream.write_all(&[0; 4])?;
    }
    let mut reply = String::new();
    stream.take(4097).read_to_string(&mut reply)?;
    if reply.len() > 4096 || !reply.ends_with('\0') {
        return Err(io::Error::other(format!("invalid clamd reply: {reply:?}")));
    }
    reply.pop();
    Ok(reply)
}

fn expect(socket: &Path, command: &[u8], payload: Option<&[u8]>, expected: &str) -> io::Result<()> {
    let actual = request(socket, command, payload)?;
    if actual != expected {
        return Err(io::Error::other(format!(
            "expected {expected:?}, received {actual:?}"
        )));
    }
    Ok(())
}

struct Daemon {
    child: Child,
    log: NamedTempFile,
}

impl Daemon {
    fn start(config: &Path, socket: &Path, group: &Path) -> io::Result<Self> {
        if socket.exists()
            || !fs::read_to_string(group.join("cgroup.procs"))?
                .trim()
                .is_empty()
        {
            return Err(io::Error::other(
                "requires an unused socket and empty scanner cgroup",
            ));
        }
        let log = NamedTempFile::new()?;
        let child = Command::new("/bin/sh")
            .arg("-ec").arg("echo $$ > \"$1/cgroup.procs\"; exec stdbuf -oL -eL /usr/sbin/clamd --config-file \"$2\"")
            .arg("stock_profile").arg(group).arg(config)
            .stdin(Stdio::null()).stdout(log.as_file().try_clone()?).stderr(log.as_file().try_clone()?).spawn()?;
        let mut daemon = Self { child, log };
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = daemon.child.try_wait()? {
                return Err(io::Error::other(format!(
                    "clamd exited {status}: {}",
                    fs::read_to_string(daemon.log.path())?
                )));
            }
            match expect(socket, b"zPING\0", None, "PONG") {
                Ok(()) => return Ok(daemon),
                Err(e)
                    if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {}
                Err(e) => return Err(e),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("clamd readiness timed out"));
            }
            thread::sleep(POLL);
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn replay(
    socket: &Path,
    file: &File,
    trace: &[(u64, usize)],
    concurrency: usize,
    done: &AtomicUsize,
) -> io::Result<Value> {
    let next = AtomicUsize::new(0);
    let start = Instant::now();
    let mut timings = thread::scope(|scope| {
        let workers: Vec<_> = (0..concurrency)
            .map(|_| {
                scope.spawn(|| {
                    let mut timings = Vec::new();
                    let mut buffer = vec![0; 262144];
                    loop {
                        let id = next.fetch_add(1, Ordering::Relaxed);
                        let Some(&(offset, size)) = trace.get(id) else {
                            break;
                        };
                        let began = Instant::now();
                        let data = &mut buffer[..size];
                        file.read_exact_at(data, offset)?;
                        expect(socket, b"zINSTREAM\0", Some(data), "stream: OK")?;
                        timings.push(began.elapsed().as_nanos());
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok::<_, io::Error>(timings)
                })
            })
            .collect();
        let mut all = Vec::with_capacity(trace.len());
        for worker in workers {
            all.extend(
                worker
                    .join()
                    .map_err(|_| io::Error::other("scan worker panicked"))??,
            );
        }
        Ok::<_, io::Error>(all)
    })?;
    let elapsed = start.elapsed();
    timings.sort_unstable();
    let p95 = timings[(timings.len() * 95).div_ceil(100) - 1];
    Ok(
        json!({"requests":timings.len(),"elapsed_ns":elapsed.as_nanos(), "p95_ns":p95,
        "per_second":timings.len() as f64 / elapsed.as_secs_f64()}),
    )
}

fn run() -> io::Result<Value> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [mode, config, socket, group, file, concurrency] = args.as_slice() else {
        return Err(io::Error::other(
            "usage: stock_profile full|ready CONFIG SOCKET SCANNER_CGROUP CORPUS 1|4",
        ));
    };
    if mode != "ready" && mode != "full" {
        return Err(io::Error::other("unsupported profiling mode"));
    }
    let concurrency = match concurrency.to_str() {
        Some("1") => 1,
        Some("4") => 4,
        _ => return Err(io::Error::other("concurrency must be 1 or 4")),
    };
    let package = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    if !package.status.success() || package.stdout != b"1.4.3+dfsg-1" {
        return Err(io::Error::other(
            "expected Debian clamav-daemon 1.4.3+dfsg-1",
        ));
    }
    let group = Path::new(group);
    let socket = Path::new(socket);
    let before = Counters::read(group)?;
    let start = Instant::now();
    let daemon = Daemon::start(Path::new(config), socket, group)?;
    let startup_ms = start.elapsed().as_secs_f64() * 1000.;
    let ready = Counters::read(group)?;
    let version = request(socket, b"zVERSION\0", None)?;
    if version.split('/').next() != Some("ClamAV 1.4.3") {
        return Err(io::Error::other(format!("unexpected version: {version:?}")));
    }
    let mut report = json!({"mode":mode.to_str(),"package":"1.4.3+dfsg-1","concurrency":concurrency,"version":version,"startup_ms":startup_ms,
        "stages":{"before_start":before.json(),"ready":ready.json()}, "passes":{}});
    if mode == "ready" {
        return Ok(report);
    }
    let mut file = File::open(file)?;
    let trace: Vec<_> = corpus::spans().collect();
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let checksum: String = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if checksum != "ceb040d353d99e018381733c3331f2cffe2f4f8489e400865823d562aaad199d" {
        return Err(io::Error::other(
            "file corpus differs from the frozen trace",
        ));
    }
    report["corpus_sha256"] = json!(checksum);
    for phase in ["cold", "warm", "reload"] {
        let done = AtomicUsize::new(0);
        let mut peak = Counters::read(group)?;
        let mut issued = None;
        let mut reload_peak: Option<Counters> = None;
        let mut count_at_activation = None;
        let pass = thread::scope(|scope| {
            let work = scope.spawn(|| replay(socket, &file, &trace, concurrency, &done));
            while !work.is_finished() || (issued.is_some() && count_at_activation.is_none()) {
                let measured = Counters::read(group)?;
                if measured.current > peak.current {
                    peak = measured.clone();
                }
                let count = done.load(Ordering::Relaxed);
                if phase == "reload"
                    && issued.is_none()
                    && (concurrency..trace.len()).contains(&count)
                {
                    let start = Instant::now();
                    report["stages"]["reload_begin"] = measured.json();
                    expect(socket, b"zRELOAD\0", None, "RELOADING")?;
                    issued = Some((start, count));
                }
                if let Some((start, _)) = issued
                    && count_at_activation.is_none()
                {
                    if reload_peak
                        .as_ref()
                        .is_none_or(|p| measured.current > p.current)
                    {
                        reload_peak = Some(measured.clone());
                    }
                    let log = fs::read_to_string(daemon.log.path())?;
                    if log.contains("Database correctly reloaded (")
                        && log.contains("Activating the newly loaded database")
                    {
                        let completed = done.load(Ordering::Relaxed);
                        if completed == trace.len() {
                            return Err(io::Error::other(
                                "traffic ended before reload activation was observed",
                            ));
                        }
                        count_at_activation = Some(completed);
                        report["stages"]["reload_activation"] = measured.json();
                        report["reload_activation_ms"] =
                            json!(start.elapsed().as_secs_f64() * 1000.);
                    } else if start.elapsed() >= TIMEOUT {
                        return Err(io::Error::other("stock database activation timed out"));
                    }
                }
                thread::sleep(POLL);
            }
            work.join()
                .map_err(|_| io::Error::other("traffic thread panicked"))?
        })?;
        report["passes"][phase] = pass;
        if phase == "reload" {
            let (_, count) =
                issued.ok_or_else(|| io::Error::other("traffic ended before reload was issued"))?;
            report["stages"]["reload_window_peak"] = reload_peak.unwrap().json();
            expect(
                socket,
                b"zINSTREAM\0",
                Some(b"post-reload harmless scan"),
                "stream: OK",
            )?;
            report["passes"][phase]["activation_observed"] = json!(true);
            report["passes"][phase]["requests_before_reload"] = json!(count);
            report["passes"][phase]["requests_at_activation"] = json!(count_at_activation);
        }
        report["stages"][format!("{phase}_active_peak")] = peak.json();
        report["stages"][format!("{phase}_end")] = Counters::read(group)?.json();
        if phase == "warm" {
            thread::sleep(Duration::from_secs(10));
            report["stages"]["warm_idle"] = Counters::read(group)?.json();
        }
    }
    Ok(report)
}

fn main() -> io::Result<()> {
    println!("{}", run()?);
    Ok(())
}
