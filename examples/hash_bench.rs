//! Replay the pinned file and digest traces directly against a resident hash index.
#[path = "bench/corpus.rs"]
mod corpus;

use barnacle::{Algorithm, Feed, PINNED_FLEVEL, hash_reader, index::Index};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufRead, BufWriter, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const LOOKUP_COUNT: usize = 65536;

fn prepare_files(output: &Path) -> io::Result<()> {
    use sha3::{Shake256, digest::ExtendableOutput};
    let mut file = tempfile::NamedTempFile::new_in(output.parent().unwrap_or(Path::new(".")))?;
    let mut buffer = Vec::new();
    for (id, (offset, length)) in corpus::spans().enumerate() {
        if offset == 0 && id != 0 {
            continue;
        }
        buffer.resize(length, 0);
        Shake256::digest_xof(format!("barnacle-v1/{id}").as_bytes(), &mut buffer);
        file.write_all(&buffer)?;
    }
    file.persist_noclobber(output)?;
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn prepare_queries(output: &Path, paths: &[PathBuf]) -> io::Result<()> {
    let (mut rules, _) = Feed::load_eligible(paths, true, PINNED_FLEVEL)?;
    if rules.is_empty() {
        return Err(invalid("empty eligible rule set"));
    }
    rules.sort_unstable_by(|a, b| {
        (a.algorithm, a.digest, a.size, &a.name).cmp(&(b.algorithm, b.digest, b.size, &b.name))
    });
    let mut out = BufWriter::new(File::create(output)?);
    for i in 0..LOOKUP_COUNT {
        let random = Sha256::digest(i.to_string().as_bytes());
        let position = u64::from_be_bytes(random[..8].try_into().unwrap()) % rules.len() as u64;
        let rule = &rules[position as usize];
        let mut digest = rule.digest;
        if i % 2 == 1 {
            digest[0] ^= 0x80;
        }
        out.write_all(&[rule.algorithm as u8])?;
        out.write_all(&digest)?;
        out.write_all(&rule.size.unwrap_or(65536).to_le_bytes())?;
    }
    out.flush()
}

enum Trace {
    Files(File, Vec<(u64, usize)>),
    Digests(Vec<(Algorithm, [u8; 32], u32)>),
}

impl Trace {
    fn open(kind: &str, path: &Path) -> io::Result<Self> {
        match kind {
            "file" => {
                let file = File::open(path)?;
                let spans: Vec<_> = corpus::spans().collect();
                let &(last, length) = spans.last().unwrap();
                if file.metadata()?.len() != last + length as u64 {
                    return Err(invalid("unexpected corpus size"));
                }
                Ok(Self::Files(file, spans))
            }
            "digest" => {
                let bytes = std::fs::read(path)?;
                if bytes.len() != LOOKUP_COUNT * 37 {
                    return Err(invalid("unexpected query file size"));
                }
                let mut queries = Vec::with_capacity(LOOKUP_COUNT);
                for row in bytes.as_chunks::<37>().0 {
                    let algorithm = Algorithm::ALL
                        .get(usize::from(row[0]))
                        .ok_or_else(|| invalid("invalid query algorithm"))?;
                    let hash = row[1..33].try_into().unwrap();
                    let size = u32::from_le_bytes(row[33..].try_into().unwrap());
                    queries.push((*algorithm, hash, size));
                }
                Ok(Self::Digests(queries))
            }
            _ => Err(invalid("unknown trace")),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Files(_, spans) => spans.len(),
            Self::Digests(queries) => queries.len(),
        }
    }

    fn lookup(&self, i: usize, index: &Index, buffer: &mut Vec<u8>) -> io::Result<Option<String>> {
        match self {
            Self::Files(file, spans) => {
                let (offset, size) = spans[i];
                buffer.resize(size, 0);
                file.read_exact_at(buffer, offset)?;
                hash_reader(buffer.as_slice())?.lookup(|a, d, s| index.lookup(a, d, s))
            }
            Self::Digests(queries) => {
                let (algorithm, digest, size) = &queries[i];
                match index.lookup(*algorithm, digest, Some(*size))? {
                    Some(name) => Ok(Some(name)),
                    None => index.lookup(*algorithm, digest, None),
                }
            }
        }
    }
}

fn replay(trace: &Trace, index: &Index, concurrency: usize) -> io::Result<()> {
    let next = AtomicUsize::new(0);
    let start = Instant::now();
    let mut results = std::thread::scope(|s| {
        let mut workers = Vec::new();
        for _ in 0..concurrency {
            workers.push(s.spawn(|| {
                let mut buffer = Vec::new();
                let mut rows = Vec::new();
                loop {
                    let started = Instant::now();
                    let id = next.fetch_add(1, Ordering::Relaxed);
                    if id >= trace.len() {
                        break;
                    }
                    let label = trace.lookup(id, index, &mut buffer)?;
                    rows.push((id, started.elapsed().as_nanos(), label));
                }
                Ok::<_, io::Error>(rows)
            }));
        }
        let mut rows = Vec::with_capacity(trace.len());
        for worker in workers {
            rows.extend(
                worker
                    .join()
                    .map_err(|_| io::Error::other("worker panic"))??,
            );
        }
        Ok::<_, io::Error>(rows)
    })?;
    let elapsed = start.elapsed().as_nanos();
    results.sort_unstable_by_key(|row| row.0);
    let mut checksum = Sha256::new();
    let mut hits = 0;
    for (_, _, label) in &results {
        if let Some(name) = label {
            checksum.update([1]);
            checksum.update((name.len() as u64).to_le_bytes());
            checksum.update(name.as_bytes());
            hits += 1;
        } else {
            checksum.update([0]);
        }
    }
    let count = results.len();
    if count != trace.len() || (matches!(trace, Trace::Files(..)) && hits != 0) {
        return Err(invalid("unexpected file detection or incomplete trace"));
    }
    results.sort_unstable_by_key(|row| row.1);
    let p95 = results[(95 * count).div_ceil(100) - 1].1;
    let hex: String = checksum
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("{count} {elapsed} {p95} {hits} {hex}");
    io::stdout().flush()
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [action, output] = args.as_slice()
        && action == "prepare-files"
    {
        return prepare_files(Path::new(output));
    }
    if args.first().map(String::as_str) == Some("prepare") && args.len() >= 3 {
        return prepare_queries(
            Path::new(&args[1]),
            &args[2..].iter().map(PathBuf::from).collect::<Vec<_>>(),
        );
    }
    let [backend, index, kind, input, concurrency] = args.as_slice() else {
        return Err(invalid(
            "usage: hash_bench prepare-files OUTPUT | prepare OUTPUT DB... | BACKEND INDEX file|digest INPUT 1|4",
        ));
    };
    let concurrency = match concurrency.as_str() {
        "1" => 1,
        "4" => 4,
        _ => return Err(invalid("unsupported concurrency")),
    };
    let path = Path::new(index);
    let index = match backend.as_str() {
        "memory" => Index::open_memory(path)?,
        "pread" => Index::open_pread(path)?,
        // The harness keeps an immutable index on a private disk for the entire trial.
        "mmap" => unsafe { Index::open_mapped(path)? },
        _ => return Err(invalid("unknown backend")),
    };
    let trace = Trace::open(kind, Path::new(input))?;
    println!("READY");
    io::stdout().flush()?;
    for line in io::stdin().lock().lines() {
        match line?.as_str() {
            "run" => replay(&trace, &index, concurrency)?,
            _ => return Err(invalid("unknown benchmark command")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::corpus;

    #[test]
    fn file_trace_reuses_the_first_object_without_advancing_the_offset() {
        let spans: Vec<_> = corpus::spans().collect();
        assert_eq!(spans.len(), 4096);
        assert_eq!(spans[4], spans[0]);
        assert_eq!(spans[5], (348160, 16384));
        let &(last, size) = spans.last().unwrap();
        assert_eq!(last + size as u64, 352325632);
        assert_eq!(spans.iter().map(|(_, size)| size).sum::<usize>(), 356515840);
    }
}
