//! Offline compiler and matcher for whole-file hash databases.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barnacle::index::{self, Index};
use barnacle::{Algorithm, Feed, PINNED_FLEVEL, hash_reader};

const USAGE: &str = "usage:
  barnacle build INDEX [--official] [--flevel LEVEL] DATABASE...
  barnacle scan BACKEND INDEX FILE
  barnacle lookup BACKEND INDEX ALGORITHM HEX SIZE
BACKEND: memory, pread, mmap. ALGORITHM: md5, sha1, sha256.
Use - for FILE to read standard input.";

fn input_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn text(arg: &OsStr) -> io::Result<&str> {
    arg.to_str()
        .ok_or_else(|| input_error("expected a UTF-8 argument"))
}

fn open(backend: &OsStr, path: &Path) -> io::Result<Index> {
    match text(backend)? {
        "memory" => Index::open_memory(path),
        "pread" => Index::open_pread(path),
        "mmap" => {
            // SAFETY: the documented CLI contract requires an immutable generation.
            // The compiler publishes a read-only inode and never modifies it later.
            unsafe { Index::open_mapped(path) }
        }
        _ => Err(input_error(USAGE)),
    }
}

fn build(path: &Path, inputs: &[OsString]) -> io::Result<()> {
    let mut official = false;
    let mut level = PINNED_FLEVEL;
    let mut paths = Vec::new();
    let mut inputs = inputs.iter();
    while let Some(arg) = inputs.next() {
        if arg == "--official" {
            official = true;
        } else if arg == "--flevel" {
            let value = inputs
                .next()
                .ok_or_else(|| input_error("missing functionality level"))?;
            level = text(value)?
                .parse()
                .map_err(|_| input_error("invalid functionality level"))?;
        } else {
            paths.push(PathBuf::from(arg));
        }
    }
    if paths.is_empty() {
        return Err(input_error("at least one database path is required"));
    }
    let mut feed = Feed::load(&paths, official, level)?;
    index::build(path, &mut feed.rules)?;
    for file in feed.inventory {
        println!("{file}");
    }
    println!(
        "unique_keys={} duplicate_keys={}",
        feed.rules.len(),
        feed.duplicate_keys
    );
    Ok(())
}

fn scan(index: &Index, file: impl Read) -> io::Result<Option<String>> {
    hash_reader(file)?.lookup(|alg, digest, size| index.lookup(alg, digest, size))
}

fn lookup(index: &Index, alg: &OsStr, hex: &OsStr, size: &OsStr) -> io::Result<Option<String>> {
    let (algorithm, width) = match text(alg)? {
        "md5" => (Algorithm::Md5, 16),
        "sha1" => (Algorithm::Sha1, 20),
        "sha256" => (Algorithm::Sha256, 32),
        _ => return Err(input_error("unknown hash algorithm")),
    };
    let hex = text(hex)?;
    if hex.len() != width * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(input_error("invalid hexadecimal digest for algorithm"));
    }
    let mut digest = [0; 32];
    for (i, b) in digest[..width].iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let size: u64 = text(size)?
        .parse()
        .map_err(|_| input_error("expected a file size in bytes (u64)"))?;
    if let Ok(size) = u32::try_from(size)
        && let Some(name) = index.lookup(algorithm, &digest, Some(size))?
    {
        return Ok(Some(name));
    }
    index.lookup(algorithm, &digest, None)
}

fn run(args: &[OsString]) -> io::Result<()> {
    let result = match args {
        [cmd, path, inputs @ ..] if cmd == "build" => return build(Path::new(path), inputs),
        [cmd, backend, path, input] if cmd == "scan" => {
            let index = open(backend, Path::new(path))?;
            if input == "-" {
                scan(&index, io::stdin().lock())?
            } else {
                scan(&index, File::open(input)?)?
            }
        }
        [cmd, backend, path, algorithm, hex, size] if cmd == "lookup" => {
            lookup(&open(backend, Path::new(path))?, algorithm, hex, size)?
        }
        _ => return Err(input_error(USAGE)),
    };
    match result {
        Some(name) => println!("matched\t{name}"),
        None => println!("unmatched"),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(&env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("barnacle: {error}");
            ExitCode::FAILURE
        }
    }
}
