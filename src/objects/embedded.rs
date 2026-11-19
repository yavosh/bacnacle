use super::{ChildSink, Handling, archive};
use aho_corasick::AhoCorasick;
use std::io;
use std::sync::LazyLock;

const MAGICS: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "CL_TYPE_ZIP"),
    (b"MSCF\0\0\0\0", "CL_TYPE_MSCAB"),
    (b"7z\xbc\xaf\x27\x1c", "CL_TYPE_7Z"),
    (b"\x60\xea", "CL_TYPE_ARJ"),
    (b"Rar!\x1a\x07\0", "CL_TYPE_RAR"),
];
static FINDER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(MAGICS.iter().map(|(magic, _)| *magic)).expect("static archive file types")
});

pub(super) fn contents(bytes: &[u8], kind: &str, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    if kind == "CL_TYPE_ZIP" {
        archive::zip_single(bytes, sink)
    } else {
        archive::extract(bytes, sink)
    }
}

pub(super) fn enabled(carrier: &str) -> bool {
    !matches!(
        carrier,
        "CL_TYPE_GZ"
            | "CL_TYPE_CPIO_OLD"
            | "CL_TYPE_ZIP"
            | "CL_TYPE_OLD_TAR"
            | "CL_TYPE_POSIX_TAR"
            | "CL_TYPE_PART_ANY"
    )
}

pub(super) fn extract(
    bytes: &[u8],
    carrier: &str,
    offsets: std::ops::Range<usize>,
    count: &mut usize,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let mut result = Handling::Unrecognized;
    let max_files = sink.max_files();
    let mut start = offsets.start;
    while start < offsets.end {
        sink.check()?;
        let end = start.saturating_add(65536).min(offsets.end);
        // Look ahead for the eight-byte CAB identifier at a chunk boundary.
        let window = &bytes[start..end.saturating_add(7).min(bytes.len())];
        for found in FINDER.find_iter(window) {
            let at = start + found.start();
            if at >= end {
                break;
            }
            let kind = MAGICS[found.pattern().as_usize()].1;
            let suffix = &bytes[at..];
            if kind == "CL_TYPE_ARJ" && !matches!(suffix.get(9..11), Some([0..=2, 2])) {
                continue;
            }
            // Both counters include offset zero and same-type markers, which stock
            // records before deciding whether this carrier permits extraction.
            if kind == "CL_TYPE_ZIP" {
                if max_files != 0 && *count > max_files {
                    continue;
                }
            } else if *count >= 10 {
                continue;
            }
            *count += 1;
            if at == 0 || kind == carrier || kind == "CL_TYPE_RAR" {
                continue;
            }
            sink.check()?;
            match sink.embedded_archive(kind, suffix)? {
                Handling::Stopped => return Ok(Handling::Stopped),
                Handling::Incomplete => return Ok(Handling::Incomplete),
                Handling::Complete if result == Handling::Unrecognized => {
                    result = Handling::Complete
                }
                _ => {}
            }
        }
        start = end;
    }
    Ok(result)
}
