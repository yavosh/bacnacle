//! Conservative admission to the pinned engine's raw whole-file match stage.
//! ClamAV 1.4.3 runs format parsers before that stage and skips some types entirely.
//! These guards deliberately accept fewer files than the built-in filetypes_int.h.
//! External type definitions are never used with this path.

/// This is CL_FILE_MBUFF_SIZE in the pinned engine's filetypes.h.
pub(super) const HEADER_SIZE: usize = 1024;

pub(super) fn eligible(header: &[u8]) -> bool {
    if header.len() <= 5 {
        return false;
    }
    // Exclude the leading pairs of all fixed-offset-zero built-in types. Python
    // bytecode uses CR LF at bytes 2 and 3 instead. Include BOMs for encoded text.
    const PREFIXES: &[&[u8; 2]] = &[
        b"\x1f\x8b",
        b"#@",
        b"%!",
        b"%P",
        b"(T",
        b".R",
        b"07",
        b"7z",
        b"7\x7f",
        b">F",
        b"AL",
        b"BM",
        b"BZ",
        b"CW",
        b"Da",
        b"De",
        b"EG",
        b"En",
        b"ER",
        b"FW",
        b"Fo",
        b"Fr",
        b"GI",
        b"HW",
        b"Hi",
        b"ID",
        b"II",
        b"IT",
        b"L\0",
        b"MM",
        b"MS",
        b"MZ",
        b"Me",
        b"Og",
        b"PK",
        b"RI",
        b"Ra",
        b"SI",
        b"SQ",
        b"SY",
        b"SZ",
        b"Su",
        b"To",
        b"X-",
        b"ZW",
        b"[a",
        b"\x60\xea",
        b"q\xc7",
        b"v:",
        b"xa",
        b"x\x9f",
        b"{\n",
        b"{ ",
        b"{\\",
        b"\x7fE",
        b"\x89P",
        b"\xb6\xb9",
        b"\xc7q",
        b"\xca\xfe",
        b"\xce\xfa",
        b"\xcf\xfa",
        b"\xd0\xcf",
        b"\xd9\xd5",
        b"\xe4R",
        b"\xfd7",
        b"\xfe\xed",
        b"\xff\xd8",
        b"\xff\xfb",
        b"\xef\xbb",
        b"\xfe\xff",
        b"\xff\xfe",
    ];
    // The built-in types with two leading NULs are JPEG2000 and MPEG.
    // Keep their three-byte prefixes and the UTF-32 byte-order markers guarded.
    let zero_prefix = matches!(header[..3], [0, 0, 0 | 1 | 0xfe | 0xff]);
    if zero_prefix
        || PREFIXES.iter().any(|prefix| header.starts_with(*prefix))
        || [
            b"Received: ".as_slice(),
            b"Received-SPF: ",
            b"Return-Path: ",
            b"Return-path: ",
        ]
        .iter()
        .any(|field| header.starts_with(field))
        || header.starts_with(b"begin ")
        || header[2..4] == *b"\r\n"
        || header[1..4] == *b"\r\r\n"
        || header.get(2..4).is_some_and(|p| p == b"-l" || p == b"-p")
        || header.get(4..6) == Some(b"\xd0\xcf")
        || header.get(510..512) == Some(b"\x55\xaa")
        || header.get(512..516) == Some(b"EFI ")
        || header.get(257..262) == Some(b"ustar")
    {
        return false;
    }
    // The other file-type records use content markers (some without a fixed offset).
    // A short prefix suffices to withhold a verdict for a possible format match.
    const MARKERS: &[&[u8]] = &[
        b"\x01CD",
        b"\x00BE",
        b"%PDF",
        b"7z\xbc",
        b"InstallS",
        b"MSCF",
        b"MZ",
        b"PK\x03\x04",
        b"Rar!",
        b"\x60\xea",
        b"\xa3H",
        b"\xef\xbe",
        b"MIME",
        b"\nFrom",
        b"\nMessage",
        b"\nReceiv",
        b"Delivere",
        b"/RGB",
        b"\x19\x04\x00\x10",
        b"koly",
    ];
    if MARKERS
        .iter()
        .any(|m| header.windows(m.len()).any(|s| s.eq_ignore_ascii_case(m)))
    {
        return false;
    }
    // HTML recognition also checks UTF-16 text. Cover single- and double-byte markup.
    if header.iter().enumerate().any(|(i, &byte)| {
        byte == b'<'
            && [1, 2].iter().any(|step| {
                header
                    .get(i + step)
                    .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'?' | b'%'))
            })
    }) {
        return false;
    }
    // The built-in Mydoom log heuristic can run before the raw scan. Withhold
    // a result if its first 32-byte record passes the reference checksum.
    if header.len() >= 64 {
        let words = header[..32].as_chunks::<4>().0;
        let first = u32::from_be_bytes(words[0]);
        let sum = words[1..].iter().fold(0u32, |sum, &w| {
            sum.wrapping_add(u32::from_be_bytes(w) ^ !first)
        });
        if sum == first {
            return false;
        }
    }
    true
}
