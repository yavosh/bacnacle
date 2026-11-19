//! Conservative admission to the pinned engine's raw whole-file match stage.
//! ClamAV 1.4.3 runs format parsers before that stage and skips some types entirely.
//! These guards deliberately accept fewer files than the built-in filetypes_int.h.
//! External type definitions are never used with this path.

/// This is CL_FILE_MBUFF_SIZE in the pinned engine's filetypes.h.
pub(super) const HEADER_SIZE: usize = 1024;

pub(super) fn eligible(header: &[u8], file_type: &str) -> bool {
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
    // A zero-filled sector alone does not select either format.
    let zero_prefix = header.starts_with(b"\0\0\0\x0cjP  \r\n\x87\n")
        || matches!(
            header[..4],
            [0, 0, 1, 0xb3 | 0xba] | [0, 0, 0xfe, 0xff] | [0, 0, 0xff, 0xfe]
        );
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
    // Stock defers embedded archive markers to its post-raw pass. Other
    // content markers can still change the outer type before raw matching.
    const MARKERS: &[&[u8]] = &[
        b"\x01CD",
        b"\x00BE",
        b"%PDF",
        b"InstallS",
        b"MZ",
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
    // The classifier already checked HTML and mail in a printable text header.
    // Office XML and XDP can select separate document parsers.
    let generic_xml = file_type == "CL_TYPE_TEXT_ASCII"
        && header.starts_with(b"<")
        && header
            .iter()
            .all(|b| !b.is_ascii() || b.is_ascii_graphic() || b.is_ascii_whitespace())
        && std::str::from_utf8(header)
            .err()
            .is_none_or(|e| e.error_len().is_none())
        && ![
            b"<%".as_slice(),
            b"<!",
            b"workbook",
            b"worddocument",
            b"word.document",
            b"hwpml",
            b"<xdp:",
        ]
        .iter()
        .any(|m| header.windows(m.len()).any(|s| s.eq_ignore_ascii_case(m)));
    if !generic_xml
        && header.iter().enumerate().any(|(i, &byte)| {
            byte == b'<'
                && [1, 2].iter().any(|&width| {
                    [
                        b"a ".as_slice(),
                        b"head",
                        b"html",
                        b"iframe",
                        b"img",
                        b"object",
                        b"script",
                        b"table",
                        b"%",
                        b"?",
                        b"!",
                        b"xdp:",
                    ]
                    .iter()
                    .any(|tag| {
                        tag.iter().enumerate().all(|(j, b)| {
                            header
                                .get(i + (j + 1) * width)
                                .is_some_and(|s| s.eq_ignore_ascii_case(b))
                        })
                    })
                })
        })
    {
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

#[cfg(test)]
mod tests {
    use super::eligible;

    #[test]
    fn powerpoint_atom_admission_preserves_zero_prefix_and_partition_checks() {
        let eligible = |header: &[u8]| eligible(header, "CL_TYPE_BINARY_DATA");
        assert!(eligible(b"\0\0\xa0\x0f\x04\0\0\0H\0i\0"));
        for guarded in [
            b"\0\0\0\x0cjP  \r\n\x87\n".as_slice(),
            b"\0\0\x01\xb3ordinary",
            b"\0\0\x01\xbaordinary",
            b"\0\0\xfe\xff\0\0\0A",
        ] {
            assert!(!eligible(guarded));
        }
        let mut partition = [0; 516];
        partition[..4].copy_from_slice(b"\0\0\xa0\x0f");
        partition[510..512].copy_from_slice(b"\x55\xaa");
        assert!(!eligible(&partition));
        partition[510..512].fill(0);
        partition[512..].copy_from_slice(b"EFI ");
        assert!(!eligible(&partition));
    }

    #[test]
    fn text_classification_and_specialized_xml_control_raw_admission() {
        let document = b"<?xml version=\"1.0\"?><report><price>30</price></report>";
        assert!(eligible(document, "CL_TYPE_TEXT_ASCII"));
        assert!(!eligible(document, "CL_TYPE_HTML"));
        for header in [
            b"<?xml version=\"1.0\"?><Workbook/>".as_slice(),
            b"<xdp:xdp/>",
            b"<% directive %>",
        ] {
            assert!(!eligible(header, "CL_TYPE_TEXT_ASCII"));
        }
    }
}
