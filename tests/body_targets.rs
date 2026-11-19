//! Resolve extended signature offsets against the same harmless executable objects as stock clamd.
#[path = "../examples/compat_oracle/daemon.rs"]
mod daemon;
#[path = "common/pe.rs"]
mod pe;

use barnacle::body::{BodyIndex, ObjectContext, Offset, Target};
use barnacle::{IgnoreSet, PINNED_FLEVEL};
use std::{fs, io, path::Path, process::Command};

fn put16(bytes: &mut [u8], index: usize, n: u16) {
    bytes[index..index + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(bytes: &mut [u8], index: usize, n: u32) {
    bytes[index..index + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(bytes: &mut [u8], index: usize, n: u64) {
    bytes[index..index + 8].copy_from_slice(&n.to_le_bytes());
}

// Each image has a single data section and carries no instructions.
type Image = (Target, Vec<u8>, usize, usize, usize);

fn images() -> Vec<Image> {
    let mut pe = pe::benign_pe();
    put32(&mut pe, 152 + 16, 0x1020);
    pe.resize(1536, 0);

    let mut elf = vec![0; 1536];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut elf, 16, 2);
    put16(&mut elf, 18, 62);
    put32(&mut elf, 20, 1);
    put64(&mut elf, 24, 0x4020);
    put64(&mut elf, 32, 64);
    put64(&mut elf, 40, 128);
    put16(&mut elf, 52, 64);
    put16(&mut elf, 54, 56);
    put16(&mut elf, 56, 1);
    put16(&mut elf, 58, 64);
    put16(&mut elf, 60, 1);
    put32(&mut elf, 64, 1);
    put32(&mut elf, 68, 4);
    put64(&mut elf, 72, 1024);
    put64(&mut elf, 80, 0x4000);
    put64(&mut elf, 96, 128);
    put64(&mut elf, 104, 128);
    put32(&mut elf, 132, 1);
    put64(&mut elf, 144, 0x4000);
    put64(&mut elf, 152, 1024);
    put64(&mut elf, 160, 128);

    let mut mach = vec![0; 1536];
    mach[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    put32(&mut mach, 4, 0x0100_000c);
    put32(&mut mach, 12, 1);
    put32(&mut mach, 16, 1);
    put32(&mut mach, 20, 152);
    put32(&mut mach, 32, 0x19);
    put32(&mut mach, 36, 152);
    mach[40..46].copy_from_slice(b"__DATA");
    put32(&mut mach, 96, 1);
    mach[104..110].copy_from_slice(b"__data");
    mach[120..126].copy_from_slice(b"__DATA");
    put64(&mut mach, 136, 0x4000);
    put64(&mut mach, 144, 128);
    put32(&mut mach, 152, 1024);
    let mut pe64 = pe.clone();
    pe64.copy_within(376..416, 392);
    put16(&mut pe64, 132, 0x8664);
    put16(&mut pe64, 148, 240);
    put16(&mut pe64, 152, 0x20b);
    put32(&mut pe64, 152 + 108, 16);

    let mut elf32 = vec![0; 1536];
    elf32[..7].copy_from_slice(b"\x7fELF\x01\x02\x01");
    for (at, n) in [
        (16, 2u16),
        (18, 20),
        (40, 52),
        (42, 32),
        (44, 1),
        (46, 40),
        (48, 1),
    ] {
        elf32[at..at + 2].copy_from_slice(&n.to_be_bytes());
    }
    for (at, n) in [
        (20, 1u32),
        (24, 0x4020),
        (28, 52),
        (32, 96),
        (52, 1),
        (56, 1024),
        (60, 0x4000),
        (68, 128),
        (72, 128),
        (100, 1),
        (108, 0x4000),
        (112, 1024),
        (116, 128),
    ] {
        elf32[at..at + 4].copy_from_slice(&n.to_be_bytes());
    }

    let mut mach32 = vec![0; 1536];
    for (at, n) in [
        (0, 0xfeedfaceu32),
        (4, 18),
        (12, 1),
        (16, 2),
        (20, 300),
        (28, 1),
        (32, 124),
        (76, 1),
        (116, 0x4000),
        (120, 128),
        (124, 1024),
        (152, 5),
        (156, 176),
        (160, 1),
        (164, 40),
        (168, 0x4020),
    ] {
        mach32[at..at + 4].copy_from_slice(&n.to_be_bytes());
    }
    vec![
        (Target::Pe, pe64, 544, 512, 512),
        (Target::Elf, elf32, 1056, 1024, 128),
        (Target::MachO, mach32, 1056, 1024, 128),
        (Target::Pe, pe, 544, 512, 512),
        (Target::Elf, elf, 1056, 1024, 128),
        (Target::MachO, mach, 0, 1024, 128),
    ]
}

#[test]
fn sections_entry_points_and_typed_eligibility() -> io::Result<()> {
    for (target, bytes, entry, raw, size) in images() {
        let ctx = ObjectContext::raw(&bytes);
        assert_eq!(ctx.target(), target);
        assert!(ctx.accepts(target) && ctx.accepts(Target::Generic));
        assert!(!ctx.accepts(Target::Html));
        assert_eq!(ctx.is_valid_pe(), target == Target::Pe);
        for (spec, lo, hi) in [
            ("EP+20,5", entry + 20, entry + 25),
            ("S0+13,4", raw + 13, raw + 17),
            ("SL+12", raw + 12, raw + 12),
            ("SE0,3", raw, raw + size + 3),
            ("EOF-16", bytes.len() - 16, bytes.len() - 16),
            ("22,3", 22, 25),
        ] {
            assert_eq!(
                ctx.offset_range(&Offset::parse(spec, target)?, bytes.len()),
                Some(lo..=hi),
                "{spec} on {target:?}"
            );
        }
        assert!(
            ctx.offset_range(&Offset::parse("S1+0", target)?, bytes.len())
                .is_none()
        );
        assert!(
            ctx.offset_range(&Offset::parse("EOF-4096", target)?, bytes.len())
                .is_none()
        );
        assert_eq!(
            ctx.offset_range(&Offset::parse("EP-1", target)?, bytes.len()),
            entry.checked_sub(1).map(|n| n..=n)
        );
    }
    assert!(Offset::parse("EP+0", Target::Html).is_err());
    for invalid in ["S+5", "S2", "EOF-", "*,2", "3,-1", "9999999999"] {
        assert!(Offset::parse(invalid, Target::Pe).is_err(), "{invalid}");
    }
    let plain = b"an ordinary text object";
    assert!(!ObjectContext::raw(plain).accepts(Target::Ascii));
    assert!(ObjectContext::typed(Target::Ascii, plain).accepts(Target::Ascii));
    Ok(())
}

#[test]
fn truncated_executables_keep_absolute_offsets() -> io::Result<()> {
    for (target, bytes, ..) in images() {
        let truncated = &bytes[..16];
        let ctx = ObjectContext::raw(truncated);
        assert_eq!(ctx.target(), target);
        assert!(!ctx.is_valid_pe());
        assert_eq!(
            ctx.offset_range(&Offset::parse("4,2", target)?, 16),
            Some(4..=6)
        );
        for relative in ["EP+0", "SE0", "EOF-2"] {
            assert!(
                ctx.offset_range(&Offset::parse(relative, target)?, 16)
                    .is_none(),
                "{relative}"
            );
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires pinned Debian clamd 1.4.3+dfsg-1"]
fn live_clamd_resolves_executable_offset_boundaries() -> io::Result<()> {
    let version = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "clamav-daemon"])
        .output()?;
    assert_eq!(version.stdout, b"1.4.3+dfsg-1");
    let root = tempfile::tempdir_in("/tmp")?;
    let db = root.path().join("db");
    fs::create_dir(&db)?;
    let mut rules = String::new();
    let mut cases = Vec::new();
    for (variant, (target, image, entry, raw, section_size)) in images().into_iter().enumerate() {
        let ctx = ObjectContext::raw(&image);
        for (n, (spec, low, high)) in [
            ("EP+288,3", entry + 288, entry + 291),
            ("S0+12,2", raw + 12, raw + 14),
            ("SL+16", raw + 16, raw + 16),
            ("SE0", raw, raw + section_size),
        ]
        .into_iter()
        .enumerate()
        {
            let name = format!("Barnacle.Offset.T{}.V{variant}.N{n}", target.id());
            let marker = format!("Marker-{variant}-{}-{n}", target.id());
            let hex: String = marker.bytes().map(|b| format!("{b:02x}")).collect();
            rules.push_str(&format!("{name}:{}:{spec}:{hex}\n", target.id()));
            let range = ctx
                .offset_range(&Offset::parse(spec, target)?, image.len())
                .unwrap();
            for pos in [low - 1, low, high, high + 1] {
                let mut sample = image.clone();
                sample[pos..pos + marker.len()].copy_from_slice(marker.as_bytes());
                let expected = if range.contains(&pos) {
                    format!("stream: {name}.UNOFFICIAL FOUND\0")
                } else {
                    "stream: OK\0".into()
                };
                cases.push((format!("{target:?}/{spec}@{pos}"), sample, expected));
            }
        }
    }
    let path = db.join("positions.ndb");
    fs::write(&path, rules)?;
    let index = BodyIndex::load_sources(&[(&path, false)], PINNED_FLEVEL, &IgnoreSet::default())?;
    let socket = root.path().join("sock");
    let config = root.path().join("clamd.conf");
    fs::write(
        &config,
        format!(
            "Foreground yes\nDatabaseDirectory {}\nLocalSocket {}\nDisableCache yes\n",
            db.display(),
            socket.display()
        ),
    )?;
    let _service = daemon::Daemon::start(Path::new("/usr/sbin/clamd"), &config, &socket)?;
    for (label, sample, expected) in cases {
        let hit = index.first_match(&sample, &ObjectContext::raw(&sample))?;
        let expected_name = expected
            .strip_prefix("stream: ")
            .and_then(|s| s.strip_suffix(" FOUND\0"));
        assert_eq!(hit, expected_name, "Barnacle matcher on {label}");
        assert_eq!(
            daemon::unix_request(&socket, &daemon::stream_frame(&sample)?)?,
            expected,
            "{label}"
        );
    }
    Ok(())
}
