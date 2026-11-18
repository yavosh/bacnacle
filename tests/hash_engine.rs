//! Small fixtures for hash streams and database eligibility.
use barnacle::{Algorithm, Feed, PINNED_FLEVEL, hash_reader};
use std::fs;
use std::io::{self, Read};

#[test]
fn single_pass_stream_matches_all_three_known_digests() {
    // This reader returns one byte per read. It cannot rewind.
    struct Stream(Option<&'static [u8]>);
    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some(bytes) = self.0 else {
                self.0 = Some(b"abc");
                return Err(io::ErrorKind::Interrupted.into());
            };
            if let Some((&head, tail)) = bytes.split_first() {
                buf[0] = head;
                self.0 = Some(tail);
                Ok(1)
            } else {
                Ok(0)
            }
        }
    }
    let hashes = hash_reader(Stream(None)).unwrap();
    assert_eq!(hashes.size, 3);
    let mut probes = Vec::new();
    hashes
        .lookup(|alg, digest, size| {
            let hex: String = digest[..alg.digest_len()]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert!(digest[alg.digest_len()..].iter().all(|b| *b == 0));
            let expected = match alg {
                Algorithm::Md5 => "900150983cd24fb0d6963f7d28e17f72",
                Algorithm::Sha1 => "a9993e364706816aba3e25717850c26c9cd0d89d",
                Algorithm::Sha256 => {
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                }
            };
            assert_eq!(hex, expected);
            probes.push((alg, size));
            Ok(None)
        })
        .unwrap();
    assert_eq!(
        probes,
        [
            (Algorithm::Md5, Some(3)),
            (Algorithm::Md5, None),
            (Algorithm::Sha1, Some(3)),
            (Algorithm::Sha1, None),
            (Algorithm::Sha256, Some(3)),
            (Algorithm::Sha256, None),
        ]
    );
}

#[test]
fn read_and_lookup_errors_are_reported() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    let stream = (&b"abc"[..]).chain(Broken);
    assert!(matches!(hash_reader(stream), Err(e) if e.kind() == io::ErrorKind::BrokenPipe));
    let hashes = hash_reader(&b""[..]).unwrap();
    assert_eq!(hashes.size, 0);
    assert!(
        matches!(hashes.lookup(|_,_,_| Err(io::ErrorKind::UnexpectedEof.into())),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
}

#[test]
fn inventory_accounts_for_families_levels_ignores_and_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let signature = "900150983cd24fb0d6963f7d28e17f72";
    let positives = dir.path().join("fixture.hsb");
    let pua = dir.path().join("fixture.hdu");
    let allow = dir.path().join("fixture.sfp");
    let ignore = dir.path().join("fixture.ign2");
    let ignored_line = format!("{signature}:3:IgnoredByDigest");
    let md5 = |s: &str| {
        use md5::{Digest, Md5};
        Md5::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    fs::write(
        &ignore,
        format!(
            "IgnoredName\nfake:1:IgnoredLegacy\nIgnoredByDigest:{}\n",
            md5(&ignored_line)
        ),
    )
    .unwrap();
    fs::write(&pua, format!("{signature}:3:PotentiallyUnwanted\n")).unwrap();
    fs::write(&allow, format!("{signature}:3:Allow\n")).unwrap();
    let text = format!(
        "# fixture\r\n{signature}:3:First\n{signature}:3:Second\n{signature}:3:Third (Clam)\n\
         {signature}:*:Wildcard:73:213\n{signature}:3:IgnoredName.UNOFFICIAL\n\
         {signature}:3:IgnoredLegacy.{{2}}\n{ignored_line}\n{signature}:4:IgnoredByDigest\n\
         {signature}:3:Expired:73:212\n{signature}:*:Future:214\n"
    );
    fs::write(&positives, text).unwrap();
    let paths = [positives, pua, allow, ignore];
    let (all, _) = Feed::load_eligible(&paths, true, PINNED_FLEVEL).unwrap();
    assert_eq!(all.len(), 5);
    let feed = Feed::load(&paths, false, PINNED_FLEVEL).unwrap();
    assert_eq!(feed.rules.len(), 3);
    assert_eq!(feed.duplicate_keys, 2);
    assert!(
        feed.rules
            .iter()
            .any(|r| r.size == Some(3) && r.name == "Third.UNOFFICIAL")
    );
    assert!(
        feed.rules
            .iter()
            .any(|r| r.size.is_none() && r.name == "Wildcard.UNOFFICIAL")
    );
    assert!(
        all.iter()
            .any(|r| r.size == Some(4) && r.name == "IgnoredByDigest")
    );
    let positive = feed
        .inventory
        .iter()
        .find(|stats| stats.path == paths[0])
        .unwrap();
    assert_eq!(positive.records, 10);
    assert_eq!(positive.eligible, [[4, 1], [0, 0], [0, 0]]);
    assert_eq!(positive.skipped_flevel, 2);
    assert_eq!(positive.skipped_ignored, 3);
    assert_eq!(
        feed.inventory.iter().map(|f| f.skipped_pua).sum::<usize>(),
        1
    );
    assert_eq!(
        feed.inventory
            .iter()
            .map(|f| f.outside_matcher)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        feed.inventory
            .iter()
            .map(|f| f.ignore_entries)
            .sum::<usize>(),
        3
    );
}

#[test]
fn invalid_inputs_fail_with_the_bad_line_number() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.hdb");
    let hex = "900150983cd24fb0d6963f7d28e17f72";
    for record in [
        format!("{hex}:*:NoLevel"),
        format!("{hex}:*:Old:72"),
        format!("{hex}:0:Zero"),
        format!("{hex}:4294967295:Reserved"),
        format!("{hex}:1::73"),
        "000000000000000000000000000000+1:1:BadHex".to_owned(),
        format!("{hex}:1:Name:73:215:unknown"),
        format!("{hex}:1:Name:bad"),
        format!("{hex}:1:{}", "x".repeat(8192)),
    ] {
        fs::write(&path, format!("{hex}:10:Valid\n{record}\n")).unwrap();
        let result = Feed::load(std::slice::from_ref(&path), true, PINNED_FLEVEL);
        assert!(
            matches!(result,Err(e) if e.kind()==io::ErrorKind::InvalidData && e.to_string().contains("bad.hdb:2:"))
        );
    }
    let unsupported = dir.path().join("other.ndb");
    assert!(
        matches!(Feed::load(&[unsupported],true,PINNED_FLEVEL),Err(e) if e.to_string().contains("unsupported database family"))
    );
}

#[test]
fn short_ignore_names_use_three_byte_space_padding() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("fixture.hdb");
    let ignore = dir.path().join("fixture.ign2");
    let hex = "900150983cd24fb0d6963f7d28e17f72";
    let conditional_line = format!("{hex}:5:BC");
    fs::write(&db, format!("{hex}:1:A  \n{hex}:2:A\n{hex}:3:A .{{1}}\n{hex}:4:A   \n{conditional_line}\n{hex}:6:BC \n")).unwrap();
    use md5::{Digest, Md5};
    let md5: String = Md5::digest(conditional_line.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    fs::write(&ignore, format!("A\nBC :{md5}\n")).unwrap();
    let paths = [db, ignore];
    let (rules, _) = Feed::load_eligible(&paths, true, PINNED_FLEVEL).unwrap();
    assert_eq!(
        rules.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        ["A   ", "BC "]
    );
    fs::write(&paths[1], format!("BC:{md5}\n")).unwrap();
    assert!(
        matches!(Feed::load(&paths, true, PINNED_FLEVEL), Err(e) if e.kind() == io::ErrorKind::InvalidData)
    );
}
