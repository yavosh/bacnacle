use crate::{Algorithm, Rule};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

/// libclamav 1.4.3 functionality level.
pub const PINNED_FLEVEL: u32 = 213;
// ClamAV 1.4.3 reads hash database lines into a FILEBUFF-sized C string.
const FILEBUFF: usize = 8192;

#[derive(Debug, Default)]
pub struct FileInventory {
    pub path: PathBuf,
    pub sha256: String,
    pub records: usize,
    /// Indexed by Algorithm, then by exact (0) or wildcard (1).
    pub eligible: [[usize; 2]; 3],
    pub skipped_flevel: usize,
    pub skipped_pua: usize,
    pub skipped_ignored: usize,
    pub ignore_entries: usize,
    pub outside_matcher: usize,
}

impl fmt::Display for FileInventory {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{} sha256={} records={}",
            self.path.display(),
            self.sha256,
            self.records
        )?;
        for alg in Algorithm::ALL {
            let [exact, wildcard] = self.eligible[alg as usize];
            write!(out, " {alg:?}_exact={exact} {alg:?}_wildcard={wildcard}")?;
        }
        write!(
            out,
            " skipped_flevel={} skipped_pua={} skipped_ignored={} ignore_entries={} outside_matcher={}",
            self.skipped_flevel,
            self.skipped_pua,
            self.skipped_ignored,
            self.ignore_entries,
            self.outside_matcher
        )
    }
}

#[derive(Default)]
pub struct Feed {
    pub inventory: Vec<FileInventory>,
    /// One stock-selected name per eligible key. Inventory counts include duplicates.
    pub rules: Vec<Rule>,
    /// The number of eligible records sharing a key with a retained record.
    pub duplicate_keys: usize,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Family {
    Positive,
    Pua,
    Ignore,
    Allowlist,
}

fn family(path: &Path) -> io::Result<Family> {
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "hdb" | "hsb" => Ok(Family::Positive),
        "hdu" | "hsu" => Ok(Family::Pua),
        "ign" | "ign2" => Ok(Family::Ignore),
        "fp" | "sfp" => Ok(Family::Allowlist),
        _ => Err(invalid(format!(
            "{}: unsupported database family",
            path.display()
        ))),
    }
}

#[derive(Default)]
pub struct IgnoreSet(HashMap<String, Option<[u8; 16]>>);

// ClamAV pads names shorter than three bytes with ASCII spaces. Removing those
// spaces from a key of at most three bytes gives the same equality comparison.
fn ignore_key(name: &str) -> &str {
    if name.len() <= 3 {
        name.trim_end_matches(' ')
    } else {
        name
    }
}

impl IgnoreSet {
    fn add(&mut self, line: &str) -> io::Result<()> {
        let fields: Vec<_> = line.split(':').collect();
        let (name, digest) = match fields.as_slice() {
            [name] | [_, _, name] => (*name, None),
            [name, hex] => {
                // In 1.4.3, in-place padding of the name overwrites part of this MD5.
                if name.len() < 3 {
                    return Err(invalid(
                        "conditional ignore names require at least three bytes",
                    ));
                }
                let mut digest = [0; 16];
                decode_hex(hex, &mut digest)?;
                (*name, Some(digest))
            }
            _ => return Err(invalid("unsupported ignore entry")),
        };
        if name.is_empty() {
            return Err(invalid("empty ignore name"));
        }
        if let Some(old) = self.0.insert(ignore_key(name).into(), digest)
            && old != digest
        {
            return Err(invalid(
                "unsupported conflicting ignore entries for the same name",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches(&self, name: &str, line: &str) -> bool {
        let normalized = if name.len() > 3 && name.ends_with('}') {
            name.split_once(".{").map_or(name, |(base, _)| base)
        } else if name.len() > ".UNOFFICIAL".len() {
            name.strip_suffix(".UNOFFICIAL").unwrap_or(name)
        } else {
            name
        };
        match self.0.get(ignore_key(normalized)) {
            Some(Some(digest)) => Md5::digest(line.as_bytes()).as_slice() == digest,
            Some(None) => true,
            None => false,
        }
    }
}

fn decode_hex(hex: &str, out: &mut [u8]) -> io::Result<()> {
    if hex.len() != out.len() * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("invalid digest length or encoding"));
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .map_err(|_| invalid("invalid hexadecimal digest"))?;
    }
    Ok(())
}

fn decimal(field: &str, label: &str) -> io::Result<u32> {
    if !field.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!("invalid {label}")));
    }
    field
        .parse()
        .map_err(|_| invalid(format!("invalid {label}")))
}

fn parse_rule(
    line: &str,
    official: bool,
    flevel: u32,
    ignores: &IgnoreSet,
    stats: &mut FileInventory,
) -> io::Result<Option<Rule>> {
    let mut fields = line.split(':');
    let hex = fields.next().unwrap_or("");
    let size = fields.next().ok_or_else(|| invalid("missing size"))?;
    let name = fields.next().ok_or_else(|| invalid("missing name"))?;
    let min = fields
        .next()
        .map(|s| decimal(s, "minimum functionality level"))
        .transpose()?
        .unwrap_or(0);
    let max = fields
        .next()
        .map(|s| decimal(s, "maximum functionality level"))
        .transpose()?
        .unwrap_or(u32::MAX);
    if fields.next().is_some() {
        return Err(invalid("unsupported extra hash fields"));
    }
    if !(min..=max).contains(&flevel) {
        stats.skipped_flevel += 1;
        return Ok(None);
    }
    let size = match size {
        "*" if min >= 73 => None,
        "*" => {
            return Err(invalid(
                "wildcard size requires minimum functionality level 73",
            ));
        }
        s => match decimal(s, "file size")? {
            0 | u32::MAX => return Err(invalid("file size is outside the supported range")),
            n => Some(n),
        },
    };
    if ignores.matches(name, line) {
        stats.skipped_ignored += 1;
        return Ok(None);
    }
    let name = name.split_once(" (Clam)").map_or(name, |(name, _)| name);
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(invalid("unsupported empty or control-containing name"));
    }
    let algorithm = match hex.len() {
        32 => Algorithm::Md5,
        40 => Algorithm::Sha1,
        64 => Algorithm::Sha256,
        _ => return Err(invalid("unsupported digest length")),
    };
    let mut digest = [0; 32];
    decode_hex(hex, &mut digest[..algorithm.digest_len()])?;
    let name = if official {
        name.to_owned()
    } else {
        format!("{name}.UNOFFICIAL")
    };
    stats.eligible[algorithm as usize][size.is_none() as usize] += 1;
    Ok(Some(Rule {
        algorithm,
        digest,
        size,
        name,
    }))
}

impl Feed {
    /// Load explicit paths in reference load order. Process all ignore files before hash files.
    pub fn load(paths: &[PathBuf], official: bool, flevel: u32) -> io::Result<Self> {
        Ok(Self::from_eligible(Self::load_eligible(
            paths, official, flevel,
        )?))
    }

    /// Validate daemon database records and resolve duplicate keys across all provenances.
    pub fn load_sources(paths: &[(&Path, bool)], flevel: u32) -> io::Result<Self> {
        Ok(Self::load_sources_with_ignores(paths, flevel)?.0)
    }

    /// Keep the generation’s ignore entries available to the other signature families.
    pub fn load_sources_with_ignores(
        paths: &[(&Path, bool)],
        flevel: u32,
    ) -> io::Result<(Self, IgnoreSet)> {
        let mut ignores = IgnoreSet::default();
        let records = Self::eligible_sources(paths, flevel, true, &mut ignores)?;
        Ok((Self::from_eligible(records), ignores))
    }

    fn from_eligible((mut rules, inventory): (Vec<Rule>, Vec<FileInventory>)) -> Self {
        let original_count = rules.len();
        reduce_duplicate_keys(&mut rules);
        Self {
            inventory,
            duplicate_keys: original_count - rules.len(),
            rules,
        }
    }

    /// Return all eligible records in database order, including names that share a key.
    pub fn load_eligible(
        paths: &[PathBuf],
        official: bool,
        flevel: u32,
    ) -> io::Result<(Vec<Rule>, Vec<FileInventory>)> {
        Self::eligible_sources(
            &paths
                .iter()
                .map(|p| (p.as_path(), official))
                .collect::<Vec<_>>(),
            flevel,
            false,
            &mut IgnoreSet::default(),
        )
    }

    fn eligible_sources(
        paths: &[(&Path, bool)],
        flevel: u32,
        validate_allowlists: bool,
        ignores: &mut IgnoreSet,
    ) -> io::Result<(Vec<Rule>, Vec<FileInventory>)> {
        if paths.is_empty() {
            return Err(invalid("no database files"));
        }
        let mut inputs = paths
            .iter()
            .map(|&(path, official)| Ok((family(path)?, path, official)))
            .collect::<io::Result<Vec<_>>>()?;
        inputs.sort_by_key(|(family, _, _)| *family != Family::Ignore);
        let mut rules = Vec::new();
        let mut inventory = Vec::new();
        for (family, path, official) in inputs {
            let mut stats = FileInventory {
                path: path.to_owned(),
                ..Default::default()
            };
            let mut hasher = Sha256::new();
            let file = File::open(path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
            let mut input = BufReader::new(file);
            let mut line = String::new();
            let mut number = 0;
            loop {
                line.clear();
                let n = input
                    .by_ref()
                    .take(FILEBUFF as u64)
                    .read_line(&mut line)
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("{}:{}: {e}", path.display(), number + 1))
                    })?;
                if n == 0 {
                    break;
                }
                number += 1;
                if n == FILEBUFF {
                    return Err(invalid(format!(
                        "{}:{number}: database line exceeds {} bytes",
                        path.display(),
                        FILEBUFF - 1
                    )));
                }
                hasher.update(line.as_bytes());
                let line = line.trim_end_matches(['\r', '\n']);
                if line.starts_with('#') {
                    continue;
                }
                stats.records += 1;
                let result = match family {
                    Family::Ignore => {
                        stats.ignore_entries += 1;
                        ignores.add(line)
                    }
                    Family::Positive => parse_rule(line, official, flevel, ignores, &mut stats)
                        .map(|r| {
                            if let Some(rule) = r {
                                rules.push(rule)
                            }
                        }),
                    Family::Pua => {
                        stats.skipped_pua += 1;
                        Ok(())
                    }
                    Family::Allowlist => {
                        stats.outside_matcher += 1;
                        if validate_allowlists {
                            parse_rule(
                                line,
                                official,
                                flevel,
                                ignores,
                                &mut FileInventory::default(),
                            )
                            .map(|_| ())
                        } else {
                            Ok(())
                        }
                    }
                };
                result.map_err(|e| invalid(format!("{}:{number}: {e}", path.display())))?;
            }
            if number == 0
                && (family == Family::Positive
                    || (family == Family::Allowlist && validate_allowlists))
            {
                return Err(invalid(format!("{}: empty hash database", path.display())));
            }
            for byte in hasher.finalize() {
                write!(stats.sha256, "{byte:02x}").expect("writing to a String cannot fail");
            }
            inventory.push(stats);
        }
        Ok((rules, inventory))
    }
}

// Equal keys can carry different names. The pinned little-endian clamd build compares the
// first four bytes as a descending integer, then compares the remaining bytes lexically.
fn reference_cmp(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    let first = |key: &[u8; 32]| u32::from_le_bytes(key[..4].try_into().unwrap());
    first(b).cmp(&first(a)).then_with(|| a[4..].cmp(&b[4..]))
}

fn reference_sort(bucket: &mut [Rule]) {
    // Use an explicit stack for the reference engine's first-pivot partition order.
    let mut ranges = vec![(0, bucket.len())];
    while let Some((begin, end)) = ranges.pop() {
        if end - begin < 2 {
            continue;
        }
        let pivot = bucket[begin].digest;
        let (mut next, mut split) = (begin + 1, end);
        let mut all_equal = true;
        while next < split {
            let order = reference_cmp(&bucket[next].digest, &pivot);
            all_equal &= order.is_eq();
            if order.is_gt() {
                split -= 1;
                bucket.swap(next, split);
            } else {
                next += 1;
            }
        }
        if all_equal {
            // Repeatedly placing the first pivot last rotates an equal-key run once.
            bucket[begin..end].rotate_left(1);
            continue;
        }
        bucket.swap(begin, split - 1);
        ranges.extend([(begin, split - 1), (split, end)]);
    }
}

fn reference_winner(bucket: &[Rule], key: &[u8; 32]) -> usize {
    let (mut lo, mut hi) = (0, bucket.len());
    while lo < hi {
        // clamd chooses the lower midpoint when the remaining count is even.
        let mid = lo + (hi - lo - 1) / 2;
        match reference_cmp(key, &bucket[mid].digest) {
            Ordering::Equal => return mid,
            Ordering::Less => hi = mid,
            Ordering::Greater => lo = mid + 1,
        }
    }
    unreachable!("the key came from this sorted bucket")
}

fn reduce_duplicate_keys(rules: &mut Vec<Rule>) {
    // The stable group sort preserves database load order inside each search bucket.
    rules.sort_by_key(|r| (r.algorithm, r.size));
    for bucket in rules.chunk_by_mut(|a, b| a.algorithm == b.algorithm && a.size == b.size) {
        let mut seen = HashSet::new();
        if !bucket.iter().any(|r| !seen.insert(r.digest)) {
            continue;
        }
        reference_sort(bucket);
        let mut start = 0;
        while start < bucket.len() {
            let key = bucket[start].digest;
            let length = bucket[start..].partition_point(|r| r.digest == key);
            if length > 1 {
                let winner = reference_winner(bucket, &key);
                bucket.swap(start, winner);
            }
            start += length;
        }
    }
    rules.dedup_by(|a, b| a.algorithm == b.algorithm && a.size == b.size && a.digest == b.digest);
}
