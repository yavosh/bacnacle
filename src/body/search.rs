//! Find candidate parts using shared literal seeds, then verify their complete programs.
use super::pattern::{MatchState, Part};
use super::{BodyMatch, ObjectContext, Rule, Target, invalid};
use aho_corasick::{AhoCorasick, AhoCorasickKind};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::ops::Range;

pub(super) const STOCK_WINDOW: usize = 131_072;
const SEED_BYTES: usize = 6;
const BLOCK: usize = 8192;
const EVENT_LIMIT: usize = 16_384;

// The seed need not begin at the stock AC trigger. A rare sequence can also index
// a long literal with a common prefix. Store its relative position to recover it.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Seed {
    bytes: [u8; SEED_BYTES],
    len: u8,
}

impl Seed {
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

struct Site {
    rule: u32,
    part: u16,
    shift: u16,
    group: u32,
}

struct Group {
    head_part: usize,
    head_rule: u32,
    count: u32,
}

fn part_number(rule: &Rule, index: usize) -> usize {
    if rule.pattern.parts().len() == 1 {
        0
    } else {
        index + 1
    }
}

fn pair(bytes: &[u8]) -> usize {
    usize::from(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn seed(part: &Part, freq: &[u32]) -> (Seed, u16) {
    let bytes = part.anchor();
    let len = bytes.len().min(SEED_BYTES);
    // Adjacent-pair frequencies come from this target's own candidate literals.
    let mut best = 0;
    let mut score: u64 = bytes[..len]
        .windows(2)
        .map(|w| u64::from(freq[pair(w)]))
        .sum();
    let mut minimum = score;
    for end in len..bytes.len() {
        let start = end + 1 - len;
        score -= u64::from(freq[pair(&bytes[start - 1..])]);
        score += u64::from(freq[pair(&bytes[end - 1..])]);
        if score < minimum {
            best = start;
            minimum = score;
        }
    }
    let mut key = Seed {
        bytes: [0; SEED_BYTES],
        len: len as u8,
    };
    key.bytes[..len].copy_from_slice(&bytes[best..best + len]);
    (key, best as u16)
}

// Stock checks windows in increasing order, then the applicable target root,
// then generic. Within a root it runs static patterns before AC patterns.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Order {
    ac: bool,
    trigger: usize,
    depth: Reverse<usize>,
    head_part: usize,
    group_size: Reverse<u32>,
    head_rule: u32,
    part: usize,
    member: u32,
}

#[derive(Clone, Copy)]
struct Event {
    site: usize,
    start: usize,
    end: usize,
    trigger: usize,
    order: Order,
}

struct Seeds {
    anchors: AhoCorasick,
    offsets: Vec<usize>,
    max_shift: usize,
}

impl Seeds {
    fn build(mut entries: Vec<(Seed, Site)>, sites: &mut Vec<Site>) -> io::Result<Self> {
        entries.sort_unstable_by_key(|(key, _)| *key);
        let mut offsets = Vec::new();
        let mut keys = Vec::new();
        let mut max_shift = 0;
        for (key, site) in entries {
            if keys.last() != Some(&key) {
                offsets.push(sites.len());
                keys.push(key);
            }
            max_shift = max_shift.max(usize::from(site.shift));
            sites.push(site);
        }
        offsets.push(sites.len());
        // Keep dense root transitions. Sparse deeper states save over 50 MiB
        // on the pinned feed while preserving the same matching automaton.
        let anchors = AhoCorasick::builder()
            .dense_depth(1)
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .build(keys.iter().map(Seed::bytes))
            .map_err(io::Error::other)?;
        Ok(Self {
            anchors,
            offsets,
            max_shift,
        })
    }
}

#[derive(Default)]
struct Progress {
    multipart: HashMap<u32, MatchState>,
    deferred_active: bool,
}

struct Root {
    target: Target,
    primary: Seeds,
    deferred: Option<Seeds>,
    deferred_rules: HashSet<u32>,
    groups: Vec<Group>,
    sites: Vec<Site>,
    max_span: usize,
}

impl Root {
    fn build(target: Target, ids: &[u32], rules: &[Rule]) -> io::Result<Self> {
        let mut freq = vec![0u32; 65536];
        for &id in ids {
            for part in rules[id as usize].pattern.parts() {
                for bytes in part.anchor().windows(2) {
                    freq[pair(bytes)] = freq[pair(bytes)].saturating_add(1);
                }
            }
        }
        let mut entries = Vec::new();
        let mut later = Vec::new();
        let mut deferred_rules = HashSet::new();
        let mut groups: Vec<Group> = Vec::new();
        let mut group_ids = HashMap::new();
        let mut max_span = 0;
        for &id in ids {
            let rule = &rules[id as usize];
            for (i, part) in rule.pattern.parts().iter().enumerate() {
                let (key, shift) = seed(part, &freq);
                max_span = max_span.max(part.max_span());
                let group = if rule.bm_prefix.is_some() {
                    0
                } else {
                    let partno = part_number(rule, i);
                    let group = *group_ids.entry(part.shape_key()).or_insert_with(|| {
                        let number = groups.len();
                        groups.push(Group {
                            head_part: partno,
                            head_rule: id,
                            count: 0,
                        });
                        number
                    });
                    let g = &mut groups[group];
                    if (partno, id) < (g.head_part, g.head_rule) {
                        g.head_rule = id;
                        g.head_part = partno;
                    }
                    g.count += 1;
                    u32::try_from(group).map_err(|_| invalid("too many AC groups"))?
                };
                // A run of identical bytes can report a candidate at every byte of
                // padding. A later part is irrelevant until a first part has matched.
                let dest = if i != 0 && key.bytes().iter().all(|&b| b == key.bytes[0]) {
                    deferred_rules.insert(id);
                    &mut later
                } else {
                    &mut entries
                };
                dest.push((
                    key,
                    Site {
                        rule: id,
                        part: i as u16,
                        shift,
                        group,
                    },
                ));
            }
        }
        drop(group_ids);
        drop(freq);
        let mut sites = Vec::with_capacity(entries.len() + later.len());
        let primary = Seeds::build(entries, &mut sites)?;
        let deferred = if later.is_empty() {
            None
        } else {
            Some(Seeds::build(later, &mut sites)?)
        };
        Ok(Self {
            target,
            primary,
            deferred,
            deferred_rules,
            groups,
            sites,
            max_span,
        })
    }

    // Collect events in a bounded interval of reference AC trigger positions. The
    // matcher may verify bytes on either side of the seed. It reads the same window
    // for every block to retain boundary and cross-block matches.
    fn collect(
        &self,
        seeds: &Seeds,
        block: Range<usize>,
        object: &Window<'_>,
        events: &mut Vec<Event>,
        check: &mut impl FnMut() -> io::Result<()>,
    ) -> io::Result<bool> {
        let before = block.start.saturating_sub(3);
        let after = (block.end + seeds.max_shift + SEED_BYTES).min(object.bytes.len());
        if before >= after {
            return Ok(true);
        }
        let mut calls = 0;
        for hit in seeds
            .anchors
            .find_overlapping_iter(&object.bytes[before..after])
        {
            let key = hit.pattern().as_usize();
            for i in seeds.offsets[key]..seeds.offsets[key + 1] {
                calls += 1;
                if calls % 1024 == 0 {
                    check()?;
                }
                let site = &self.sites[i];
                let rule = &object.rules[site.rule as usize];
                let part = &rule.pattern.parts()[site.part as usize];
                let Some(anchor_start) =
                    (before + hit.start()).checked_sub(usize::from(site.shift))
                else {
                    continue;
                };
                let depth = part.stock_anchor_len();
                let trigger = anchor_start + depth;
                if !block.contains(&trigger) {
                    continue;
                }
                let Some(range) = object.range(rule, site.part, object.base, object.bytes.len())
                else {
                    continue;
                };
                part.hits_for_anchor(object.bytes, anchor_start, range, |start, end| {
                    let order = if let Some(prefix) = rule.bm_prefix {
                        // Equal static buckets in 1.4.3 insert a new record at the head.
                        Order {
                            ac: false,
                            trigger: start + usize::from(prefix) + 3,
                            depth: Reverse(0),
                            head_part: 0,
                            group_size: Reverse(0),
                            head_rule: u32::MAX - site.rule,
                            part: 0,
                            member: 0,
                        }
                    } else {
                        let g = &self.groups[site.group as usize];
                        Order {
                            ac: true,
                            trigger,
                            depth: Reverse(depth),
                            head_part: g.head_part,
                            group_size: Reverse(g.count),
                            head_rule: g.head_rule,
                            part: part_number(rule, site.part as usize),
                            member: site.rule,
                        }
                    };
                    events.push(Event {
                        site: i,
                        start: start + object.base,
                        end: end + object.base,
                        trigger: trigger + object.base,
                        order,
                    });
                })?;
                if events.len() >= EVENT_LIMIT && block.len() > 1 {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn window(
        &self,
        object: &Window<'_>,
        progress: &mut Progress,
        events: &mut Vec<Event>,
        check: &mut impl FnMut() -> io::Result<()>,
        emit: &mut impl FnMut(BodyMatch),
    ) -> io::Result<Option<BodyMatch>> {
        let mut best: Option<(Order, BodyMatch)> = None;
        let mut start = 1;
        while start <= object.bytes.len() {
            check()?;
            let mut stop = (start + BLOCK).min(object.bytes.len() + 1);
            loop {
                events.clear();
                if self.collect(&self.primary, start..stop, object, events, check)? {
                    let Some(deferred) = &self.deferred else {
                        break;
                    };
                    let need_deferred = progress.deferred_active
                        || events.iter().any(|e| {
                            let site = &self.sites[e.site];
                            site.part == 0 && self.deferred_rules.contains(&site.rule)
                        });
                    if !need_deferred
                        || self.collect(deferred, start..stop, object, events, check)?
                    {
                        progress.deferred_active = need_deferred;
                        break;
                    }
                }
                // Always advance by at least one byte. For one trigger position the
                // event count is bounded by the number of parts in the database.
                stop = start + (stop - start).div_ceil(2);
            }
            // At a given position, stock evaluates a part before its dependent part.
            events.sort_unstable_by_key(|e| e.order);
            for e in events.iter() {
                let site = &self.sites[e.site];
                let rule = &object.rules[site.rule as usize];
                if object.already_seen(rule, site.part, e.trigger)? {
                    continue;
                }
                let interval = if rule.pattern.parts().len() == 1 {
                    Some((e.start, e.end))
                } else {
                    let state = if site.part == 0 {
                        progress.multipart.entry(site.rule).or_default()
                    } else if let Some(state) = progress.multipart.get_mut(&site.rule) {
                        state
                    } else {
                        continue;
                    };
                    state.advance(&rule.pattern, site.part as usize, e.start, e.end)
                };
                if let Some((start, end)) = interval {
                    let hit = BodyMatch {
                        rule_id: site.rule,
                        start,
                        end,
                    };
                    emit(hit);
                    if best.is_none_or(|(prior, _)| e.order < prior) {
                        best = Some((e.order, hit));
                    }
                }
            }
            start = stop;
        }
        Ok(best.map(|(_, hit)| hit))
    }
}

struct Window<'a> {
    rules: &'a [Rule],
    context: &'a ObjectContext,
    bytes: &'a [u8],
    total_size: usize,
    base: usize,
    previous: Option<(usize, &'a [u8])>,
}

impl Window<'_> {
    fn range(
        &self,
        rule: &Rule,
        part: u16,
        base: usize,
        len: usize,
    ) -> Option<std::ops::RangeInclusive<usize>> {
        if part != 0 {
            return Some(0..=len);
        }
        let range = self.context.offset_range(&rule.offset, self.total_size)?;
        Some(range.start().saturating_sub(base)..=range.end().checked_sub(base)?.min(len))
    }

    // Recheck only successful candidates in the overlap. This bounds memory even
    // when thousands of rules produce many occurrences at the same position.
    fn already_seen(&self, rule: &Rule, index: u16, trigger: usize) -> io::Result<bool> {
        let Some((base, bytes)) = self.previous else {
            return Ok(false);
        };
        if trigger > base + bytes.len() {
            return Ok(false);
        }
        let part = &rule.pattern.parts()[index as usize];
        let anchor = trigger - part.stock_anchor_len() - base;
        let Some(range) = self.range(rule, index, base, bytes.len()) else {
            return Ok(false);
        };
        let mut seen = false;
        part.hits_for_anchor(bytes, anchor, range, |_, _| seen = true)?;
        Ok(seen)
    }
}

pub(super) struct SearchIndex(Vec<Root>);

impl SearchIndex {
    pub(super) fn build(rules: &[Rule]) -> io::Result<Self> {
        let mut by_target: BTreeMap<Target, Vec<u32>> = BTreeMap::new();
        for (i, r) in rules.iter().enumerate() {
            by_target.entry(r.target).or_default().push(i as u32);
        }
        let mut roots = Vec::with_capacity(by_target.len());
        for (target, ids) in by_target.into_iter().rev() {
            roots.push(Root::build(target, &ids, rules)?);
        }
        Ok(Self(roots))
    }

    pub(super) fn run(
        &self,
        rules: &[Rule],
        input: &[u8],
        context: &ObjectContext,
        first: bool,
        mut check: impl FnMut() -> io::Result<()>,
        emit: &mut impl FnMut(BodyMatch),
    ) -> io::Result<Option<BodyMatch>> {
        let mut roots: Vec<_> = self
            .0
            .iter()
            .filter(|r| context.accepts(r.target))
            .map(|r| (r, Progress::default()))
            .collect();
        let Some(overlap) = roots.iter().map(|(r, _)| r.max_span).max() else {
            return Ok(None);
        };
        let mut previous = None;
        let mut events = Vec::new();
        let mut base: usize = 0;
        loop {
            let end = base.saturating_add(STOCK_WINDOW).min(input.len());
            let next_base = (end < input.len()).then(|| end - overlap);
            let window = Window {
                rules,
                context,
                bytes: &input[base..end],
                total_size: input.len(),
                base,
                previous,
            };
            for (root, progress) in &mut roots {
                let hit = root.window(&window, progress, &mut events, &mut check, emit)?;
                if first && hit.is_some() {
                    return Ok(hit);
                }
            }
            let Some(next) = next_base else {
                return Ok(None);
            };
            previous = Some((base, &input[base..end]));
            base = next;
        }
    }
}
