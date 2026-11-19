//! Compile a ClamAV hex body into literal-anchored parts.
//! Bracket ranges check surrounding bytes. Brace ranges and stars join parts.
use std::collections::HashSet;
use std::hash::Hash;
use std::io;
use std::ops::RangeInclusive;

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[derive(Clone, Copy, Debug, Default)]
struct Gap {
    min: u32,
    // The pinned multipart matcher uses zero for an unrestricted upper bound.
    max: u32,
}

fn number(text: &str) -> io::Result<u32> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return Err(invalid("expected a decimal wildcard distance"));
    }
    text.parse()
        .map_err(|_| invalid("wildcard distance overflow"))
}

fn distance(text: &str) -> io::Result<Gap> {
    if let Some((min, max)) = text.split_once('-') {
        if min.is_empty() && max.is_empty() {
            return Err(invalid("missing wildcard distances"));
        }
        let min = if min.is_empty() { 0 } else { number(min)? };
        let max = if max.is_empty() { 0 } else { number(max)? };
        if max != 0 && max < min {
            return Err(invalid("reversed wildcard distances"));
        }
        Ok(Gap { min, max })
    } else {
        let n = number(text)?;
        Ok(Gap { min: n, max: n })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Byte {
    value: u8,
    mask: u8,
}

impl Byte {
    fn parse(pair: &[u8]) -> io::Result<Self> {
        if pair.len() != 2 {
            return Err(invalid("byte pattern needs two nibbles"));
        }
        let nibble = |c| match c {
            b'?' => Ok((0, 0)),
            b'0'..=b'9' => Ok((c - b'0', 15)),
            b'a'..=b'f' => Ok((c - b'a' + 10, 15)),
            b'A'..=b'F' => Ok((c - b'A' + 10, 15)),
            _ => Err(invalid("invalid hexadecimal nibble")),
        };
        let (a, am) = nibble(pair[0])?;
        let (b, bm) = nibble(pair[1])?;
        Ok(Self {
            value: a << 4 | b,
            mask: am << 4 | bm,
        })
    }

    fn matches(self, actual: u8) -> bool {
        actual & self.mask == self.value
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
enum Atom {
    Literal(Box<[u8]>),
    Byte(Byte),
    Skip(usize),
    Choice {
        options: Box<[Box<[Byte]>]>,
        negative: bool,
    },
}

impl Atom {
    fn max_len(&self) -> usize {
        match self {
            Self::Literal(s) => s.len(),
            Self::Byte(_) => 1,
            Self::Skip(n) => *n,
            Self::Choice { options, .. } => options.iter().map(|s| s.len()).max().unwrap_or(0),
        }
    }

    // Input coordinates mark gaps between bytes, allowing identical forward and backward checks.
    fn step(&self, data: &[u8], pos: usize, reverse: bool, mut success: impl FnMut(usize)) {
        let span = |n| {
            if reverse {
                let start = pos.checked_sub(n)?;
                Some((data.get(start..pos)?, start))
            } else {
                let end = pos.checked_add(n)?;
                Some((data.get(pos..end)?, end))
            }
        };
        match self {
            Self::Literal(bytes) => {
                if let Some((s, next)) = span(bytes.len())
                    && s == bytes.as_ref()
                {
                    success(next);
                }
            }
            Self::Byte(byte) => {
                if let Some((s, next)) = span(1)
                    && byte.matches(s[0])
                {
                    success(next);
                }
            }
            Self::Skip(n) => {
                if let Some((_, next)) = span(*n) {
                    success(next);
                }
            }
            Self::Choice { options, negative } => {
                for option in options {
                    if let Some((s, next)) = span(option.len())
                        && option.iter().zip(s).all(|(b, &actual)| b.matches(actual))
                    {
                        if *negative {
                            return;
                        }
                        success(next);
                    }
                }
                if *negative && let Some((_, next)) = span(options[0].len()) {
                    success(next);
                }
            }
        }
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct Flank {
    byte: Byte,
    min: usize,
    max: usize,
}

impl Flank {
    fn parse(byte: &str, range: &str) -> io::Result<Self> {
        let (min, max) = range.split_once('-').unwrap_or((range, range));
        let (min, max) = (number(min)? as usize, number(max)? as usize);
        if min > max || max > 32 {
            return Err(invalid("bracket distances must be ordered and at most 32"));
        }
        Ok(Self {
            byte: Byte::parse(byte.as_bytes())?,
            min,
            max,
        })
    }

    fn matches(&self, input: &[u8], pos: usize, left: bool) -> bool {
        // A full wildcard in the flank occupies the reference engine's "ignore" slot.
        if self.byte.mask == 0 {
            return true;
        }
        (self.min..=self.max).any(|gap| {
            let at = if left {
                pos.checked_sub(gap + 1)
            } else {
                pos.checked_add(gap)
            };
            at.and_then(|i| input.get(i))
                .is_some_and(|&b| self.byte.matches(b))
        })
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
enum Body {
    Literal { bytes: Box<[u8]>, anchor: usize },
    Program(Box<Program>),
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct Program {
    atoms: Box<[Atom]>,
    anchor: usize,
    span: usize,
    left: Option<Flank>,
    right: Option<Flank>,
}

#[derive(Debug)]
pub(super) struct Part {
    gap: Gap,
    body: Body,
}

#[derive(Debug)]
pub(super) enum Pattern {
    Single(Part),
    Multipart(Box<[Part]>),
}

impl Pattern {
    pub(super) fn compile(text: &str) -> io::Result<Self> {
        if text.is_empty() || !text.is_ascii() {
            return Err(invalid("expected a nonempty ASCII hex pattern"));
        }
        // The reference expands leading exact brace counts below 128 into byte wildcards.
        // Once it reaches a multipart range, subsequent braces separate indexed parts.
        let mut parts = Vec::new();
        let mut gap = Gap::default();
        let mut expand = true;
        let mut start = 0;
        let mut i = 0;
        let mut group = false;
        while i < text.len() {
            match text.as_bytes()[i] {
                b'(' if !group => group = true,
                b')' if group => group = false,
                b'(' | b')' => return Err(invalid("unbalanced or nested alternatives")),
                b'{' | b'*' => {
                    let (next, new_gap, split) = if text.as_bytes()[i] == b'*' {
                        (i + 1, Gap::default(), true)
                    } else {
                        let close = text[i + 1..]
                            .find('}')
                            .ok_or_else(|| invalid("unclosed brace wildcard"))?
                            + i
                            + 1;
                        let range = &text[i + 1..close];
                        let g = distance(range)?;
                        let fixed = expand && !range.contains('-') && (1..128).contains(&g.min);
                        if !fixed {
                            expand = false;
                        }
                        (close + 1, g, !fixed)
                    };
                    if split {
                        if group {
                            return Err(invalid("multipart range inside an alternative"));
                        }
                        parts.push(Part::compile(&text[start..i], gap)?);
                        start = next;
                        gap = new_gap;
                    }
                    i = next;
                    continue;
                }
                _ => (),
            }
            i += 1;
        }
        if group {
            return Err(invalid("unclosed alternative"));
        }
        let last = Part::compile(&text[start..], gap)?;
        if parts.is_empty() {
            return Ok(Self::Single(last));
        }
        parts.push(last);
        if parts.len() > u16::MAX.into() {
            return Err(invalid("too many pattern parts"));
        }
        Ok(Self::Multipart(parts.into_boxed_slice()))
    }

    pub(super) fn parts(&self) -> &[Part] {
        match self {
            Self::Single(part) => std::slice::from_ref(part),
            Self::Multipart(parts) => parts,
        }
    }
}

// Stock indexes up to three static bytes and prefers a prefix without two leading zeroes.
fn anchor_position(atoms: &[Atom]) -> io::Result<(usize, usize)> {
    if let Some(Atom::Literal(s)) = atoms.first()
        && (s.len() >= 3 || atoms.len() == 1)
        && s.iter().take(3).any(|&b| b != 0)
        && s.len() >= 2
    {
        return Ok((0, 0));
    }
    let mut best = None;
    let mut nonzero = None;
    let mut depth = 0;
    let mut nonzero_depth = 0;
    for (index, atom) in atoms.iter().enumerate() {
        let Atom::Literal(bytes) = atom else {
            continue;
        };
        for (shift, pair) in bytes.windows(2).enumerate() {
            let n = (bytes.len() - shift).min(3);
            if n >= depth {
                depth = n;
                best = Some((index, shift));
                if pair != [0, 0] {
                    if n == 3 {
                        return Ok((index, shift));
                    }
                    if n > nonzero_depth {
                        nonzero = best;
                        nonzero_depth = n;
                    }
                }
            }
        }
    }
    let best = best.ok_or_else(|| invalid("pattern part needs two adjacent literal bytes"))?;
    if let Atom::Literal(s) = &atoms[best.0]
        && s[best.1..].starts_with(&[0, 0])
    {
        Ok(nonzero.unwrap_or(best))
    } else {
        Ok(best)
    }
}

fn parse_atoms(mut text: &str) -> io::Result<Vec<Atom>> {
    let mut atoms = Vec::new();
    let mut literal = Vec::new();
    while !text.is_empty() {
        let atom = match text.as_bytes()[0] {
            b'{' => {
                let close = text
                    .find('}')
                    .ok_or_else(|| invalid("unclosed exact wildcard"))?;
                let n = number(&text[1..close])? as usize;
                if !(1..128).contains(&n) {
                    return Err(invalid("invalid inline exact wildcard"));
                }
                text = &text[close + 1..];
                Atom::Skip(n)
            }
            b'(' | b'!' => {
                let negative = text.starts_with('!');
                let rest = text
                    .strip_prefix('!')
                    .unwrap_or(text)
                    .strip_prefix('(')
                    .ok_or_else(|| invalid("expected parenthesized alternatives"))?;
                let (options, tail) = rest
                    .split_once(')')
                    .ok_or_else(|| invalid("unclosed alternative"))?;
                text = tail;
                let mut choices: Vec<Box<[Byte]>> = Vec::new();
                for option in options.split('|') {
                    if option.is_empty() {
                        return Err(invalid("empty alternative"));
                    }
                    let mut bytes = Vec::new();
                    let mut raw = option;
                    while !raw.is_empty() {
                        if let Some(rest) = raw.strip_prefix('{') {
                            let (count, tail) = rest
                                .split_once('}')
                                .ok_or_else(|| invalid("unclosed alternative wildcard"))?;
                            let n = number(count)? as usize;
                            if !(1..128).contains(&n) {
                                return Err(invalid("invalid alternative wildcard"));
                            }
                            bytes.extend(std::iter::repeat_n(Byte { value: 0, mask: 0 }, n));
                            raw = tail;
                        } else {
                            let pair = raw
                                .get(..2)
                                .ok_or_else(|| invalid("invalid alternative byte"))?;
                            bytes.push(Byte::parse(pair.as_bytes())?);
                            raw = &raw[2..];
                        }
                    }
                    if negative
                        && (bytes.iter().any(|b| b.mask != 255)
                            || choices.first().is_some_and(|s| s.len() != bytes.len()))
                    {
                        return Err(invalid(
                            "negated alternatives need equal-length literal strings",
                        ));
                    }
                    choices.push(bytes.into_boxed_slice());
                }
                if choices.len() < 2 {
                    return Err(invalid("unsupported special or single alternative"));
                }
                if choices
                    .iter()
                    .all(|s| s.len() == choices[0].len() && s.iter().all(|b| b.mask == 255))
                {
                    choices.sort_unstable();
                }
                Atom::Choice {
                    options: choices.into_boxed_slice(),
                    negative,
                }
            }
            _ => {
                let pair = text
                    .get(..2)
                    .ok_or_else(|| invalid("truncated byte pattern"))?;
                let b = Byte::parse(pair.as_bytes())?;
                text = &text[2..];
                if b.mask == 255 {
                    literal.push(b.value);
                    continue;
                }
                if b.mask == 0 {
                    Atom::Skip(1)
                } else {
                    Atom::Byte(b)
                }
            }
        };
        if !literal.is_empty() {
            atoms.push(Atom::Literal(
                std::mem::take(&mut literal).into_boxed_slice(),
            ));
        }
        if let Atom::Skip(n) = &atom
            && let Some(Atom::Skip(last)) = atoms.last_mut()
        {
            *last += n;
        } else {
            atoms.push(atom);
        }
    }
    if !literal.is_empty() {
        atoms.push(Atom::Literal(literal.into_boxed_slice()));
    }
    Ok(atoms)
}

impl Part {
    fn compile(mut text: &str, gap: Gap) -> io::Result<Self> {
        let mut left = None;
        let mut right = None;
        if text.as_bytes().get(2) == Some(&b'[') {
            let (range, rest) = text[3..]
                .split_once(']')
                .ok_or_else(|| invalid("unclosed left bracket"))?;
            left = Some(Flank::parse(&text[..2], range)?);
            text = rest;
        }
        if let Some((core, rest)) = text.split_once('[') {
            let (range, byte) = rest
                .split_once(']')
                .ok_or_else(|| invalid("unclosed right bracket"))?;
            right = Some(Flank::parse(byte, range)?);
            text = core;
        }
        let mut atoms = parse_atoms(text)?;
        let (mut anchor, shift) = anchor_position(&atoms)?;
        let span = atoms.iter().map(Atom::max_len).sum::<usize>();
        if span > u16::MAX.into() {
            return Err(invalid("pattern part exceeds the maximum width"));
        }
        if atoms.len() == 1
            && left.is_none()
            && right.is_none()
            && let Some(Atom::Literal(bytes)) = atoms.pop()
        {
            return Ok(Self {
                gap,
                body: Body::Literal {
                    bytes,
                    anchor: shift,
                },
            });
        }
        if shift != 0
            && let Atom::Literal(bytes) = &atoms[anchor]
        {
            let prefix = Atom::Literal(bytes[..shift].into());
            let tail = Atom::Literal(bytes[shift..].into());
            atoms[anchor] = prefix;
            anchor += 1;
            atoms.insert(anchor, tail);
        }
        let body = Body::Program(Box::new(Program {
            atoms: atoms.into_boxed_slice(),
            anchor,
            span,
            left,
            right,
        }));
        Ok(Self { gap, body })
    }

    pub(super) fn literal(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Literal { bytes, .. } => Some(bytes),
            _ => None,
        }
    }

    pub(super) fn shape_key(&self) -> impl Eq + Hash + '_ {
        &self.body
    }

    pub(super) fn anchor(&self) -> &[u8] {
        match &self.body {
            Body::Literal { bytes, anchor } => &bytes[*anchor..],
            Body::Program(p) => match &p.atoms[p.anchor] {
                Atom::Literal(s) => s,
                _ => unreachable!(),
            },
        }
    }

    pub(super) fn stock_anchor_len(&self) -> usize {
        self.anchor().len().min(3)
    }

    pub(super) fn max_span(&self) -> usize {
        match &self.body {
            Body::Literal { bytes, .. } => bytes.len(),
            Body::Program(p) => p.span,
        }
    }

    pub(super) fn hits_for_anchor(
        &self,
        input: &[u8],
        anchor_start: usize,
        range: RangeInclusive<usize>,
        mut emit: impl FnMut(usize, usize),
    ) -> io::Result<()> {
        match &self.body {
            Body::Literal { bytes, anchor } => {
                if let Some(start) = anchor_start.checked_sub(*anchor)
                    && range.contains(&start)
                    && input.get(start..).is_some_and(|s| s.starts_with(bytes))
                {
                    emit(start, start + bytes.len());
                }
            }
            Body::Program(p) => {
                let anchor = self.anchor();
                if !input
                    .get(anchor_start..)
                    .is_some_and(|s| s.starts_with(anchor))
                {
                    return Ok(());
                }
                let left = side(input, anchor_start, p.atoms[..p.anchor].iter().rev(), true)
                    .select(|s| {
                        range.contains(&s)
                            && p.left.as_ref().is_none_or(|f| f.matches(input, s, true))
                    });
                if let Some(start) = left {
                    let right = side(
                        input,
                        anchor_start + anchor.len(),
                        p.atoms[p.anchor + 1..].iter(),
                        false,
                    )
                    .select(|end| {
                        p.right
                            .as_ref()
                            .is_none_or(|f| f.matches(input, end, false))
                    });
                    if let Some(end) = right {
                        emit(start, end);
                    }
                }
            }
        }
        Ok(())
    }
}

// Keep the ordinary verifier allocation-free. Only variable-width alternatives can
// branch. Coalesce equal cursors after each atom so their suffix is verified once.
#[derive(Default)]
enum Positions {
    #[default]
    Empty,
    One(usize),
    Several {
        values: Vec<usize>,
        seen: HashSet<usize>,
    },
}

impl Positions {
    fn push(&mut self, n: usize) {
        match self {
            Self::Empty => *self = Self::One(n),
            Self::One(old) if *old != n => {
                *self = Self::Several {
                    values: vec![*old, n],
                    seen: HashSet::from([*old, n]),
                }
            }
            Self::One(_) => (),
            Self::Several { values, seen } => {
                if seen.insert(n) {
                    values.push(n);
                }
            }
        }
    }

    fn select(self, condition: impl Fn(usize) -> bool) -> Option<usize> {
        match self {
            Self::Empty => None,
            Self::One(n) => condition(n).then_some(n),
            Self::Several { values, .. } => values.into_iter().find(|&n| condition(n)),
        }
    }
}

fn side<'a>(
    input: &[u8],
    cursor: usize,
    atoms: impl Iterator<Item = &'a Atom>,
    reverse: bool,
) -> Positions {
    let mut active = Positions::One(cursor);
    for atom in atoms {
        let mut next = Positions::Empty;
        match active {
            Positions::Empty => break,
            Positions::One(n) => atom.step(input, n, reverse, |p| next.push(p)),
            Positions::Several { values, .. } => {
                for n in values {
                    atom.step(input, n, reverse, |p| next.push(p));
                }
            }
        }
        active = next;
    }
    active
}

// The pinned AC matcher keeps the first partial match plus eight replaceable slots.
// When the second part connects to another first-part match, it brings that match
// into the first slot. Logical subsignatures report its start for each final hit.
#[derive(Default)]
struct History {
    spans: Vec<(usize, usize)>,
    next: usize,
}

impl History {
    fn record(&mut self, span: (usize, usize)) {
        const SLOTS: usize = 9;
        if self.spans.len() < SLOTS {
            self.spans.push(span);
        } else {
            self.spans[self.next] = span;
        }
        self.next += 1;
        if self.next == SLOTS {
            self.next = 1;
        }
    }
}

#[derive(Default)]
pub(super) struct MatchState {
    history: Vec<History>,
}

impl MatchState {
    pub(super) fn advance(
        &mut self,
        pattern: &Pattern,
        part: usize,
        start: usize,
        end: usize,
    ) -> Option<(usize, usize)> {
        let parts = pattern.parts();
        if parts.len() == 1 {
            return Some((start, end));
        }
        if self.history.is_empty() {
            if part != 0 {
                return None;
            }
            self.history.resize_with(parts.len() - 1, History::default);
        }
        if part != 0 {
            let gap = parts[part].gap;
            let previous = &mut self.history[part - 1].spans;
            let selected = previous.iter().position(|&(_, prev_end)| {
                start.checked_sub(prev_end).is_some_and(|d| {
                    d >= gap.min as usize && (gap.max == 0 || d <= gap.max as usize)
                })
            })?;
            if part == 1 {
                previous.swap(0, selected);
            }
        }
        if part == parts.len() - 1 {
            Some((self.history[0].spans[0].0, end))
        } else {
            self.history[part].record((start, end));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part_hits(text: &str, data: &[u8], range: RangeInclusive<usize>) -> Vec<(usize, usize)> {
        let pattern = Pattern::compile(text).unwrap();
        assert_eq!(pattern.parts().len(), 1);
        let part = &pattern.parts()[0];
        let mut hits = Vec::new();
        for pos in 0..data.len() {
            part.hits_for_anchor(data, pos, range.clone(), |a, b| hits.push((a, b)))
                .unwrap();
        }
        hits
    }

    #[test]
    fn bytes_masks_alternatives_and_overlaps() {
        assert_eq!(part_hits("616161", b"aaaa", 0..=4), [(0, 3), (1, 4)]);
        assert_eq!(part_hits("6?6263?4??", b"abcd!abcd!", 1..=9), [(5, 10)]);
        assert_eq!(
            part_hits("6162(6364|6378)65", b"abcdeabcxe", 0..=10),
            [(0, 5), (5, 10)]
        );
        assert_eq!(
            part_hits("6162!(6364|6263)65", b"abcdeabcxe", 0..=10),
            [(5, 10)]
        );
        assert_eq!(
            part_hits("6162(63|6364)65", b"abcdeabce", 0..=9),
            [(0, 5), (5, 9)]
        );
        assert_eq!(
            part_hits("6162(63{1}|7?7?)65", b"abcdeabzze", 0..=10),
            [(0, 5), (5, 10)]
        );
        // Preserve alternative order when different lengths can both finish at this anchor.
        assert_eq!(part_hits("616263(6465|64)", b"abcde", 0..=5), [(0, 5)]);
    }

    #[test]
    fn bracket_flanks_keep_core_coordinates() {
        let pattern = "41[1-2]424344[0-1]45";
        assert_eq!(part_hits(pattern, b"AxBCDE", 2..=2), [(2, 5)]);
        assert_eq!(part_hits(pattern, b"AxxBCDxE", 3..=3), [(3, 6)]);
        assert!(part_hits(pattern, b"AxxxBCDE", 0..=8).is_empty());
        assert!(part_hits(pattern, b"AxBCDx", 0..=6).is_empty());
        assert!(part_hits(pattern, b"AxBCDE", 0..=0).is_empty());
    }

    #[test]
    fn multipart_reports_stock_first_position_for_each_final_hit() {
        let pattern = Pattern::compile("6162{2-5}6364*6566").unwrap();
        let mut state = MatchState::default();
        assert_eq!(state.advance(&pattern, 0, 1, 3), None);
        assert_eq!(state.advance(&pattern, 0, 9, 11), None);
        assert_eq!(state.advance(&pattern, 1, 13, 15), None);
        assert_eq!(state.advance(&pattern, 2, 15, 17), Some((9, 17)));
        assert_eq!(state.advance(&pattern, 2, 20, 22), Some((9, 22)));
    }

    #[test]
    fn multipart_tracks_first_slot_and_eight_recent_ends() {
        let pattern = Pattern::compile("6162{1-1}6364").unwrap();
        let mut state = MatchState::default();
        for start in 0..11 {
            assert_eq!(state.advance(&pattern, 0, start, start + 2), None);
        }
        // The oldest start is retained even after the history wraps.
        assert_eq!(state.advance(&pattern, 1, 3, 5), Some((0, 5)));
        assert_eq!(state.advance(&pattern, 1, 4, 6), None);
        assert_eq!(state.advance(&pattern, 1, 13, 15), Some((10, 15)));
    }

    #[test]
    fn malformed_and_unimplemented_syntax_returns_errors() {
        for text in [
            "a",
            "6162?",
            "6162**6364",
            "6162{4-2}6364",
            "6162{a}6364",
            "6162!",
            "????",
            "61[34]6263",
            "6162[1-2]ff00",
            "6162(63|646)",
            "6162!(63|6465)",
            "6162(63|)",
            "6162(6*|6465)",
            "6162(B)",
            "6162{2",
        ] {
            assert!(Pattern::compile(text).is_err(), "{text}");
        }
    }
}
