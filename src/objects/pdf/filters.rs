//! Bounded readers for sampled PDF stream filters.
use flate2::read::ZlibDecoder;
use std::io::{self, Read};
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Filter {
    Flate,
    Hex,
    Ascii85,
    RunLength,
    Jpeg,
    Unsupported,
}
impl Filter {
    pub(super) fn parse(name: &[u8]) -> Self {
        match name {
            b"/FlateDecode" | b"/Fl" => Self::Flate,
            b"/ASCIIHexDecode" | b"/AHx" => Self::Hex,
            b"/ASCII85Decode" | b"/A85" => Self::Ascii85,
            b"/RunLengthDecode" | b"/RL" => Self::RunLength,
            b"/DCTDecode" | b"/DCT" => Self::Jpeg,
            _ => Self::Unsupported,
        }
    }
    pub(super) fn dumped(&self) -> bool {
        matches!(self, Self::Flate | Self::Hex | Self::Ascii85 | Self::Jpeg)
    }
    pub(super) fn reader(self, data: &[u8]) -> io::Result<Box<dyn Read + '_>> {
        Ok(match self {
            Self::Flate => Box::new(ZlibDecoder::new(data)),
            Self::Hex => Box::new(Hex(data)),
            Self::Ascii85 => Box::new(Ascii85 {
                input: data,
                next: [0; 4],
                cursor: 0,
                len: 0,
                done: false,
            }),
            Self::RunLength => Box::new(Runs {
                input: data,
                repeat: None,
                left: 0,
            }),
            _ => return Err(invalid()),
        })
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid PDF filter data")
}
struct Hex<'a>(&'a [u8]);
impl Read for Hex<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut used = 0;
        while used < out.len() && self.0.len() >= 2 {
            if self.0[0] == b'>' {
                self.0 = &[];
                break;
            }
            if self.0[0] == b' ' {
                self.0 = &self.0[1..];
                continue;
            }
            let pair = &self.0[..2];
            match (
                char::from(pair[0]).to_digit(16),
                char::from(pair[1]).to_digit(16),
            ) {
                (Some(a), Some(b)) => {
                    out[used] = (a * 16 + b) as u8;
                    used += 1;
                    self.0 = &self.0[2..];
                }
                _ if self.0.len() < 4 => self.0 = &self.0[1..],
                _ => return Err(invalid()),
            }
        }
        Ok(used)
    }
}
struct Ascii85<'a> {
    input: &'a [u8],
    next: [u8; 4],
    cursor: usize,
    len: usize,
    done: bool,
}
impl Ascii85<'_> {
    fn group(&mut self) -> io::Result<()> {
        let mut value = 0u64;
        let mut n = 0usize;
        self.cursor = 0;
        while let Some((&b, rest)) = self.input.split_first() {
            self.input = rest;
            match b {
                b'~' => {
                    if !rest.starts_with(b">") {
                        return Err(invalid());
                    }
                    self.done = true;
                    break;
                }
                b'z' if n == 0 => {
                    self.next = [0; 4];
                    self.len = 4;
                    return Ok(());
                }
                b'!'..=b'u' => {
                    value = value * 85 + u64::from(b - b'!');
                    n += 1;
                    if n == 5 {
                        break;
                    }
                }
                b if b.is_ascii_whitespace() || b == 0 => (),
                _ => return Err(invalid()),
            }
        }
        if n < 5 {
            self.done = true;
        }
        if n == 0 {
            self.len = 0;
            return Ok(());
        }
        if n == 1 {
            return Err(invalid());
        }
        self.len = n.saturating_sub(1);
        for _ in n..5 {
            value = value * 85 + 84;
        }
        self.next = u32::try_from(value).map_err(|_| invalid())?.to_be_bytes();
        Ok(())
    }
}
impl Read for Ascii85<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < out.len() {
            if self.cursor == self.len {
                if self.done {
                    break;
                }
                self.group()?;
                if self.len == 0 {
                    break;
                }
            }
            let size = (out.len() - n).min(self.len - self.cursor);
            out[n..n + size].copy_from_slice(&self.next[self.cursor..self.cursor + size]);
            n += size;
            self.cursor += size;
        }
        Ok(n)
    }
}
struct Runs<'a> {
    input: &'a [u8],
    repeat: Option<u8>,
    left: usize,
}
impl Read for Runs<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut used = 0;
        while used < out.len() {
            if self.left == 0 {
                let Some((&first, rest)) = self.input.split_first() else {
                    break;
                };
                self.input = rest;
                match first {
                    128 => {
                        self.input = &[];
                        break;
                    }
                    0..=127 => {
                        self.left = usize::from(first) + 1;
                        self.repeat = None;
                    }
                    other => {
                        let Some((&byte, rest)) = self.input.split_first() else {
                            return Err(invalid());
                        };
                        self.left = 257 - usize::from(other);
                        self.repeat = Some(byte);
                        self.input = rest;
                    }
                }
            }
            let n = self.left.min(out.len() - used);
            if let Some(v) = self.repeat {
                out[used..used + n].fill(v);
            } else {
                let (src, rest) = self.input.split_at_checked(n).ok_or_else(invalid)?;
                out[used..used + n].copy_from_slice(src);
                self.input = rest;
            }
            used += n;
            self.left -= n;
        }
        Ok(used)
    }
}
