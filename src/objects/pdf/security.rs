//! Open standard-security PDF streams using the empty user credential.
use super::{ChildSink, Id, Output, Snapshot, Tokens};
use aes::cipher::{Block, BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7, consts::U16};
use flate2::{Decompress, FlushDecompress, Status};
use lopdf::{Dictionary, Document, EncryptionState, Object, ObjectId, StringFormat};
use std::io::{self, Write};

pub(super) const MAX_METADATA: usize = 16 * 1024;

// Only bounded direct metadata enters the security library. PDF bodies keep
// their original offsets and physical order in the existing scanner.
fn value(input: &mut Tokens<'_>, token: &[u8], depth: usize) -> Option<Object> {
    if depth > 4 {
        return None;
    }
    match token {
        b"<<" => {
            let mut dict = Dictionary::new();
            loop {
                let key = input.next()?;
                if key == b">>" {
                    return Some(Object::Dictionary(dict));
                }
                let key = key.strip_prefix(b"/")?;
                if key.is_empty() || key.len() > 64 || dict.len() >= 32 || dict.has(key) {
                    return None;
                }
                let token = input.next()?;
                dict.set(key, value(input, token, depth + 1)?);
            }
        }
        b"[" => {
            let mut array = Vec::new();
            loop {
                let item = input.next()?;
                if item == b"]" {
                    return Some(Object::Array(array));
                }
                if array.len() == 8 {
                    return None;
                }
                array.push(value(input, item, depth + 1)?);
            }
        }
        b"true" => Some(Object::Boolean(true)),
        b"false" => Some(Object::Boolean(false)),
        [b'/', name @ ..] if !name.is_empty() && name.len() <= 64 => {
            Some(Object::Name(name.to_vec()))
        }
        [b'<', hex @ .., b'>'] if hex.len() <= 256 && hex.len().is_multiple_of(2) => {
            let bytes = hex
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .collect::<Option<_>>()?;
            Some(Object::String(bytes, StringFormat::Hexadecimal))
        }
        _ => {
            let number = std::str::from_utf8(token).ok()?.parse::<i64>().ok()?;
            let mut look = input.clone();
            if let Some(generation) = look.next().and_then(super::number)
                && look.next() == Some(b"R")
            {
                *input = look;
                return Some(Object::Reference((
                    number.try_into().ok()?,
                    generation.try_into().ok()?,
                )));
            }
            Some(Object::Integer(number))
        }
    }
}

fn dictionary(bytes: &[u8]) -> Option<Dictionary> {
    let mut input = Tokens {
        data: &bytes[..bytes.len().min(MAX_METADATA)],
        pos: 0,
    };
    let token = input.next()?;
    let Object::Dictionary(dictionary) = value(&mut input, token, 0)? else {
        return None;
    };
    Some(dictionary)
}

// The only escaped name sampled here is a direct EmbeddedFile MIME subtype.
// Other name escapes can change a PDF type, filter or action.
pub(super) fn embedded_mime(header: &[u8], escaped: &[u8]) -> bool {
    let mut input = Tokens {
        data: &header[..header.len().min(MAX_METADATA)],
        pos: 0,
    };
    if input.next() != Some(b"<<") {
        return false;
    }
    let mut embedded = None;
    let mut subtype = None;
    let mut depth = 1;
    while let Some(token) = input.next() {
        match token {
            b"<<" | b"[" => depth += 1,
            b">>" | b"]" => {
                depth -= 1;
                if depth == 0 {
                    return embedded == Some(true) && subtype == Some(true);
                }
            }
            b"/Type" if depth == 1 && embedded.is_none() => {
                embedded = Some(input.next() == Some(b"/EmbeddedFile"));
            }
            b"/Subtype" if depth == 1 && subtype.is_none() => {
                subtype = Some(
                    input
                        .next()
                        .is_some_and(|v| std::ptr::eq(v, escaped) && mime_name(v)),
                );
            }
            b"/Type" | b"/Subtype" if depth == 1 => return false,
            _ => (),
        }
    }
    false
}

fn mime_name(token: &[u8]) -> bool {
    let Some(name) = token.strip_prefix(b"/") else {
        return false;
    };
    let Some(index) = name.iter().position(|b| *b == b'#') else {
        return false;
    };
    let (kind, rest) = name.split_at(index);
    let Some(subtype) = rest
        .strip_prefix(b"#2f")
        .or_else(|| rest.strip_prefix(b"#2F"))
    else {
        return false;
    };
    [kind, subtype].iter().all(|part| {
        part.len() <= 127
            && part.first().is_some_and(u8::is_ascii_alphanumeric)
            && part.iter().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(c, b'!' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+')
            })
    })
}

pub(super) fn ciphertext<'a>(
    header: &[u8],
    stream: &'a [u8],
    lengths: &std::collections::HashMap<Id, usize>,
) -> Option<(&'a [u8], bool)> {
    let mut input = Tokens {
        data: &header[..header.len().min(MAX_METADATA)],
        pos: 0,
    };
    if input.next()? != b"<<" {
        return None;
    }
    let mut depth = 1;
    let mut length = None;
    let mut filter_visible = false;
    let mut closed_dictionary = false;
    while depth != 0 {
        match input.next()? {
            b"<<" | b"[" => depth += 1,
            b">>" => {
                closed_dictionary = true;
                depth -= 1;
            }
            b"]" => depth -= 1,
            b"/Filter" if depth == 1 => filter_visible = !closed_dictionary,
            b"/Filter" => return None,
            b"/Length" if depth == 1 => {
                if length.is_some() {
                    return None;
                }
                length = Some(match input.reference() {
                    Some(id) => *lengths.get(&id)?,
                    None => super::number(input.next()?)?,
                });
            }
            _ => (),
        }
    }
    let (cipher, rest) = stream.split_at_checked(length?)?;
    matches!(rest, b"" | b"\n" | b"\r" | b"\r\n").then_some((cipher, filter_visible))
}

pub(super) struct Security(EncryptionState);

impl Security {
    pub(super) fn open(id: Id, metadata: &[u8], trailer: &[u8]) -> Option<Self> {
        let id: ObjectId = (id.0.try_into().ok()?, id.1.try_into().ok()?);
        let trailer = dictionary(trailer)?;
        if trailer.get(b"Encrypt").ok()?.as_reference().ok()? != id
            || trailer.has(b"Prev")
            || trailer.has(b"XRefStm")
        {
            return None;
        }
        let dict = dictionary(metadata)?;
        let revision = dict.get(b"R").ok()?.as_i64().ok()?;
        let (method, version, length) = match revision {
            4 => (b"AESV2", 4, 128),
            5 | 6 => (b"AESV3", 5, 256),
            _ => return None,
        };
        let cf = dict.get(b"CF").ok()?.as_dict().ok()?;
        let std_cf = cf.get(b"StdCF").ok()?.as_dict().ok()?;
        if dict.get(b"Filter").ok()?.as_name().ok()? != b"Standard"
            || dict.get(b"V").ok()?.as_i64().ok()? != version
            || dict.get(b"Length").ok()?.as_i64().ok()? != length
            || std_cf.get(b"Length").ok()?.as_i64().ok()? != length / 8
            || dict.get(b"StmF").ok()?.as_name().ok()? != b"StdCF"
            || dict.get(b"StrF").ok()?.as_name().ok()? != b"StdCF"
            || std_cf.get(b"CFM").ok()?.as_name().ok()? != method
            || std_cf.get(b"AuthEvent").ok()?.as_name().ok()? != b"DocOpen"
            || dict.get(b"P").ok()?.as_i64().ok()? & 0x10 == 0
            || dict.has(b"EFF")
            || dict.has(b"EncryptMetadata")
        {
            return None;
        }
        let mut doc = Document::new();
        doc.trailer.set("ID", trailer.get(b"ID").ok()?.clone());
        doc.trailer.set("Encrypt", Object::Reference(id));
        doc.objects.insert(id, Object::Dictionary(dict));
        doc.authenticate_raw_user_password(b"").ok()?;
        let state = EncryptionState::decode(&doc, b"").ok()?;
        (state.get_stream_filter().method() == method).then_some(Self(state))
    }

    pub(super) fn inflate(
        &self,
        id: Id,
        bytes: &[u8],
        retain: bool,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Output> {
        if bytes.len() < 32 || !bytes.len().is_multiple_of(16) {
            return Ok(Output::Malformed);
        }
        let (Ok(n), Ok(generation)) = (id.0.try_into(), id.1.try_into()) else {
            return Ok(Output::Malformed);
        };
        let filter = self.0.get_stream_filter();
        let Ok(key) = filter.compute_key(self.0.file_encryption_key(), (n, generation)) else {
            return Ok(Output::Malformed);
        };
        if filter.method() == b"AESV2" {
            inflate::<cbc::Decryptor<aes::Aes128>>(&key, bytes, retain, sink)
        } else {
            inflate::<cbc::Decryptor<aes::Aes256>>(&key, bytes, retain, sink)
        }
    }
}

// Verify the final padding before accepting a zlib member that ends early.
fn inflate<D: BlockModeDecrypt<BlockSize = U16> + KeyIvInit>(
    key: &[u8],
    bytes: &[u8],
    retain: bool,
    sink: &mut dyn ChildSink,
) -> io::Result<Output> {
    let end = bytes.len();
    let Ok(last) = D::new_from_slices(key, &bytes[end - 32..end - 16]) else {
        return Ok(Output::Malformed);
    };
    let mut final_block: [u8; 16] = bytes[end - 16..].try_into().expect("one AES block");
    let Ok(tail) = last.decrypt_padded::<Pkcs7>(&mut final_block) else {
        return Ok(Output::Malformed);
    };
    let padding = 16 - tail.len();
    let mut decoder = D::new_from_slices(key, &bytes[..16]).expect("validated key and IV");
    let mut zlib = Decompress::new(true);
    let mut compressed = [0; 8192];
    let mut plain = [0; 8192];
    let limit = sink.remaining();
    let mut output = retain.then(|| Snapshot::new(sink.temporary_directory()));
    let mut chunks = bytes[16..].chunks(compressed.len()).peekable();
    while let Some(chunk) = chunks.next() {
        let final_chunk = chunks.peek().is_none();
        let data = &mut compressed[..chunk.len()];
        data.copy_from_slice(chunk);
        decoder.decrypt_blocks(Block::<D>::slice_as_chunks_mut(data).0);
        let mut input = &data[..data.len() - if final_chunk { padding } else { 0 }];
        loop {
            sink.check()?;
            let before_in = zlib.total_in();
            let before_out = zlib.total_out();
            let flush = if final_chunk && input.is_empty() {
                FlushDecompress::Finish
            } else {
                FlushDecompress::None
            };
            let Ok(status) = zlib.decompress(input, &mut plain, flush) else {
                return Ok(Output::Malformed);
            };
            if zlib.total_out() > limit {
                return Ok(Output::TooLarge(limit.saturating_add(1)));
            }
            let written = (zlib.total_out() - before_out) as usize;
            if let Some(output) = &mut output {
                output.write_all(&plain[..written])?;
            }
            if status == Status::StreamEnd {
                return Ok(output.map_or(Output::Counted(zlib.total_out()), Output::Decoded));
            }
            let used = (zlib.total_in() - before_in) as usize;
            input = &input[used..];
            if input.is_empty() && !final_chunk {
                break;
            }
            if written == 0 && used == 0 {
                return Ok(Output::Malformed);
            }
        }
    }
    Ok(Output::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accept_only_direct_embedded_file_mime_subtypes() {
        for (header, expected) in [
            ("<< /Type /EmbeddedFile /Subtype /text#2fplain >>", true),
            (
                "<< /Subtype /application#2Fvnd.openxmlformats-officedocument /Type /EmbeddedFile >>",
                true,
            ),
            ("<< /Type /XObject /Subtype /text#2fplain >>", false),
            (
                "<< /Type /EmbeddedFile /Params << /Subtype /text#2fplain >> >>",
                false,
            ),
            ("<< /Type /EmbeddedFile /Filter /text#2fplain >>", false),
            ("<< /Type /EmbeddedFile /Subtype /text#2fplain#00 >>", false),
            (
                "<< /Type /EmbeddedFile /Subtype /text#2fplain /Subtype /other >>",
                false,
            ),
        ] {
            let bytes = header.as_bytes();
            let mut tokens = Tokens {
                data: bytes,
                pos: 0,
            };
            let name = std::iter::from_fn(|| tokens.next())
                .find(|token| token.contains(&b'#'))
                .unwrap();
            assert_eq!(embedded_mime(bytes, name), expected, "{header}");
        }
    }
}
