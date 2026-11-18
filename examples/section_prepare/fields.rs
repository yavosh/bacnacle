use std::io::{self, Write};

/// PE section databases put the byte count before the digest. Keep every remaining byte intact.
pub fn transpose(line: &str, output: &mut impl Write) -> io::Result<()> {
    if line.starts_with('#') {
        return output.write_all(line.as_bytes());
    }
    let fields = line.split_once(':').and_then(|(size, rest)| {
        let (digest, tail) = rest.split_once(':')?;
        Some((size, digest, tail))
    });
    let (size, digest, tail) = fields
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing section rule fields"))?;
    write!(output, "{digest}:{size}:{tail}")
}
