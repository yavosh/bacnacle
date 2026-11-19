//! Identify ordinary records that can proceed directly to the reference raw-stream pass.
use super::{ChildSink, Document, Input, Inventory, Stream};
use std::io::{self, Read, Seek, SeekFrom};

pub(super) fn ordinary(
    doc: &mut Document,
    directory: &Inventory,
    entry: &Stream,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let word = entry.name.eq_ignore_ascii_case("worddocument");
    let biff =
        entry.name.eq_ignore_ascii_case("book") || entry.name.eq_ignore_ascii_case("workbook");
    if !word && !biff {
        return Ok(true);
    }
    let mut data = Input::open(doc, directory, entry)?;
    if word {
        // The WordBasic macro region length in the file information block is zero for ordinary text.
        if data.len() < 0x120 {
            return Ok(true);
        }
        data.seek(SeekFrom::Start(0x11c))?;
        let mut len = [0; 4];
        data.read_exact(&mut len)?;
        return Ok(u32::from_le_bytes(len) == 0);
    }
    let mut pos = 0u64;
    while data.len().saturating_sub(pos) >= 4 {
        sink.check()?;
        let mut buf = [0; 4];
        data.read_exact(&mut buf)?;
        let kind = u16::from_le_bytes([buf[0], buf[1]]);
        let len = u16::from_le_bytes([buf[2], buf[3]]);
        if kind == 0x00eb && len > 0 {
            return Ok(false);
        } // MSODRAWINGGROUP can contain images.
        if kind == 0x0085 && len >= 6 && data.len().saturating_sub(pos + 4) >= 6 {
            let mut sheet = [0; 6];
            data.read_exact(&mut sheet)?;
            if sheet[5] == 1 {
                return Ok(false);
            } // BOUNDSHEET marks an Excel 4 macro sheet.
        }
        pos += 4 + u64::from(len);
        if pos >= data.len() {
            break;
        }
        data.seek(SeekFrom::Start(pos))?;
    }
    Ok(true)
}
