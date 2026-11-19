//! Identify ordinary records that can proceed directly to the reference raw-stream pass.
use super::{ChildSink, Document, Inventory, Stream};
use std::io::{self, Read, Seek, SeekFrom};

pub(super) fn ordinary(
    doc: &mut Document,
    directory: &Inventory,
    entry: &Stream,
    sink: &mut dyn ChildSink,
) -> io::Result<bool> {
    let word = entry.name.eq_ignore_ascii_case("worddocument");
    let ppt = entry.name.eq_ignore_ascii_case("powerpoint document");
    let biff =
        entry.name.eq_ignore_ascii_case("book") || entry.name.eq_ignore_ascii_case("workbook");
    if !word && !ppt && !biff {
        return Ok(true);
    }
    let mut data = doc.open_stream(directory.path(entry))?;
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
    let header = if ppt { 8 } else { 4 };
    while data.len().saturating_sub(pos) >= header as u64 {
        sink.check()?;
        let mut buf = [0; 8];
        data.read_exact(&mut buf[..header])?;
        let n = if ppt {
            let kind = u16::from_le_bytes([buf[2], buf[3]]);
            let len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            if len == 0 {
                return Ok(true);
            }
            if kind == 0x1011 {
                return Ok(false);
            } // ExOleObjStg records contain embedded storage.
            u64::from(len)
        } else {
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
            u64::from(len)
        };
        pos += header as u64 + n;
        if pos >= data.len() {
            break;
        }
        data.seek(SeekFrom::Start(pos))?;
    }
    Ok(true)
}
