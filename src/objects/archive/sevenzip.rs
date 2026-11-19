use super::{ChildSink, Handling, decoded};
use sevenz_rust2::{ArchiveReader, EntryDecision, Password};
use std::io::{self, Cursor};

pub(super) fn extract(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<Handling> {
    // Stock's 7z allocator uses the same individual-allocation ceiling as its XZ decoder.
    let Ok(mut archive) =
        ArchiveReader::new_with_memory_limit(Cursor::new(bytes), Password::empty(), 1024 * 1024)
    else {
        return Ok(Handling::Incomplete);
    };
    archive.set_thread_count(1);
    let solid = archive.archive().is_solid;
    let mut outcome = Ok(Handling::Complete);
    let scanned = archive.for_each_entries_with_decision(|entry, mut reader| {
        // A solid block shares its dictionary across files. Consume any skipped
        // prefix with deadline checks to reach the next file in that same block.
        let visit = (|| -> io::Result<EntryDecision> {
            sink.check()?;
            if entry.is_directory || entry.size == 0 {
                return Ok(EntryDecision::Continue);
            }
            if !sink.skip_declared_size(entry.size) {
                // The pinned reader passes the low byte of each UTF-16 unit as metadata.
                let name: Vec<_> = entry
                    .name
                    .encode_utf16()
                    .map(|u| u as u8)
                    .take_while(|&b| b != 0)
                    .collect();
                let result = decoded(&mut reader, Some(&name), false, sink)?;
                if result != Handling::Complete {
                    outcome = Ok(result);
                    return Ok(EntryDecision::Stop);
                }
            } else if !solid {
                return Ok(EntryDecision::SkipBlock);
            }
            let mut block = [0; 8192];
            loop {
                sink.check()?;
                match reader.read(&mut block) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => {
                        outcome = Ok(Handling::Incomplete);
                        return Ok(EntryDecision::Stop);
                    }
                }
            }
            Ok(EntryDecision::Continue)
        })();
        match visit {
            Ok(d) => Ok(d),
            Err(e) => {
                outcome = Err(e);
                Ok(EntryDecision::Stop)
            }
        }
    });
    match scanned {
        Ok(()) => outcome,
        Err(_) => Ok(Handling::Incomplete),
    }
}
