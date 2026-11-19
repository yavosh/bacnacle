//! Match the directory order of the Office-specific extractor on the configured scratch filesystem.
use super::directory::{Inventory, Member};
use super::{
    ChildSink, Document, Handling, native, native_payload, normalized_name, raw, temp_name,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

struct Layout {
    files: HashMap<String, usize>,
    native: HashMap<usize, Vec<usize>>,
    folders: HashMap<String, usize>,
}

impl Layout {
    fn create(
        root: &Path,
        directory: &Inventory,
        sink: &mut dyn ChildSink,
    ) -> io::Result<Option<Self>> {
        let mut layout = Self {
            files: HashMap::new(),
            native: HashMap::new(),
            folders: HashMap::new(),
        };
        let mut counts = HashMap::new();
        // The names and insertion order affect readdir. File contents stay in the source CFB.
        for &member in &directory.members {
            sink.check()?;
            match member {
                Member::Folder(id) => {
                    let path = directory.temporary_path(id);
                    fs::create_dir(root.join(&path))?;
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .expect("numeric storage name");
                    layout.folders.insert(name.to_owned(), id);
                }
                Member::File(id) => {
                    let entry = &directory.streams[id];
                    let Some(normalized) = normalized_name(&entry.name) else {
                        return Ok(None);
                    };
                    let count = counts.entry(normalized.clone()).or_insert(0);
                    *count += 1;
                    let name = temp_name(&normalized, *count);
                    fs::File::create_new(
                        root.join(directory.temporary_path(entry.parent))
                            .join(&name),
                    )?;
                    layout.files.insert(name, id);
                    if native(&entry.name) {
                        layout.native.entry(entry.parent).or_default().push(id);
                    }
                }
            }
        }
        Ok(Some(layout))
    }

    fn raw_walk(
        &self,
        path: &Path,
        doc: &mut Document,
        directory: &Inventory,
        sink: &mut dyn ChildSink,
    ) -> io::Result<bool> {
        for file in fs::read_dir(path)? {
            sink.check()?;
            let file = file?;
            let mut stopped = false;
            if file.file_type()?.is_dir() {
                stopped = self.raw_walk(&file.path(), doc, directory, sink)?;
            } else if let Some((name, &id)) = file
                .file_name()
                .to_str()
                .and_then(|n| self.files.get_key_value(n))
            {
                stopped = raw(
                    doc,
                    directory,
                    &directory.streams[id],
                    Some(name.as_bytes()),
                    sink,
                )?;
            }
            if stopped {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn visit(
        &self,
        path: &Path,
        folder: usize,
        doc: &mut Document,
        directory: &Inventory,
        sink: &mut dyn ChildSink,
    ) -> io::Result<bool> {
        // The caller already compared root Package attachments before checking for Office-specific stages.
        if folder != 0
            && let Some(files) = self.native.get(&folder)
        {
            for &id in files.iter().rev() {
                if native_payload(doc, directory, &directory.streams[id], sink)? {
                    return Ok(true);
                }
            }
        }
        if self.raw_walk(path, doc, directory, sink)? {
            return Ok(true);
        }
        for entry in fs::read_dir(path)? {
            sink.check()?;
            let file = entry?;
            if file.file_type()?.is_dir()
                && let Some(&id) = file.file_name().to_str().and_then(|n| self.folders.get(n))
                && self.visit(&file.path(), id, doc, directory, sink)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

pub(super) fn scan(
    doc: &mut Document,
    directory: &Inventory,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let scratch = tempfile::tempdir_in(sink.temporary_directory())?;
    let Some(layout) = Layout::create(scratch.path(), directory, sink)? else {
        return Ok(Handling::Incomplete);
    };
    Ok(if layout.visit(scratch.path(), 0, doc, directory, sink)? {
        Handling::Stopped
    } else {
        Handling::Complete
    })
}
