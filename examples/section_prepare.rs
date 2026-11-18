//! Prepare the frozen PE section databases for the existing compact hash-index builder.
#[path = "section_prepare/fields.rs"]
mod fields;

use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::Path;

// Digests identify the members of the verified archives recorded in the benchmark report.
const MEMBERS: [(&str, &str); 8] = [
    (
        "daily.ign",
        "6829fb1d1689dcf115a8ee26cf8f3c93aa521da3637a2e5d3b58b1c7bb8ba4be",
    ),
    (
        "daily.ign2",
        "de3e4212d5c1e1175a88e2e4ff930e00848437384b41375ca1c98c5f3c602c46",
    ),
    (
        "daily.mdb",
        "33cd6e60d31d4f90b4741102c8ae2a08d4807bde87bee1100fba2acaff00f135",
    ),
    (
        "daily.msb",
        "7619a3f6cf7f097890b29a437e2382e22e2a8cb40c2c3cc5771201ea7beb57e2",
    ),
    (
        "main.mdb",
        "fecbbc24e4b5aa6e7ae63d351b16ed927514413b56b62a4b8e90b0dc1c1bafc7",
    ),
    (
        "main.msb",
        "5e873aa23244505cd5630f3747487b4a8e71a048137a3d47192be61db90ab622",
    ),
    (
        "daily.mdu",
        "4e24daa3984130eea95d490957b2e14075e934c799d06b681e4f14b59c7fc324",
    ),
    (
        "daily.msu",
        "5e873aa23244505cd5630f3747487b4a8e71a048137a3d47192be61db90ab622",
    ),
];

fn prepare(source: &Path, output: &Path) -> io::Result<()> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::tempdir_in(parent)?;
    for (name, expected) in MEMBERS {
        let mut reader = BufReader::new(File::open(source.join(name))?);
        let ignored_pua = name.ends_with(".mdu") || name.ends_with(".msu");
        let ignore_list = name.ends_with(".ign") || name.ends_with(".ign2");
        let destination = if ignore_list {
            name.to_owned()
        } else {
            format!("{name}.hsb")
        };
        let mut writer = if ignored_pua {
            None
        } else {
            Some(BufWriter::new(File::create_new(
                staging.path().join(destination),
            )?))
        };
        let mut digest = Sha256::new();
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            digest.update(line.as_bytes());
            if let Some(ref mut writer) = writer {
                if ignore_list {
                    // A conditional ignore hashes the original line. Transposition would change it.
                    if !line.starts_with('#') && line.split(':').count() == 2 {
                        return Err(io::Error::other(
                            "conditional ignore requires original rule text",
                        ));
                    }
                    writer.write_all(line.as_bytes())?;
                } else {
                    fields::transpose(&line, writer)?;
                }
            }
        }
        if let Some(mut writer) = writer {
            writer.flush()?;
        }
        let hex: String = digest
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if hex != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name} differs from the verified generation"),
            ));
        }
    }
    // Reserve the destination. Unix rename publishes every member over our empty directory.
    fs::create_dir(output)?;
    if let Err(error) = fs::rename(staging.path(), output) {
        let _ = fs::remove_dir(output);
        return Err(error);
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [source, output] = args.as_slice() else {
        return Err(io::Error::other(
            "usage: section_prepare EXTRACTED_MEMBERS NEW_DIRECTORY",
        ));
    };
    prepare(Path::new(source), Path::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_input_validation_leaves_destination_available_for_retry() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let output = root.path().join("converted");
        assert_eq!(
            prepare(root.path(), &output).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!output.exists());
        fs::write(root.path().join("daily.ign"), "Unpinned.Ignore\n")?;
        assert_eq!(
            prepare(root.path(), &output).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!output.exists());
        Ok(())
    }
}
