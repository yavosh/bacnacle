use serde_json::{Value, json};
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

fn invalid(message: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

fn number(field: &str) -> io::Result<u64> {
    field
        .trim()
        .parse()
        .map_err(|_| invalid("invalid cgroup number"))
}

fn keyed(stats: &str, key: &str) -> io::Result<u64> {
    let field = stats
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == key).then_some(value)
        })
        .ok_or_else(|| invalid(&format!("missing cgroup counter {key}")))?;
    number(field)
}

fn read_bytes(stats: &str) -> io::Result<u64> {
    let mut total: u64 = 0;
    for device in stats.lines() {
        let field = device
            .split_whitespace()
            .find_map(|f| f.strip_prefix("rbytes="))
            .ok_or_else(|| invalid("missing device read counter"))?;
        total = total
            .checked_add(number(field)?)
            .ok_or_else(|| invalid("I/O counter overflow"))?;
    }
    Ok(total)
}

#[derive(Clone)]
pub struct Counters {
    pub current: u64,
    kernel_peak: u64,
    anon: u64,
    file: u64,
    reads: u64,
    faults: u64,
}

impl Counters {
    pub fn read(cgroup: &Path) -> io::Result<Self> {
        let memory = fs::read_to_string(cgroup.join("memory.stat"))?;
        Ok(Self {
            current: number(&fs::read_to_string(cgroup.join("memory.current"))?)?,
            kernel_peak: number(&fs::read_to_string(cgroup.join("memory.peak"))?)?,
            anon: keyed(&memory, "anon")?,
            file: keyed(&memory, "file")?,
            reads: read_bytes(&fs::read_to_string(cgroup.join("io.stat"))?)?,
            faults: keyed(&memory, "pgmajfault")?,
        })
    }

    pub fn json(&self) -> Value {
        json!({"current_bytes":self.current,"peak_bytes":self.kernel_peak,"anon_bytes":self.anon,
               "file_bytes":self.file,"disk_read_bytes":self.reads,"major_faults":self.faults})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_devices_and_rejects_missing_fields() {
        assert_eq!(
            read_bytes("254:0 rios=3 rbytes=35\n254:1 rbytes=7 wbytes=6\n").unwrap(),
            42
        );
        assert_eq!(read_bytes("").unwrap(), 0);
        assert!(read_bytes("254:0 wbytes=3").is_err());
        assert!(keyed("file_mapped 3\n", "file").is_err());
        assert_eq!(keyed("file_mapped 3\nfile 17\n", "file").unwrap(), 17);
    }
}
