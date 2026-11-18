//! File offsets for the barnacle-v1 file trace. Every fourth request repeats file zero.
pub fn spans() -> impl Iterator<Item = (u64, usize)> {
    let mut offset = 0;
    (0..4096).map(move |id| {
        let size = [4096, 16384, 65536, 262144][id % 4];
        if id > 0 && id % 4 == 0 {
            (0, size)
        } else {
            let start = offset;
            offset += size as u64;
            (start, size)
        }
    })
}
