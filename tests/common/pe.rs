pub fn benign_pe() -> Vec<u8> {
    // A PE32 header and one read-only, non-executable .data section. The image has no entry point.
    let mut image = vec![0u8; 1024];
    image[..2].copy_from_slice(b"MZ");
    image[60] = 128;
    image[128..132].copy_from_slice(b"PE\0\0");
    let coff = &mut image[132..152];
    coff[..2].copy_from_slice(&0x014cu16.to_le_bytes());
    coff[2] = 1; // sections
    coff[16] = 224; // size of optional header
    coff[18] = 2; // image
    let optional = &mut image[152..376];
    optional[..2].copy_from_slice(&0x010bu16.to_le_bytes());
    for (offset, value) in [
        (8, 512u32),
        (28, 0x00400000),
        (32, 4096),
        (36, 512),
        (56, 8192),
        (60, 512),
        (92, 16),
    ] {
        optional[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    optional[68] = 3; // console subsystem
    let section = &mut image[376..416];
    section[..5].copy_from_slice(b".data");
    for (offset, value) in [
        (8, 512u32),
        (12, 4096),
        (16, 512),
        (20, 512),
        (36, 0x40000040),
    ] {
        section[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in image[512..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    image
}
