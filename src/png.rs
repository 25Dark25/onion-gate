//! Minimal PNG encoder. No dependencies and no real compression: the data
//! goes into "stored" deflate blocks (BTYPE=00), valid per RFC 1951.
//! With a 1-bit-per-pixel image the result is about 12 KB.

fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for part in parts {
        for &b in part.iter() {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
    }
    !c
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Wraps `data` in a zlib stream using only "stored" blocks.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + (data.len() / 65535 + 1) * 5 + 6);
    // CMF=0x78 (deflate, 32K window), FLG=0x01 -> (0x7801 % 31 == 0)
    out.extend_from_slice(&[0x78, 0x01]);
    if data.is_empty() {
        // a single, empty, final block
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
    } else {
        let total = data.chunks(65535).count();
        for (i, chunk) in data.chunks(65535).enumerate() {
            let last = i + 1 == total;
            let len = chunk.len() as u16; // <= 65535, fits
            out.push(if last { 1 } else { 0 }); // BFINAL, BTYPE=00
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

fn push_chunk(out: &mut Vec<u8>, kind: &[u8], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    out.extend_from_slice(&crc32(&[kind, data]).to_be_bytes());
}

/// `raw` holds the scanlines, each already prefixed with its filter byte (always 0 here).
pub fn encode(width: u32, height: u32, bit_depth: u8, color_type: u8, raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 128);
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    // bit depth, color type, compression=0, filter=0, interlace=0
    ihdr.extend_from_slice(&[bit_depth, color_type, 0, 0, 0]);

    push_chunk(&mut out, b"IHDR", &ihdr);
    push_chunk(&mut out, b"IDAT", &zlib_stored(raw));
    push_chunk(&mut out, b"IEND", &[]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(&[&b"123456789"[..]]), 0xCBF4_3926);
    }

    #[test]
    fn crc32_in_parts_equals_whole() {
        assert_eq!(crc32(&[&b"1234"[..], &b"56789"[..]]), 0xCBF4_3926);
    }

    #[test]
    fn adler32_known_vector() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn zlib_length_with_several_blocks() {
        let data = vec![7u8; 70_000];
        let z = zlib_stored(&data);
        // 2 (header) + (5+65535) + (5+4465) + 4 (adler)
        assert_eq!(z.len(), 2 + 5 + 65535 + 5 + 4465 + 4);
        assert_eq!(z[2], 0); // first block is not final
        assert_eq!(z[2 + 5 + 65535], 1); // second one is
    }

    #[test]
    fn png_has_signature_and_iend() {
        let p = encode(8, 1, 1, 0, &[0, 0xFF]);
        assert_eq!(&p[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert!(p.ends_with(&[0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]));
        assert_eq!(&p[12..16], b"IHDR");
    }
}
