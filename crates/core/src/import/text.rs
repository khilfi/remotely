//! Text encodings of import files (SS-02).
//!
//! regedit writes `.reg` files as UTF-16 LE with a byte order mark, MobaXterm writes its exports in
//! the Windows ANSI code page (Windows-1252 on Western systems), and CSV files come from anywhere.

/// Decodes an import file: a UTF-8, UTF-16 LE or UTF-16 BE byte order mark picks the encoding (and is
/// dropped); without one the bytes are UTF-8, or Windows-1252 when they are not valid UTF-8.
/// Never fails: undecodable UTF-16 becomes U+FFFD.
pub fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(b"\xEF\xBB\xBF") {
        return utf8_or_ansi(rest);
    }
    if let Some(rest) = bytes.strip_prefix(b"\xFF\xFE") {
        return utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(b"\xFE\xFF") {
        return utf16(rest, u16::from_be_bytes);
    }
    utf8_or_ansi(bytes)
}

/// UTF-8, or Windows-1252 when the bytes are not valid UTF-8.
pub(crate) fn utf8_or_ansi(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => bytes.iter().map(|&b| windows_1252(b)).collect(),
    }
}

/// An odd last byte is dropped.
fn utf16(bytes: &[u8], word: fn([u8; 2]) -> u16) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units = pairs.iter().map(|pair| word(*pair));
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Windows-1252 differs from Latin-1 only in 0x80-0x9F. The five unassigned bytes map to the C1
/// control characters, as browsers do.
const CP1252_80_TO_9F: [char; 32] = [
    '\u{20AC}', '\u{81}', '\u{201A}', '\u{192}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}', '\u{2C6}', '\u{2030}',
    '\u{160}', '\u{2039}', '\u{152}', '\u{8D}', '\u{17D}', '\u{8F}', '\u{90}', '\u{2018}', '\u{2019}', '\u{201C}',
    '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}', '\u{2DC}', '\u{2122}', '\u{161}', '\u{203A}', '\u{153}', '\u{9D}',
    '\u{17E}', '\u{178}',
];

fn windows_1252(byte: u8) -> char {
    match byte {
        0x80..=0x9F => CP1252_80_TO_9F[usize::from(byte - 0x80)],
        _ => char::from(byte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le_with_bom(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes
    }

    #[test]
    fn utf16_le_with_a_bom_is_decoded_without_it() {
        let reg = "Windows Registry Editor Version 5.00\r\n\r\n\"HostName\"=\"caf\u{e9}.example.com\"\r\n";
        assert_eq!(decode_text(&utf16le_with_bom(reg)), reg);
    }

    #[test]
    fn utf16_be_with_a_bom_is_decoded() {
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend("web01".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(decode_text(&bytes), "web01");
    }

    #[test]
    fn utf8_with_or_without_a_bom() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFname,host"), "name,host");
        assert_eq!(decode_text("caf\u{e9}".as_bytes()), "caf\u{e9}");
        assert_eq!(decode_text(b""), "");
    }

    #[test]
    fn invalid_utf8_is_read_as_windows_1252() {
        // MobaXterm's ANSI export: e9 is e-acute, 80 the euro sign, 92 a right single quote.
        assert_eq!(
            decode_text(b"caf\xE9 \x80 alice\x92s"),
            "caf\u{e9} \u{20ac} alice\u{2019}s"
        );
        assert_eq!(decode_text(b"\x81\xFF"), "\u{81}\u{ff}");
    }

    #[test]
    fn broken_utf16_does_not_panic() {
        // A lone high surrogate and an odd trailing byte.
        assert_eq!(decode_text(&[0xFF, 0xFE, 0x00, 0xD8, 0x41]), "\u{FFFD}");
    }
}
