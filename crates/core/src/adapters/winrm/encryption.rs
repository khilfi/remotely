//! SS-12: how WinRM carries a message sealed by the sign-in over HTTP (MS-WSMV 2.2.9.1): a `multipart/encrypted`
//! body of two parts, the first naming the protocol and the plain message's length, the second the sealed bytes
//! behind a 4-byte little-endian length of the signature (the security token) that comes first.
//!
//! ```text
//! --Encrypted Boundary\r\n
//! \tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n
//! \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=<n>\r\n
//! --Encrypted Boundary\r\n
//! \tContent-Type: application/octet-stream\r\n
//! <signature length, LE u32><signature><sealed message>--Encrypted Boundary--\r\n
//! ```

use crate::error::{CoreError, Result};

pub const BOUNDARY: &str = "Encrypted Boundary";
/// NTLM and Negotiate (SPNEGO) sealing.
pub const PROTOCOL_SPNEGO: &str = "application/HTTP-SPNEGO-session-encrypted";

const OCTET_STREAM: &[u8] = b"\tContent-Type: application/octet-stream\r\n";
/// A signature longer than this is not one (NTLM's is 16 bytes, Kerberos' tens).
const MAX_SIGNATURE: usize = 1024;

/// The request's `Content-Type`.
pub fn content_type(protocol: &str) -> String {
    format!("multipart/encrypted;protocol=\"{protocol}\";boundary=\"{BOUNDARY}\"")
}

/// Whether a response's `Content-Type` says it is sealed.
pub fn is_sealed(content_type: &str) -> bool {
    content_type
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("multipart/encrypted")
}

/// The body for a sealed message: `signature` and `sealed` from the security context, `plain_len` the length of
/// the message before sealing.
pub fn wrap(protocol: &str, plain_len: usize, signature: &[u8], sealed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(sealed.len() + signature.len() + 256);
    out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(format!("\tContent-Type: {protocol}\r\n").as_bytes());
    out.extend_from_slice(
        format!("\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={plain_len}\r\n").as_bytes(),
    );
    out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(OCTET_STREAM);
    let length = u32::try_from(signature.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(signature);
    out.extend_from_slice(sealed);
    out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    out
}

/// A sealed body taken apart.
#[derive(Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The plain message's length, as the first part says.
    pub plain_len: usize,
    pub signature: Vec<u8>,
    pub sealed: Vec<u8>,
}

fn bad(what: &str) -> CoreError {
    CoreError::Winrm(format!("the host's sealed answer is not laid out as WinRM's: {what}"))
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| at + from)
}

/// Takes a sealed body apart (one message; WinRM sends one per answer except with CredSSP, which Remotely doesn't
/// use). Read by position, so sealed bytes that happen to look like a boundary can't cut it short.
pub fn unwrap(body: &[u8]) -> Result<Sealed> {
    let open = format!("--{BOUNDARY}\r\n");
    let close = format!("--{BOUNDARY}--\r\n");
    if !body.starts_with(open.as_bytes()) {
        return Err(bad("it doesn't start with the boundary"));
    }
    // The first part is a few short lines.
    let second = find(body, open.as_bytes(), open.len())
        .filter(|at| *at < 1024)
        .ok_or_else(|| bad("no second part"))?;
    let head = std::str::from_utf8(&body[open.len()..second]).map_err(|_| bad("its first part is not text"))?;
    let plain_len = head
        .split(';')
        .find_map(|part| {
            let (name, value) = part.trim().split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("Length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| bad("its first part has no length"))?;
    let mut at = second + open.len();
    if !body[at..].starts_with(OCTET_STREAM) {
        return Err(bad("its second part is not an octet stream"));
    }
    at += OCTET_STREAM.len();
    let length_bytes: [u8; 4] = body
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("it ends before the signature's length"))?;
    let signature_len = u32::from_le_bytes(length_bytes) as usize;
    if signature_len > MAX_SIGNATURE {
        return Err(bad("its signature is too long"));
    }
    at += 4;
    let signature = body
        .get(at..at + signature_len)
        .ok_or_else(|| bad("it ends inside the signature"))?
        .to_vec();
    at += signature_len;
    let rest = &body[at..];
    let sealed = rest
        .strip_suffix(close.as_bytes())
        .ok_or_else(|| bad("it doesn't end with the closing boundary"))?;
    Ok(Sealed {
        plain_len,
        signature,
        sealed: sealed.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_message_round_trips() {
        // Sealed bytes that look like the boundary don't cut it short.
        let sealed = b"\x00\x01--Encrypted Boundary\r\n\xff".to_vec();
        let body = wrap(PROTOCOL_SPNEGO, 42, &[7u8; 16], &sealed);
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.starts_with("--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n")
        );
        assert!(text.contains("Length=42\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n"));
        let back = unwrap(&body).unwrap();
        assert_eq!(back.plain_len, 42);
        assert_eq!(back.signature, vec![7u8; 16]);
        assert_eq!(back.sealed, sealed);
        assert_eq!(
            content_type(PROTOCOL_SPNEGO),
            "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\""
        );
        assert!(is_sealed("Multipart/Encrypted;protocol=x"));
    }

    #[test]
    fn broken_bodies_are_refused() {
        let good = wrap(PROTOCOL_SPNEGO, 3, &[1u8; 16], b"abc");
        assert!(unwrap(&good[..good.len() - 3]).is_err(), "cut short");
        assert!(unwrap(b"<s:Envelope/>").is_err());
        let mut long = good.clone();
        let at = good
            .windows(OCTET_STREAM.len())
            .position(|w| w == OCTET_STREAM)
            .unwrap()
            + OCTET_STREAM.len();
        long[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unwrap(&long).is_err(), "a signature length past the end");
    }
}
