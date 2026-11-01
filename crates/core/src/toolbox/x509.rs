//! FD-09: what the certificate viewer shows of an X.509 certificate, read from its DER bytes. A server or a file may
//! be hostile, so the reader checks every length against what is left, never recurses deeper than the certificate's
//! own structure, and every text it returns has control and Unicode format characters removed (A8).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use sha2::Digest;
use time::OffsetDateTime;

use crate::error::{CoreError, Result};

/// One certificate, as the viewer shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    /// `CN=web01.example.com, O=Example, C=US`: RFC 4514's order, the name's last part first (for most
    /// certificates the most specific).
    pub subject: String,
    pub subject_common_name: Option<String>,
    pub issuer: String,
    /// DNS names, IP addresses, e-mail addresses and URIs, as `DNS:web01.example.com`, `IP:192.0.2.10`...
    pub alternative_names: Vec<String>,
    /// RFC 3339, UTC.
    pub not_before: String,
    pub not_after: String,
    /// Hex, colon-separated.
    pub serial: String,
    /// "RSA 2048 bits", "EC P-256", "Ed25519".
    pub key: String,
    /// "SHA-256 with RSA", "ECDSA with SHA-384".
    pub signature_algorithm: String,
    /// Upper-case hex, colon-separated.
    pub sha256: String,
    pub sha1: String,
    /// It may issue certificates (basic constraints: CA).
    pub is_ca: bool,
    /// Its subject is its issuer.
    pub self_issued: bool,
    #[serde(skip)]
    pub(crate) dns_names: Vec<String>,
    #[serde(skip)]
    pub(crate) ip_names: Vec<IpAddr>,
    #[serde(skip)]
    pub(crate) not_after_at: Option<OffsetDateTime>,
    #[serde(skip)]
    pub(crate) not_before_at: Option<OffsetDateTime>,
}

impl CertificateInfo {
    /// Whole days from `now` until it expires; negative once it has.
    pub fn days_left(&self, now: OffsetDateTime) -> Option<i64> {
        self.not_after_at.map(|end| (end - now).whole_days())
    }

    /// Valid at `now`: after its start and before its end.
    pub fn valid_at(&self, now: OffsetDateTime) -> bool {
        self.not_before_at.is_some_and(|start| start <= now) && self.not_after_at.is_some_and(|end| now <= end)
    }

    /// RFC 6125: whether it names `host`. An IP address matches an IP alternative name; a name matches a DNS
    /// alternative name, `*.` only for the leftmost label of three or more. Only without DNS alternative names does
    /// the common name count, as old clients read it.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.');
        if let Some(ip) = crate::adapters::network::ip_literal(host) {
            return self.ip_names.contains(&ip);
        }
        let host = host.to_ascii_lowercase();
        if self.dns_names.is_empty() {
            return self
                .subject_common_name
                .as_deref()
                .is_some_and(|cn| name_matches(&cn.to_ascii_lowercase(), &host));
        }
        self.dns_names.iter().any(|name| name_matches(name, &host))
    }
}

fn name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    if let Some(rest) = pattern.strip_prefix("*.") {
        // A wildcard stands for one whole label, and only with at least two labels after it.
        if !rest.contains('.') {
            return false;
        }
        return host
            .split_once('.')
            .is_some_and(|(label, after)| !label.is_empty() && after == rest);
    }
    pattern == host
}

/// A DER element: its tag, its contents and the bytes it took in all.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

struct Reader<'a> {
    data: &'a [u8],
}

fn bad(what: &str) -> CoreError {
    CoreError::InvalidInput(format!("not a certificate Remotely can read ({what})"))
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    fn next(&mut self) -> Result<Tlv<'a>> {
        let (&tag, rest) = self.data.split_first().ok_or_else(|| bad("it ends early"))?;
        if tag & 0x1f == 0x1f {
            return Err(bad("a long tag"));
        }
        let (&first, rest) = rest.split_first().ok_or_else(|| bad("it ends early"))?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || rest.len() < count {
                return Err(bad("a length"));
            }
            let len = rest[..count].iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            (len, &rest[count..])
        };
        if rest.len() < len {
            return Err(bad("a length past its end"));
        }
        let (content, after) = rest.split_at(len);
        self.data = after;
        Ok(Tlv { tag, content })
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8]> {
        let tlv = self.next()?;
        if tlv.tag != tag {
            return Err(bad(what));
        }
        Ok(tlv.content)
    }
}

/// Reads one DER certificate.
pub fn parse(der: &[u8]) -> Result<CertificateInfo> {
    let mut outer = Reader::new(der);
    let certificate = outer.expect(0x30, "the certificate")?;
    let mut cert = Reader::new(certificate);
    let tbs = cert.expect(0x30, "its body")?;
    let signature_algorithm = algorithm(cert.expect(0x30, "its signature algorithm")?)?;

    let mut body = Reader::new(tbs);
    if body.peek_tag() == Some(0xa0) {
        body.next()?;
    }
    let serial = body.expect(0x02, "its serial number")?;
    body.expect(0x30, "the inner signature algorithm")?;
    let issuer_der = body.expect(0x30, "its issuer")?;
    let mut validity = Reader::new(body.expect(0x30, "its validity")?);
    let not_before = time_value(validity.next()?)?;
    let not_after = time_value(validity.next()?)?;
    let subject_der = body.expect(0x30, "its subject")?;
    let key = public_key(body.expect(0x30, "its public key")?)?;

    let mut alternative_names = Vec::new();
    let mut dns_names = Vec::new();
    let mut ip_names = Vec::new();
    let mut is_ca = false;
    while !body.is_empty() {
        let field = body.next()?;
        if field.tag != 0xa3 {
            continue;
        }
        let mut wrapper = Reader::new(field.content);
        let mut extensions = Reader::new(wrapper.expect(0x30, "its extensions")?);
        while !extensions.is_empty() {
            let mut extension = Reader::new(extensions.expect(0x30, "an extension")?);
            let oid = oid_text(extension.expect(0x06, "an extension's id")?);
            if extension.peek_tag() == Some(0x01) {
                extension.next()?;
            }
            let value = extension.expect(0x04, "an extension's value")?;
            match oid.as_str() {
                "2.5.29.17" => {
                    let mut names = Reader::new(Reader::new(value).expect(0x30, "the alternative names")?);
                    while !names.is_empty() {
                        let name = names.next()?;
                        match name.tag {
                            0x82 => {
                                let text = clean(&String::from_utf8_lossy(name.content));
                                dns_names.push(text.to_ascii_lowercase());
                                alternative_names.push(format!("DNS:{text}"));
                            }
                            0x87 => {
                                if let Some(ip) = ip_from(name.content) {
                                    ip_names.push(ip);
                                    alternative_names.push(format!("IP:{ip}"));
                                }
                            }
                            0x81 => alternative_names
                                .push(format!("email:{}", clean(&String::from_utf8_lossy(name.content)))),
                            0x86 => {
                                alternative_names.push(format!("URI:{}", clean(&String::from_utf8_lossy(name.content))))
                            }
                            _ => {}
                        }
                        if alternative_names.len() >= 500 {
                            break;
                        }
                    }
                }
                "2.5.29.19" => {
                    let mut constraints = Reader::new(Reader::new(value).expect(0x30, "the basic constraints")?);
                    if constraints.peek_tag() == Some(0x01) {
                        is_ca = constraints.next()?.content.first().is_some_and(|&b| b != 0);
                    }
                }
                _ => {}
            }
        }
    }

    let (subject, subject_common_name) = name(subject_der)?;
    let (issuer, _) = name(issuer_der)?;
    let format = |at: Option<OffsetDateTime>| {
        at.and_then(|at| at.format(&time::format_description::well_known::Rfc3339).ok())
            .unwrap_or_default()
    };
    Ok(CertificateInfo {
        self_issued: issuer_der == subject_der,
        subject,
        subject_common_name,
        issuer,
        alternative_names,
        not_before: format(not_before),
        not_after: format(not_after),
        serial: colon_hex(strip_leading_zero(serial), false),
        key,
        signature_algorithm,
        sha256: colon_hex(&sha2::Sha256::digest(der), true),
        sha1: colon_hex(&sha1::Sha1::digest(der), true),
        is_ca,
        dns_names,
        ip_names,
        not_after_at: not_after,
        not_before_at: not_before,
    })
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0, rest @ ..] if !rest.is_empty() => rest,
        _ => bytes,
    }
}

fn colon_hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| if upper { format!("{b:02X}") } else { format!("{b:02x}") })
        .collect::<Vec<_>>()
        .join(":")
}

fn ip_from(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// An OID's dotted text.
fn oid_text(bytes: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    for &b in bytes.iter().take(64) {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (value / 40).min(2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// A signature algorithm's name.
fn algorithm(content: &[u8]) -> Result<String> {
    let oid = oid_text(Reader::new(content).expect(0x06, "an algorithm")?);
    Ok(match oid.as_str() {
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA".to_owned(),
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA".to_owned(),
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA".to_owned(),
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA".to_owned(),
        "1.2.840.113549.1.1.10" => "RSA-PSS".to_owned(),
        "1.2.840.113549.1.1.4" => "MD5 with RSA".to_owned(),
        "1.2.840.10045.4.1" => "ECDSA with SHA-1".to_owned(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256".to_owned(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384".to_owned(),
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512".to_owned(),
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        other => other.to_owned(),
    })
}

/// The public key's kind and size.
fn public_key(content: &[u8]) -> Result<String> {
    let mut info = Reader::new(content);
    let mut algorithm = Reader::new(info.expect(0x30, "the key's algorithm")?);
    let oid = oid_text(algorithm.expect(0x06, "the key's algorithm")?);
    let key = info.expect(0x03, "the key")?;
    Ok(match oid.as_str() {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            // The bit string's first byte counts unused bits; then RSAPublicKey { modulus, exponent }.
            let bits = key
                .get(1..)
                .and_then(|rsa| Reader::new(rsa).expect(0x30, "an RSA key").ok())
                .and_then(|rsa| Reader::new(rsa).expect(0x02, "an RSA modulus").ok())
                .map(|modulus| {
                    let modulus = strip_leading_zero(modulus);
                    let lead = modulus.first().map_or(8, |b| b.leading_zeros() as usize);
                    modulus.len() * 8 - lead
                });
            match bits {
                Some(bits) => format!("RSA {bits} bits"),
                None => "RSA".to_owned(),
            }
        }
        "1.2.840.10045.2.1" => {
            let curve = algorithm
                .next()
                .ok()
                .filter(|t| t.tag == 0x06)
                .map(|t| oid_text(t.content));
            match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => "EC P-256".to_owned(),
                Some("1.3.132.0.34") => "EC P-384".to_owned(),
                Some("1.3.132.0.35") => "EC P-521".to_owned(),
                Some(other) => format!("EC {other}"),
                None => "EC".to_owned(),
            }
        }
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        other => other.to_owned(),
    })
}

/// A name as `CN=..., O=...` (most specific first), and its common name.
fn name(content: &[u8]) -> Result<(String, Option<String>)> {
    let mut parts = Vec::new();
    let mut common_name = None;
    let mut sets = Reader::new(content);
    while !sets.is_empty() {
        let mut set = Reader::new(sets.expect(0x31, "a name part")?);
        while !set.is_empty() {
            let mut pair = Reader::new(set.expect(0x30, "a name part")?);
            let oid = oid_text(pair.expect(0x06, "a name part's type")?);
            let value = string_value(pair.next()?);
            let label = match oid.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.5" => "SERIALNUMBER",
                "1.2.840.113549.1.9.1" => "E",
                "0.9.2342.19200300.100.1.25" => "DC",
                _ => "",
            };
            if label == "CN" && common_name.is_none() {
                common_name = Some(value.clone());
            }
            let label = if label.is_empty() { oid } else { label.to_owned() };
            parts.push(format!("{label}={value}"));
            if parts.len() >= 64 {
                break;
            }
        }
    }
    parts.reverse();
    Ok((parts.join(", "), common_name))
}

fn string_value(tlv: Tlv<'_>) -> String {
    let text = match tlv.tag {
        // BMPString: UTF-16 big-endian.
        0x1e => {
            let units: Vec<u16> = tlv
                .content
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        }
        // UniversalString: UTF-32 big-endian.
        0x1c => tlv
            .content
            .as_chunks::<4>()
            .0
            .iter()
            .filter_map(|c| char::from_u32(u32::from_be_bytes(*c)))
            .collect(),
        // T61String: read as Latin-1.
        0x14 => tlv.content.iter().map(|&b| char::from(b)).collect(),
        _ => String::from_utf8_lossy(tlv.content).into_owned(),
    };
    clean(&text)
}

/// Text from a certificate without control or format characters (U+202E and the like), at most 512 characters.
pub(crate) fn clean(text: &str) -> String {
    text.chars()
        .filter(|&c| !c.is_control() && !crate::untrusted::is_format_char(c))
        .take(512)
        .collect()
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`). `None` for a time it can't read.
fn time_value(tlv: Tlv<'_>) -> Result<Option<OffsetDateTime>> {
    let text = std::str::from_utf8(tlv.content).map_err(|_| bad("a time"))?;
    let digits = text.strip_suffix('Z').unwrap_or(text);
    let (year, rest) = match tlv.tag {
        0x17 if digits.len() >= 12 => {
            let yy: i32 = digits[..2].parse().map_err(|_| bad("a time"))?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        0x18 if digits.len() >= 14 => (digits[..4].parse().map_err(|_| bad("a time"))?, &digits[4..]),
        0x17 | 0x18 => return Ok(None),
        _ => return Err(bad("a time")),
    };
    let field = |at: usize| rest.get(at..at + 2).and_then(|s| s.parse::<u8>().ok());
    let (Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (field(0), field(2), field(4), field(6), field(8))
    else {
        return Ok(None);
    };
    let Ok(month) = time::Month::try_from(month) else {
        return Ok(None);
    };
    let date = time::Date::from_calendar_date(year, month, day).ok();
    let clock = time::Time::from_hms(hour, minute, second.min(59)).ok();
    Ok(date.zip(clock).map(|(d, t)| d.with_time(t).assume_utc()))
}

/// The certificates in a file's bytes: PEM blocks (`-----BEGIN CERTIFICATE-----`), or one DER certificate.
pub fn certificates_in(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("-----BEGIN") {
        use base64::Engine;
        let mut found = Vec::new();
        let mut rest = text.as_ref();
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let after = &rest[start + "-----BEGIN CERTIFICATE-----".len()..];
            let Some(end) = after.find("-----END CERTIFICATE-----") else {
                break;
            };
            let body: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .map_err(|_| bad("a PEM block that isn't base64"))?;
            found.push(der);
            rest = &after[end..];
            if found.len() >= 32 {
                break;
            }
        }
        if found.is_empty() {
            return Err(CoreError::InvalidInput(
                "the file has no certificate (only other PEM blocks, such as a key)".into(),
            ));
        }
        return Ok(found);
    }
    // DER: one certificate, the whole file.
    parse(bytes)?;
    Ok(vec![bytes.to_vec()])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cert(names: &[&str]) -> Vec<u8> {
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "web01.example.com");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Example");
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn a_certificate_is_read_with_its_names_key_dates_and_fingerprints() {
        let der = cert(&["web01.example.com", "*.web.example.com", "192.0.2.10"]);
        let info = parse(&der).unwrap();
        // RFC 4514's order: the last part of the name first (rcgen writes CN, then O).
        assert_eq!(info.subject, "O=Example, CN=web01.example.com");
        assert_eq!(info.subject_common_name.as_deref(), Some("web01.example.com"));
        assert_eq!(info.issuer, info.subject);
        assert!(info.self_issued);
        assert_eq!(
            info.alternative_names,
            ["DNS:web01.example.com", "DNS:*.web.example.com", "IP:192.0.2.10"]
        );
        assert_eq!(info.key, "EC P-256");
        assert_eq!(info.signature_algorithm, "ECDSA with SHA-256");
        assert_eq!(info.sha256.len(), 32 * 3 - 1);
        assert_eq!(info.sha1.len(), 20 * 3 - 1);
        let now = OffsetDateTime::now_utc();
        assert!(info.valid_at(now));
        assert!(info.days_left(now).unwrap() > 300);
    }

    #[test]
    fn names_match_by_alternative_name_with_one_label_wildcards() {
        let info = parse(&cert(&["web01.example.com", "*.web.example.com", "192.0.2.10"])).unwrap();
        assert!(info.matches_host("web01.example.com"));
        assert!(info.matches_host("WEB01.example.com."));
        assert!(info.matches_host("a.web.example.com"));
        assert!(!info.matches_host("a.b.web.example.com"), "one label only");
        assert!(!info.matches_host("web.example.com"), "the wildcard needs a label");
        assert!(info.matches_host("192.0.2.10"));
        assert!(!info.matches_host("192.0.2.11"));
        assert!(!info.matches_host("db01.example.com"));
        assert!(
            !name_matches("*.com", "example.com"),
            "no wildcard for a top-level domain"
        );
    }

    #[test]
    fn hostile_bytes_are_refused_without_a_panic() {
        let der = cert(&["web01.example.com"]);
        for len in 0..der.len() {
            let _ = parse(&der[..len]);
        }
        let mut flipped = der.clone();
        for i in (0..flipped.len()).step_by(7) {
            flipped[i] ^= 0xff;
            let _ = parse(&flipped);
        }
        assert!(parse(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(parse(b"not a certificate").is_err());
    }

    #[test]
    fn format_characters_are_removed_from_names() {
        assert_eq!(clean("evil\u{202e}gnp.exe\u{7}"), "evilgnp.exe");
    }

    #[test]
    fn pem_files_give_every_certificate_and_der_files_one() {
        use base64::Engine;
        let a = cert(&["a.example.com"]);
        let b = cert(&["b.example.com"]);
        let pem = |der: &[u8]| {
            let body = base64::engine::general_purpose::STANDARD.encode(der);
            let lines: Vec<String> = body
                .as_bytes()
                .chunks(64)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect();
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            )
        };
        let both = format!("{}{}", pem(&a), pem(&b));
        assert_eq!(certificates_in(both.as_bytes()).unwrap(), vec![a.clone(), b]);
        assert_eq!(certificates_in(&a).unwrap(), vec![a]);
        let key_only = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(certificates_in(key_only.as_bytes()).is_err());
    }

    #[test]
    fn utc_and_generalized_times_are_read() {
        let utc = time_value(Tlv {
            tag: 0x17,
            content: b"260101120000Z",
        })
        .unwrap()
        .unwrap();
        assert_eq!(utc.year(), 2026);
        let general = time_value(Tlv {
            tag: 0x18,
            content: b"20991231235959Z",
        })
        .unwrap()
        .unwrap();
        assert_eq!(general.year(), 2099);
        assert!(time_value(Tlv {
            tag: 0x17,
            content: b"26",
        })
        .unwrap()
        .is_none());
    }
}
