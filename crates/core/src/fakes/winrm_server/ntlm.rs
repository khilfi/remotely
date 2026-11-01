//! The fake WinRM server's NTLM (MS-NLMP): the server's side of NTLMv2 with extended session security, key exchange
//! and a MIC, and message sealing and signing, so the client's real SSPI NTLM is tested end to end. Test code only:
//! checked against MS-NLMP 4.2.4's published values (`tests`), never used to protect anything.

use md5::{Digest, Md5};

pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const REQUEST_TARGET: u32 = 0x0000_0004;
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub const NEGOTIATE_128: u32 = 0x2000_0000;
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub const NEGOTIATE_56: u32 = 0x8000_0000;

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

/// MD4 (RFC 1320), for NTOWFv1.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());
    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
    for block in message.chunks(64) {
        let mut x = [0u32; 16];
        for (i, word) in block.chunks(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for &i in &[0usize, 4, 8, 12] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(x[i]).rotate_left(3);
            d = d.wrapping_add(f(a, b, c)).wrapping_add(x[i + 1]).rotate_left(7);
            c = c.wrapping_add(f(d, a, b)).wrapping_add(x[i + 2]).rotate_left(11);
            b = b.wrapping_add(f(c, d, a)).wrapping_add(x[i + 3]).rotate_left(19);
        }
        for &i in &[0usize, 1, 2, 3] {
            a = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(0x5a82_7999)
                .rotate_left(3);
            d = d
                .wrapping_add(g(a, b, c))
                .wrapping_add(x[i + 4])
                .wrapping_add(0x5a82_7999)
                .rotate_left(5);
            c = c
                .wrapping_add(g(d, a, b))
                .wrapping_add(x[i + 8])
                .wrapping_add(0x5a82_7999)
                .rotate_left(9);
            b = b
                .wrapping_add(g(c, d, a))
                .wrapping_add(x[i + 12])
                .wrapping_add(0x5a82_7999)
                .rotate_left(13);
        }
        for &i in &[0usize, 2, 1, 3] {
            a = a
                .wrapping_add(h(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(3);
            d = d
                .wrapping_add(h(a, b, c))
                .wrapping_add(x[i + 8])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(9);
            c = c
                .wrapping_add(h(d, a, b))
                .wrapping_add(x[i + 4])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(11);
            b = b
                .wrapping_add(h(c, d, a))
                .wrapping_add(x[i + 12])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(15);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

pub fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// HMAC-MD5 (RFC 2104).
pub fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&md5(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let inner_pad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    let outer_pad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    let mut inner: Vec<&[u8]> = vec![&inner_pad];
    inner.extend_from_slice(parts);
    let inner_hash = md5(&inner);
    md5(&[&outer_pad, &inner_hash])
}

/// RC4, its state kept between messages (NTLM's sealing handle).
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

pub fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn from_utf16(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&words)
}

/// NTOWFv2: HMAC-MD5 of MD4(password) over the upper-case user and the domain as given.
pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let nt = md4(&utf16(password));
    hmac_md5(&nt, &[&utf16(&user.to_uppercase()), &utf16(domain)])
}

/// The server's AV pairs: names and, when `timestamp` is given, MsvAvTimestamp (which makes a client add a MIC).
pub fn target_info(domain: &str, computer: &str, timestamp: Option<u64>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pair = |id: u16, value: &[u8]| {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
    };
    pair(2, &utf16(domain));
    pair(1, &utf16(computer));
    if let Some(time) = timestamp {
        pair(7, &time.to_le_bytes());
    }
    pair(0, &[]);
    out
}

/// The CHALLENGE message for a NEGOTIATE's `client_flags`.
pub fn challenge(client_flags: u32, server_challenge: [u8; 8], target_name: &str, info: &[u8]) -> (Vec<u8>, u32) {
    let wanted = NEGOTIATE_UNICODE
        | REQUEST_TARGET
        | NEGOTIATE_SIGN
        | NEGOTIATE_SEAL
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NEGOTIATE_VERSION
        | NEGOTIATE_128
        | NEGOTIATE_KEY_EXCH
        | NEGOTIATE_56;
    let flags = (client_flags & wanted) | TARGET_TYPE_SERVER | NEGOTIATE_TARGET_INFO | NEGOTIATE_UNICODE;
    let name = utf16(target_name);
    let header = 56u32;
    let mut out = Vec::new();
    out.extend_from_slice(SIGNATURE);
    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&server_challenge);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&(info.len() as u16).to_le_bytes());
    out.extend_from_slice(&(info.len() as u16).to_le_bytes());
    out.extend_from_slice(&(header + name.len() as u32).to_le_bytes());
    // Version: 10.0 build 20348, NTLM revision 15.
    out.extend_from_slice(&[10, 0, 0x7c, 0x4f, 0, 0, 0, 15]);
    out.extend_from_slice(&name);
    out.extend_from_slice(info);
    (out, flags)
}

/// A message's type (1, 2 or 3); `None` for something that isn't NTLM.
pub fn message_type(message: &[u8]) -> Option<u32> {
    if message.len() < 12 || &message[..8] != SIGNATURE {
        return None;
    }
    Some(u32::from_le_bytes([message[8], message[9], message[10], message[11]]))
}

/// The NEGOTIATE message's flags.
pub fn negotiate_flags(message: &[u8]) -> Option<u32> {
    (message_type(message)? == 1 && message.len() >= 16)
        .then(|| u32::from_le_bytes([message[12], message[13], message[14], message[15]]))
}

fn field(message: &[u8], at: usize) -> Option<&[u8]> {
    let len = u16::from_le_bytes([*message.get(at)?, *message.get(at + 1)?]) as usize;
    let offset = u32::from_le_bytes([
        *message.get(at + 4)?,
        *message.get(at + 5)?,
        *message.get(at + 6)?,
        *message.get(at + 7)?,
    ]) as usize;
    message.get(offset..offset + len)
}

/// What a signed-in client's keys are, for sealing both ways.
pub struct Keys {
    pub client_seal: Rc4,
    pub client_sign: [u8; 16],
    pub client_seq: u32,
    pub server_seal: Rc4,
    pub server_sign: [u8; 16],
    pub server_seq: u32,
    pub user: String,
    pub domain: String,
}

/// Why an AUTHENTICATE was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Malformed,
    WrongUser,
    WrongPassword,
    BadMic,
    /// The channel binding (MsvAvChannelBindings) isn't this TLS channel's.
    BadBindings,
    NoSealing,
}

/// The session keys of `exported` for the negotiated `flags` (extended session security).
pub fn keys(exported: &[u8; 16], flags: u32) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
    let sign = |direction: &str| {
        md5(&[
            exported,
            format!("session key to {direction} signing key magic constant\0").as_bytes(),
        ])
    };
    let key_len = if flags & NEGOTIATE_128 != 0 {
        16
    } else if flags & NEGOTIATE_56 != 0 {
        7
    } else {
        5
    };
    let seal = |direction: &str| {
        md5(&[
            &exported[..key_len],
            format!("session key to {direction} sealing key magic constant\0").as_bytes(),
        ])
    };
    (
        sign("client-to-server"),
        seal("client-to-server"),
        sign("server-to-client"),
        seal("server-to-client"),
    )
}

/// Checks an AUTHENTICATE against `user` and `password` (the user's letter case aside), the MIC over the three
/// messages included, and gives the session's keys. `bindings`: over TLS, the channel binding the client must send.
#[allow(clippy::too_many_arguments)]
pub fn authenticate(
    negotiate: &[u8],
    challenge_message: &[u8],
    server_challenge: [u8; 8],
    flags: u32,
    message: &[u8],
    user: &str,
    password: &str,
    bindings: Option<[u8; 16]>,
) -> Result<Keys, Refused> {
    if message_type(message) != Some(3) || message.len() < 72 {
        return Err(Refused::Malformed);
    }
    if flags & NEGOTIATE_SEAL == 0 || flags & NEGOTIATE_EXTENDED_SESSIONSECURITY == 0 {
        return Err(Refused::NoSealing);
    }
    let nt_response = field(message, 20).ok_or(Refused::Malformed)?;
    let domain = from_utf16(field(message, 28).ok_or(Refused::Malformed)?);
    let name = from_utf16(field(message, 36).ok_or(Refused::Malformed)?);
    let encrypted_key = field(message, 52).ok_or(Refused::Malformed)?;
    let auth_flags = u32::from_le_bytes([message[60], message[61], message[62], message[63]]);
    let bare = name.rsplit('\\').next().unwrap_or(&name);
    if !bare.eq_ignore_ascii_case(user) {
        return Err(Refused::WrongUser);
    }
    if nt_response.len() < 48 {
        return Err(Refused::Malformed);
    }
    let response_key = ntowf_v2(password, &name, &domain);
    let (proof, temp) = nt_response.split_at(16);
    let expected = hmac_md5(&response_key, &[&server_challenge, temp]);
    if proof != expected {
        return Err(Refused::WrongPassword);
    }
    let session_base = hmac_md5(&response_key, &[proof]);
    let mut exported = session_base;
    if auth_flags & NEGOTIATE_KEY_EXCH != 0 {
        if encrypted_key.len() != 16 {
            return Err(Refused::Malformed);
        }
        exported.copy_from_slice(encrypted_key);
        Rc4::new(&session_base).apply(&mut exported);
    }
    // The MIC is there when the client's AV pairs say so (MsvAvFlags bit 0x2).
    // Over TLS: MsvAvChannelBindings must be the MD5 of this channel's bindings (Extended Protection).
    if let Some(expected) = bindings {
        if av_pair(&temp[28..], 0x000a) != Some(&expected[..]) {
            return Err(Refused::BadBindings);
        }
    }
    if mic_present(&temp[28..]) {
        let mut zeroed = message.to_vec();
        zeroed[72..88].fill(0);
        let mic = hmac_md5(&exported, &[negotiate, challenge_message, &zeroed]);
        if message.get(72..88) != Some(&mic[..]) {
            return Err(Refused::BadMic);
        }
    }
    let (client_sign, client_seal, server_sign, server_seal) = keys(&exported, auth_flags);
    Ok(Keys {
        client_seal: Rc4::new(&client_seal),
        client_sign,
        client_seq: 0,
        server_seal: Rc4::new(&server_seal),
        server_sign,
        server_seq: 0,
        user: name,
        domain,
    })
}

/// An AV pair's value, by its id.
fn av_pair(pairs: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut at = 0;
    while at + 4 <= pairs.len() {
        let id = u16::from_le_bytes([pairs[at], pairs[at + 1]]);
        let len = u16::from_le_bytes([pairs[at + 2], pairs[at + 3]]) as usize;
        if id == 0 {
            return None;
        }
        if id == wanted {
            return pairs.get(at + 4..at + 4 + len);
        }
        at += 4 + len;
    }
    None
}

/// MsvAvChannelBindings for a TLS channel: the MD5 of the GSS channel bindings with only `tls-server-end-point:` and
/// the certificate's hash as application data (RFC 5929, MS-NLMP 3.1.5.1.2).
pub fn channel_bindings_hash(application: &[u8]) -> [u8; 16] {
    let mut gss = vec![0u8; 16];
    gss.extend_from_slice(&(application.len() as u32).to_le_bytes());
    gss.extend_from_slice(application);
    md5(&[&gss])
}

fn mic_present(pairs: &[u8]) -> bool {
    let mut at = 0;
    while at + 4 <= pairs.len() {
        let id = u16::from_le_bytes([pairs[at], pairs[at + 1]]);
        let len = u16::from_le_bytes([pairs[at + 2], pairs[at + 3]]) as usize;
        if id == 0 {
            return false;
        }
        if id == 6 && len == 4 {
            if let Some(value) = pairs.get(at + 4..at + 8) {
                let flags = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                return flags & 0x2 != 0;
            }
        }
        at += 4 + len;
    }
    false
}

/// Seals `data` (one direction's handle, signing key and sequence number): (signature, sealed).
pub fn seal(handle: &mut Rc4, sign_key: &[u8; 16], seq: &mut u32, data: &[u8]) -> ([u8; 16], Vec<u8>) {
    let mut sealed = data.to_vec();
    handle.apply(&mut sealed);
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&hmac_md5(sign_key, &[&seq.to_le_bytes(), data])[..8]);
    handle.apply(&mut checksum);
    let mut signature = [0u8; 16];
    signature[..4].copy_from_slice(&1u32.to_le_bytes());
    signature[4..12].copy_from_slice(&checksum);
    signature[12..].copy_from_slice(&seq.to_le_bytes());
    *seq = seq.wrapping_add(1);
    (signature, sealed)
}

/// Unseals and checks one message: `None` when its signature doesn't hold.
pub fn unseal(
    handle: &mut Rc4,
    sign_key: &[u8; 16],
    seq: &mut u32,
    signature: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    if signature.len() != 16 {
        return None;
    }
    let mut plain = sealed.to_vec();
    handle.apply(&mut plain);
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&hmac_md5(sign_key, &[&seq.to_le_bytes(), &plain])[..8]);
    handle.apply(&mut checksum);
    let ok = signature[..4] == 1u32.to_le_bytes()[..]
        && signature[4..12] == checksum[..]
        && signature[12..] == seq.to_le_bytes()[..];
    *seq = seq.wrapping_add(1);
    ok.then_some(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn md4_matches_rfc_1320() {
        assert_eq!(md4(b"").to_vec(), hex("31d6cfe0d16ae931b73c59d7e0c089c0"));
        assert_eq!(md4(b"abc").to_vec(), hex("a448017aaf21d8525fc10ae87aa6729d"));
        assert_eq!(
            md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890").to_vec(),
            hex("e33b4ddc9c38f2199c3e7b164fcc0536")
        );
    }

    #[test]
    fn hmac_md5_and_rc4_match_their_rfcs() {
        // RFC 2202 case 2, RFC 6229's first key.
        assert_eq!(
            hmac_md5(b"Jefe", &[b"what do ya want for nothing?"]).to_vec(),
            hex("750c783e6ab0b503eaa86e310a5db738")
        );
        let mut stream = [0u8; 16];
        Rc4::new(&[1, 2, 3, 4, 5]).apply(&mut stream);
        assert_eq!(stream.to_vec(), hex("b2396305f03dc027ccc3524a0a1118a8"));
    }

    /// MS-NLMP 4.2.4 (NTLMv2 authentication): user "User", domain "Domain", password "Password", server challenge
    /// 0123456789abcdef, client challenge aa..., time 0, random session key 55...
    #[test]
    fn ntlm_v2_matches_ms_nlmp_4_2_4() {
        let response_key = ntowf_v2("Password", "User", "Domain");
        assert_eq!(response_key.to_vec(), hex("0c868a403bfd7a93a3001ef22ef02e3f"));
        let server_challenge: [u8; 8] = hex("0123456789abcdef").try_into().unwrap();
        let mut temp = hex("0101000000000000 0000000000000000 aaaaaaaaaaaaaaaa 00000000");
        temp.extend(target_info("Domain", "Server", None));
        temp.extend_from_slice(&[0, 0, 0, 0]);
        let proof = hmac_md5(&response_key, &[&server_challenge, &temp]);
        assert_eq!(proof.to_vec(), hex("68cd0ab851e51c96aabc927bebef6a1c"));
        let session_base = hmac_md5(&response_key, &[&proof]);
        assert_eq!(session_base.to_vec(), hex("8de40ccadbc14a82f15cb0ad0de95ca3"));
        let mut encrypted = [0x55u8; 16];
        Rc4::new(&session_base).apply(&mut encrypted);
        assert_eq!(encrypted.to_vec(), hex("c5dad2544fc9799094ce1ce90bc9d03e"));

        // 4.2.4.4: "Plaintext" in UTF-16, sealed with the client-to-server keys of the random session key.
        let flags = NEGOTIATE_128 | NEGOTIATE_KEY_EXCH | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_SEAL;
        let (client_sign, client_seal, _, _) = keys(&[0x55; 16], flags);
        let mut handle = Rc4::new(&client_seal);
        let mut seq = 0;
        let (signature, sealed) = seal(&mut handle, &client_sign, &mut seq, &utf16("Plaintext"));
        assert_eq!(sealed, hex("54e50165bf1936dc996020c1811b0f06fb5f"));
        assert_eq!(signature.to_vec(), hex("010000007fb38ec5c55d497600000000"));
        // The other side unseals it with the same keys, in order.
        let mut theirs = Rc4::new(&client_seal);
        let mut their_seq = 0;
        assert_eq!(
            unseal(&mut theirs, &client_sign, &mut their_seq, &signature, &sealed).unwrap(),
            utf16("Plaintext")
        );
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(unseal(&mut Rc4::new(&client_seal), &client_sign, &mut 0, &signature, &tampered).is_none());
    }
}
