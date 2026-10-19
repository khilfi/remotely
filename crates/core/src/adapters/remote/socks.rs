//! SS-07: the SOCKS side of a dynamic forward. Versions 4, 4a and 5, CONNECT only, and no login: the
//! proxy listens on this PC (loopback unless the user chose otherwise), and each client says where it
//! wants to go. Browsers, `curl --socks5-hostname` and database tools speak one of these.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long a client may take to say where it wants to go.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Version {
    Four,
    Five,
}

/// Where a SOCKS client wants to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Request {
    pub host: String,
    pub port: u16,
    pub version: Version,
}

/// Reads the client's greeting and request. Answers what it can't do itself (a login it wants, a
/// command other than CONNECT) before giving up.
pub(super) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Request, String> {
    tokio::time::timeout(HANDSHAKE_WAIT, read_request(stream))
        .await
        .unwrap_or_else(|_| Err("the SOCKS client did not say where to go".into()))
}

/// Tells the client whether its connection is open.
pub(super) async fn reply<S: AsyncWrite + Unpin>(stream: &mut S, request: &Request, ok: bool) -> std::io::Result<()> {
    let answer: &[u8] = match (request.version, ok) {
        (Version::Four, true) => &[0, 0x5A, 0, 0, 0, 0, 0, 0],
        (Version::Four, false) => &[0, 0x5B, 0, 0, 0, 0, 0, 0],
        (Version::Five, true) => &[5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        // General failure: the reason stays in the forward's last error.
        (Version::Five, false) => &[5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
    };
    stream.write_all(answer).await?;
    stream.flush().await
}

fn broken(err: std::io::Error) -> String {
    format!("the SOCKS client hung up: {err}")
}

async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Request, String> {
    match stream.read_u8().await.map_err(broken)? {
        4 => socks4(stream).await,
        5 => socks5(stream).await,
        other => Err(format!(
            "a program that is no SOCKS client connected (it sent {other:#04x} first)"
        )),
    }
}

/// A NUL-terminated string of at most 255 bytes.
async fn read_text<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String, String> {
    let mut text = Vec::new();
    loop {
        match stream.read_u8().await.map_err(broken)? {
            0 => return String::from_utf8(text).map_err(|_| "the SOCKS client sent a name that is no text".into()),
            byte if text.len() < 255 => text.push(byte),
            _ => return Err("the SOCKS client sent a name that is too long".into()),
        }
    }
}

async fn socks4<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Request, String> {
    let command = stream.read_u8().await.map_err(broken)?;
    let port = stream.read_u16().await.map_err(broken)?;
    let mut ip = [0u8; 4];
    stream.read_exact(&mut ip).await.map_err(broken)?;
    let _user = read_text(stream).await?;
    // SOCKS 4a: 0.0.0.x (x not 0) means a host name follows.
    let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
        read_text(stream).await?
    } else {
        Ipv4Addr::from(ip).to_string()
    };
    let request = Request {
        host,
        port,
        version: Version::Four,
    };
    if command != 1 {
        let _ = reply(stream, &request, false).await;
        return Err("the SOCKS client asked for something other than a connection".into());
    }
    Ok(request)
}

async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<Request, String> {
    let count = stream.read_u8().await.map_err(broken)?;
    let mut methods = vec![0u8; usize::from(count)];
    stream.read_exact(&mut methods).await.map_err(broken)?;
    if !methods.contains(&0) {
        let _ = stream.write_all(&[5, 0xFF]).await;
        return Err("the SOCKS client wants to log in, and this proxy takes no login".into());
    }
    stream.write_all(&[5, 0]).await.map_err(broken)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(broken)?;
    let [version, command, _, kind] = head;
    if version != 5 {
        return Err("the SOCKS client changed its version mid-way".into());
    }
    let host = match kind {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await.map_err(broken)?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let len = stream.read_u8().await.map_err(broken)?;
            let mut name = vec![0u8; usize::from(len)];
            stream.read_exact(&mut name).await.map_err(broken)?;
            String::from_utf8(name).map_err(|_| "the SOCKS client sent a name that is no text".to_owned())?
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await.map_err(broken)?;
            Ipv6Addr::from(ip).to_string()
        }
        _ => {
            // Address type not supported.
            let _ = stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return Err("the SOCKS client named its destination in a way this proxy does not know".into());
        }
    };
    let port = stream.read_u16().await.map_err(broken)?;
    if command != 1 {
        // Command not supported.
        let _ = stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Err("the SOCKS client asked for something other than a connection".into());
    }
    Ok(Request {
        host,
        port,
        version: Version::Five,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the handshake on one end while the client writes `sent`; returns the request and the
    /// bytes the proxy answered.
    async fn talk(sent: &[u8], ok: bool) -> (Result<Request, String>, Vec<u8>) {
        let (mut client, mut proxy) = tokio::io::duplex(1024);
        client.write_all(sent).await.unwrap();
        let request = handshake(&mut proxy).await;
        if let Ok(request) = &request {
            reply(&mut proxy, request, ok).await.unwrap();
        }
        drop(proxy);
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).await.unwrap();
        (request, answer)
    }

    #[tokio::test]
    async fn socks5_names_and_addresses_are_read() {
        let mut by_name = vec![5, 1, 0, 5, 1, 0, 3, 16];
        by_name.extend_from_slice(b"db01.example.com");
        by_name.extend_from_slice(&5432u16.to_be_bytes());
        let (request, answer) = talk(&by_name, true).await;
        let request = request.unwrap();
        assert_eq!((request.host.as_str(), request.port), ("db01.example.com", 5432));
        assert_eq!(answer, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        let (request, answer) = talk(&[5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 10, 0, 22], false).await;
        assert_eq!(request.unwrap().host, "192.0.2.10");
        assert_eq!(answer[2..4], [5, 1], "a failure is reported");

        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(talk(&v6, true).await.0.unwrap().host, "2001:db8::1");
    }

    #[tokio::test]
    async fn socks4_and_4a_are_read() {
        let mut v4 = vec![4, 1, 0, 80, 192, 0, 2, 10];
        v4.extend_from_slice(b"alice\0");
        let (request, answer) = talk(&v4, true).await;
        let request = request.unwrap();
        assert_eq!((request.host.as_str(), request.port), ("192.0.2.10", 80));
        assert_eq!(answer, [0, 0x5A, 0, 0, 0, 0, 0, 0]);

        let mut v4a = vec![4, 1, 0x1F, 0x90, 0, 0, 0, 1];
        v4a.extend_from_slice(b"\0web01.example.org\0");
        let request = talk(&v4a, false).await.0.unwrap();
        assert_eq!((request.host.as_str(), request.port), ("web01.example.org", 8080));
    }

    #[tokio::test]
    async fn logins_binds_and_strangers_are_refused() {
        let (request, answer) = talk(&[5, 1, 2], true).await;
        assert!(request.unwrap_err().contains("log in"));
        assert_eq!(answer, [5, 0xFF]);

        let (request, answer) = talk(&[5, 1, 0, 5, 2, 0, 1, 192, 0, 2, 10, 0, 22], true).await;
        assert!(request.unwrap_err().contains("other than a connection"));
        assert_eq!(answer[2..4], [5, 7]);

        let (request, _) = talk(b"GET / HTTP/1.1\r\n\r\n", true).await;
        assert!(request.unwrap_err().contains("no SOCKS client"));
    }
}
