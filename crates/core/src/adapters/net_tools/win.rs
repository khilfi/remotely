//! FD-09: the Windows calls behind [`super::SystemNetworkTools`]. Each runs on a blocking thread.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::NetworkManagement::Dns::{
    DnsFree, DnsFreeRecordList, DnsQueryEx, DNS_ADDR, DNS_ADDR_ARRAY, DNS_QUERY_BYPASS_CACHE, DNS_QUERY_NO_HOSTS_FILE,
    DNS_QUERY_REQUEST, DNS_QUERY_REQUEST_VERSION1, DNS_QUERY_RESULT, DNS_QUERY_RESULTS_VERSION1, DNS_QUERY_STANDARD,
    DNS_QUERY_WIRE_ONLY, DNS_RECORDW,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, ICMPV6_ECHO_REPLY_LH, ICMP_ECHO_REPLY, IF_TYPE_SOFTWARE_LOOPBACK,
    IP_ADAPTER_ADDRESSES_LH, IP_OPTION_INFORMATION,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKET_ADDRESS,
};
use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertCreateCertificateContext, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore, CertVerifyCertificateChainPolicy,
    HTTPSPolicyCallbackData, HTTPSPolicyCallbackData_0, AUTHTYPE_SERVER, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL,
    CERT_CHAIN_CONTEXT, CERT_CHAIN_DISABLE_AIA, CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_PARA,
    CERT_CHAIN_POLICY_BASE, CERT_CHAIN_POLICY_FLAGS, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_SSL,
    CERT_CHAIN_POLICY_STATUS, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_ADD_ALWAYS,
    CERT_STORE_PROV_MEMORY, CERT_TRUST_IS_CYCLIC, CERT_TRUST_IS_EXPLICIT_DISTRUST, CERT_TRUST_IS_NOT_SIGNATURE_VALID,
    CERT_TRUST_IS_NOT_TIME_VALID, CERT_TRUST_IS_NOT_VALID_FOR_USAGE, CERT_TRUST_IS_PARTIAL_CHAIN,
    CERT_TRUST_IS_REVOKED, CERT_TRUST_IS_UNTRUSTED_ROOT, CERT_USAGE_MATCH, CTL_USAGE, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};

use super::{AdapterAddress, DnsFailure, DnsQuery, DnsRecord, Echo, EchoRequest, LocalAdapter, TrustUse, TrustVerdict};
use crate::error::{CoreError, Result};

// ICMP statuses (ipexport.h).
const IP_SUCCESS: u32 = 0;
const IP_BUF_TOO_SMALL: u32 = 11001;
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
const IP_PACKET_TOO_BIG: u32 = 11009;
const IP_REQ_TIMED_OUT: u32 = 11010;
const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;
const IP_TTL_EXPIRED_REASSEM: u32 = 11014;
const IP_BAD_DESTINATION: u32 = 11018;
const IP_DEST_UNREACHABLE: u32 = 11040;
const IP_GENERAL_FAILURE: u32 = 11050;

// DNS statuses (winerror.h).
const DNS_ERROR_RCODE_FORMAT_ERROR: i32 = 9001;
const DNS_ERROR_RCODE_SERVER_FAILURE: i32 = 9002;
const DNS_ERROR_RCODE_NAME_ERROR: i32 = 9003;
const DNS_ERROR_RCODE_REFUSED: i32 = 9005;
const DNS_INFO_NO_RECORDS: i32 = 9501;
const DNS_ERROR_INVALID_NAME: i32 = 123;
const ERROR_TIMEOUT: i32 = 1460;

const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// Room for one reply: the reply structure, the data echoed back, an ICMP error's 8 bytes and an IO_STATUS_BLOCK
/// (Microsoft's sizing), rounded up to whole 8-byte words so the structure is aligned.
fn reply_words(header: usize, size: u16) -> usize {
    (header + usize::from(size) + 8 + 16 + 64).div_ceil(8)
}

/// A request's data: `abcdefghijklmnopqrstuvw` again and again, as Windows' ping sends.
fn payload(size: u16) -> Vec<u8> {
    (0..usize::from(size)).map(|i| b'a' + (i % 23) as u8).collect()
}

/// One echo request.
pub(super) fn echo(request: EchoRequest) -> Result<Echo> {
    match request.to {
        IpAddr::V4(to) => echo_v4(to, request),
        IpAddr::V6(to) => echo_v6(to, request),
    }
}

fn timeout_ms(request: &EchoRequest) -> u32 {
    u32::try_from(request.timeout.as_millis()).unwrap_or(u32::MAX).max(1)
}

fn echo_v4(to: Ipv4Addr, request: EchoRequest) -> Result<Echo> {
    // SAFETY: no arguments; the handle is closed below.
    let handle = unsafe { IcmpCreateFile() }.map_err(|err| CoreError::Network(format!("can't send a ping: {err}")))?;
    let data = payload(request.size);
    let options = IP_OPTION_INFORMATION {
        Ttl: request.ttl,
        Tos: 0,
        Flags: 0,
        OptionsSize: 0,
        OptionsData: std::ptr::null_mut(),
    };
    let mut buffer = vec![0u64; reply_words(std::mem::size_of::<ICMP_ECHO_REPLY>(), request.size)];
    let bytes = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `handle` is open; `data` and `options` live through the call; `buffer` is writable for `bytes` bytes and
    // 8-byte aligned for the ICMP_ECHO_REPLY it receives. No event or APC: the call waits for the reply or the timeout.
    let count = unsafe {
        IcmpSendEcho2(
            handle,
            None,
            None,
            None,
            u32::from_ne_bytes(to.octets()),
            data.as_ptr().cast(),
            request.size,
            Some(&options),
            buffer.as_mut_ptr().cast(),
            bytes,
            timeout_ms(&request),
        )
    };
    // SAFETY: read straight after the call, before anything else can set it.
    let error = if count == 0 { unsafe { GetLastError() }.0 } else { 0 };
    // SAFETY: the handle came from IcmpCreateFile above and is closed once.
    let _ = unsafe { IcmpCloseHandle(handle) };
    // SAFETY: `buffer` is at least one aligned ICMP_ECHO_REPLY long and was zeroed, so this reads a valid value even
    // when Windows wrote nothing.
    let reply: ICMP_ECHO_REPLY = unsafe { std::ptr::read(buffer.as_ptr().cast()) };
    let from = (reply.Address != 0).then(|| IpAddr::V4(Ipv4Addr::from(reply.Address.to_ne_bytes())));
    let status = if count > 0 { reply.Status } else { error };
    Ok(match (status, from) {
        (IP_SUCCESS, Some(from)) if count > 0 => Echo::Reply {
            from,
            rtt_ms: reply.RoundTripTime,
            ttl: Some(reply.Options.Ttl),
        },
        _ => echo_failure(status, from, reply.RoundTripTime)?,
    })
}

fn echo_v6(to: Ipv6Addr, request: EchoRequest) -> Result<Echo> {
    // SAFETY: no arguments; the handle is closed below.
    let handle =
        unsafe { Icmp6CreateFile() }.map_err(|err| CoreError::Network(format!("can't send an IPv6 ping: {err}")))?;
    let data = payload(request.size);
    let options = IP_OPTION_INFORMATION {
        Ttl: request.ttl,
        Tos: 0,
        Flags: 0,
        OptionsSize: 0,
        OptionsData: std::ptr::null_mut(),
    };
    let source = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        ..Default::default()
    };
    let destination = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: to.octets() },
        },
        ..Default::default()
    };
    let mut buffer = vec![0u64; reply_words(std::mem::size_of::<ICMPV6_ECHO_REPLY_LH>(), request.size)];
    let bytes = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: as for IPv4: every pointer is to a live value for the call, and `buffer` is writable and aligned.
    let count = unsafe {
        Icmp6SendEcho2(
            handle,
            None,
            None,
            None,
            &source,
            &destination,
            data.as_ptr().cast(),
            request.size,
            Some(&options),
            buffer.as_mut_ptr().cast(),
            bytes,
            timeout_ms(&request),
        )
    };
    // SAFETY: read straight after the call.
    let error = if count == 0 { unsafe { GetLastError() }.0 } else { 0 };
    // SAFETY: closed once.
    let _ = unsafe { IcmpCloseHandle(handle) };
    // SAFETY: `buffer` holds at least one zeroed, aligned ICMPV6_ECHO_REPLY_LH.
    let reply: ICMPV6_ECHO_REPLY_LH = unsafe { std::ptr::read(buffer.as_ptr().cast()) };
    // The address's words hold its bytes in network order as they lie in memory.
    let mut octets = [0u8; 16];
    // A copy: the structure is packed, so its fields can't be borrowed.
    let words: [u16; 8] = reply.Address.sin6_addr;
    for (i, word) in words.iter().enumerate() {
        octets[i * 2..i * 2 + 2].copy_from_slice(&word.to_ne_bytes());
    }
    let address = Ipv6Addr::from(octets);
    let from = (!address.is_unspecified()).then_some(IpAddr::V6(address));
    let status = if count > 0 { reply.Status } else { error };
    Ok(match (status, from) {
        (IP_SUCCESS, Some(from)) if count > 0 => Echo::Reply {
            from,
            rtt_ms: reply.RoundTripTime,
            ttl: None,
        },
        _ => echo_failure(status, from, reply.RoundTripTime)?,
    })
}

/// A reply that isn't an answer from the host, or a request Windows refused to send.
fn echo_failure(status: u32, from: Option<IpAddr>, rtt_ms: u32) -> Result<Echo> {
    let unreachable = |reason: &str| Echo::Unreachable {
        from,
        reason: reason.to_owned(),
    };
    Ok(match status {
        IP_REQ_TIMED_OUT => Echo::TimedOut,
        IP_TTL_EXPIRED_TRANSIT | IP_TTL_EXPIRED_REASSEM => match from {
            Some(from) => Echo::TtlExpired { from, rtt_ms },
            None => Echo::TimedOut,
        },
        IP_DEST_NET_UNREACHABLE => unreachable("the network can't be reached"),
        IP_DEST_HOST_UNREACHABLE => unreachable("the host can't be reached"),
        IP_DEST_PROT_UNREACHABLE => unreachable("the host refused the protocol"),
        IP_DEST_PORT_UNREACHABLE => unreachable("the port can't be reached"),
        IP_DEST_UNREACHABLE => unreachable("the destination can't be reached"),
        IP_PACKET_TOO_BIG => unreachable("the packet is too big for a link on the way"),
        IP_BAD_DESTINATION => {
            return Err(CoreError::Network("Windows can't send a ping to that address".into()));
        }
        IP_BUF_TOO_SMALL | IP_GENERAL_FAILURE => {
            return Err(CoreError::Network("Windows couldn't send the ping".into()));
        }
        // A Win32 error before anything went out: no route, no network.
        other if other < 11000 => {
            let message = windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(other)).message();
            return Err(CoreError::Network(format!("Windows couldn't send the ping: {message}")));
        }
        other => unreachable(&format!("ICMP status {other}")),
    })
}

/// One DNS query through DnsQueryEx.
pub(super) fn dns(query: &DnsQuery) -> Result<std::result::Result<Vec<DnsRecord>, DnsFailure>> {
    let name: Vec<u16> = query.name.encode_utf16().chain(std::iter::once(0)).collect();
    // A chosen server: only that server, not the cache or the hosts file.
    let mut servers = query.server.map(server_list);
    let options = match servers {
        Some(_) => DNS_QUERY_WIRE_ONLY.0 | DNS_QUERY_BYPASS_CACHE.0 | DNS_QUERY_NO_HOSTS_FILE.0,
        None => DNS_QUERY_STANDARD.0,
    };
    let request = DNS_QUERY_REQUEST {
        Version: DNS_QUERY_REQUEST_VERSION1.0,
        QueryName: PCWSTR(name.as_ptr()),
        QueryType: query.record_type.code(),
        QueryOptions: u64::from(options),
        pDnsServerList: servers.as_mut().map_or(std::ptr::null_mut(), std::ptr::from_mut),
        InterfaceIndex: 0,
        pQueryCompletionCallback: None,
        pQueryContext: std::ptr::null_mut(),
    };
    let mut result = DNS_QUERY_RESULT {
        Version: DNS_QUERY_RESULTS_VERSION1.0,
        ..Default::default()
    };
    // SAFETY: `request` points at `name` and `servers`, which live through the call; with no completion callback the
    // call is synchronous and fills `result`, whose records are freed below.
    let status = unsafe { DnsQueryEx(&request, &mut result, None) };
    let first = result.pQueryRecords.cast::<DNS_RECORDW>();
    let mut records = Vec::new();
    let mut next = first;
    // At most a few thousand records: a list longer than that is not walked further.
    let mut left = 4096;
    while !next.is_null() && left > 0 {
        left -= 1;
        // SAFETY: `next` is a record of the list DnsQueryEx returned, not freed yet.
        let record = unsafe { &*next };
        // SAFETY: the flags are a plain u32 either way.
        let section = unsafe { record.Flags.DW } & 0x3;
        // The answer (1); Windows marks what it answers itself (localhost, the hosts file, its cache) 0. Authority (2)
        // and additional (3) records are not the answer.
        if section <= 1 {
            records.push(DnsRecord {
                name: wide(record.pName),
                record_type: super::RecordType::name_of(record.wType),
                ttl: record.dwTtl,
                data: record_data(record),
            });
        }
        next = record.pNext;
    }
    if !first.is_null() {
        // SAFETY: the list DnsQueryEx returned, freed once.
        unsafe { DnsFree(Some(first.cast_const().cast()), DnsFreeRecordList) };
    }
    Ok(match status {
        0 if !records.is_empty() => Ok(records),
        0 | DNS_INFO_NO_RECORDS => Err(DnsFailure::NoRecords),
        DNS_ERROR_RCODE_NAME_ERROR => Err(DnsFailure::NoSuchName),
        DNS_ERROR_RCODE_SERVER_FAILURE => Err(DnsFailure::Failed {
            message: "the server failed to answer (SERVFAIL)".into(),
        }),
        DNS_ERROR_RCODE_REFUSED => Err(DnsFailure::Failed {
            message: "the server refused the query".into(),
        }),
        DNS_ERROR_RCODE_FORMAT_ERROR => Err(DnsFailure::Failed {
            message: "the server didn't understand the query".into(),
        }),
        DNS_ERROR_INVALID_NAME => Err(DnsFailure::Failed {
            message: "that is not a name DNS can look up".into(),
        }),
        ERROR_TIMEOUT => Err(DnsFailure::Failed {
            message: "no answer".into(),
        }),
        other => Err(DnsFailure::Failed {
            message: windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(other as u32)).message(),
        }),
    })
}

/// A list of one server, port 53.
fn server_list(server: IpAddr) -> DNS_ADDR_ARRAY {
    let mut addr = DNS_ADDR::default();
    let family = match server {
        IpAddr::V4(v4) => {
            let sa = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 53u16.to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
            copy_sockaddr(&mut addr, &sa);
            AF_INET.0
        }
        IpAddr::V6(v6) => {
            let sa = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 53u16.to_be(),
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                ..Default::default()
            };
            copy_sockaddr(&mut addr, &sa);
            AF_INET6.0
        }
    };
    DNS_ADDR_ARRAY {
        MaxCount: 1,
        AddrCount: 1,
        Family: family,
        AddrArray: [addr],
        ..Default::default()
    }
}

/// Puts a socket address into a DNS_ADDR's 32 bytes.
fn copy_sockaddr<T>(addr: &mut DNS_ADDR, sa: &T) {
    let len = std::mem::size_of::<T>().min(addr.MaxSa.len());
    // SAFETY: copies `len` bytes, no more than either side holds; the two don't overlap.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(sa).cast::<u8>(),
            addr.MaxSa.as_mut_ptr().cast::<u8>(),
            len,
        );
    }
}

/// A wide string from a record, or "" for none.
fn wide(text: PWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: a NUL-terminated string inside a record DnsQueryEx returned, not freed yet.
    unsafe { text.to_string() }.unwrap_or_default()
}

/// A record's data as text.
fn record_data(record: &DNS_RECORDW) -> String {
    // SAFETY: each arm reads the union member that `wType` says DnsQueryEx filled in.
    unsafe {
        match record.wType {
            1 => Ipv4Addr::from(record.Data.A.IpAddress.to_ne_bytes()).to_string(),
            28 => Ipv6Addr::from(record.Data.AAAA.Ip6Address.IP6Byte).to_string(),
            2 | 5 | 12 => wide(record.Data.PTR.pNameHost),
            15 => format!("{} {}", record.Data.MX.wPreference, wide(record.Data.MX.pNameExchange)),
            16 => {
                let txt = &record.Data.TXT;
                let count = usize::try_from(txt.dwStringCount).unwrap_or(0).min(256);
                let first = txt.pStringArray.as_ptr();
                (0..count)
                    .map(|i| format!("\"{}\"", wide(*first.add(i))))
                    .collect::<Vec<_>>()
                    .join(" ")
            }
            6 => {
                let soa = &record.Data.SOA;
                format!(
                    "{} {} serial {} refresh {} retry {} expire {} minimum {}",
                    wide(soa.pNamePrimaryServer),
                    wide(soa.pNameAdministrator),
                    soa.dwSerialNo,
                    soa.dwRefresh,
                    soa.dwRetry,
                    soa.dwExpire,
                    soa.dwDefaultTtl
                )
            }
            33 => {
                let srv = &record.Data.SRV;
                format!(
                    "{} {} {} {}",
                    srv.wPriority,
                    srv.wWeight,
                    srv.wPort,
                    wide(srv.pNameTarget)
                )
            }
            _ => {
                // Types Windows doesn't parse (CAA among them) come as their raw bytes.
                let raw = &record.Data.Null;
                let len = usize::try_from(raw.dwByteCount)
                    .unwrap_or(0)
                    .min(usize::from(record.wDataLength));
                let bytes = std::slice::from_raw_parts(raw.Data.as_ptr(), len);
                if record.wType == 257 {
                    crate::toolbox::dns::caa_text(bytes)
                } else {
                    crate::toolbox::dns::raw_text(bytes)
                }
            }
        }
    }
}

const ENCODING: CERT_QUERY_ENCODING_TYPE = CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0);

/// The server authentication purpose's OID, as Windows takes it.
const SERVER_AUTH: &[u8] = b"1.3.6.1.5.5.7.3.1\0";

/// Builds and checks a chain with what this PC has.
pub(super) fn check_chain(chain: &[Vec<u8>], usage: TrustUse) -> Result<TrustVerdict> {
    let Some(leaf) = chain.first() else {
        return Err(CoreError::InvalidInput("no certificate to check".into()));
    };
    // SAFETY: `leaf` is a byte slice; Windows copies it into the context, freed below.
    let context = unsafe { CertCreateCertificateContext(ENCODING, leaf) };
    if context.is_null() {
        return Ok(TrustVerdict {
            trusted: false,
            problems: vec!["Windows can't read the certificate".into()],
            built: Vec::new(),
        });
    }
    // SAFETY: an in-memory store, closed below.
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            CERT_QUERY_ENCODING_TYPE(0),
            None,
            CERT_OPEN_STORE_FLAGS(0),
            None,
        )
    };
    let store = match store {
        Ok(store) => store,
        Err(err) => {
            // SAFETY: the context created above, freed once.
            unsafe {
                let _ = CertFreeCertificateContext(Some(context));
            }
            return Err(CoreError::Network(format!("Windows can't check the chain: {err}")));
        }
    };
    for der in &chain[1..] {
        // SAFETY: `store` is open; the bytes are copied into it. A certificate Windows can't read is left out.
        let _ = unsafe { CertAddEncodedCertificateToStore(Some(store), ENCODING, der, CERT_STORE_ADD_ALWAYS, None) };
    }
    let mut purposes = [windows::core::PSTR(SERVER_AUTH.as_ptr().cast_mut())];
    let usage_match = match usage {
        TrustUse::TlsServer => CERT_USAGE_MATCH {
            dwType: 0,
            Usage: CTL_USAGE {
                cUsageIdentifier: 1,
                rgpszUsageIdentifier: purposes.as_mut_ptr(),
            },
        },
        TrustUse::Any => CERT_USAGE_MATCH::default(),
    };
    let para = CERT_CHAIN_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
        RequestedUsage: usage_match,
        ..Default::default()
    };
    // Only what this PC has: no download of a root, an intermediate or a revocation list.
    let flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE;
    let mut built: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
    // SAFETY: `context` and `store` are live, `para` and `purposes` live through the call, and the chain it returns is
    // freed below.
    let made = unsafe { CertGetCertificateChain(None, context, None, Some(store), &para, flags, None, &mut built) };
    let verdict = if made.is_err() || built.is_null() {
        TrustVerdict {
            trusted: false,
            problems: vec!["Windows couldn't build a chain for it".into()],
            built: Vec::new(),
        }
    } else {
        // SAFETY: the chain CertGetCertificateChain returned, freed below.
        let verdict = unsafe { judge(built, usage) };
        // SAFETY: freed once.
        unsafe { CertFreeCertificateChain(built) };
        verdict
    };
    // SAFETY: closed and freed once.
    unsafe {
        let _ = CertCloseStore(Some(store), 0);
        let _ = CertFreeCertificateContext(Some(context));
    }
    Ok(verdict)
}

/// The chain's status in words, the policy's verdict, and the certificates Windows put in it.
///
/// # Safety
/// `chain` is a live chain context.
unsafe fn judge(chain: *mut CERT_CHAIN_CONTEXT, usage: TrustUse) -> TrustVerdict {
    // SAFETY: the caller hands a live chain.
    let context = unsafe { &*chain };
    let status = context.TrustStatus.dwErrorStatus;
    let mut problems = Vec::new();
    let flags = [
        (
            CERT_TRUST_IS_NOT_TIME_VALID,
            "a certificate in the chain has expired or isn't valid yet",
        ),
        (CERT_TRUST_IS_REVOKED, "a certificate in the chain was revoked"),
        (
            CERT_TRUST_IS_NOT_SIGNATURE_VALID,
            "a signature in the chain doesn't check out",
        ),
        (CERT_TRUST_IS_NOT_VALID_FOR_USAGE, "it isn't meant for a TLS server"),
        (CERT_TRUST_IS_UNTRUSTED_ROOT, "its root isn't one this PC trusts"),
        (
            CERT_TRUST_IS_PARTIAL_CHAIN,
            "the chain is incomplete: an issuer is missing (the server may not send its intermediate)",
        ),
        (CERT_TRUST_IS_CYCLIC, "the chain goes round in a loop"),
        (
            CERT_TRUST_IS_EXPLICIT_DISTRUST,
            "a certificate in the chain is marked as distrusted on this PC",
        ),
    ];
    for (flag, words) in flags {
        if status & flag != 0 && !(flag == CERT_TRUST_IS_NOT_VALID_FOR_USAGE && usage == TrustUse::Any) {
            problems.push(words.to_owned());
        }
    }
    let mut extra = HTTPSPolicyCallbackData {
        Anonymous: HTTPSPolicyCallbackData_0 {
            cbSize: std::mem::size_of::<HTTPSPolicyCallbackData>() as u32,
        },
        dwAuthType: AUTHTYPE_SERVER,
        fdwChecks: 0,
        // No name: the name is checked on its own.
        pwszServerName: PWSTR::null(),
    };
    let para = CERT_CHAIN_POLICY_PARA {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        dwFlags: CERT_CHAIN_POLICY_FLAGS(0),
        pvExtraPolicyPara: match usage {
            TrustUse::TlsServer => std::ptr::from_mut(&mut extra).cast(),
            TrustUse::Any => std::ptr::null_mut(),
        },
    };
    let mut policy = CERT_CHAIN_POLICY_STATUS {
        cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };
    let which = match usage {
        TrustUse::TlsServer => CERT_CHAIN_POLICY_SSL,
        TrustUse::Any => CERT_CHAIN_POLICY_BASE,
    };
    // SAFETY: the chain is live, and `para`, `extra` and `policy` live through the call.
    let checked = unsafe { CertVerifyCertificateChainPolicy(which, chain, &para, &mut policy) }.as_bool();
    let trusted = checked && policy.dwError == 0;
    if !trusted && problems.is_empty() {
        let message = if checked {
            windows::core::Error::from_hresult(windows::core::HRESULT(policy.dwError as i32)).message()
        } else {
            "Windows couldn't check the chain".to_owned()
        };
        problems.push(message);
    }
    // The certificates of the first simple chain, leaf first.
    let mut built = Vec::new();
    if context.cChain > 0 && !context.rgpChain.is_null() {
        // SAFETY: `rgpChain` holds `cChain` pointers to simple chains, each with `cElement` elements.
        unsafe {
            let simple = &**context.rgpChain;
            let count = usize::try_from(simple.cElement).unwrap_or(0).min(32);
            for i in 0..count {
                let element = *simple.rgpElement.add(i);
                if element.is_null() || (*element).pCertContext.is_null() {
                    continue;
                }
                let cert = &*(*element).pCertContext;
                let len = usize::try_from(cert.cbCertEncoded).unwrap_or(0);
                if !cert.pbCertEncoded.is_null() && len > 0 {
                    built.push(std::slice::from_raw_parts(cert.pbCertEncoded, len).to_vec());
                }
            }
        }
    }
    TrustVerdict {
        trusted,
        problems: if trusted { Vec::new() } else { problems },
        built,
    }
}

/// This PC's adapters, their addresses and DNS servers.
pub(super) fn adapters() -> Result<Vec<LocalAdapter>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 16 * 1024;
    let mut buffer: Vec<u64>;
    let mut tries = 0;
    loop {
        buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` is writable for `size` bytes and aligned for the structures; Windows says how much it
        // needs when that is too little.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
            )
        };
        match status {
            0 => break,
            ERROR_BUFFER_OVERFLOW if tries < 4 => tries += 1,
            // ERROR_NO_DATA: no adapter at all.
            232 => return Ok(Vec::new()),
            other => {
                return Err(CoreError::Network(format!(
                    "Windows couldn't list the network adapters (error {other})"
                )));
            }
        }
    }
    let mut out = Vec::new();
    let mut next = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut left = 256;
    while !next.is_null() && left > 0 {
        left -= 1;
        // SAFETY: an adapter of the list Windows wrote into `buffer`, which is still alive.
        let adapter = unsafe { &*next };
        let mac_len = usize::try_from(adapter.PhysicalAddressLength).unwrap_or(0).min(8);
        let mac = (mac_len == 6).then(|| {
            adapter.PhysicalAddress[..6]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        });
        let mut addresses = Vec::new();
        let mut unicast = adapter.FirstUnicastAddress;
        let mut more = 64;
        while !unicast.is_null() && more > 0 {
            more -= 1;
            // SAFETY: an address of this adapter, inside `buffer`.
            let address = unsafe { &*unicast };
            if let Some(ip) = socket_ip(&address.Address) {
                addresses.push(AdapterAddress {
                    address: ip,
                    prefix: address.OnLinkPrefixLength,
                });
            }
            unicast = address.Next;
        }
        let mut dns_servers = Vec::new();
        let mut server = adapter.FirstDnsServerAddress;
        let mut more = 16;
        while !server.is_null() && more > 0 {
            more -= 1;
            // SAFETY: a DNS server of this adapter, inside `buffer`.
            let entry = unsafe { &*server };
            if let Some(ip) = socket_ip(&entry.Address) {
                dns_servers.push(ip);
            }
            server = entry.Next;
        }
        out.push(LocalAdapter {
            name: wide(adapter.FriendlyName),
            mac,
            up: adapter.OperStatus == IfOperStatusUp,
            loopback: adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
            addresses,
            dns_servers,
        });
        next = adapter.Next;
    }
    Ok(out)
}

/// The IP address a SOCKET_ADDRESS holds.
fn socket_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    let sockaddr = address.lpSockaddr;
    if sockaddr.is_null() {
        return None;
    }
    let len = usize::try_from(address.iSockaddrLength).ok()?;
    // SAFETY: `sockaddr` points at `len` bytes of a socket address; its family says which structure it is, and the
    // length is checked against that structure before it is read.
    unsafe {
        let family = (*sockaddr.cast_const().cast::<SOCKADDR>()).sa_family;
        if family == AF_INET && len >= std::mem::size_of::<SOCKADDR_IN>() {
            let v4 = std::ptr::read_unaligned(sockaddr.cast_const().cast::<SOCKADDR_IN>());
            Some(IpAddr::V4(Ipv4Addr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes())))
        } else if family == AF_INET6 && len >= std::mem::size_of::<SOCKADDR_IN6>() {
            let v6 = std::ptr::read_unaligned(sockaddr.cast_const().cast::<SOCKADDR_IN6>());
            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
        } else {
            None
        }
    }
}
