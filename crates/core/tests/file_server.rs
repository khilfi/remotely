//! FD-09 quick file server, end to end: TFTP and HTTP on 127.0.0.1 with port 0, fetched with this file's own clients;
//! the served and upload folders are made at run time in the system temp folder. Every request is hostile here:
//! traversal in every form on both protocols, uploads past the caps or onto existing names, slow and flooding
//! clients, and every way the server stops (Stop, the time limit, cancel, a workspace switch, a window reload, the
//! vault locking, Remotely closing), each of which must give the ports back. No packet leaves 127.0.0.1.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{temp_folder, wait_finished, Setup};
use remotely_core::command_bus::{ApprovalAnswers, SubmitOutcome};
use remotely_core::fakes::FakeVmware;
use remotely_core::jobs::JobStatus;
use remotely_core::policy::Tier;
use remotely_core::presentation::Presentation;
use remotely_core::toolbox::file_server::{
    FileServerEvent, FileServerRequest, FileServerSpec, FileServerTuning, Outcome, PathChoice, PickFor, ServerStatus,
    UploadLimits, UploadRequest, UploadSpec,
};
use remotely_core::workspaces::WorkspaceInput;
use remotely_core::Core;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use uuid::Uuid;

const SECRET: &[u8] = b"outside-the-root: never served";

fn fast() -> FileServerTuning {
    FileServerTuning {
        tftp_timeout: Duration::from_millis(300),
        tftp_retries: 2,
        http_head: Duration::from_millis(600),
        http_idle: Duration::from_secs(2),
        change_every: Duration::from_millis(20),
        ..FileServerTuning::default()
    }
}

async fn core() -> Core {
    let core = Setup::new(FakeVmware::default()).build().await;
    core.file_server.runner().set_tuning(fast());
    core
}

/// A folder to serve, inside a parent that also holds a secret file next to it (what traversal would reach).
struct Tree {
    parent: PathBuf,
    root: PathBuf,
}

impl Tree {
    fn new() -> Self {
        let parent = temp_folder("file-server");
        let root = parent.join("served");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(parent.join("secret.txt"), SECRET).unwrap();
        std::fs::write(root.join("fw.bin"), pattern(5000)).unwrap();
        std::fs::write(root.join("sub").join("b.txt"), b"hello from sub").unwrap();
        std::fs::write(root.join("empty.bin"), b"").unwrap();
        std::fs::write(root.join("block.bin"), pattern(1024)).unwrap();
        Self { parent, root }
    }

    fn uploads(&self) -> PathBuf {
        let folder = self.parent.join("uploads");
        std::fs::create_dir_all(&folder).unwrap();
        folder
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.parent);
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 251) as u8).collect()
}

fn spec(root: &Path) -> FileServerSpec {
    FileServerSpec {
        root: root.display().to_string(),
        address: "127.0.0.1".parse().unwrap(),
        tftp_port: Some(0),
        http_port: Some(0),
        minutes: 30,
        uploads: None,
    }
}

fn with_uploads(spec: FileServerSpec, folder: &Path, max_file_mb: u64, max_total_mb: u64) -> FileServerSpec {
    FileServerSpec {
        uploads: Some(UploadSpec {
            folder: folder.display().to_string(),
            max_file_mb,
            max_total_mb,
        }),
        ..spec
    }
}

/// What the window sends for `spec`: its paths picked as the shell's dialogs pick them (tokens), never as paths.
async fn request_for(core: &Core, spec: &FileServerSpec) -> remotely_core::Result<FileServerRequest> {
    let ctx = core.ctx();
    let root = PathBuf::from(&spec.root);
    let purpose = if root.is_file() { PickFor::File } else { PickFor::Folder };
    let root = core.file_server.remember_pick(&ctx, purpose, root).await?;
    let uploads = match &spec.uploads {
        Some(u) => {
            let folder = core
                .file_server
                .remember_pick(&ctx, PickFor::Uploads, PathBuf::from(&u.folder))
                .await?;
            Some(UploadRequest {
                folder: PathChoice::Picked { token: folder.token },
                max_file_mb: u.max_file_mb,
                max_total_mb: u.max_total_mb,
            })
        }
        None => None,
    };
    Ok(FileServerRequest {
        root: PathChoice::Picked { token: root.token },
        address: spec.address,
        tftp_port: spec.tftp_port,
        http_port: spec.http_port,
        minutes: spec.minutes,
        uploads,
    })
}

/// Submits `spec` as the window would.
async fn submit(core: &Core, spec: FileServerSpec) -> remotely_core::Result<SubmitOutcome> {
    let request = request_for(core, &spec).await?;
    core.file_server.submit(&core.ctx(), request).await
}

/// A running server.
struct Running {
    job: Uuid,
    tftp: SocketAddr,
    http: SocketAddr,
}

/// Submits, approves what the tier asks, and waits until the server listens.
async fn start(core: &Core, spec: FileServerSpec) -> Running {
    let request = request_for(core, &spec).await.unwrap();
    start_request(core, request).await
}

/// [`start`] for a request as the window sends it.
async fn start_request(core: &Core, request: FileServerRequest) -> Running {
    let mut events = core.file_server.subscribe();
    let outcome = core.file_server.submit(&core.ctx(), request).await.unwrap();
    let job = match outcome {
        SubmitOutcome::NeedsApproval { request } => {
            let high = request.tier >= Tier::High;
            core.bus
                .approve(
                    request.id,
                    ApprovalAnswers {
                        confirmed: true,
                        typed_target_count: high.then_some(1),
                        reason: high.then(|| "hand a config to a switch".into()),
                        safety_snapshot: None,
                        vault_password: None,
                        change_id: None,
                    },
                )
                .await
                .unwrap()
        }
        SubmitOutcome::Queued { job_id, .. } => job_id,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(FileServerEvent::Started { job_id }) = events.recv().await {
                if job_id == job {
                    break;
                }
            }
        }
    })
    .await
    .expect("the server started");
    let status = core.file_server.status(&core.ctx()).unwrap();
    assert!(status.running);
    let at = |port: Option<u16>| SocketAddr::new("127.0.0.1".parse().unwrap(), port.unwrap_or(0));
    Running {
        job,
        tftp: at(status.tftp_port),
        http: at(status.http_port),
    }
}

async fn stop(core: &Core, running: &Running) -> JobStatus {
    let mut jobs = core.jobs.subscribe();
    assert!(core.file_server.stop(&core.ctx(), running.job));
    wait_finished(&mut jobs, running.job).await
}

fn status(core: &Core) -> ServerStatus {
    core.file_server.status(&core.ctx()).expect("a status")
}

/// Waits until the log holds `n` requests (they are logged as they end).
async fn logged(core: &Core, n: u64) -> ServerStatus {
    for _ in 0..200 {
        let s = status(core);
        if s.counts.requests >= n {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{n} requests were not logged: {:?}", status(core).counts);
}

// ---- A TFTP client ---------------------------------------------------------------------------------------------------

fn request(op: u16, name: &[u8], options: &[(&str, &str)]) -> Vec<u8> {
    let mut packet = op.to_be_bytes().to_vec();
    packet.extend_from_slice(name);
    packet.push(0);
    packet.extend_from_slice(b"octet");
    packet.push(0);
    for (k, v) in options {
        packet.extend_from_slice(k.as_bytes());
        packet.push(0);
        packet.extend_from_slice(v.as_bytes());
        packet.push(0);
    }
    packet
}

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn oack_blksize(packet: &[u8]) -> Option<usize> {
    let fields: Vec<&[u8]> = packet[2..].split(|b| *b == 0).collect();
    fields
        .chunks(2)
        .find(|pair| pair[0].eq_ignore_ascii_case(b"blksize"))
        .and_then(|pair| std::str::from_utf8(pair.get(1)?).ok()?.parse().ok())
}

type TftpError = (u16, String);

async fn recv(socket: &UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), socket.recv_from(buf))
        .await
        .expect("the server answered")
        .unwrap()
}

fn error_of(packet: &[u8]) -> TftpError {
    let message = packet[4..].split(|b| *b == 0).next().unwrap_or_default();
    (u16_at(packet, 2), String::from_utf8_lossy(message).into_owned())
}

async fn tftp_get(server: SocketAddr, name: &[u8], options: &[(&str, &str)]) -> Result<Vec<u8>, TftpError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&request(1, name, options), server).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let mut data = Vec::new();
    let mut expected = 1u16;
    let mut block = 512;
    loop {
        let (n, from) = recv(&socket, &mut buf).await;
        assert_ne!(from, server, "a transfer answers from a port of its own");
        let packet = &buf[..n];
        match u16_at(packet, 0) {
            5 => return Err(error_of(packet)),
            6 => {
                block = oack_blksize(packet).unwrap_or(512);
                socket.send_to(&[0, 4, 0, 0], from).await.unwrap();
            }
            3 => {
                let number = u16_at(packet, 2);
                if number == expected {
                    data.extend_from_slice(&packet[4..]);
                    expected += 1;
                }
                let mut ack = vec![0, 4];
                ack.extend_from_slice(&number.to_be_bytes());
                socket.send_to(&ack, from).await.unwrap();
                if n - 4 < block {
                    return Ok(data);
                }
            }
            other => panic!("unexpected opcode {other}"),
        }
    }
}

async fn tftp_put(server: SocketAddr, name: &[u8], content: &[u8], options: &[(&str, &str)]) -> Result<(), TftpError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&request(2, name, options), server).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let (n, peer) = recv(&socket, &mut buf).await;
    let block = match u16_at(&buf, 0) {
        5 => return Err(error_of(&buf[..n])),
        6 => oack_blksize(&buf[..n]).unwrap_or(512),
        4 => 512,
        other => panic!("unexpected opcode {other}"),
    };
    let mut chunks: Vec<&[u8]> = content.chunks(block).collect();
    if content.len().is_multiple_of(block) {
        chunks.push(&[]);
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let number = u16::try_from(i + 1).unwrap();
        let mut packet = vec![0, 3];
        packet.extend_from_slice(&number.to_be_bytes());
        packet.extend_from_slice(chunk);
        socket.send_to(&packet, peer).await.unwrap();
        let (n, _) = recv(&socket, &mut buf).await;
        match u16_at(&buf, 0) {
            5 => return Err(error_of(&buf[..n])),
            4 => assert_eq!(u16_at(&buf, 2), number),
            other => panic!("unexpected opcode {other}"),
        }
    }
    Ok(())
}

// ---- An HTTP client --------------------------------------------------------------------------------------------------

#[derive(Debug)]
struct Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }
}

fn parse_response(raw: &[u8]) -> Response {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("a whole head in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Response {
        status,
        head,
        body: raw[end + 4..].to_vec(),
    }
}

async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("the server answered and closed")
        .unwrap();
    raw
}

/// The request with `Host: <server>` after its first line, as any client puts it, unless it names a Host itself.
fn with_host(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    let head_end = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(request.len());
    let head = String::from_utf8_lossy(&request[..head_end]).to_lowercase();
    let Some(line_end) = request.windows(2).position(|w| w == b"\r\n") else {
        return request.to_vec();
    };
    if head.contains("\r\nhost:") {
        return request.to_vec();
    }
    let mut out = request[..line_end + 2].to_vec();
    out.extend_from_slice(format!("Host: {server}\r\n").as_bytes());
    out.extend_from_slice(&request[line_end + 2..]);
    out
}

/// Sends a request (with the server's Host) and reads the whole answer.
async fn http_raw(server: SocketAddr, request: &[u8]) -> Response {
    http_exact(server, &with_host(server, request)).await
}

/// Sends a request exactly as given.
async fn http_exact(server: SocketAddr, request: &[u8]) -> Response {
    let mut stream = TcpStream::connect(server).await.unwrap();
    stream.write_all(request).await.unwrap();
    parse_response(&read_all(&mut stream).await)
}

async fn get(server: SocketAddr, target: &str) -> Response {
    http_raw(server, format!("GET {target} HTTP/1.1\r\n\r\n").as_bytes()).await
}

async fn put(server: SocketAddr, target: &str, body: &[u8]) -> Response {
    let mut request = format!("PUT {target} HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(body);
    http_raw(server, &request).await
}

fn assert_no_secret(response: &Response) {
    assert!(
        !response.body.windows(SECRET.len()).any(|w| w == SECRET),
        "the secret leaked: {response:?}"
    );
}

// ---- Serving ---------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_folder_is_served_over_tftp_and_http_and_every_request_is_listed() {
    let tree = Tree::new();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;

    // TFTP: 512-byte blocks, then blksize and tsize; a file of exactly one block ends with an empty block.
    assert_eq!(tftp_get(server.tftp, b"fw.bin", &[]).await.unwrap(), pattern(5000));
    assert_eq!(
        tftp_get(server.tftp, b"/fw.bin", &[("blksize", "1468"), ("tsize", "0")])
            .await
            .unwrap(),
        pattern(5000)
    );
    assert_eq!(
        tftp_get(server.tftp, b"sub/b.txt", &[]).await.unwrap(),
        b"hello from sub"
    );
    assert_eq!(
        tftp_get(server.tftp, b"block.bin", &[("blksize", "1024")])
            .await
            .unwrap(),
        pattern(1024)
    );
    assert_eq!(tftp_get(server.tftp, b"empty.bin", &[]).await.unwrap(), b"");
    assert_eq!(tftp_get(server.tftp, b"missing.bin", &[]).await.unwrap_err().0, 1);
    assert_eq!(
        tftp_get(server.tftp, b"sub", &[]).await.unwrap_err().0,
        1,
        "a folder isn't a file"
    );

    // HTTP: a file as an attachment that never runs, HEAD, a folder's listing and its redirect.
    let file = get(server.http, "/fw.bin").await;
    assert_eq!(file.status, 200);
    assert_eq!(file.body, pattern(5000));
    assert_eq!(file.header("content-length").as_deref(), Some("5000"));
    assert_eq!(file.header("content-type").as_deref(), Some("application/octet-stream"));
    assert_eq!(file.header("x-content-type-options").as_deref(), Some("nosniff"));
    assert!(file
        .header("content-disposition")
        .unwrap()
        .starts_with("attachment; filename=\"fw.bin\""));
    let head = http_raw(server.http, b"HEAD /sub/b.txt HTTP/1.1\r\n\r\n").await;
    assert_eq!(head.status, 200);
    assert_eq!(head.header("content-length").as_deref(), Some("14"));
    assert!(head.body.is_empty());
    let listing = get(server.http, "/").await;
    assert_eq!(listing.status, 200);
    assert!(listing.header("content-type").unwrap().starts_with("text/html"));
    assert!(listing
        .header("content-security-policy")
        .unwrap()
        .contains("default-src 'none'"));
    let html = String::from_utf8(listing.body.clone()).unwrap();
    assert!(
        html.contains("href=\"fw.bin\"") && html.contains("href=\"sub/\""),
        "{html}"
    );
    let moved = get(server.http, "/sub").await;
    assert_eq!(moved.status, 301);
    assert_eq!(moved.header("location").as_deref(), Some("/sub/"));
    assert_eq!(get(server.http, "/sub/").await.status, 200);
    assert_eq!(get(server.http, "/missing").await.status, 404);
    let post = http_raw(server.http, b"POST /fw.bin HTTP/1.1\r\nContent-Length: 0\r\n\r\n").await;
    assert_eq!(post.status, 405);
    assert_eq!(post.header("allow").as_deref(), Some("GET, HEAD"));
    let no_uploads = put(server.http, "/new.bin", b"x").await;
    assert_eq!(no_uploads.status, 405, "uploads are off");
    assert_eq!(tftp_put(server.tftp, b"new.bin", b"x", &[]).await.unwrap_err().0, 2);
    assert!(!tree.root.join("new.bin").exists());

    let seen = logged(&core, 16).await;
    assert_eq!(seen.counts.sent, 10);
    assert!(seen.urls.iter().any(|u| u.starts_with("http://127.0.0.1:")));
    assert!(seen.transfers.iter().all(|r| r.ip == "127.0.0.1"));
    assert!(seen
        .transfers
        .iter()
        .any(|r| r.method == "read" && r.path == "fw.bin" && r.bytes == 5000 && r.outcome == Outcome::Sent));

    assert_eq!(stop(&core, &server).await, JobStatus::Succeeded);
    let stopped = status(&core);
    assert!(!stopped.running);
    assert_eq!(stopped.stopped.as_deref(), Some("stopped by you"));
    // The job lists every request, and its start and end are audited.
    let targets = core.store.job_targets(&core.ctx(), server.job).await.unwrap();
    let output = targets[0].output.clone().unwrap();
    assert!(output.contains("TFTP read 127.0.0.1:"), "{output}");
    assert!(output.contains("HTTP GET 127.0.0.1:"), "{output}");
    assert!(output.contains("16 requests"), "{output}");
    let audit = core.store.recent_audit(&core.ctx(), 20).await.unwrap();
    let started = audit.iter().find(|e| e.event == "job_started").unwrap();
    assert!(started.action.starts_with("Serve "), "{}", started.action);
    assert_eq!(started.tier.as_deref(), Some("medium"));
    let finished = audit.iter().find(|e| e.event == "job_finished").unwrap();
    assert!(
        finished
            .detail
            .as_deref()
            .unwrap()
            .contains("stopped by you; 16 requests"),
        "{:?}",
        finished.detail
    );
    assert!(finished.targets_json.contains("this PC (127.0.0.1)"));
}

#[tokio::test]
async fn one_file_is_served_by_its_name_only() {
    let tree = Tree::new();
    let core = core().await;
    let server = start(&core, spec(&tree.root.join("fw.bin"))).await;
    assert_eq!(get(server.http, "/fw.bin").await.body, pattern(5000));
    assert_eq!(
        get(server.http, "/FW.BIN").await.status,
        200,
        "names without case, as Windows has them"
    );
    assert_eq!(
        get(server.http, "/block.bin").await.status,
        404,
        "the rest of its folder isn't served"
    );
    assert_eq!(get(server.http, "/sub/b.txt").await.status, 404);
    assert_eq!(get(server.http, "/fw.bin/").await.status, 404);
    let listing = String::from_utf8(get(server.http, "/").await.body).unwrap();
    assert!(
        listing.contains("fw.bin") && !listing.contains("block.bin"),
        "{listing}"
    );
    assert_eq!(tftp_get(server.tftp, b"fw.bin", &[]).await.unwrap(), pattern(5000));
    assert_eq!(tftp_get(server.tftp, b"block.bin", &[]).await.unwrap_err().0, 1);
    let urls = status(&core).urls;
    assert!(
        urls.iter()
            .any(|u| u.ends_with("/fw.bin") && u.starts_with("tftp://127.0.0.1:")),
        "{urls:?}"
    );
    stop(&core, &server).await;
}

// ---- Hostile paths ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_traversal_form_is_refused_on_both_protocols() {
    let tree = Tree::new();
    let parent = tree.parent.display().to_string();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;

    let drive = parent.get(..2).unwrap_or("C:").to_owned();
    let absolute = format!("{parent}\\secret.txt");
    let http_targets = [
        "/../secret.txt".to_owned(),
        "/sub/../../secret.txt".to_owned(),
        "/%2e%2e/secret.txt".to_owned(),
        "/%2E%2E%2Fsecret.txt".to_owned(),
        "/..%2fsecret.txt".to_owned(),
        "/..%5csecret.txt".to_owned(),
        "/..\\secret.txt".to_owned(),
        "/%252e%252e/secret.txt".to_owned(),
        "/%252e%252e%252fsecret.txt".to_owned(),
        "/%c0%ae%c0%ae/secret.txt".to_owned(),
        format!("/{}", absolute.replace('\\', "/")),
        format!("/{}", absolute.replace('\\', "%5c")),
        format!("/{drive}%5c..%5csecret.txt"),
        "//127.0.0.1/c$/secret.txt".to_owned(),
        "/%5c%5c127.0.0.1%5cc$%5csecret.txt".to_owned(),
        "/%5c%5c%3f%5cC:%5cWindows%5cwin.ini".to_owned(),
        "/%5c%5c.%5cPhysicalDrive0".to_owned(),
        "/NUL".to_owned(),
        "/sub/con.txt".to_owned(),
        "/fw.bin:hidden".to_owned(),
        "/fw.bin::$DATA".to_owned(),
        "/fw.bin.".to_owned(),
        "/fw.bin%20".to_owned(),
        "/fw.bin%00.txt".to_owned(),
        format!("http://127.0.0.1{}", "/fw.bin"),
        "*".to_owned(),
    ];
    for target in &http_targets {
        let response = get(server.http, target).await;
        assert!(
            matches!(response.status, 400 | 403 | 404),
            "{target}: {} {:?}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
        assert_no_secret(&response);
    }
    let tftp_names = [
        b"../secret.txt".to_vec(),
        b"sub/../../secret.txt".to_vec(),
        b"..\\secret.txt".to_vec(),
        b"sub\\..\\..\\secret.txt".to_vec(),
        absolute.clone().into_bytes(),
        absolute.replace('\\', "/").into_bytes(),
        format!("{drive}secret.txt").into_bytes(),
        b"//127.0.0.1/c$/secret.txt".to_vec(),
        b"\\\\127.0.0.1\\c$\\secret.txt".to_vec(),
        b"\\\\?\\C:\\Windows\\win.ini".to_vec(),
        b"\\\\.\\PhysicalDrive0".to_vec(),
        b"NUL".to_vec(),
        b"com1.bin".to_vec(),
        b"fw.bin:hidden".to_vec(),
        b"fw.bin.".to_vec(),
        b"fw.bin ".to_vec(),
        vec![0xff, 0xfe],
    ];
    for name in &tftp_names {
        let refused = tftp_get(server.tftp, name, &[]).await;
        assert!(matches!(refused, Err((1 | 2 | 4, _))), "{name:?}: {refused:?}");
    }
    let seen = logged(&core, (http_targets.len() + tftp_names.len()) as u64).await;
    assert_eq!(seen.counts.sent, 0, "nothing was served");
    assert_eq!(seen.transfer_rows, 0, "no request reached a file");
    // Folded: one row per client and protocol.
    assert_eq!(seen.refusal_rows, 2);
    assert!(seen
        .refusals
        .iter()
        .all(|r| r.outcome == Outcome::Refused && r.ip == "127.0.0.1"));
    let times: u64 = seen.refusals.iter().map(|r| r.times).sum();
    assert_eq!(times, seen.counts.requests);
    stop(&core, &server).await;
}

#[cfg(windows)]
#[tokio::test]
async fn links_junctions_and_streams_never_lead_out_of_the_root() {
    let tree = Tree::new();
    // An alternate data stream on a served file.
    let mut stream = tree.root.join("fw.bin").into_os_string();
    stream.push(":hidden");
    std::fs::write(PathBuf::from(stream), SECRET).unwrap();
    // A junction (no rights needed) and, when Windows allows it, a symbolic link, both to the secret's folder.
    let junction = tree.root.join("junction");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&tree.parent)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let linked = std::os::windows::fs::symlink_file(tree.parent.join("secret.txt"), tree.root.join("link.txt")).is_ok();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;

    for target in ["/fw.bin:hidden", "/fw.bin%3ahidden"] {
        let response = get(server.http, target).await;
        assert_eq!(response.status, 403, "{target}");
        assert_no_secret(&response);
    }
    if made {
        for target in ["/junction/secret.txt", "/junction/", "/junction"] {
            let response = get(server.http, target).await;
            assert!(matches!(response.status, 403 | 404), "{target}: {}", response.status);
            assert_no_secret(&response);
        }
        assert!(tftp_get(server.tftp, b"junction/secret.txt", &[]).await.is_err());
        let listing = String::from_utf8(get(server.http, "/").await.body).unwrap();
        assert!(!listing.contains("junction"), "links aren't listed: {listing}");
    } else {
        eprintln!("mklink /J failed here; the junction part was skipped");
    }
    if linked {
        let response = get(server.http, "/link.txt").await;
        assert_eq!(response.status, 403);
        assert_no_secret(&response);
        assert!(tftp_get(server.tftp, b"link.txt", &[]).await.is_err());
    } else {
        eprintln!("symbolic links need Developer Mode here; that part was skipped");
    }
    stop(&core, &server).await;
}

// ---- Uploads ---------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn uploads_go_into_the_empty_folder_capped_marked_and_never_replace_a_file() {
    let tree = Tree::new();
    let uploads = tree.uploads();
    let core = core().await;
    let server = start(&core, with_uploads(spec(&tree.root), &uploads, 1, 2)).await;
    // High: the full approval was asked and given.
    let audit = core.store.recent_audit(&core.ctx(), 20).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e.event == "job_started" && e.tier.as_deref() == Some("high")));

    // TFTP, with and without options; HTTP PUT, with Expect: 100-continue.
    tftp_put(server.tftp, b"sw1-confg", b"hostname sw1\n", &[])
        .await
        .unwrap();
    tftp_put(
        server.tftp,
        b"sw2-confg",
        &pattern(3000),
        &[("blksize", "1024"), ("tsize", "3000")],
    )
    .await
    .unwrap();
    let created = put(server.http, "/web01.tar", &pattern(70_000)).await;
    assert_eq!(created.status, 201, "{:?}", String::from_utf8_lossy(&created.body));
    let mut stream = TcpStream::connect(server.http).await.unwrap();
    stream
        .write_all(&with_host(
            server.http,
            b"PUT /with-expect.bin HTTP/1.1\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
        ))
        .await
        .unwrap();
    let mut interim = [0u8; 25];
    stream.read_exact(&mut interim).await.unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    stream.write_all(b"abcd").await.unwrap();
    assert_eq!(parse_response(&read_all(&mut stream).await).status, 201);
    // A8: format characters become `_`.
    assert_eq!(put(server.http, "/invoice%E2%80%AEfdp.exe", b"x").await.status, 201);
    assert!(uploads.join("invoice_fdp.exe").exists());

    // Never onto a name that is there, whatever its case.
    assert_eq!(put(server.http, "/SW1-CONFG", b"evil").await.status, 409);
    assert_eq!(
        tftp_put(server.tftp, b"sw1-confg", b"evil", &[]).await.unwrap_err().0,
        6
    );
    assert_eq!(std::fs::read(uploads.join("sw1-confg")).unwrap(), b"hostname sw1\n");

    // Only into the folder itself, by a clean name.
    for target in [
        "/sub/x.bin",
        "/../x.bin",
        "/%2e%2e%2fx.bin",
        "/x.bin:stream",
        "/NUL",
        "/x.bin.",
    ] {
        let response = put(server.http, target, b"x").await;
        assert!(matches!(response.status, 403 | 404), "{target}: {}", response.status);
    }
    for name in [
        &b"../x.bin"[..],
        b"..\\x.bin",
        b"sub/x.bin",
        b"C:\\x.bin",
        b"x.bin:s",
        b"aux",
    ] {
        assert!(tftp_put(server.tftp, name, b"x", &[]).await.is_err(), "{name:?}");
    }
    assert!(!tree.parent.join("x.bin").exists());

    // The caps: 1 MB a file, 2 MB in all. A declared size is checked before any byte; a TFTP upload without one is
    // cut off as it passes the cap, and its part deleted.
    let mut over = format!("PUT /big.bin HTTP/1.1\r\nContent-Length: {}\r\n\r\n", 1024 * 1024 + 1).into_bytes();
    over.extend_from_slice(b"x");
    assert_eq!(http_raw(server.http, &over).await.status, 413);
    let refused = tftp_put(
        server.tftp,
        b"big.bin",
        &pattern(1024 * 1024 + 10),
        &[("blksize", "65464")],
    )
    .await;
    assert_eq!(refused.unwrap_err().0, 3);
    assert!(!uploads.join("big.bin").exists(), "a cut-off upload is deleted");
    let declared = tftp_put(server.tftp, b"big2.bin", b"x", &[("tsize", "2000000")]).await;
    assert_eq!(declared.unwrap_err().0, 3);
    // Without a length, or chunked: refused.
    assert_eq!(http_raw(server.http, b"PUT /c.bin HTTP/1.1\r\n\r\n").await.status, 411);
    let chunked = http_raw(
        server.http,
        b"PUT /c.bin HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(chunked.status, 501);
    let twice = http_raw(
        server.http,
        b"PUT /c.bin HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
    )
    .await;
    assert_eq!(twice.status, 400);
    // A body that stops short: the part is deleted.
    let mut short = TcpStream::connect(server.http).await.unwrap();
    short
        .write_all(&with_host(
            server.http,
            b"PUT /short.bin HTTP/1.1\r\nContent-Length: 1000\r\n\r\nonly a bit",
        ))
        .await
        .unwrap();
    short.shutdown().await.unwrap();
    let _ = read_all(&mut short).await;
    // 1 MB fits in one file, but twice is more than the 2 MB in all. (The refusal comes before the body, as clients
    // that send a large one ask with Expect: 100-continue.)
    assert_eq!(put(server.http, "/fill1.bin", &pattern(1_040_000)).await.status, 201);
    let full = http_raw(
        server.http,
        b"PUT /fill2.bin HTTP/1.1\r\nContent-Length: 1040000\r\nExpect: 100-continue\r\n\r\n",
    )
    .await;
    assert_eq!(full.status, 413, "{:?}", String::from_utf8_lossy(&full.body));
    assert!(!uploads.join("fill2.bin").exists());

    // What is being uploaded isn't served, and uploads are files of their own: nothing in the served folder changed.
    assert!(!tree.root.join("sw1-confg").exists());
    let seen = logged(&core, 28).await;
    assert!(seen.counts.received >= 6, "{:?}", seen.counts);
    let upload = seen.uploads.unwrap();
    assert_eq!(upload.max_file_mb, 1);
    assert!(upload.files >= 6);

    assert_eq!(stop(&core, &server).await, JobStatus::Succeeded);
    assert!(
        !uploads.join("short.bin").exists(),
        "an upload that stopped short is deleted"
    );
    // Each finished upload is marked as from the internet.
    for name in ["sw1-confg", "sw2-confg", "web01.tar", "with-expect.bin"] {
        assert!(uploads.join(name).exists(), "{name}");
        #[cfg(windows)]
        {
            let mut stream = uploads.join(name).into_os_string();
            stream.push(":Zone.Identifier");
            let mark = std::fs::read_to_string(PathBuf::from(stream)).unwrap();
            assert!(mark.contains("ZoneId=3"), "{name}: {mark}");
        }
    }
    assert_eq!(std::fs::read(uploads.join("sw2-confg")).unwrap(), pattern(3000));
    assert_eq!(std::fs::read(uploads.join("web01.tar")).unwrap(), pattern(70_000));
    let audit = core.store.recent_audit(&core.ctx(), 20).await.unwrap();
    let finished = audit.iter().find(|e| e.event == "job_finished").unwrap();
    let detail = finished.detail.clone().unwrap();
    assert!(
        detail.contains("uploaded into") && detail.contains("sw1-confg") && detail.contains("from 127.0.0.1"),
        "{detail}"
    );
}

#[tokio::test]
async fn the_upload_folder_must_be_empty_outside_git_and_on_this_pc() {
    let tree = Tree::new();
    let core = core().await;
    let ctx = core.ctx();
    let not_empty = tree.uploads();
    std::fs::write(not_empty.join("there.bin"), b"x").unwrap();
    let err = submit(&core, with_uploads(spec(&tree.root), &not_empty, 1, 1))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("isn't empty"), "{err}");
    let repo = tree.parent.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("in")).unwrap();
    let err = submit(&core, with_uploads(spec(&tree.root), &repo.join("in"), 1, 1))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("inside a Git repository"), "{err}");
    let err = submit(&core, with_uploads(spec(&tree.root), &tree.root.join("missing"), 1, 1))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("can't be used"), "{err}");
    // A file or folder that isn't there, an address this PC doesn't have, and every address are refused.
    assert!(submit(&core, spec(&tree.root.join("gone"))).await.is_err());
    let elsewhere = FileServerSpec {
        address: "192.0.2.10".parse().unwrap(),
        ..spec(&tree.root)
    };
    let err = submit(&core, elsewhere).await.unwrap_err();
    assert!(
        err.to_string().contains("no adapter with the address 192.0.2.10"),
        "{err}"
    );
    let all = FileServerSpec {
        address: "0.0.0.0".parse().unwrap(),
        ..spec(&tree.root)
    };
    assert!(submit(&core, all).await.is_err());
    // Nothing ran, so nothing was kept as the last choices.
    assert!(core.file_server.options(&ctx).await.unwrap().last.is_none());
    assert!(core.jobs.open_jobs() == 0);
}

#[tokio::test]
async fn paths_come_only_from_the_dialogs_or_the_last_choices_and_never_from_the_window() {
    let tree = Tree::new();
    let core = core().await;
    let ctx = core.ctx();
    let request = |root: PathChoice| FileServerRequest {
        root,
        address: "127.0.0.1".parse().unwrap(),
        tftp_port: Some(0),
        http_port: Some(0),
        minutes: 30,
        uploads: None,
    };
    // A token nobody handed out, one for another purpose, one from another workspace: refused.
    let made_up = core
        .file_server
        .submit(&ctx, request(PathChoice::Picked { token: Uuid::new_v4() }))
        .await
        .unwrap_err();
    assert!(
        made_up.to_string().contains("Choose the file or folder again"),
        "{made_up}"
    );
    let uploads_pick = core
        .file_server
        .remember_pick(&ctx, PickFor::Uploads, tree.uploads())
        .await
        .unwrap();
    assert!(core
        .file_server
        .submit(
            &ctx,
            request(PathChoice::Picked {
                token: uploads_pick.token
            })
        )
        .await
        .is_err());
    let elsewhere = remotely_core::domain::Context {
        workspace_id: remotely_core::domain::WorkspaceId(Uuid::new_v4()),
        user_id: ctx.user_id,
    };
    let theirs = core
        .file_server
        .remember_pick(&elsewhere, PickFor::Folder, tree.root.clone())
        .await
        .unwrap();
    assert!(core
        .file_server
        .submit(&ctx, request(PathChoice::Picked { token: theirs.token }))
        .await
        .is_err());
    // A file picked as a folder, and the other way round, are refused at the pick.
    assert!(core
        .file_server
        .remember_pick(&ctx, PickFor::Folder, tree.root.join("fw.bin"))
        .await
        .is_err());
    assert!(core
        .file_server
        .remember_pick(&ctx, PickFor::File, tree.root.clone())
        .await
        .is_err());
    // No last choice yet; then the last choice is used, and checked again like a new one.
    assert!(core.file_server.submit(&ctx, request(PathChoice::Last)).await.is_err());
    let server = start(&core, spec(&tree.root)).await;
    stop(&core, &server).await;
    let again = start_request(&core, request(PathChoice::Last)).await;
    assert!(status(&core).served.to_lowercase().ends_with("served"));
    stop(&core, &again).await;
    std::fs::remove_dir_all(&tree.root).unwrap();
    let gone = core
        .file_server
        .submit(&ctx, request(PathChoice::Last))
        .await
        .unwrap_err();
    assert!(gone.to_string().contains("can't be served"), "{gone}");
}

#[tokio::test]
async fn remotelys_data_a_drive_root_and_the_profile_folder_are_never_served() {
    let tree = Tree::new();
    let core = core().await;
    let ctx = core.ctx();
    // As the core does for its database's folder at start.
    let data = tree.parent.join("data");
    std::fs::create_dir_all(data.join("logs")).unwrap();
    std::fs::write(data.join("remotely.db"), b"the database").unwrap();
    core.file_server.runner().protect(&data);
    for (purpose, path) in [
        (PickFor::Folder, data.clone()),
        (PickFor::Folder, data.join("logs")),
        (PickFor::File, data.join("remotely.db")),
        (PickFor::Uploads, data.join("logs")),
        // Holding it: the data folder would be served inside it.
        (PickFor::Folder, tree.parent.clone()),
    ] {
        let err = core
            .file_server
            .remember_pick(&ctx, purpose, path.clone())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Remotely's own data"),
            "{}: {err}",
            path.display()
        );
    }
    // A folder beside it is fine.
    assert!(core
        .file_server
        .remember_pick(&ctx, PickFor::Folder, tree.root.clone())
        .await
        .is_ok());
    // A whole drive, and the user's own folder.
    let drive = std::path::absolute(&tree.root)
        .unwrap()
        .ancestors()
        .last()
        .unwrap()
        .to_path_buf();
    let err = core
        .file_server
        .remember_pick(&ctx, PickFor::Folder, drive)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("whole drive"), "{err}");
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let err = core
            .file_server
            .remember_pick(&ctx, PickFor::Folder, PathBuf::from(profile))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("whole user folder"), "{err}");
    }
    // A last choice that became protected is refused when it is used again.
    let server = start(&core, spec(&tree.root)).await;
    stop(&core, &server).await;
    core.file_server.runner().protect(&tree.root);
    let request = FileServerRequest {
        root: PathChoice::Last,
        address: "127.0.0.1".parse().unwrap(),
        tftp_port: Some(0),
        http_port: None,
        minutes: 30,
        uploads: None,
    };
    let err = core.file_server.submit(&ctx, request).await.unwrap_err();
    assert!(err.to_string().contains("Remotely's own data"), "{err}");
}

// ---- Bounds ----------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn slow_and_flooding_http_clients_are_bounded() {
    let tree = Tree::new();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;

    // Slowloris: a head that never ends gets 408 once its time is up.
    let mut slow = TcpStream::connect(server.http).await.unwrap();
    slow.write_all(b"GET /fw.bin HTTP/1.1\r\nX-Slow: yes\r\n")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let answer = parse_response(&read_all(&mut slow).await);
    assert_eq!(answer.status, 408);
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(slow);

    // Too many headers, a head too large, a target too long, junk.
    let mut many = String::from("GET / HTTP/1.1\r\n");
    for i in 0..40 {
        many.push_str(&format!("X-{i}: y\r\n"));
    }
    many.push_str("\r\n");
    assert_eq!(http_raw(server.http, many.as_bytes()).await.status, 431);
    let huge = format!("GET / HTTP/1.1\r\nX-Big: {}\r\n\r\n", "a".repeat(20_000));
    assert_eq!(http_raw(server.http, huge.as_bytes()).await.status, 431);
    let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(5000));
    assert_eq!(http_raw(server.http, long.as_bytes()).await.status, 414);
    assert_eq!(
        http_raw(server.http, b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\r\n\r\n")
            .await
            .status,
        400
    );
    stop(&core, &server).await;

    // Two idle connections from one client fill its share; a third is closed at once, unanswered.
    core.file_server.runner().set_tuning(FileServerTuning {
        max_http: 4,
        max_http_per_client: 2,
        ..fast()
    });
    let server = start(&core, spec(&tree.root)).await;
    let idle1 = TcpStream::connect(server.http).await.unwrap();
    let idle2 = TcpStream::connect(server.http).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut third = TcpStream::connect(server.http).await.unwrap();
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_millis(400), third.read(&mut byte)).await;
    assert!(matches!(closed, Ok(Ok(0)) | Ok(Err(_))), "{closed:?}");
    drop((idle1, idle2));
    // Once they are gone (each ends at its head timeout at the latest), a request goes through again.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(get(server.http, "/fw.bin").await.status, 200);
    stop(&core, &server).await;
}

#[tokio::test]
async fn tftp_retransmits_only_on_timeout_a_bounded_number_of_times() {
    let tree = Tree::new();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;

    // A client that never ACKs: DATA 1, then 2 retransmits (fast(): 2 retries of 300 ms), then nothing.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    silent.send_to(&request(1, b"fw.bin", &[]), server.tftp).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let mut data = 0;
    while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(1500), silent.recv_from(&mut buf)).await {
        assert_eq!(u16_at(&buf[..n], 0), 3);
        assert_eq!(u16_at(&buf[..n], 2), 1);
        data += 1;
    }
    assert_eq!(data, 3, "the block and its 2 retransmits");

    // A duplicate ACK never sends the next block twice (the Sorcerer's Apprentice bug).
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&request(1, b"fw.bin", &[]), server.tftp).await.unwrap();
    let (_, peer) = recv(&client, &mut buf).await;
    client.send_to(&[0, 4, 0, 1], peer).await.unwrap();
    client.send_to(&[0, 4, 0, 1], peer).await.unwrap();
    let mut second = 0;
    while let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut buf)).await {
        if u16_at(&buf[..n], 0) == 3 && u16_at(&buf[..n], 2) == 2 {
            second += 1;
        }
    }
    assert_eq!(second, 1);

    // Block numbers never wrap round: 65,535 blocks of 8 bytes is under 512 KB.
    std::fs::write(tree.root.join("wraps.bin"), vec![0u8; 600 * 1024]).unwrap();
    let refused = tftp_get(server.tftp, b"wraps.bin", &[("blksize", "8")])
        .await
        .unwrap_err();
    assert!(refused.1.contains("too large"), "{refused:?}");
    // A stray packet to the listening port gets nothing back; a malformed request an error.
    let stray = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stray.send_to(&[0, 4, 0, 1], server.tftp).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), stray.recv_from(&mut buf))
            .await
            .is_err()
    );
    stray.send_to(&[0, 1, b'f', b'w'], server.tftp).await.unwrap();
    let (n, _) = recv(&stray, &mut buf).await;
    assert_eq!(u16_at(&buf[..n], 0), 5);
    stray
        .send_to(&request(1, b"fw.bin", &[("blksize", "4")]), server.tftp)
        .await
        .unwrap();
    let (n, _) = recv(&stray, &mut buf).await;
    assert_eq!(&buf[..4], &[0, 5, 0, 8], "{:?}", &buf[..n]);

    let seen = logged(&core, 5).await;
    assert!(seen
        .transfers
        .iter()
        .any(|r| r.outcome == Outcome::Failed && r.detail.contains("stopped answering")));
    stop(&core, &server).await;
}

#[tokio::test]
async fn tftp_transfers_are_capped_in_all_and_per_client() {
    let tree = Tree::new();
    let core = core().await;
    core.file_server.runner().set_tuning(FileServerTuning {
        max_tftp: 3,
        max_tftp_per_client: 2,
        tftp_timeout: Duration::from_millis(500),
        ..fast()
    });
    let server = start(&core, spec(&tree.root)).await;
    // Two transfers left waiting for their ACK hold this client's share.
    let mut buf = vec![0u8; 65536];
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for socket in [&a, &b] {
        socket.send_to(&request(1, b"fw.bin", &[]), server.tftp).await.unwrap();
        recv(socket, &mut buf).await;
    }
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.send_to(&request(1, b"fw.bin", &[]), server.tftp).await.unwrap();
    let (n, _) = recv(&c, &mut buf).await;
    assert_eq!(u16_at(&buf[..n], 0), 5);
    assert!(String::from_utf8_lossy(&buf[4..n]).contains("busy"));
    stop(&core, &server).await;
}

// ---- Stopping --------------------------------------------------------------------------------------------------------

/// The ports are free again: something else can listen on them.
async fn released(running: &Running) {
    UdpSocket::bind(running.tftp)
        .await
        .expect("the TFTP port was given back");
    TcpListener::bind(running.http)
        .await
        .expect("the HTTP port was given back");
}

#[tokio::test]
async fn the_time_limit_ends_it_and_gives_the_ports_back() {
    let tree = Tree::new();
    let core = core().await;
    core.file_server.runner().set_tuning(FileServerTuning {
        minute: Duration::from_millis(300),
        ..fast()
    });
    let mut jobs = core.jobs.subscribe();
    let server = start(
        &core,
        FileServerSpec {
            minutes: 1,
            ..spec(&tree.root)
        },
    )
    .await;
    assert_eq!(wait_finished(&mut jobs, server.job).await, JobStatus::Succeeded);
    assert_eq!(
        status(&core).stopped.as_deref(),
        Some("its time limit of 1 minute ran out")
    );
    released(&server).await;
    let audit = core.store.recent_audit(&core.ctx(), 10).await.unwrap();
    assert!(audit
        .iter()
        .any(|e| e.event == "job_finished" && e.detail.as_deref().is_some_and(|d| d.contains("time limit"))));
}

#[tokio::test]
async fn cancel_stops_it_mid_transfer_and_deletes_the_half_upload() {
    let tree = Tree::new();
    let uploads = tree.uploads();
    let core = core().await;
    core.file_server.runner().set_tuning(FileServerTuning {
        tftp_timeout: Duration::from_secs(5),
        ..fast()
    });
    let mut jobs = core.jobs.subscribe();
    let server = start(&core, with_uploads(spec(&tree.root), &uploads, 1, 1)).await;
    // An upload half way: one block in, the rest never sent.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&request(2, b"half.bin", &[]), server.tftp)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65536];
    let (_, peer) = recv(&client, &mut buf).await;
    let mut block = vec![0, 3, 0, 1];
    block.extend_from_slice(&[7u8; 512]);
    client.send_to(&block, peer).await.unwrap();
    recv(&client, &mut buf).await;
    assert!(uploads.join("half.bin").exists());
    assert!(core.jobs.cancel(server.job));
    assert_eq!(wait_finished(&mut jobs, server.job).await, JobStatus::Cancelled);
    assert!(!uploads.join("half.bin").exists(), "the half upload is deleted");
    released(&server).await;
    let seen = status(&core);
    assert_eq!(seen.stopped.as_deref(), Some("cancelled"));
    assert!(seen
        .transfers
        .iter()
        .any(|r| r.path == "half.bin" && r.detail.contains("cut off: the server stopped")));
}

#[tokio::test]
async fn a_workspace_switch_stops_it_instead_of_being_refused() {
    let tree = Tree::new();
    let core = core().await;
    let home = core.ctx();
    let server = start(&core, spec(&tree.root)).await;
    let other = core
        .workspaces
        .create(WorkspaceInput {
            name: "Initech".into(),
            color: None,
        })
        .await
        .unwrap();
    let preview = core.switch_preview(other.id).await.unwrap();
    assert_eq!(preview.open_jobs, 0, "the file server doesn't hold the switch back");
    assert!(preview.file_server);
    core.switch_workspace(other.id).await.unwrap();
    assert!(core.file_server.runner().running().is_none());
    released(&server).await;
    // Its job ended in the old workspace, which still shows how it stopped; the new one has no server.
    assert_eq!(
        core.store.job_status(server.job).await.unwrap(),
        Some(JobStatus::Succeeded)
    );
    assert!(core.file_server.status(&core.ctx()).is_none());
    let old = core.file_server.status(&home).unwrap();
    assert_eq!(old.stopped.as_deref(), Some("stopped: another workspace was opened"));
}

#[tokio::test]
async fn a_server_still_in_its_countdown_never_starts_after_a_switch_or_a_reload() {
    let tree = Tree::new();
    let mut setup = Setup::new(FakeVmware::default());
    setup.rules.countdown_seconds = 60;
    let core = setup.build().await;
    core.file_server.runner().set_tuning(fast());
    async fn approve(core: &Core, outcome: SubmitOutcome) -> remotely_core::Result<Uuid> {
        let SubmitOutcome::NeedsApproval { request } = outcome else {
            panic!("uploads need the full approval");
        };
        core.bus
            .approve(
                request.id,
                ApprovalAnswers {
                    confirmed: true,
                    typed_target_count: Some(1),
                    reason: Some("receive a config".into()),
                    safety_snapshot: None,
                    vault_password: None,
                    change_id: None,
                },
            )
            .await
    }
    let uploads = tree.uploads();
    let spec = with_uploads(spec(&tree.root), &uploads, 1, 1);

    // A workspace switch cancels it in its countdown, so it never serves in a workspace nobody shows.
    let mut jobs = core.jobs.subscribe();
    let outcome = submit(&core, spec.clone()).await.unwrap();
    let job = approve(&core, outcome).await.unwrap();
    let other = core
        .workspaces
        .create(WorkspaceInput {
            name: "Initech".into(),
            color: None,
        })
        .await
        .unwrap();
    assert!(core.switch_preview(other.id).await.unwrap().file_server);
    core.switch_workspace(other.id).await.unwrap();
    assert_eq!(wait_finished(&mut jobs, job).await, JobStatus::Cancelled);
    assert!(core.file_server.runner().running().is_none());

    // So does a window reload.
    let outcome = submit(&core, spec).await.unwrap();
    let job = approve(&core, outcome).await.unwrap();
    let shown = core.ui_snapshot();
    assert_eq!(shown.file_servers, [job]);
    core.release_ui(shown).await;
    assert_eq!(core.store.job_status(job).await.unwrap(), Some(JobStatus::Cancelled));
    assert!(core.file_server.runner().running().is_none());
}

#[tokio::test]
async fn a_window_reload_and_the_app_closing_stop_it() {
    let tree = Tree::new();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;
    let shown = core.ui_snapshot();
    assert_eq!(shown.file_servers, [server.job]);
    let released_ui = core.release_ui(shown).await;
    assert_eq!(released_ui.file_servers, 1);
    assert_eq!(status(&core).stopped.as_deref(), Some("stopped: the window reloaded"));
    released(&server).await;

    let again = start(&core, spec(&tree.root)).await;
    core.shutdown().await;
    assert_eq!(
        core.store.job_status(again.job).await.unwrap(),
        Some(JobStatus::Succeeded)
    );
    assert_eq!(status(&core).stopped.as_deref(), Some("stopped: Remotely closed"));
    released(&again).await;
}

#[tokio::test]
async fn the_vault_locking_stops_it() {
    let tree = Tree::new();
    let core = Setup::new(FakeVmware::default()).with_real_vault().build().await;
    core.file_server.runner().set_tuning(fast());
    let mut jobs = core.jobs.subscribe();
    let server = start(&core, spec(&tree.root)).await;
    core.vault.lock(&core.ctx()).await.unwrap();
    assert_eq!(wait_finished(&mut jobs, server.job).await, JobStatus::Succeeded);
    assert_eq!(status(&core).stopped.as_deref(), Some("stopped: the vault locked"));
    released(&server).await;
}

#[tokio::test]
async fn one_at_a_time_never_while_presenting_and_the_last_choices_are_kept_per_workspace() {
    let tree = Tree::new();
    let core = core().await;
    let ctx = core.ctx();
    let chosen = spec(&tree.root);
    let server = start(&core, chosen.clone()).await;
    let err = submit(&core, spec(&tree.root)).await.unwrap_err();
    assert!(err.to_string().contains("running already"), "{err}");
    let options = core.file_server.options(&ctx).await.unwrap();
    assert_eq!(options.last, Some(chosen));
    assert!(options.addresses.iter().any(|a| a.address == "127.0.0.1" && a.loopback));
    assert!(options.status.unwrap().running);
    // Another workspace sees neither the server nor the choices.
    assert!(!core.file_server.stop(
        &remotely_core::domain::Context {
            workspace_id: remotely_core::domain::WorkspaceId(Uuid::new_v4()),
            user_id: ctx.user_id,
        },
        server.job
    ));
    stop(&core, &server).await;

    core.presentation
        .set(Presentation {
            enabled: true,
            read_only: true,
        })
        .await
        .unwrap();
    let err = submit(&core, spec(&tree.root)).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("read-only"), "{err}");
}

// ---- Review fixes: rebinding, the log, Explorer's files, the upload quota ---------------------------------------------

#[tokio::test]
async fn a_web_page_reaching_the_server_by_a_name_of_its_own_is_refused() {
    let tree = Tree::new();
    let uploads = tree.uploads();
    let core = core().await;
    let server = start(&core, with_uploads(spec(&tree.root), &uploads, 1, 1)).await;
    let port = server.http.port();
    // DNS rebinding: the page's own name (or anything but this address and port) in Host.
    for host in [
        format!("attacker.example:{port}"),
        "attacker.example".to_owned(),
        format!("localhost:{port}"),
        "127.0.0.1".to_owned(),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
    ] {
        let file = http_exact(
            server.http,
            format!("GET /fw.bin HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        )
        .await;
        assert_eq!(file.status, 421, "{host}");
        assert_ne!(file.body, pattern(5000));
        let listing = http_exact(
            server.http,
            format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        )
        .await;
        assert_eq!(listing.status, 421, "{host}");
        assert!(!String::from_utf8_lossy(&listing.body).contains("fw.bin"));
        let upload = http_exact(
            server.http,
            format!("PUT /evil.bin HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n\r\nevil").as_bytes(),
        )
        .await;
        assert_eq!(upload.status, 421, "{host}");
        assert!(!uploads.join("evil.bin").exists());
    }
    // HTTP/1.1 without Host is refused; HTTP/1.0 without one (U-Boot's wget) and the right Host are served.
    assert_eq!(
        http_exact(server.http, b"GET /fw.bin HTTP/1.1\r\n\r\n").await.status,
        400
    );
    let old = http_exact(server.http, b"GET /fw.bin HTTP/1.0\r\n\r\n").await;
    assert_eq!((old.status, old.body.len()), (200, 5000));
    let right = http_exact(
        server.http,
        format!("GET /fw.bin HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(right.body, pattern(5000));
    let seen = logged(&core, 18).await;
    // The 15 with another Host and the one without: refused, folded into this client's row.
    assert_eq!(seen.counts.refused, 16);
    assert_eq!((seen.refusal_rows, seen.refusals[0].times), (1, 16));
    assert_eq!(seen.counts.sent, 2);
    stop(&core, &server).await;
}

#[tokio::test]
async fn a_flood_of_bogus_requests_never_hides_a_transfer() {
    let tree = Tree::new();
    let core = core().await;
    let server = start(&core, spec(&tree.root)).await;
    assert_eq!(tftp_get(server.tftp, b"fw.bin", &[]).await.unwrap(), pattern(5000));
    // More bogus datagrams than the old log kept, from the same socket a spoofer would use.
    let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..700u32 {
        let packet = if i % 2 == 0 {
            request(1, b"../secret.txt", &[])
        } else {
            vec![0, 1, b'x']
        };
        flood.send_to(&packet, server.tftp).await.unwrap();
        if i % 20 == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    let seen = logged(&core, 551).await;
    assert!(seen
        .transfers
        .iter()
        .any(|r| r.path == "fw.bin" && r.outcome == Outcome::Sent && r.bytes == 5000));
    assert_eq!(seen.transfer_rows, 1);
    assert_eq!(seen.refusal_rows, 1, "one client's refusals are one row");
    assert!(seen.refusals[0].times >= 550);
    assert_eq!(stop(&core, &server).await, JobStatus::Succeeded);
    let output = core.store.job_targets(&core.ctx(), server.job).await.unwrap()[0]
        .output
        .clone()
        .unwrap();
    assert!(output.contains("TFTP read 127.0.0.1:"), "{output}");
    assert!(output.contains("fw.bin sent 5 KB"), "{output}");
    assert!(output.contains("127.0.0.1 TFTP:"), "{output}");
}

#[tokio::test]
async fn one_client_holds_neither_the_quota_nor_every_slot_and_explorer_files_never_arrive() {
    let tree = Tree::new();
    let uploads = tree.uploads();
    let core = core().await;
    core.file_server.runner().set_tuning(FileServerTuning {
        uploads: UploadLimits {
            per_client: 2,
            window: Duration::from_millis(600),
            min_bytes: 64 * 1024,
        },
        ..fast()
    });
    let server = start(&core, with_uploads(spec(&tree.root), &uploads, 2, 2)).await;
    let head = |name: &str, length: u64| {
        with_host(
            server.http,
            format!("PUT /{name} HTTP/1.1\r\nContent-Length: {length}\r\n\r\nx").as_bytes(),
        )
    };
    // Declares nearly all of the 2 MB, sends a byte: only that byte counts, so another upload fits beside it.
    let mut slow = TcpStream::connect(server.http).await.unwrap();
    slow.write_all(&head("big.bin", 2_000_000)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fits = put(server.http, "/fits.bin", &pattern(1_500_000)).await;
    assert_eq!(fits.status, 201, "{:?}", String::from_utf8_lossy(&fits.body));
    // Two under way from one address: a third is refused until one ends.
    let mut second = TcpStream::connect(server.http).await.unwrap();
    second.write_all(&head("second.bin", 10)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(put(server.http, "/third.bin", b"x").await.status, 429);
    // Under 64 KB in 600 ms: cut off at its next bytes, and its part deleted.
    tokio::time::sleep(Duration::from_millis(650)).await;
    slow.write_all(b"y").await.unwrap();
    let cut = parse_response(&read_all(&mut slow).await);
    assert_eq!(cut.status, 408, "{:?}", String::from_utf8_lossy(&cut.body));
    assert!(!uploads.join("big.bin").exists());
    drop(second);
    // Files Explorer acts on by itself (a .url's icon on a share would send the user's sign-in there).
    for name in ["readme.url", "Desktop.ini", "x.lnk", "lib.library-ms"] {
        assert_eq!(
            put(server.http, &format!("/{name}"), b"[x]").await.status,
            403,
            "{name}"
        );
        assert_eq!(
            tftp_put(server.tftp, name.as_bytes(), b"[x]", &[]).await.unwrap_err().0,
            2,
            "{name}"
        );
        assert!(!uploads.join(name).exists());
    }
    stop(&core, &server).await;
    assert!(uploads.join("fits.bin").exists());
    assert!(!uploads.join("second.bin").exists());
}
