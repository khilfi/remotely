//! SSH servers on 127.0.0.1 for trying the terminal (SS-03, SS-05), MultiExec (SS-10), Compare output
//! (BX-02 to BX-07) and guest metrics (MO-02) without a real host:
//!
//! ```text
//! cargo run -p remotely-core --example dev_ssh_server --features fakes [port] [count]
//! ```
//!
//! It is the test suite's toy server (`fakes::ssh_server`): `count` servers (default 1) on ports from
//! `port` (default 2222) up, each with its own host key, user `alice` and one password made at start,
//! and sudo taking that same password. In the terminal's shell, `drop-connection` simulates a network
//! failure (the terminal reconnects) and `change-host-key` gives the next connection a new host key (the
//! terminal blocks it). For P5's helpers: `sudo <command>` asks for the password without echoing it
//! (try "Type vault password"), `sleep <s>` brings the prompt back after that long and `work <s>`
//! prints for that long, then goes quiet (QL-07 notifications). For MultiExec: `top` is a full-screen program
//! (the alternate screen; `q` quits), Ctrl+C drops the line. Commands MultiExec (QL-12 records them for Compare) and
//! Compare output can try: `hostname`, `uptime`,
//! `cat /etc/os-release` (the
//! last of 3 or more servers has another release, so the results show two groups), `seq <n>`,
//! `sleep <s>`, `exit <code>`, and any of them with sudo. Each server also serves an Ubuntu guest's
//! /proc files and `df`, with counters that move every 5 seconds, so watching it on the dashboard shows
//! moving charts. For file transfer (SS-08): SFTP serves a temp folder (printed at start, deleted when it
//! stops), with a few files in /home/alice and /srv/www; /etc, /root and /usr refuse uploads like folders
//! alice may not write to. The login shell counts as bash, so the terminal sets up its folder hook: `cd <dir>`
//! and `pwd` move the shell, and the "Files here" drawer follows. QL-09: /home/bob/.app is bob's alone, so
//! SFTP (as alice) can't open it while the shell can `cd` there: the drawer says why and still goes Back,
//! Up and Home. `su [-] [user]` starts a shell as that user (no password; root by default) without the
//! hook, as a real switch would, and the drawer says the shell may have switched; `exit` goes back.
//! Nothing it prints is a real credential; it all goes away when it stops.
//!
//! Jump hosts and tunnels (SS-07): every server reaches the others by the names `dev-host-01.test`,
//! `dev-host-02.test` and so on (any port), which this PC can't resolve, so a session to
//! `dev-host-02.test` needs server 1 as its jump host, and `dev-host-03.test` can go through
//! `dev-host-02.test` in turn: a two-hop chain. They also reach `web.test`, a small web page on the
//! port after the last server, for trying a local forward (`127.0.0.1:8080 -> web.test:80`, then
//! http://127.0.0.1:8080) or a SOCKS one (`curl --socks5-hostname 127.0.0.1:1080 http://web.test/`). A
//! remote forward listens on 127.0.0.1 of this PC (the servers run here), on the port it asks for.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::metrics::procfs::samples;

/// SS-08: a log file of a few hundred KB, so a download shows its progress.
fn dev_log() -> Vec<u8> {
    (0..8000)
        .map(|i| {
            format!(
                "2026-10-19T10:{:02}:{:02}Z info request {i} served in {} ms\n",
                i / 60 % 60,
                i % 60,
                i % 97
            )
        })
        .collect::<String>()
        .into_bytes()
}

/// SS-07: `web.test`, a page to reach through a tunnel. Answers any request with one page.
async fn serve_web(port: u16) -> Option<u16> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.ok()?;
    let port = listener.local_addr().ok()?.port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = socket.read(&mut request).await;
                let body = "<h1>Reached web.test through a Remotely tunnel</h1>\n";
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
    Some(port)
}

/// MO-02: the guest's /proc files as of `round`.
fn serve_proc(server: &TestSshServer, round: u64) {
    let s = samples::ubuntu(round);
    server.set_file("/proc/stat", &s.stat);
    server.set_file("/proc/meminfo", &s.meminfo);
    server.set_file("/proc/loadavg", &s.loadavg);
    server.set_file("/proc/uptime", &s.uptime);
    server.set_file("/proc/diskstats", &s.diskstats);
    server.set_file("/proc/net/dev", &s.netdev);
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(2222);
    let count: u16 = args.next().and_then(|c| c.parse().ok()).unwrap_or(1).clamp(1, 200);
    let password = format!("dev-{}", uuid::Uuid::new_v4().simple());
    let web = serve_web(port + count).await;
    let mut servers = Vec::new();
    for i in 0..count {
        let release = if count >= 3 && i == count - 1 { "24.04" } else { "22.04" };
        let server = TestSshServer::start_on(port + i)
            .await
            .with_password("alice", &password)
            .with_sudo(SudoMode::Password(password.clone()))
            .with_hostname(&format!("dev-host-{:02}", i + 1))
            .with_file(
                "/etc/os-release",
                &format!("NAME=\"Ubuntu\"\nVERSION_ID=\"{release}\"\n"),
            )
            .with_program("df", &samples::ubuntu(0).df)
            .with_banner("Remotely dev SSH server: a toy shell, not a real host.\n")
            // SS-08: a bash login (the folder hook), and files to download.
            .with_login_shell("bash")
            .with_sftp_file("/home/alice/notes.txt", b"Remotely dev server: a file to download.\n")
            .with_sftp_file("/home/alice/logs/app.log", &dev_log())
            .with_sftp_file("/srv/www/index.html", b"<h1>It works</h1>\n")
            // QL-09: another user's folder that alice can't open.
            .with_sftp_file("/home/bob/notes.txt", b"bob's notes\n")
            .with_unreadable("/home/bob/.app")
            .with_sftp_file("/home/bob/.app/app.ini", b"[app]\n");
        // SS-07: the other servers and the web page, by names only they resolve.
        let mut server = server;
        for other in 0..count {
            server = server.with_route(&format!("dev-host-{:02}.test", other + 1), port + other);
        }
        if let Some(web) = web {
            server = server.with_route("web.test", web);
        }
        serve_proc(&server, 0);
        println!(
            "Listening on 127.0.0.1:{}  host key ssh-ed25519 {}  SFTP folder {}",
            server.port(),
            server.host_key_fingerprint(),
            server.sftp_root().display()
        );
        servers.push(server);
    }
    println!("User:        alice");
    println!("Password:    {password} (sudo takes it too)");
    println!("Shell commands: whoami, echo <text>, exit [code], drop-connection, change-host-key");
    println!("  and for P5: sudo <command> (no echo), sleep <s> (prompt back after), work <s> (output, then quiet)");
    println!("  and for MultiExec: top (full screen, q quits), Ctrl+C drops the line");
    println!("MultiExec and Compare output commands: hostname, uptime, cat /etc/os-release, seq <n>, sleep <s>");
    println!("Files: cd <dir> and pwd move the shell (the drawer follows); /etc refuses uploads");
    println!("  and for QL-09: cd /home/bob/.app (alice can't open it over SFTP); su [-] [user] switches user");
    println!("Guest metrics: watch a session on 127.0.0.1 on the dashboard; its counters move every 5 s");
    if count >= 2 {
        println!(
            "Jump hosts: a session to dev-host-02.test (port 22) with 127.0.0.1:{port} as its jump host{}",
            if count >= 3 {
                "; dev-host-03.test through that one makes two hops"
            } else {
                ""
            }
        );
    }
    if let Some(web) = web {
        println!("Tunnels: web.test:80 is the page on 127.0.0.1:{web}, reached from the servers by that name");
    }
    println!("Stop with Ctrl+C.");
    // Runs until the process is stopped; the servers go with it.
    let servers = Arc::new(servers);
    let mut round = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        round += 1;
        for server in servers.iter() {
            serve_proc(server, round);
        }
    }
}
