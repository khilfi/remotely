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
//! (the alternate screen; `q` quits), Ctrl+C drops the line. Commands Compare output can try: `hostname`, `uptime`,
//! `cat /etc/os-release` (the
//! last of 3 or more servers has another release, so the results show two groups), `seq <n>`,
//! `sleep <s>`, `exit <code>`, and any of them with sudo. Each server also serves an Ubuntu guest's
//! /proc files and `df`, with counters that move every 5 seconds, so watching it on the dashboard shows
//! moving charts. Nothing it prints is a real credential; it all goes away when it stops.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};
use remotely_core::metrics::procfs::samples;

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
            .with_banner("Remotely dev SSH server: a toy shell, not a real host.\n");
        serve_proc(&server, 0);
        println!(
            "Listening on 127.0.0.1:{}  host key ssh-ed25519 {}",
            server.port(),
            server.host_key_fingerprint()
        );
        servers.push(server);
    }
    println!("User:        alice");
    println!("Password:    {password} (sudo takes it too)");
    println!("Shell commands: whoami, echo <text>, exit [code], drop-connection, change-host-key");
    println!("  and for P5: sudo <command> (no echo), sleep <s> (prompt back after), work <s> (output, then quiet)");
    println!("  and for MultiExec: top (full screen, q quits), Ctrl+C drops the line");
    println!("Compare output commands: hostname, uptime, cat /etc/os-release, seq <n>, sleep <s>, exit <code>");
    println!("Guest metrics: watch a session on 127.0.0.1 on the dashboard; its counters move every 5 s");
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
