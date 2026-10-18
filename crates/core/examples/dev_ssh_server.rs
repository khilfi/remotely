//! SSH servers on 127.0.0.1 for trying the terminal (SS-03, SS-05) and bulk runs (BX-02 to BX-07)
//! without a real host:
//!
//! ```text
//! cargo run -p remotely-core --example dev_ssh_server --features fakes [port] [count]
//! ```
//!
//! It is the test suite's toy server (`fakes::ssh_server`): `count` servers (default 1) on ports from
//! `port` (default 2222) up, each with its own host key, user `alice` and one password made at start,
//! and sudo taking that same password. In the terminal's shell, `drop-connection` simulates a network
//! failure (the terminal reconnects) and `change-host-key` gives the next connection a new host key (the
//! terminal blocks it). Commands a bulk run can try: `hostname`, `uptime`, `cat /etc/os-release` (the
//! last of 3 or more servers has another release, so the results show two groups), `seq <n>`,
//! `sleep <s>`, `exit <code>`, and any of them with sudo. Nothing it prints is a real credential; it
//! all goes away when it stops.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use remotely_core::fakes::ssh_server::{SudoMode, TestSshServer};

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
            .with_banner("Remotely dev SSH server: a toy shell, not a real host.\n");
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
    println!("Bulk run commands: hostname, uptime, cat /etc/os-release, seq <n>, sleep <s>, exit <code>");
    println!("Stop with Ctrl+C.");
    // Runs until the process is stopped; the servers go with it.
    std::future::pending::<()>().await;
    drop(servers);
}
