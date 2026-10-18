//! An SSH server on 127.0.0.1 for trying the terminal (SS-03, SS-05) without a real host:
//!
//! ```text
//! cargo run -p remotely-core --example dev_ssh_server --features fakes [port]
//! ```
//!
//! It is the test suite's toy server (`fakes::ssh_server`): a host key and a password made at start,
//! user `alice`, and a shell that echoes. In the shell, `drop-connection` simulates a network failure
//! (the terminal reconnects) and `change-host-key` gives the next connection a new host key (the
//! terminal blocks it). Nothing it prints is a real credential; it all goes away when it stops.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use remotely_core::fakes::ssh_server::TestSshServer;

#[tokio::main]
async fn main() {
    let port = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(2222);
    let password = format!("dev-{}", uuid::Uuid::new_v4().simple());
    let server = TestSshServer::start_on(port)
        .await
        .with_password("alice", &password)
        .with_banner("Remotely dev SSH server: a toy shell, not a real host.\n");
    println!("Listening on 127.0.0.1:{}", server.port());
    println!("User:        alice");
    println!("Password:    {password}");
    println!("Host key:    ssh-ed25519 {}", server.host_key_fingerprint());
    println!("Shell commands: whoami, echo <text>, exit [code], drop-connection, change-host-key");
    println!("Stop with Ctrl+C.");
    // Runs until the process is stopped; the server goes with it.
    std::future::pending::<()>().await;
    drop(server);
}
