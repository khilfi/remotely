//! VM-29: the install watcher's reading of a VM's serial log, pure so it is tested on the lines S1 to S3 saw
//! (CLAUDE.md, "Unattended installs"). The runner ([`super::install`]) feeds it what the serial file grew by and the
//! hypervisor's signals (Windows' resets); it says which stage the install is at, what it is doing, and when it failed.
//!
//! * Escapes go first: the kernel and Subiquity write plain lines, but Debian's installer runs inside GNU screen and
//!   newt (cursor moves, colours, line drawing) and VirtualBox's UEFI firmware echoes its own console.
//! * Ubuntu: `Command line: BOOT_IMAGE=/casper/...` (the installer booted), `start: subiquity/...` (installing),
//!   `reboot: Restarting system` then the installed kernel's `Command line:` (rebooted), `<hostname> login:`. A failure
//!   is `install_fail` or `An error occurred`; `Continue with autoinstall?` means the boot menu lacks `autoinstall`.
//! * Debian: `Detecting hardware to find installation media`, then each step's title; `reboot: Restarting system`
//!   then GRUB; `<hostname> login:`. Any `[!!] ` title is a question at priority=critical: the install waits for a
//!   key no one will press, so it counts as failed.
//! * Windows writes nothing by itself: the answer file's `remotely-stage <stage>` lines and the
//!   `remotely-winrm SHA256:...` line with its WinRM certificate's fingerprint; the resets come from the hypervisor.

use crate::catalog::install::unattend::{STAGE_MARKER, WINRM_FINGERPRINT_MARKER};

/// The longest line kept; the rest of a longer one is dropped.
const MAX_LINE: usize = 4096;
/// The longest detail shown for a stage.
const MAX_DETAIL: usize = 120;

/// Which installer writes the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Ubuntu,
    Debian,
    Windows,
}

/// Where an install is, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Powered on, nothing read yet.
    Starting,
    InstallerBooted,
    Installing,
    Rebooted,
    /// The installed system answers: Remotely signs in (SSH's banner, or WinRM over HTTPS).
    SigningIn,
    Done,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Stage::Starting => "starting",
            Stage::InstallerBooted => "installer booted",
            Stage::Installing => "installing",
            Stage::Rebooted => "rebooted",
            Stage::SigningIn => "first sign-in",
            Stage::Done => "done",
        }
    }

    /// For the job's progress bar.
    pub fn percent(self) -> f64 {
        match self {
            Stage::Starting => 2.0,
            Stage::InstallerBooted => 10.0,
            Stage::Installing => 30.0,
            Stage::Rebooted => 80.0,
            Stage::SigningIn => 90.0,
            Stage::Done => 100.0,
        }
    }
}

/// What a read of the log found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchEvent {
    /// A later stage, with what it is doing.
    Stage(Stage, String),
    /// What the install does now, within its stage.
    Detail(String),
    /// The installed system's login prompt for this VM's hostname.
    LoginPrompt,
    /// Windows: the WinRM certificate's fingerprint (`SHA256:<base64>`), as the VM wrote it.
    Fingerprint(String),
    /// The install stopped and won't go on by itself.
    Failed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    Esc,
    Csi,
    Osc,
    OscEsc,
    Charset,
}

/// The serial log's reader for one VM.
#[derive(Debug)]
pub struct SerialWatcher {
    os: Os,
    hostname: String,
    stage: Stage,
    escape: Escape,
    params: Vec<u8>,
    line: Vec<u8>,
    /// The installer said it restarts (Linux), so the next kernel is the installed one.
    restarting: bool,
    /// The last line with words, for the hang check.
    last_text: String,
    login_seen: bool,
    fingerprint: Option<String>,
    failed: bool,
    /// Windows: resets the hypervisor saw so far.
    resets: u32,
    /// Marks the current (unfinished) line already matched, so a prompt without a line break is reported once.
    partial_matched: bool,
}

/// Text with escapes and controls taken out, as a person reading the console would see its words.
pub fn strip_escapes(bytes: &[u8]) -> String {
    let mut w = SerialWatcher::new(Os::Ubuntu, "");
    let mut out = String::new();
    let mut previous = 0u8;
    for &b in bytes {
        // CR LF is one line break.
        let crlf = b == b'\n' && previous == b'\r';
        previous = b;
        if crlf {
            continue;
        }
        if let Some(c) = w.byte(b) {
            if c == b'\n' {
                out.push_str(&String::from_utf8_lossy(&std::mem::take(&mut w.line)));
                out.push('\n');
            }
        }
    }
    out.push_str(&String::from_utf8_lossy(&w.line));
    out
}

fn cut(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// GNU screen and newt draw frames with the line-drawing set, which reads as stray letters around a title.
fn title(text: &str) -> String {
    let mut words: Vec<&str> = text.split_whitespace().collect();
    let frame = |w: &str| w.chars().count() == 1 && (!w.chars().all(char::is_alphanumeric) || "qxtujklmn".contains(w));
    while words.last().is_some_and(|w| frame(w)) {
        words.pop();
    }
    let joined = words.join(" ");
    // A title ends where the frame's blank run starts.
    cut(joined.split("  ").next().unwrap_or(&joined), 80)
}

impl SerialWatcher {
    pub fn new(os: Os, hostname: &str) -> Self {
        Self {
            os,
            hostname: hostname.to_ascii_lowercase(),
            stage: Stage::Starting,
            escape: Escape::None,
            params: Vec::new(),
            line: Vec::new(),
            restarting: false,
            last_text: String::new(),
            login_seen: false,
            fingerprint: None,
            failed: false,
            resets: 0,
            partial_matched: false,
        }
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    pub fn login_seen(&self) -> bool {
        self.login_seen
    }

    /// One byte through the escape filter: `Some(b'\n')` ends a line, other text goes into the line.
    fn byte(&mut self, b: u8) -> Option<u8> {
        match self.escape {
            Escape::Esc => {
                self.escape = match b {
                    b'[' => {
                        self.params.clear();
                        Escape::Csi
                    }
                    b']' => Escape::Osc,
                    b'(' | b')' | b'*' | b'+' | b'#' | b'%' => Escape::Charset,
                    _ => Escape::None,
                };
                None
            }
            Escape::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    self.escape = Escape::None;
                    let n: usize = std::str::from_utf8(&self.params)
                        .ok()
                        .and_then(|p| p.split(';').next())
                        .and_then(|p| p.trim_start_matches('?').parse().ok())
                        .unwrap_or(1);
                    match b {
                        // Cursor forward: spaces, as screen writes them.
                        b'C' => {
                            for _ in 0..n.min(16) {
                                self.push(b' ');
                            }
                            None
                        }
                        // A move to another row: a new line of text.
                        b'H' | b'f' | b'd' | b'A' | b'B' | b'E' | b'F' => Some(b'\n'),
                        _ => None,
                    }
                } else {
                    if self.params.len() < 32 {
                        self.params.push(b);
                    }
                    None
                }
            }
            Escape::Osc => {
                match b {
                    0x07 => self.escape = Escape::None,
                    0x1b => self.escape = Escape::OscEsc,
                    _ => {}
                }
                None
            }
            Escape::OscEsc => {
                self.escape = if b == b'\\' { Escape::None } else { Escape::Osc };
                None
            }
            Escape::Charset => {
                self.escape = Escape::None;
                None
            }
            Escape::None => match b {
                0x1b => {
                    self.escape = Escape::Esc;
                    None
                }
                b'\n' | b'\r' => Some(b'\n'),
                b'\t' => {
                    self.push(b' ');
                    None
                }
                0x00..=0x1f | 0x7f => None,
                _ => {
                    self.push(b);
                    None
                }
            },
        }
    }

    fn push(&mut self, b: u8) {
        if self.line.len() < MAX_LINE {
            self.line.push(b);
        }
    }

    /// What `bytes` (the log's next bytes) says.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<WatchEvent> {
        let mut out = Vec::new();
        for &b in bytes {
            if self.byte(b) == Some(b'\n') {
                let line = String::from_utf8_lossy(&std::mem::take(&mut self.line)).into_owned();
                if !self.partial_matched {
                    self.line_events(&line, &mut out);
                }
                self.partial_matched = false;
            }
        }
        // A prompt waits without a line break: the line so far, once.
        if !self.line.is_empty() && !self.partial_matched {
            let line = String::from_utf8_lossy(&self.line).into_owned();
            let before = out.len();
            self.prompt_events(&line, &mut out);
            if out.len() > before {
                self.partial_matched = true;
            }
        }
        out
    }

    /// Windows: the hypervisor saw `resets` resets of the guest since power-on (Setup restarts twice).
    pub fn resets(&mut self, resets: u32) -> Vec<WatchEvent> {
        let mut out = Vec::new();
        if self.os != Os::Windows || resets <= self.resets {
            return out;
        }
        self.resets = resets;
        if resets >= 2 {
            self.advance(Stage::Rebooted, "Windows starts for the first time", &mut out);
        } else {
            self.advance(
                Stage::Installing,
                "the image is applied; Windows sets up its devices",
                &mut out,
            );
        }
        out
    }

    /// Windows: the VM is on and Setup runs from the ISO (nothing of windowsPE reaches the serial port).
    pub fn started(&mut self) -> Vec<WatchEvent> {
        let mut out = Vec::new();
        if self.os == Os::Windows {
            self.advance(Stage::InstallerBooted, "Setup runs from the ISO", &mut out);
        }
        out
    }

    /// Remotely signs in to the installed system now.
    pub fn signing_in(&mut self, detail: &str) -> Vec<WatchEvent> {
        let mut out = Vec::new();
        self.advance(Stage::SigningIn, detail, &mut out);
        out
    }

    pub fn done(&mut self, detail: &str) -> Vec<WatchEvent> {
        let mut out = Vec::new();
        self.advance(Stage::Done, detail, &mut out);
        out
    }

    fn advance(&mut self, stage: Stage, detail: &str, out: &mut Vec<WatchEvent>) {
        if stage > self.stage {
            self.stage = stage;
            out.push(WatchEvent::Stage(stage, cut(detail, MAX_DETAIL)));
        }
    }

    fn fail(&mut self, why: String, out: &mut Vec<WatchEvent>) {
        if !self.failed {
            self.failed = true;
            out.push(WatchEvent::Failed(why));
        }
    }

    /// The point VirtualBox under Hyper-V hangs at (S1, S2), when the last words are there: a long silence then
    /// means a hang, which a reset gets past.
    pub fn hang_point(&self) -> Option<&'static str> {
        let last = self.last_text.as_str();
        match self.os {
            Os::Ubuntu
                if last.contains("Loading essential drivers")
                    || last.starts_with("raid6:")
                    || last.contains(" raid6: ") =>
            {
                Some("the initramfs's RAID6 benchmark")
            }
            Os::Debian if last.contains("Starting up the partitioner") => Some("starting the partitioner"),
            _ => None,
        }
    }

    fn is_login(&self, line: &str) -> bool {
        let line = line.trim().to_ascii_lowercase();
        !self.hostname.is_empty()
            && line.strip_suffix("login:").is_some_and(|rest| {
                rest.trim_end() == self.hostname || rest.trim_end().ends_with(&format!(" {}", self.hostname))
            })
    }

    /// What an unfinished line says: prompts that wait for input.
    fn prompt_events(&mut self, line: &str, out: &mut Vec<WatchEvent>) {
        if self.is_login(line) && self.stage >= Stage::Installing && !self.login_seen {
            self.login_seen = true;
            self.advance(Stage::Rebooted, "the installed system is up", out);
            out.push(WatchEvent::LoginPrompt);
            return;
        }
        match self.os {
            Os::Ubuntu if line.contains("Continue with autoinstall?") => self.fail(
                "The installer asks whether to go on (\"Continue with autoinstall?\"): its boot menu lacks 'autoinstall'."
                    .into(),
                out,
            ),
            Os::Ubuntu if line.contains("An error occurred. Press enter to start a shell") => {
                self.fail("The installer failed and waits at its error prompt.".into(), out)
            }
            Os::Debian if line.contains("[!!] ") => self.debian_question(line, out),
            _ => {}
        }
    }

    fn debian_question(&mut self, line: &str, out: &mut Vec<WatchEvent>) {
        let after = line.split("[!!] ").nth(1).unwrap_or_default();
        self.fail(
            format!(
                "The installer stopped to ask \"{}\": the preseed doesn't answer it.",
                title(after)
            ),
            out,
        );
    }

    fn line_events(&mut self, line: &str, out: &mut Vec<WatchEvent>) {
        let text = line.trim();
        if text.is_empty() {
            return;
        }
        self.last_text = cut(text, 200);
        if self.is_login(text) && self.stage >= Stage::Installing {
            if !self.login_seen {
                self.login_seen = true;
                self.advance(Stage::Rebooted, "the installed system is up", out);
                out.push(WatchEvent::LoginPrompt);
            }
            return;
        }
        match self.os {
            Os::Ubuntu => self.ubuntu(text, out),
            Os::Debian => self.debian(text, out),
            Os::Windows => self.windows(text, out),
        }
    }

    fn ubuntu(&mut self, text: &str, out: &mut Vec<WatchEvent>) {
        if let Some(rest) = text.split("Command line: BOOT_IMAGE=").nth(1) {
            if rest.starts_with("/casper/") {
                if self.stage < Stage::Installing {
                    self.advance(Stage::InstallerBooted, "the installer's kernel started", out);
                }
            } else if self.stage >= Stage::Installing {
                self.advance(Stage::Rebooted, "the installed system starts", out);
            }
            return;
        }
        if text.contains("install_fail") {
            self.fail(
                "The installer reported a failed install (its crash report is under /var/crash in the installer)."
                    .into(),
                out,
            );
            return;
        }
        if text.contains("An error occurred. Press enter to start a shell")
            || text.contains("Continue with autoinstall?")
        {
            self.prompt_events(text, out);
            return;
        }
        if text.contains("reboot: Restarting system") && self.stage >= Stage::Installing {
            self.restarting = true;
            out.push(WatchEvent::Detail("the installer restarts the VM".into()));
            return;
        }
        if let Some(step) = text.split("start: subiquity/").nth(1) {
            let step = step.trim();
            if self.stage < Stage::Installing {
                self.advance(Stage::Installing, step, out);
            } else if self.stage == Stage::Installing {
                out.push(WatchEvent::Detail(cut(step, MAX_DETAIL)));
            }
        }
    }

    fn debian(&mut self, text: &str, out: &mut Vec<WatchEvent>) {
        if text.contains("[!!] ") {
            self.debian_question(text, out);
            return;
        }
        if text.contains("Detecting hardware to find installation media") {
            self.advance(Stage::InstallerBooted, "the installer looks for its CD", out);
            return;
        }
        const STEPS: [&str; 10] = [
            "Detecting disks and all other hardware",
            "Starting up the partitioner",
            "Partitions formatting",
            "Installing the base system",
            "Configuring apt",
            "Select and install software",
            "Installing GRUB boot loader",
            "Installing GRUB",
            "Finishing the installation",
            "Configuring the network with DHCP",
        ];
        if let Some(step) = STEPS.iter().find(|s| text.contains(**s)) {
            if self.stage < Stage::Installing {
                self.advance(Stage::Installing, step, out);
            } else if self.stage == Stage::Installing {
                out.push(WatchEvent::Detail((*step).to_owned()));
            }
            return;
        }
        if text.contains("reboot: Restarting system") && self.stage >= Stage::Installing {
            self.restarting = true;
            out.push(WatchEvent::Detail("the installer restarts the VM".into()));
            return;
        }
        if self.restarting
            && (text.contains("GNU GRUB") || text.contains("Booting `Debian") || text.contains("Debian GNU/Linux"))
        {
            self.advance(Stage::Rebooted, "the installed system starts", out);
        }
    }

    fn windows(&mut self, text: &str, out: &mut Vec<WatchEvent>) {
        if let Some(rest) = text.split(WINRM_FINGERPRINT_MARKER).nth(1) {
            let fingerprint = rest.split_whitespace().next().unwrap_or_default();
            let digest = fingerprint.strip_prefix("SHA256:").unwrap_or_default();
            let valid = digest.len() == 43
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
            if valid && self.fingerprint.is_none() {
                self.fingerprint = Some(fingerprint.to_owned());
                self.advance(Stage::Rebooted, "Windows is up and WinRM is on", out);
                out.push(WatchEvent::Fingerprint(fingerprint.to_owned()));
            }
            return;
        }
        if let Some(rest) = text.split(STAGE_MARKER).nth(1) {
            let stage = rest.split_whitespace().next().unwrap_or_default();
            match stage {
                "specialize" => self.advance(Stage::Installing, "Windows applies its settings (specialize)", out),
                other if !other.is_empty() => out.push(WatchEvent::Detail(format!("Windows: {}", cut(other, 40)))),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn stages(events: &[WatchEvent]) -> Vec<Stage> {
        events
            .iter()
            .filter_map(|e| match e {
                WatchEvent::Stage(s, _) => Some(*s),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn escapes_and_controls_go() {
        assert_eq!(
            strip_escapes(b"\x1b[31mInstalling\x1b[1Cthe base system\x1b[0m\r\n"),
            "Installing the base system\n"
        );
        assert_eq!(strip_escapes(b"\x1b(0qqq\x1b(B ok\x1b]0;title\x07!"), "qqq ok!");
        assert_eq!(strip_escapes(b"a\x1b[5;10Hb"), "a\nb");
        assert_eq!(strip_escapes(b"x\x00\x08y\tz"), "xy z");
    }

    #[test]
    fn an_ubuntu_install_goes_through_its_stages() {
        let mut w = SerialWatcher::new(Os::Ubuntu, "web-1");
        let mut all = Vec::new();
        for chunk in [
            &b"[    0.000000] Command line: BOOT_IMAGE=/casper/vmlinuz autoinstall console=tty0 console=ttyS0,115200n8 --- console=tty0\r\n"[..],
            b"Begin: Loading essential drivers ... raid6: avx2x4 gen() 1000 MB/s\r\n",
            b"start: subiquity/Early/apply_autoinstall_config: \r\nstart: subiquity/Install/install/postinstall/run_unattended_upgrades: downloading and installing security updates\r\n",
            b"start: subiquity/Shutdown/shutdown: mode=REBOOT\r\n[  400.1] reboot: Restarting system\r\n",
            b"[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-6.8.0-45-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro\r\n",
            b"\r\nweb-1 login: ",
        ] {
            all.extend(w.feed(chunk));
        }
        assert_eq!(
            stages(&all),
            [Stage::InstallerBooted, Stage::Installing, Stage::Rebooted],
            "{all:?}"
        );
        assert!(all.contains(&WatchEvent::LoginPrompt));
        assert!(w.login_seen());
        assert!(all
            .iter()
            .any(|e| matches!(e, WatchEvent::Detail(d) if d.contains("run_unattended_upgrades"))));
        // The prompt is reported once, however the next reads end.
        assert!(w.feed(b"").is_empty());
        assert!(w.feed(b"\r\n").is_empty());
    }

    #[test]
    fn ubuntu_failures_and_the_hang_point() {
        let mut w = SerialWatcher::new(Os::Ubuntu, "web-1");
        w.feed(b"Command line: BOOT_IMAGE=/casper/vmlinuz autoinstall ---\nBegin: Loading essential drivers ... ");
        w.feed(b"\n");
        assert_eq!(w.hang_point(), Some("the initramfs's RAID6 benchmark"));
        let events = w.feed(b"start:  subiquity/ErrorReporter/1731500000.123.install_fail/add_info:\n");
        assert!(
            matches!(&events[..], [WatchEvent::Failed(why)] if why.contains("failed install")),
            "{events:?}"
        );
        let mut asks = SerialWatcher::new(Os::Ubuntu, "web-1");
        let events = asks.feed(b"Continue with autoinstall? (yes|no) ");
        assert!(
            matches!(&events[..], [WatchEvent::Failed(why)] if why.contains("lacks 'autoinstall'")),
            "{events:?}"
        );
        // The live installer's own login prompt isn't the VM's.
        let mut live = SerialWatcher::new(Os::Ubuntu, "web-1");
        assert!(live.feed(b"ubuntu-server login: ").is_empty());
    }

    #[test]
    fn a_debian_install_through_gnu_screen() {
        let mut w = SerialWatcher::new(Os::Debian, "db-1");
        let mut all = Vec::new();
        all.extend(
            w.feed(b"\x1b[H\x1b[2J\x1b[1;1H\x1b(0lqqqq\x1b(B Detecting hardware to find installation media\x1b[K"),
        );
        all.extend(w.feed(b"\x1b[5;3H\x1b[31mInstalling the base system\x1b[0m\x1b[6;3HStarting up the partitioner"));
        all.extend(w.feed(b"\x1b[7;1H"));
        assert_eq!(w.hang_point(), Some("starting the partitioner"));
        all.extend(w.feed(b"\r\nreboot: Restarting system\r\n\x1b[2J GNU GRUB  version 2.12-9+deb13u2\r\n"));
        all.extend(w.feed(b"Debian GNU/Linux 13 db-1 ttyS0\r\n\r\ndb-1 login: "));
        assert_eq!(
            stages(&all),
            [Stage::InstallerBooted, Stage::Installing, Stage::Rebooted],
            "{all:?}"
        );
        assert!(all.contains(&WatchEvent::LoginPrompt));
    }

    #[test]
    fn a_debian_question_fails_the_install() {
        let mut w = SerialWatcher::new(Os::Debian, "db-1");
        let events = w.feed(b"\x1b[3;10H\x1b(0u\x1b(B\x1b[31m [!!] Partition disks \x1b[0m\x1b(0t\x1b(B\x1b[4;1H");
        assert!(
            matches!(&events[..], [WatchEvent::Failed(why)] if why.contains("\"Partition disks\"")),
            "{events:?}"
        );
        // Once only.
        assert!(w.feed(b"\x1b[3;10H [!!] Partition disks\r\n").is_empty());
    }

    #[test]
    fn windows_stages_come_from_resets_and_com1() {
        let mut w = SerialWatcher::new(Os::Windows, "win-1");
        assert_eq!(stages(&w.started()), [Stage::InstallerBooted]);
        assert_eq!(stages(&w.resets(1)), [Stage::Installing]);
        assert!(stages(&w.feed(b"remotely-stage specialize 10:01:02.03 \r\n")).is_empty());
        assert_eq!(stages(&w.resets(2)), [Stage::Rebooted]);
        assert!(w.resets(2).is_empty(), "the same count says nothing new");
        let fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        let events = w.feed(format!("\x1b[0m{WINRM_FINGERPRINT_MARKER} {fp}\r\n").as_bytes());
        assert!(events.contains(&WatchEvent::Fingerprint(fp.into())), "{events:?}");
        assert_eq!(w.fingerprint(), Some(fp));
        // A damaged fingerprint is never taken.
        let mut bad = SerialWatcher::new(Os::Windows, "win-1");
        assert!(bad.feed(b"remotely-winrm SHA256:not-base64!\r\n").is_empty());
        assert_eq!(bad.fingerprint(), None);
        assert_eq!(stages(&w.signing_in("signing in")), [Stage::SigningIn]);
        assert_eq!(stages(&w.done("done")), [Stage::Done]);
    }

    #[test]
    fn hostile_logs_never_panic_and_lines_stay_bounded() {
        let mut w = SerialWatcher::new(Os::Debian, "x");
        let mut seed = 7u32;
        let mut bytes = Vec::new();
        for _ in 0..200_000 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((seed >> 16) as u8);
        }
        w.feed(&bytes);
        w.feed(&[0x1b, b'[']);
        w.feed(&vec![b'9'; 100_000]);
        assert!(w.line.len() <= MAX_LINE);
        assert!(w.params.len() <= 32);
        let long = vec![b'a'; 3 * MAX_LINE];
        let mut u = SerialWatcher::new(Os::Ubuntu, "x");
        u.feed(&long);
        assert!(u.line.len() <= MAX_LINE);
    }
}
