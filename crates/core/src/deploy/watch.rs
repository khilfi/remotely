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
    /// The last line with words, for Ubuntu's hang check.
    last_text: String,
    /// Debian: the last step title the installer showed, for the hang check. Its dialogs go on drawing after the
    /// title (the frame, then the progress bar's numbers), so the last line is rarely the title itself.
    debian_step: Option<&'static str>,
    login_seen: bool,
    fingerprint: Option<String>,
    failed: bool,
    /// Windows: resets the hypervisor saw so far.
    resets: u32,
    /// Marks the current (unfinished) line already matched, so a prompt without a line break is reported once.
    partial_matched: bool,
    /// Windows: the resets of Setup's to see before the certificate's line counts (2; a sysprepped clone's 0).
    setup_resets: u32,
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

/// Debian's step titles on the serial console (S2), in the order the watcher tries them.
const DEBIAN_STEPS: [&str; 10] = [
    "Detecting disks and all other hardware",
    DEBIAN_PARTITIONER,
    "Partitions formatting",
    "Installing the base system",
    "Configuring apt",
    "Select and install software",
    "Installing GRUB boot loader",
    "Installing GRUB",
    "Finishing the installation",
    "Configuring the network with DHCP",
];

/// Where VirtualBox under Hyper-V hangs (S2: at 13 %, as the md and RAID modules load).
const DEBIAN_PARTITIONER: &str = "Starting up the partitioner";

/// `title` shown as a whole title: not the start of a longer name, such as the component `apt-cdrom-setup` the
/// installer configures as it loads ("Configuring apt-cdrom-setup"), or a package line ("Configuring apt (amd64)").
fn shows_title(text: &str, title: &str) -> bool {
    text.match_indices(title).any(|(at, _)| {
        let rest = &text[at + title.len()..];
        let next = rest.chars().next();
        let ends_word = next.is_none_or(|c| !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.'));
        ends_word && !rest.trim_start().starts_with('(')
    })
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
            debian_step: None,
            login_seen: false,
            fingerprint: None,
            failed: false,
            resets: 0,
            partial_matched: false,
            setup_resets: 2,
        }
    }

    /// VM-30: a clone of a sysprepped Windows image: no Setup from an ISO and no restarts to wait for before its
    /// certificate's line (its serial log is new, so nothing in it is older than this clone).
    pub fn sysprepped(mut self) -> Self {
        self.setup_resets = 0;
        self
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
        if self.os != Os::Windows || resets <= self.resets || self.setup_resets == 0 {
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
        if self.os == Os::Windows && self.setup_resets == 0 {
            self.advance(
                Stage::InstallerBooted,
                "the clone of a sysprepped image starts",
                &mut out,
            );
        } else if self.os == Os::Windows {
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
            Os::Debian if self.debian_step == Some(DEBIAN_PARTITIONER) => Some("starting the partitioner"),
            _ => None,
        }
    }

    /// `<hostname> login:` anywhere in the line: what the system logs to the console (cloud-init's last lines on
    /// Ubuntu, seen in PR 98's hand check) can be written onto the prompt's line right after it.
    fn is_login(&self, line: &str) -> bool {
        let line = line.trim().to_ascii_lowercase();
        !self.hostname.is_empty()
            && line.match_indices("login:").any(|(at, _)| {
                let rest = line[..at].trim_end();
                rest == self.hostname || rest.ends_with(&format!(" {}", self.hostname))
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
            // Also after a reset: the installer starts again.
            self.debian_step = None;
            self.advance(Stage::InstallerBooted, "the installer looks for its CD", out);
            return;
        }
        if let Some(step) = DEBIAN_STEPS.iter().find(|s| shows_title(text, s)) {
            self.debian_step = Some(*step);
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

    /// The installed system's certificate: the first is pinned; another one fails the install, since the VM's own
    /// serial port then says two things and neither can be trusted.
    fn take_fingerprint(&mut self, fingerprint: String, out: &mut Vec<WatchEvent>) {
        match &self.fingerprint {
            None => {
                self.fingerprint = Some(fingerprint.clone());
                self.advance(Stage::Rebooted, "Windows is up and WinRM is on", out);
                out.push(WatchEvent::Fingerprint(fingerprint));
            }
            Some(pinned) if *pinned == fingerprint => {}
            Some(pinned) => {
                let why = format!(
                    "The VM wrote two different WinRM certificates to its serial port ({pinned}, then {fingerprint}): Remotely trusts neither."
                );
                self.fail(why, out);
            }
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
            if !valid {
                return;
            }
            // Only after a round that counted Setup's second restart: the runner reads the log to its end before it
            // counts, so a line written before the restarts is read (and dropped) here first. The installed system
            // writes its line minutes after that restart, rounds seconds apart.
            if self.resets >= self.setup_resets {
                self.take_fingerprint(fingerprint.to_owned(), out);
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

    /// The hand check of PR 98: cloud-init's last lines went onto the console right after the getty's prompt, on the
    /// same line, within one read.
    #[test]
    fn a_login_prompt_with_the_consoles_next_lines_written_onto_it() {
        let mut w = SerialWatcher::new(Os::Ubuntu, "web-1");
        w.feed(b"Command line: BOOT_IMAGE=/casper/vmlinuz autoinstall ---\nstart: subiquity/Install/install: x\n");
        w.feed(b"reboot: Restarting system\nCommand line: BOOT_IMAGE=/vmlinuz-6.8.0-45-generic ro\n");
        let events = w.feed(
            b"\r\nUbuntu 24.04.5 LTS web-1 ttyS0\r\n\r\nweb-1 login: <14>Nov 13 23:59:26 cloud-init: ####\r\n\
              <14>Nov 13 23:59:26 cloud-init: -----END SSH HOST KEY FINGERPRINTS-----\r\n",
        );
        assert!(events.contains(&WatchEvent::LoginPrompt), "{events:?}");
        assert!(w.login_seen());
        // Another host's prompt isn't it.
        let mut other = SerialWatcher::new(Os::Ubuntu, "web-1");
        other.feed(b"start: subiquity/Install/install: x\n");
        assert!(other.feed(b"web-10 login: <14>Nov 13 cloud-init: x\r\n").is_empty());
        assert!(!other.login_seen());
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

    /// The hand check of PR 98: the partitioner's dialog goes on drawing after its title (the frame, "Please wait...",
    /// the progress bar's numbers), so the hang is told by the last title, not the last line.
    #[test]
    fn a_debian_hang_is_seen_behind_the_dialogs_frame_and_progress() {
        let mut w = SerialWatcher::new(Os::Debian, "db-1");
        let mut all = w.feed(b"\x1b[1;1H Detecting hardware to find installation media\x1b[K");
        // Loading the installer's components: their names aren't the "Configuring apt" step.
        all.extend(w.feed(b"\x1b[13;5H\x1b[30m\x1b[47mConfiguring apt-cdrom-setup   \x1b[26D\x1b[14;1H"));
        all.extend(w.feed(b"\x1b[13;5HConfiguring apt (amd64)\x1b[14;1H"));
        assert!(
            !all.iter()
                .any(|e| matches!(e, WatchEvent::Stage(_, d) | WatchEvent::Detail(d) if d.contains("apt"))),
            "{all:?}"
        );
        all.extend(w.feed(
            b"\x1b[10;20H\x1b(0lqqqu\x1b(B Starting up the partitioner \x1b(0tqqqk\x1b(B\x1b[11;20Hx\x1b[11;40H0%\
              \x1b[13;20H\x1b(0mqqqqj\x1b(B\x1b[15;30HPlease wait...\x1b[11;40H4\x1b[11;40H8\x1b[11;40H13",
        ));
        assert_eq!(w.hang_point(), Some("starting the partitioner"));
        // After a reset the installer starts again: no hang point until it reaches the partitioner again.
        w.feed(b"\x1b[2J\x1b[1;1H Detecting hardware to find installation media\x1b[K\x1b[2;1H");
        assert_eq!(w.hang_point(), None);
        w.feed(b"\x1b[10;20H Starting up the partitioner \x1b[11;40H4");
        assert_eq!(w.hang_point(), Some("starting the partitioner"));
        // The next step: no longer there.
        w.feed(b"\x1b[10;20H Installing the base system \x1b[11;40H2");
        assert_eq!(w.hang_point(), None);
        // The real "Configuring apt" step is still seen.
        let events = w.feed(b"\x1b[10;20H\x1b(0u\x1b(B Configuring apt \x1b(0t\x1b(B\x1b[11;40H1");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, WatchEvent::Detail(d) if d == "Configuring apt")),
            "{events:?}"
        );
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
    fn only_the_installed_systems_fingerprint_is_taken_and_a_second_one_fails() {
        let fp = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        let other = "SHA256:AAAAQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        let line = |f: &str| format!("{WINRM_FINGERPRINT_MARKER} {f}\r\n");
        // At power-on (windowsPE, a boot loader): ignored, and not taken later either.
        let mut w = SerialWatcher::new(Os::Windows, "win-1");
        assert!(w.feed(line(other).as_bytes()).is_empty());
        assert!(w.resets(1).iter().all(|e| !matches!(e, WatchEvent::Fingerprint(_))));
        assert!(w.feed(b"x\r\n").is_empty());
        assert!(w.resets(2).iter().all(|e| !matches!(e, WatchEvent::Fingerprint(_))));
        assert_eq!(w.fingerprint(), None);
        // Read in the round the second restart shows up in (read before the count): not taken either.
        let mut same_round = SerialWatcher::new(Os::Windows, "win-1");
        same_round.resets(1);
        assert!(same_round.feed(line(other).as_bytes()).is_empty());
        assert!(same_round
            .resets(2)
            .iter()
            .all(|e| !matches!(e, WatchEvent::Fingerprint(_))));
        assert_eq!(same_round.fingerprint(), None);
        // After it: taken; the same again is nothing; another one fails the install.
        let events = w.feed(line(fp).as_bytes());
        assert!(events.contains(&WatchEvent::Fingerprint(fp.into())), "{events:?}");
        assert!(w.feed(line(fp).as_bytes()).is_empty());
        let events = w.feed(line(other).as_bytes());
        assert!(
            matches!(&events[..], [WatchEvent::Failed(why)] if why.contains("two different WinRM certificates")),
            "{events:?}"
        );
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
