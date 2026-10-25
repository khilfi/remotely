//! What a terminal is doing, read from its own traffic: the line the cursor is on (QL-06 checks it
//! shows a password prompt before typing a vault password; SS-10 MultiExec passes keys typed at a password
//! or one-time code prompt straight through, never rated or journaled), whether a full-screen program is open
//! (SS-10 MultiExec passes keys straight to it), and whether a command is running and has finished
//! (QL-07 notifies when one in a background tab ends after a long run).
//!
//! * [`ScreenLine`] follows the output well enough to know the line the cursor is on: escapes are
//!   dropped, a carriage return starts the line over, backspace takes a character back. A full-screen
//!   program switches to xterm's alternate screen buffer (`CSI ? 1049 h`, or the older 47 and 1047)
//!   and back (`l`), which it notes.
//! * [`RunWatch`]: Enter starts a run (remembering the line it was pressed on, which starts with the
//!   prompt). The run ends when a prompt comes back: the same prompt as before (that line starts with
//!   it), or a line that looks like a shell prompt. Or it ends when the output stops for a while after
//!   some came: the command finished but its prompt was not recognized, or it waits for an answer. A
//!   run that lasted at least the threshold reports [`Finished`]; shorter ones end quietly.
//!
//! Only the shape of the output is looked at; nothing is kept but the current line, and nothing is
//! logged.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Serialize;

/// The cursor's line is kept to this many characters (its end), enough for any prompt.
const MAX_LINE_CHARS: usize = 512;

// Constant patterns, compiled by the tests: `expect` cannot fire on input here.
//
// A password prompt names a password, passphrase or PIN, then ends with a colon (ASCII or full-width, as
// Chinese and Japanese prompts do) where the cursor waits: sudo, su, ssh, a key's passphrase, openssl's "pass
// phrase", PAM, databases and CLIs, in English and the languages Linux distributions translate sudo, su and PAM
// into. Up to 200 characters may stand between the word and the colon (a key's path, `'alice@example.com'`).
#[allow(clippy::expect_used)]
static PASSWORD_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:password|passphrase|pass phrase|passcode|\bpin\b|",
        // German, French, Spanish, Portuguese, Italian, Dutch, Swedish, Danish and Norwegian, Finnish
        r"passwort|kennwort|mot de passe|phrase secrète|contraseña|\bclave\b|senha|parola d'ordine|wachtwoord|",
        r"lösenord|adgangskode|passord|salasana|",
        // Polish, Czech and Slovak, Hungarian, Romanian, Turkish, Russian and Ukrainian, Greek
        r"hasło|heslo|jelsz[óa]|parolă|\bparola\b|şifre|şifresi|пароль|κωδικός|",
        // Japanese, Chinese, Korean, Vietnamese, Indonesian and Malay, Hebrew, Arabic
        r"パスワード|暗証番号|密码|密碼|口令|암호|비밀번호|mật khẩu|kata sandi|kata laluan|סיסמה|كلمة المرور|كلمة السر)",
        r"[^\n]{0,200}[:：]\s*$"
    ))
    .expect("valid password prompt regex")
});
/// A one-time code prompt: two-factor PAM modules (Google Authenticator's "Verification code:", Duo's "Passcode
/// or option", RSA SecurID's "PASSCODE:"), a cloud CLI's MFA code, an OTP or token. What is typed there doesn't
/// echo either, and is a secret for a while. The words must come shortly before the colon.
#[allow(clippy::expect_used)]
static CODE_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(?:\b(?:otp|totp|hotp|mfa|2fa|two[- ]factor|one[- ]time|token|verification|authenticator|",
        r"authentication code|security code|sms code|auth code|\d-digit code|enter (?:the |your )?code)\b|",
        // German, French, Spanish and Portuguese, Italian, Dutch
        r"bestätigungscode|code de vérification|c[oó]digo de verifica|codice di verifica|verificatiecode)",
        r"[^\n]{0,80}[:：]\s*$"
    ))
    .expect("valid code prompt regex")
});
/// A shell prompt: `alice@web01:~$ `, `[root@web01 ~]# `, `PS C:\> `, or just `$ `. `%` only alone, so a
/// progress counter (`45% `) is not taken for zsh's prompt.
#[allow(clippy::expect_used)]
static SHELL_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:\S.{0,160}[$#>❯] |[$#%>❯] ?)$").expect("valid shell prompt regex"));

/// QL-06: the line asks for a password or passphrase (sudo, su, ssh, a key, a PIN), so a vault password may
/// be typed there.
pub fn is_password_prompt(line: &str) -> bool {
    PASSWORD_PROMPT.is_match(line)
}

/// SS-10: the line asks for a secret: a password prompt, or a one-time code or token. MultiExec passes keys
/// typed there straight through (never rated, journaled or audited), a run is not over while one shows (QL-07,
/// QL-12), and it is never a shell prompt.
pub fn is_secret_prompt(line: &str) -> bool {
    is_password_prompt(line) || CODE_PROMPT.is_match(line)
}

/// QL-07: the line looks like a shell waiting for a command.
pub fn is_shell_prompt(line: &str) -> bool {
    !is_secret_prompt(line) && SHELL_PROMPT.is_match(line)
}

/// Where the line follower is in an escape sequence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    Started,
    Csi,
    /// OSC, DCS and the like: until BEL or `ESC \`.
    String,
    StringEsc,
}

/// The longest control sequence parameters kept: enough for any private mode.
const MAX_CSI_CHARS: usize = 32;

/// The line the cursor is on, as far as plain output shows it.
pub struct ScreenLine {
    line: String,
    escape: Escape,
    /// The parameters of the control sequence being read.
    csi: String,
    carriage_return: bool,
    /// Bytes of a character split across two reads.
    partial: Vec<u8>,
    /// SS-10: the alternate screen buffer is in use (a full-screen program).
    alternate: bool,
}

impl Default for ScreenLine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenLine {
    pub fn new() -> Self {
        Self {
            line: String::new(),
            escape: Escape::None,
            csi: String::new(),
            carriage_return: false,
            partial: Vec::new(),
            alternate: false,
        }
    }

    pub fn line(&self) -> &str {
        &self.line
    }

    /// SS-10: a full-screen program is open.
    pub fn alternate(&self) -> bool {
        self.alternate
    }

    /// `CSI ? Pm h` / `CSI ? Pm l`: the private modes that switch to the alternate screen and back.
    fn private_mode(&mut self, set: bool) {
        if let Some(params) = self.csi.strip_prefix('?') {
            if params.split(';').any(|p| matches!(p, "47" | "1047" | "1049")) {
                self.alternate = set;
            }
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(bytes);
        let text = match std::str::from_utf8(&data) {
            Ok(text) => text.to_owned(),
            Err(err) if err.error_len().is_none() => {
                let valid = err.valid_up_to();
                self.partial = data[valid..].to_vec();
                String::from_utf8_lossy(&data[..valid]).into_owned()
            }
            Err(_) => String::from_utf8_lossy(&data).into_owned(),
        };
        for ch in text.chars() {
            self.push(ch);
        }
        let extra = self.line.chars().count().saturating_sub(MAX_LINE_CHARS);
        if extra > 0 {
            self.line = self.line.chars().skip(extra).collect();
        }
    }

    fn push(&mut self, ch: char) {
        match self.escape {
            Escape::Started => {
                self.escape = match ch {
                    '[' => {
                        self.csi.clear();
                        Escape::Csi
                    }
                    ']' | 'P' | 'X' | '^' | '_' => Escape::String,
                    // RIS, a full reset, leaves the alternate screen.
                    'c' => {
                        self.alternate = false;
                        Escape::None
                    }
                    _ => Escape::None,
                };
                return;
            }
            Escape::Csi => {
                if ('@'..='~').contains(&ch) {
                    self.escape = Escape::None;
                    if matches!(ch, 'h' | 'l') {
                        self.private_mode(ch == 'h');
                    }
                } else if self.csi.len() < MAX_CSI_CHARS {
                    self.csi.push(ch);
                }
                return;
            }
            Escape::String => {
                match ch {
                    '\x07' => self.escape = Escape::None,
                    '\x1b' => self.escape = Escape::StringEsc,
                    _ => {}
                }
                return;
            }
            Escape::StringEsc => {
                self.escape = if ch == '\\' { Escape::None } else { Escape::String };
                return;
            }
            Escape::None => {}
        }
        if self.carriage_return && ch != '\n' {
            self.line.clear();
        }
        self.carriage_return = false;
        match ch {
            '\x1b' => self.escape = Escape::Started,
            '\r' => self.carriage_return = true,
            '\n' => self.line.clear(),
            '\x08' => {
                self.line.pop();
            }
            '\t' => self.line.push(' '),
            c if c.is_control() => {}
            c => self.line.push(c),
        }
    }
}

/// QL-07 settings for one pane's watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchConfig {
    /// Off: no run is ever reported (the cursor's line is still followed, for QL-06).
    pub enabled: bool,
    /// A run reports when it ends only if it lasted this long.
    pub threshold: Duration,
    /// No output for this long after some came ends a run; `None` waits for a prompt only.
    pub quiet: Option<Duration>,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: Duration::from_secs(30),
            quiet: Some(Duration::from_secs(30)),
        }
    }
}

/// How a long run was seen to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FinishedHow {
    /// The shell prompt came back.
    Prompt,
    /// The output stopped: finished without a prompt Remotely knows, or waiting for an answer.
    Quiet,
}

/// QL-07: a command that ran at least the threshold has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    /// From Enter to the prompt, or to the last output.
    pub after: Duration,
    pub how: FinishedHow,
}

#[derive(Debug)]
enum Run {
    Idle,
    Running {
        started: Instant,
        /// The line Enter was pressed on: the prompt, then what was typed.
        typed_on: String,
        last_output: Option<Instant>,
    },
}

/// One pane's watch over its shell (see the module comment).
pub struct RunWatch {
    config: WatchConfig,
    screen: ScreenLine,
    run: Run,
}

impl RunWatch {
    pub fn new(config: WatchConfig) -> Self {
        Self {
            config,
            screen: ScreenLine::new(),
            run: Run::Idle,
        }
    }

    pub fn set_config(&mut self, config: WatchConfig) {
        self.config = config;
        if !config.enabled {
            self.run = Run::Idle;
        }
    }

    /// The line the cursor is on.
    pub fn line(&self) -> &str {
        self.screen.line()
    }

    /// SS-10: a full-screen program is open.
    pub fn alternate(&self) -> bool {
        self.screen.alternate()
    }

    pub fn is_running(&self) -> bool {
        matches!(self.run, Run::Running { .. })
    }

    /// What the user sent. Enter starts a run, unless one is running (then it answers the command).
    pub fn input(&mut self, bytes: &[u8], now: Instant) {
        if !self.config.enabled || self.is_running() || !bytes.iter().any(|b| *b == b'\r' || *b == b'\n') {
            return;
        }
        self.run = Run::Running {
            started: now,
            typed_on: self.screen.line().to_owned(),
            last_output: None,
        };
    }

    /// What the shell printed. Returns a long run that this output ended.
    pub fn output(&mut self, bytes: &[u8], now: Instant) -> Option<Finished> {
        self.screen.feed(bytes);
        let Run::Running {
            started,
            typed_on,
            last_output,
        } = &mut self.run
        else {
            return None;
        };
        *last_output = Some(now);
        let line = self.screen.line();
        if !prompt_came_back(line, typed_on) {
            return None;
        }
        let after = now.saturating_duration_since(*started);
        self.run = Run::Idle;
        (after >= self.config.threshold).then_some(Finished {
            after,
            how: FinishedHow::Prompt,
        })
    }

    /// When [`RunWatch::tick`] should next be called, if at all.
    pub fn deadline(&self) -> Option<Instant> {
        match (&self.run, self.config.quiet) {
            (
                Run::Running {
                    last_output: Some(at), ..
                },
                Some(quiet),
            ) => Some(*at + quiet),
            _ => None,
        }
    }

    /// Time passed: a run whose output stopped long enough ago ends.
    pub fn tick(&mut self, now: Instant) -> Option<Finished> {
        let deadline = self.deadline()?;
        if now < deadline {
            return None;
        }
        let Run::Running {
            started,
            last_output: Some(last),
            ..
        } = self.run
        else {
            return None;
        };
        self.run = Run::Idle;
        let after = last.saturating_duration_since(started);
        (after >= self.config.threshold).then_some(Finished {
            after,
            how: FinishedHow::Quiet,
        })
    }

    /// A new connection: a new shell, nothing running.
    pub fn reset(&mut self) {
        self.screen = ScreenLine::new();
        self.run = Run::Idle;
    }
}

/// The line now shows a prompt: the same one Enter was pressed after (the line then started with it),
/// or one that looks like a shell prompt. QL-12's recordings end on it too.
pub(crate) fn prompt_came_back(line: &str, typed_on: &str) -> bool {
    let shown = line.trim_end();
    if shown.is_empty() {
        return false;
    }
    let same_prompt = typed_on.starts_with(line)
        && shown.chars().last().is_some_and(|c| !c.is_alphanumeric())
        && !is_secret_prompt(line);
    same_prompt || is_shell_prompt(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_after(chunks: &[&[u8]]) -> String {
        let mut screen = ScreenLine::new();
        for chunk in chunks {
            screen.feed(chunk);
        }
        screen.line().to_owned()
    }

    #[test]
    fn the_cursor_line_drops_escapes_and_follows_returns() {
        assert_eq!(line_after(&[b"one\r\ntwo\r\n$ "]), "$ ");
        assert_eq!(
            line_after(&[b"\x1b]0;alice@web01: ~\x07\x1b[01;32malice@web01\x1b[00m:~$ "]),
            "alice@web01:~$ "
        );
        assert_eq!(line_after(&[b"10%\r50%"]), "50%");
        assert_eq!(line_after(&[b"pas", b"sx\x08word: "]), "password: ");
        assert_eq!(line_after(&[&[b'c', b'a', b'f', 0xC3], &[0xA9]]), "café");
        let long = "x".repeat(MAX_LINE_CHARS * 2);
        assert_eq!(line_after(&[long.as_bytes()]).len(), MAX_LINE_CHARS);
    }

    #[test]
    fn full_screen_programs_are_noticed_and_their_end_too() {
        let mut screen = ScreenLine::new();
        screen.feed(b"$ vim notes.txt\r\n");
        assert!(!screen.alternate());
        screen.feed(b"\x1b[?1049h\x1b[22;0;0t\x1b[1;24r\x1b[?12h");
        assert!(screen.alternate(), "vim switched to the alternate screen");
        screen.feed(b"\x1b[?25l\x1b[?12l");
        assert!(screen.alternate(), "other private modes change nothing");
        // Split across two reads, and switched back.
        screen.feed(b"\x1b[?10");
        screen.feed(b"49l\r\n$ ");
        assert!(!screen.alternate());
        assert_eq!(screen.line(), "$ ");
        // The older forms, several modes in one sequence, and a full reset.
        screen.feed(b"\x1b[?47h");
        assert!(screen.alternate());
        screen.feed(b"\x1b[?1;1047l");
        assert!(!screen.alternate());
        screen.feed(b"\x1b[?1049h\x1bc");
        assert!(!screen.alternate());
        // Not private: `CSI 4 h` is insert mode.
        screen.feed(b"\x1b[4h\x1b[1049h");
        assert!(!screen.alternate());
    }

    /// Prompts as sudo, su, ssh, PAM and common CLIs print them, in English and translated.
    const PASSWORD_PROMPTS: &[&str] = &[
        "[sudo] password for alice: ",
        "Password: ",
        "password:",
        "alice@web01.example.com's password: ",
        "(alice@web01.example.com) Password: ",
        "Enter passphrase for key '/home/alice/.ssh/id_ed25519': ",
        "Enter passphrase for key '/home/alice/projects/customer-deployments/example-org/keys/deploy/production/id_ed25519_web01': ",
        "Enter passphrase (empty for no passphrase): ",
        "Enter same passphrase again: ",
        "Enter pass phrase for /etc/ssl/private/web01.example.com.key:",
        "Password for alice@EXAMPLE.ORG:",
        "Password for 'https://alice@example.com': ",
        "Password for user alice: ",
        "Enter password: ",
        "Vault password: ",
        "Enter keystore password:  ",
        "Enter PIN for 'PIV Card Holder pin': ",
        "Enter PIN for alice: ",
        "Passcode or option (1-3): ",
        "Enter PASSCODE:",
        "One-time password (OATH) for `alice': ",
        "Passwort: ",
        "[sudo] Passwort für alice: ",
        "Kennwort: ",
        "[sudo] Mot de passe de alice : ",
        "[sudo] contraseña para alice: ",
        "[sudo] senha para alice: ",
        "Password per alice: ",
        "[sudo] wachtwoord voor alice: ",
        "[sudo] lösenord för alice: ",
        "[sudo] adgangskode til alice: ",
        "[sudo] passord for alice: ",
        "[sudo] salasana käyttäjälle alice: ",
        "[sudo] hasło użytkownika alice: ",
        "[sudo] heslo pro alice: ",
        "[sudo] alice jelszava: ",
        "Jelszó: ",
        "[sudo] parola pentru alice: ",
        "[sudo] alice için parola: ",
        "[sudo] пароль для alice: ",
        "Пароль: ",
        "[sudo] κωδικός πρόσβασης για alice: ",
        "[sudo] alice のパスワード: ",
        "パスワード：",
        "[sudo] alice 的密码：",
        "密碼：",
        "[sudo] alice의 암호: ",
        "비밀번호: ",
        "[sudo] mật khẩu cho alice: ",
        "[sudo] kata sandi untuk alice: ",
        "Kata laluan: ",
    ];

    /// One-time code prompts: PAM's two-factor modules, cloud CLIs, VPN clients.
    const CODE_PROMPTS: &[&str] = &[
        "Verification code: ",
        "Verification code for alice: ",
        "Enter verification code: ",
        "Token: ",
        "Token code:",
        "Enter your MFA token: ",
        "Enter MFA code for arn:aws:iam::111111111111:mfa/alice: ",
        "OTP: ",
        "Enter OTP: ",
        "TOTP code: ",
        "2FA code: ",
        "Two-factor code: ",
        "Authenticator code: ",
        "Security code: ",
        "Enter the 6-digit code: ",
        "Enter code: ",
        "One-time code: ",
        "Bestätigungscode: ",
        "Code de vérification : ",
        "Código de verificación: ",
        "Código de verificação: ",
        "Codice di verifica: ",
        "Verificatiecode: ",
    ];

    #[test]
    fn password_prompts_are_recognised() {
        for prompt in PASSWORD_PROMPTS {
            assert!(is_password_prompt(prompt), "{prompt}");
            assert!(is_secret_prompt(prompt), "{prompt}");
            assert!(!is_shell_prompt(prompt), "{prompt}");
        }
        for line in [
            "alice@web01:~$ ",
            "$ ",
            "password changed",
            "Verification code: ",
            "alice@web01:~$ passwd",
            "spinning",
        ] {
            assert!(!is_password_prompt(line), "{line}");
        }
    }

    #[test]
    fn one_time_code_prompts_are_secret_prompts_but_not_password_prompts() {
        for prompt in CODE_PROMPTS {
            assert!(is_secret_prompt(prompt), "{prompt}");
            assert!(!is_password_prompt(prompt), "QL-06 types no vault password at {prompt}");
            assert!(!is_shell_prompt(prompt), "{prompt}");
        }
    }

    #[test]
    fn shell_prompts_and_output_are_not_secret_prompts() {
        for line in [
            "alice@web01:~$ ",
            "[root@web01 ~]# ",
            "PS C:\\Users\\alice> ",
            "$ ",
            "# ",
            "% ",
            "❯ ",
            "alice@token-server:~$ ",
            "alice@otp-gw ~ % ",
            "[bob@pin01 passwords]$ ",
            "PS C:\\passwords> ",
            "alice@web01:~/tokens$ ",
            "Username: ",
            "login: ",
            "Username for 'https://example.com': ",
            "Enter file in which to save the key (/home/alice/.ssh/id_ed25519): ",
            "Do you want to continue? [Y/n] ",
            "password changed",
            "passwd: password updated successfully",
            "Token: abc123 (expires in 1 h)",
            "Verification succeeded.",
            "Your verification code is 123456",
            "45% ",
            "Exit code: 2",
            "",
        ] {
            assert!(!is_secret_prompt(line), "{line}");
        }
    }

    #[test]
    fn shell_prompts_are_recognised_and_progress_is_not() {
        for prompt in [
            "alice@web01:~$ ",
            "[root@web01 ~]# ",
            "PS C:\\Users\\alice> ",
            "$ ",
            "# ",
            "% ",
            "❯ ",
        ] {
            assert!(is_shell_prompt(prompt), "{prompt}");
        }
        for line in ["45% ", "45%", "Downloading 3 MB", "", "alice@web01:~$ ls", "a > b"] {
            assert!(!is_shell_prompt(line), "{line}");
        }
    }

    const SECOND: Duration = Duration::from_secs(1);

    fn watch(threshold_secs: u64, quiet_secs: Option<u64>) -> RunWatch {
        RunWatch::new(WatchConfig {
            enabled: true,
            threshold: Duration::from_secs(threshold_secs),
            quiet: quiet_secs.map(Duration::from_secs),
        })
    }

    #[test]
    fn a_long_command_reports_when_its_prompt_comes_back() {
        let t0 = Instant::now();
        let mut w = watch(30, Some(30));
        assert_eq!(w.output(b"Welcome\r\nalice@web01:~$ ", t0), None, "no run yet");
        assert_eq!(w.output(b"apt upgrade", t0), None, "the echo of typing");
        w.input(b"\r", t0);
        assert!(w.is_running());
        assert_eq!(w.output(b"\r\nReading package lists...\r\n", t0 + SECOND), None);
        let done = w.output(b"Done\r\nalice@web01:~$ ", t0 + 40 * SECOND).unwrap();
        assert_eq!(done.how, FinishedHow::Prompt);
        assert_eq!(done.after, 40 * SECOND);
        assert!(!w.is_running());
        // The next prompt alone starts nothing.
        assert_eq!(w.output(b"\r\nalice@web01:~$ ", t0 + 50 * SECOND), None);
    }

    #[test]
    fn a_short_command_ends_without_a_report() {
        let t0 = Instant::now();
        let mut w = watch(30, Some(30));
        w.output(b"$ uptime", t0);
        w.input(b"\r", t0);
        assert_eq!(w.output(b"\r\n 10:00 up 3 days\r\n$ ", t0 + SECOND), None);
        assert!(!w.is_running(), "the prompt ended it");
    }

    #[test]
    fn the_same_prompt_counts_even_when_it_looks_unusual() {
        let t0 = Instant::now();
        let mut w = watch(5, None);
        // A zsh prompt ending in `%`, which the shell-prompt pattern leaves alone.
        w.output(b"web01% make", t0);
        w.input(b"\r", t0);
        assert_eq!(w.output(b"\r\n45% ", t0 + 3 * SECOND), None, "progress is not a prompt");
        let done = w.output(b"\r\nweb01% ", t0 + 9 * SECOND).unwrap();
        assert_eq!(done.how, FinishedHow::Prompt);
    }

    #[test]
    fn output_that_stops_ends_a_long_run() {
        let t0 = Instant::now();
        let mut w = watch(30, Some(20));
        w.output("➜  ~ cd /srv && ./build.sh".as_bytes(), t0);
        w.input(b"\r", t0);
        assert_eq!(w.deadline(), None, "nothing printed yet");
        w.output(b"\r\nstep 1\r\n", t0 + 10 * SECOND);
        // The prompt changed with the folder, and has no `$`: not recognised.
        w.output("step 2\r\n➜  srv ".as_bytes(), t0 + 45 * SECOND);
        assert!(w.is_running(), "an unknown prompt");
        assert_eq!(w.deadline(), Some(t0 + 65 * SECOND));
        assert_eq!(w.tick(t0 + 60 * SECOND), None, "not quiet long enough");
        let done = w.tick(t0 + 65 * SECOND).unwrap();
        assert_eq!(done.how, FinishedHow::Quiet);
        assert_eq!(done.after, 45 * SECOND, "until the last output");
        assert!(!w.is_running());
        assert_eq!(w.deadline(), None);
    }

    #[test]
    fn the_same_prompt_after_a_folder_change_back_is_recognised() {
        let t0 = Instant::now();
        let mut w = watch(5, Some(20));
        w.output("➜  ~ ./build.sh".as_bytes(), t0);
        w.input(b"\r", t0);
        let done = w.output("\r\ndone\r\n➜  ~ ".as_bytes(), t0 + 8 * SECOND).unwrap();
        assert_eq!(done.how, FinishedHow::Prompt);
    }

    #[test]
    fn a_quick_answer_then_silence_is_no_long_run() {
        let t0 = Instant::now();
        let mut w = watch(30, Some(20));
        w.output(b"$ sudo apt upgrade", t0);
        w.input(b"\r", t0);
        w.output(b"\r\n[sudo] password for alice: ", t0 + SECOND);
        // Waiting for the password: quiet, but the run was short.
        assert_eq!(w.tick(t0 + 30 * SECOND), None);
        assert!(!w.is_running());
    }

    #[test]
    fn without_quiet_only_a_prompt_ends_a_run() {
        let t0 = Instant::now();
        let mut w = watch(30, None);
        w.output(b"$ tail -f app.log", t0);
        w.input(b"\r", t0);
        w.output(b"\r\nline\r\n", t0 + SECOND);
        assert_eq!(w.deadline(), None);
        assert_eq!(w.tick(t0 + 3600 * SECOND), None);
        assert!(w.is_running());
    }

    #[test]
    fn enter_while_running_answers_the_command() {
        let t0 = Instant::now();
        let mut w = watch(30, Some(30));
        w.output(b"$ sudo apt upgrade", t0);
        w.input(b"\r", t0);
        w.output(b"\r\nDo you want to continue? [Y/n] ", t0 + 5 * SECOND);
        w.input(b"y\r", t0 + 6 * SECOND);
        let done = w.output(b"\r\nDone\r\n$ ", t0 + 50 * SECOND).unwrap();
        assert_eq!(done.after, 50 * SECOND, "measured from the first Enter");
    }

    #[test]
    fn a_password_prompt_is_not_the_end() {
        let t0 = Instant::now();
        let mut w = watch(1, Some(30));
        w.output(b"$ su -", t0);
        w.input(b"\r", t0);
        assert_eq!(w.output(b"\r\nPassword: ", t0 + 5 * SECOND), None);
        assert!(w.is_running());
    }

    #[test]
    fn off_reports_nothing_but_still_follows_the_line() {
        let t0 = Instant::now();
        let mut w = RunWatch::new(WatchConfig {
            enabled: false,
            ..WatchConfig::default()
        });
        w.output(b"$ sleep 100", t0);
        w.input(b"\r", t0);
        assert!(!w.is_running());
        assert_eq!(w.output(b"\r\n$ ", t0 + 200 * SECOND), None);
        w.output(b"\r\n[sudo] password for alice: ", t0);
        assert!(is_password_prompt(w.line()));
        // Turning it off ends a run.
        let mut w = watch(1, None);
        w.output(b"$ x", t0);
        w.input(b"\r", t0);
        w.set_config(WatchConfig {
            enabled: false,
            ..WatchConfig::default()
        });
        assert!(!w.is_running());
    }

    #[test]
    fn a_new_connection_starts_over() {
        let t0 = Instant::now();
        let mut w = watch(1, Some(1));
        w.output(b"$ sleep 100", t0);
        w.input(b"\r", t0);
        w.reset();
        assert!(!w.is_running());
        assert_eq!(w.line(), "");
    }
}
