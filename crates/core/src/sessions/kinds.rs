//! SS-12 session kinds: what a saved session opens. SSH is a terminal with everything the app does over SSH;
//! Telnet and serial are terminal panes too (no SFTP, tunnels, Compare hosts or Type in all tabs); RDP and VNC
//! open a window of another program (`mstsc.exe`, the owner's VNC viewer), which asks for the password itself.
//!
//! The kind is the `sessions.protocol` column, and each kind's own fields are one JSON object in
//! `sessions.kind_options` (migration 0031), checked here before it is saved and read back leniently (a field this
//! version doesn't know is dropped, a missing one gets its default). F4 adds WinRM as one more variant.
//!
//! What the folders give (QL-16: user, label, tags, the jump host) works for every kind. A login only means
//! something for SSH: every other kind logs in with what its own program or the remote side asks for, so its
//! login is always "asked when connecting" and no vault password is ever sent by it ([`SessionKind::tidy`]). A
//! jump host (an SSH session) is for SSH, RDP and VNC; Telnet and serial never take one, not even from a folder.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// What Enter sends (Telnet and serial). xterm.js sends a carriage return.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LineEnding {
    /// CR, which Telnet sends as CR NUL (RFC 854).
    #[default]
    Cr,
    Lf,
    CrLf,
}

impl LineEnding {
    pub fn label(self) -> &'static str {
        match self {
            LineEnding::Cr => "CR",
            LineEnding::Lf => "LF",
            LineEnding::CrLf => "CR LF",
        }
    }

    /// The bytes Enter becomes on a byte stream (serial). Telnet's own rule for a bare CR is the transport's.
    pub fn bytes(self) -> &'static [u8] {
        match self {
            LineEnding::Cr => b"\r",
            LineEnding::Lf => b"\n",
            LineEnding::CrLf => b"\r\n",
        }
    }
}

/// RDP: how big the remote desktop's window is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RdpScreen {
    /// Full screen on the monitor the window opens on.
    #[default]
    Full,
    /// Full screen across every monitor.
    AllMonitors,
    /// A window of this size, in pixels.
    Window { width: u32, height: u32 },
}

/// RDP's own fields. Clipboard on, drives, printers and audio off, as decided for 0.7.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RdpOptions {
    pub screen: RdpScreen,
    pub clipboard: bool,
    pub drives: bool,
    pub printers: bool,
    /// Sound from the remote desktop played here. Off: not played at all.
    pub audio: bool,
    /// The administrative (console) session (`mstsc /admin`).
    pub admin: bool,
}

impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            screen: RdpScreen::Full,
            clipboard: true,
            drives: false,
            printers: false,
            audio: false,
            admin: false,
        }
    }
}

/// VNC's own fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VncOptions {
    /// The viewer sends no keys or mouse moves.
    pub view_only: bool,
}

/// Telnet's own fields. Its port is the session's port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TelnetOptions {
    pub line_ending: LineEnding,
}

impl Default for TelnetOptions {
    fn default() -> Self {
        Self {
            line_ending: LineEnding::CrLf,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Parity {
    #[default]
    None,
    Odd,
    Even,
    Mark,
    Space,
}

impl Parity {
    /// The letter of `8N1`.
    pub fn letter(self) -> char {
        match self {
            Parity::None => 'N',
            Parity::Odd => 'O',
            Parity::Even => 'E',
            Parity::Mark => 'M',
            Parity::Space => 'S',
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StopBits {
    #[default]
    One,
    OnePointFive,
    Two,
}

impl StopBits {
    pub fn label(self) -> &'static str {
        match self {
            StopBits::One => "1",
            StopBits::OnePointFive => "1.5",
            StopBits::Two => "2",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FlowControl {
    #[default]
    None,
    XonXoff,
    RtsCts,
    DsrDtr,
}

impl FlowControl {
    pub fn label(self) -> &'static str {
        match self {
            FlowControl::None => "no flow control",
            FlowControl::XonXoff => "XON/XOFF",
            FlowControl::RtsCts => "RTS/CTS",
            FlowControl::DsrDtr => "DSR/DTR",
        }
    }
}

/// Serial's own fields. The COM port is the session's host (`COM3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SerialOptions {
    /// Bits per second.
    pub speed: u32,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub flow_control: FlowControl,
    pub line_ending: LineEnding,
    /// Shows what is typed here, for devices that don't echo it.
    pub local_echo: bool,
}

impl Default for SerialOptions {
    fn default() -> Self {
        Self {
            speed: 9600,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
            line_ending: LineEnding::Cr,
            local_echo: false,
        }
    }
}

impl SerialOptions {
    /// `9600 8N1`.
    pub fn frame(&self) -> String {
        format!(
            "{} {}{}{}",
            self.speed,
            self.data_bits,
            self.parity.letter(),
            self.stop_bits.label()
        )
    }
}

/// The highest serial speed a session may ask for (USB adapters go to a few Mbit/s).
pub const MAX_SERIAL_SPEED: u32 = 4_000_000;
/// The highest COM port number Windows gives out.
pub const MAX_COM_PORT: u32 = 256;
/// The `port` column of a serial session, which has no network port: nothing reads it.
pub const SERIAL_PORT_COLUMN: u16 = 1;

/// What a session opens, with that kind's own fields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "camelCase")]
pub enum SessionKind {
    #[default]
    Ssh,
    Rdp(RdpOptions),
    Vnc(VncOptions),
    Telnet(TelnetOptions),
    Serial(SerialOptions),
}

impl SessionKind {
    /// The `sessions.protocol` value.
    pub fn protocol(&self) -> &'static str {
        match self {
            SessionKind::Ssh => "ssh",
            SessionKind::Rdp(_) => "rdp",
            SessionKind::Vnc(_) => "vnc",
            SessionKind::Telnet(_) => "telnet",
            SessionKind::Serial(_) => "serial",
        }
    }

    /// "SSH", "Remote desktop (RDP)"... for messages and the audit log.
    pub fn label(&self) -> &'static str {
        match self {
            SessionKind::Ssh => "SSH",
            SessionKind::Rdp(_) => "remote desktop (RDP)",
            SessionKind::Vnc(_) => "VNC",
            SessionKind::Telnet(_) => "Telnet",
            SessionKind::Serial(_) => "serial",
        }
    }

    /// The kind as it is read back: `protocol` and the JSON of its fields. A field this version doesn't know is
    /// dropped and a missing one gets its default; an unreadable object gives the kind's defaults. `None` for a
    /// protocol this version doesn't open (F4's `winrm` in a newer database).
    pub fn read(protocol: &str, options: Option<&str>) -> Option<Self> {
        fn options_of<T: Default + for<'de> Deserialize<'de>>(json: Option<&str>) -> T {
            json.and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default()
        }
        Some(match protocol {
            "ssh" => SessionKind::Ssh,
            "rdp" => SessionKind::Rdp(options_of(options)),
            "vnc" => SessionKind::Vnc(options_of(options)),
            "telnet" => SessionKind::Telnet(options_of(options)),
            "serial" => SessionKind::Serial(options_of(options)),
            _ => return None,
        })
    }

    /// The `sessions.kind_options` value: this kind's fields as JSON, `None` for SSH.
    pub fn options_json(&self) -> Option<String> {
        let json = match self {
            SessionKind::Ssh => return None,
            SessionKind::Rdp(o) => serde_json::to_string(o),
            SessionKind::Vnc(o) => serde_json::to_string(o),
            SessionKind::Telnet(o) => serde_json::to_string(o),
            SessionKind::Serial(o) => serde_json::to_string(o),
        };
        json.ok()
    }

    pub fn is_ssh(&self) -> bool {
        matches!(self, SessionKind::Ssh)
    }

    /// Opens in a terminal pane (SSH, Telnet, serial).
    pub fn is_terminal(&self) -> bool {
        matches!(self, SessionKind::Ssh | SessionKind::Telnet(_) | SessionKind::Serial(_))
    }

    /// Opens a window of another program (RDP, VNC).
    pub fn is_window(&self) -> bool {
        matches!(self, SessionKind::Rdp(_) | SessionKind::Vnc(_))
    }

    /// May go through a jump host (an SSH session): SSH itself, and RDP and VNC through a tunnel.
    pub fn takes_jump_host(&self) -> bool {
        matches!(self, SessionKind::Ssh | SessionKind::Rdp(_) | SessionKind::Vnc(_))
    }

    /// Has a network port (everything but serial).
    pub fn has_port(&self) -> bool {
        !matches!(self, SessionKind::Serial(_))
    }

    /// Sends what is typed in clear text over the network (Telnet).
    pub fn clear_text(&self) -> bool {
        matches!(self, SessionKind::Telnet(_))
    }

    /// The port a new session of this kind gets.
    pub fn default_port(&self) -> u16 {
        match self {
            SessionKind::Ssh => 22,
            SessionKind::Rdp(_) => 3389,
            SessionKind::Vnc(_) => 5900,
            SessionKind::Telnet(_) => 23,
            SessionKind::Serial(_) => SERIAL_PORT_COLUMN,
        }
    }

    /// Checks this kind's fields and tidies a session of it: a serial session's host is its COM port (`COM3`, as
    /// Windows names it) and its port column [`SERIAL_PORT_COLUMN`]. Only an SSH session logs in with a login of the
    /// app's (every other kind's program or remote side asks for it), so the rest get "asked when connecting" and
    /// never send a vault password; Telnet and serial take no jump host, not even their folders'.
    pub(crate) fn tidy(&self, host: &mut String, port: &mut u16) -> Result<()> {
        match self {
            SessionKind::Ssh | SessionKind::Vnc(_) | SessionKind::Telnet(_) => {}
            SessionKind::Rdp(o) => {
                if let RdpScreen::Window { width, height } = o.screen {
                    if !(200..=8192).contains(&width) || !(200..=8192).contains(&height) {
                        return invalid("A remote desktop window is 200 to 8192 pixels wide and high.");
                    }
                }
            }
            SessionKind::Serial(o) => {
                *host = com_port_name(host)?;
                *port = SERIAL_PORT_COLUMN;
                if !(50..=MAX_SERIAL_SPEED).contains(&o.speed) {
                    return invalid(format!("A serial speed is 50 to {MAX_SERIAL_SPEED} bits per second."));
                }
                if !(5..=8).contains(&o.data_bits) {
                    return invalid("A serial port sends 5 to 8 data bits.");
                }
                if o.stop_bits == StopBits::OnePointFive && o.data_bits != 5 {
                    return invalid("1.5 stop bits only go with 5 data bits; choose 1 or 2.");
                }
                if o.stop_bits == StopBits::Two && o.data_bits == 5 {
                    return invalid("5 data bits go with 1 or 1.5 stop bits, not 2.");
                }
            }
        }
        Ok(())
    }

    /// One part of the audit log's line about a session: "Telnet, Enter sends CR LF".
    pub fn describe(&self) -> Option<String> {
        Some(match self {
            SessionKind::Ssh => return None,
            SessionKind::Rdp(o) => {
                let screen = match o.screen {
                    RdpScreen::Full => "full screen".to_owned(),
                    RdpScreen::AllMonitors => "full screen on all monitors".to_owned(),
                    RdpScreen::Window { width, height } => format!("a {width}x{height} window"),
                };
                let mut shared: Vec<&str> = Vec::new();
                for (on, what) in [
                    (o.clipboard, "clipboard"),
                    (o.drives, "drives"),
                    (o.printers, "printers"),
                    (o.audio, "audio"),
                ] {
                    if on {
                        shared.push(what);
                    }
                }
                let shared = if shared.is_empty() {
                    "nothing shared".to_owned()
                } else {
                    format!("shares {}", shared.join(", "))
                };
                let admin = if o.admin { ", admin session" } else { "" };
                format!("remote desktop (RDP), {screen}, {shared}{admin}")
            }
            SessionKind::Vnc(o) => {
                if o.view_only {
                    "VNC, view only".to_owned()
                } else {
                    "VNC".to_owned()
                }
            }
            SessionKind::Telnet(o) => format!("Telnet, Enter sends {}", o.line_ending.label()),
            SessionKind::Serial(o) => format!(
                "serial, {}, {}, Enter sends {}{}",
                o.frame(),
                o.flow_control.label(),
                o.line_ending.label(),
                if o.local_echo { ", local echo" } else { "" }
            ),
        })
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// `com3`, ` COM3 ` -> `COM3`. Only Windows' own COM port names: never a path or another device.
pub fn com_port_name(text: &str) -> Result<String> {
    let text = text.trim();
    let number = text
        .get(..3)
        .filter(|p| p.eq_ignore_ascii_case("com"))
        .and_then(|_| text.get(3..))
        .filter(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0'))
        .and_then(|n| n.parse::<u32>().ok())
        .filter(|n| (1..=MAX_COM_PORT).contains(n));
    match number {
        Some(n) => Ok(format!("COM{n}")),
        None => invalid(format!("'{text}' is not a COM port. Choose one such as COM3.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_through_their_columns() {
        let kinds = [
            SessionKind::Ssh,
            SessionKind::Rdp(RdpOptions {
                screen: RdpScreen::Window {
                    width: 1600,
                    height: 900,
                },
                admin: true,
                ..RdpOptions::default()
            }),
            SessionKind::Vnc(VncOptions { view_only: true }),
            SessionKind::Telnet(TelnetOptions {
                line_ending: LineEnding::Cr,
            }),
            SessionKind::Serial(SerialOptions {
                speed: 115_200,
                flow_control: FlowControl::RtsCts,
                local_echo: true,
                ..SerialOptions::default()
            }),
        ];
        for kind in kinds {
            let json = kind.options_json();
            assert_eq!(SessionKind::read(kind.protocol(), json.as_deref()), Some(kind));
        }
        assert_eq!(
            SessionKind::read("winrm", None),
            None,
            "F4's kind is not this version's"
        );
    }

    #[test]
    fn options_are_read_leniently() {
        // A field this version doesn't know is dropped; a missing one gets its default; junk gives the defaults.
        assert_eq!(
            SessionKind::read("rdp", Some(r#"{"admin":true,"futureField":3}"#)),
            Some(SessionKind::Rdp(RdpOptions {
                admin: true,
                ..RdpOptions::default()
            }))
        );
        assert_eq!(
            SessionKind::read("serial", Some("not json")),
            Some(SessionKind::Serial(SerialOptions::default()))
        );
        assert_eq!(
            SessionKind::read("telnet", None),
            Some(SessionKind::Telnet(TelnetOptions::default()))
        );
    }

    #[test]
    fn the_editor_sends_the_kind_with_its_fields() {
        let kind: SessionKind =
            serde_json::from_str(r#"{"protocol":"serial","speed":115200,"parity":"even"}"#).unwrap();
        assert_eq!(
            kind,
            SessionKind::Serial(SerialOptions {
                speed: 115_200,
                parity: Parity::Even,
                ..SerialOptions::default()
            })
        );
        let rdp: SessionKind =
            serde_json::from_str(r#"{"protocol":"rdp","screen":{"mode":"window","width":1280,"height":800}}"#).unwrap();
        assert!(matches!(
            rdp,
            SessionKind::Rdp(RdpOptions {
                screen: RdpScreen::Window { width: 1280, .. },
                clipboard: true,
                ..
            })
        ));
        let ssh: SessionKind = serde_json::from_str(r#"{"protocol":"ssh"}"#).unwrap();
        assert_eq!(ssh, SessionKind::Ssh);
    }

    #[test]
    fn com_ports_are_windows_names_only() {
        assert_eq!(com_port_name(" com3 ").unwrap(), "COM3");
        assert_eq!(com_port_name("COM256").unwrap(), "COM256");
        for bad in [
            "",
            "COM",
            "COM0",
            "COM03",
            "COM257",
            "LPT1",
            "\\\\.\\COM3",
            "COM3:",
            "COM 3",
            "NUL",
            "web01",
        ] {
            assert!(com_port_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn serial_fields_are_checked_and_the_port_column_is_fixed() {
        let mut host = "com7".to_owned();
        let mut port = 22;
        SessionKind::Serial(SerialOptions::default())
            .tidy(&mut host, &mut port)
            .unwrap();
        assert_eq!((host.as_str(), port), ("COM7", SERIAL_PORT_COLUMN));
        for bad in [
            SerialOptions {
                speed: 10,
                ..SerialOptions::default()
            },
            SerialOptions {
                data_bits: 9,
                ..SerialOptions::default()
            },
            SerialOptions {
                stop_bits: StopBits::OnePointFive,
                ..SerialOptions::default()
            },
            SerialOptions {
                data_bits: 5,
                stop_bits: StopBits::Two,
                ..SerialOptions::default()
            },
        ] {
            let (mut host, mut port) = ("COM1".to_owned(), 1);
            assert!(SessionKind::Serial(bad).tidy(&mut host, &mut port).is_err(), "{bad:?}");
        }
        let small = SessionKind::Rdp(RdpOptions {
            screen: RdpScreen::Window {
                width: 100,
                height: 600,
            },
            ..RdpOptions::default()
        });
        let (mut host, mut port) = ("win01.example.com".to_owned(), 3389);
        assert!(small.tidy(&mut host, &mut port).is_err());
    }

    #[test]
    fn what_each_kind_may_do() {
        let telnet = SessionKind::Telnet(TelnetOptions::default());
        let serial = SessionKind::Serial(SerialOptions::default());
        let rdp = SessionKind::Rdp(RdpOptions::default());
        assert!(SessionKind::Ssh.is_terminal() && telnet.is_terminal() && serial.is_terminal() && !rdp.is_terminal());
        assert!(rdp.is_window() && SessionKind::Vnc(VncOptions::default()).is_window());
        assert!(rdp.takes_jump_host() && !telnet.takes_jump_host() && !serial.takes_jump_host());
        assert!(telnet.clear_text() && !SessionKind::Ssh.clear_text());
        assert_eq!(
            [
                SessionKind::Ssh.default_port(),
                rdp.default_port(),
                telnet.default_port()
            ],
            [22, 3389, 23]
        );
        assert_eq!(
            serial.describe().unwrap(),
            "serial, 9600 8N1, no flow control, Enter sends CR"
        );
    }
}
