//! SS-12 serial consoles: this PC's COM ports, listed from `HKLM\HARDWARE\DEVICEMAP\SERIALCOMM` and opened with
//! Windows' serial API (`CreateFileW` on `\\.\COMn`, `SetCommState`, `SetCommTimeouts`, `SetCommBreak`), behind the
//! [`SerialPorts`] trait so tests use an in-memory port ([`crate::fakes::FakeSerialPorts`]) and never a real one.
//!
//! A port is read and written on one thread of its own ([`serial_shell`]): reads wait at most [`READ_WAIT`] for the
//! first byte (`ReadIntervalTimeout` and `ReadTotalTimeoutMultiplier` at `MAXDWORD`), so what is typed goes out at
//! once and a device's output shows as it comes. Windows opens a COM port for one program at a time, and Remotely
//! keeps one pane per port (`crate::terminal`).

use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc;

use super::remote::{ShellEnd, ShellInput, ShellOutput};
use crate::error::Result;
use crate::sessions::kinds::SerialOptions;

/// The longest a read waits for a device's first byte, which is also how long typing waits behind it.
pub const READ_WAIT: Duration = Duration::from_millis(25);
/// How long Send Break holds the line.
pub const BREAK_LENGTH: Duration = Duration::from_millis(250);

/// One COM port of this PC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComPort {
    /// `COM3`.
    pub name: String,
    /// The driver's device, e.g. `\Device\USBSER000` or `\Device\Serial0`, to tell ports apart.
    pub device: String,
}

/// An open COM port, used from one thread.
pub trait SerialLink: Send {
    /// Up to `buf.len()` bytes, waiting at most [`READ_WAIT`]; `Ok(0)` when nothing came.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()>;
    /// Holds the line in the break state for [`BREAK_LENGTH`].
    fn send_break(&mut self) -> std::io::Result<()>;
}

/// This PC's COM ports.
pub trait SerialPorts: Send + Sync {
    /// The ports Windows has now, by number.
    fn list(&self) -> Result<Vec<ComPort>>;
    /// Opens `port` (`COM3`, checked) with the session's settings. [`crate::error::CoreError::SerialPort`] when it is missing, in
    /// use by another program, or refuses the settings.
    fn open(&self, port: &str, options: &SerialOptions) -> Result<Box<dyn SerialLink>>;
}

/// The COM port number of `COM12`, to sort by.
fn number(name: &str) -> u32 {
    name.get(3..).and_then(|n| n.parse().ok()).unwrap_or(u32::MAX)
}

/// Sorts ports by number and drops repeats.
pub fn sorted(mut ports: Vec<ComPort>) -> Vec<ComPort> {
    ports.sort_by_key(|p| (number(&p.name), p.name.clone()));
    ports.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
    ports
}

/// A serial pane's two ends, like an SSH shell's: Enter goes as the session's line ending, what is typed shows here
/// too with local echo on, and Break holds the line. A port that goes away (an unplugged USB adapter) ends it as
/// lost, so the pane tries again by itself.
pub fn serial_shell(
    mut link: Box<dyn SerialLink>,
    options: SerialOptions,
) -> (mpsc::Sender<ShellInput>, mpsc::Receiver<ShellOutput>) {
    let (input_tx, mut input_rx) = mpsc::channel::<ShellInput>(256);
    let (output_tx, output_rx) = mpsc::channel::<ShellOutput>(256);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 4096];
        let lost = |err: std::io::Error| ShellEnd::Lost {
            reason: format!("the COM port stopped answering ({err})"),
        };
        let end = 'run: loop {
            loop {
                match input_rx.try_recv() {
                    Ok(ShellInput::Data(bytes)) => {
                        let mut out = Vec::with_capacity(bytes.len());
                        for b in &bytes {
                            match b {
                                b'\r' => out.extend_from_slice(options.line_ending.bytes()),
                                b => out.push(*b),
                            }
                        }
                        if let Err(err) = link.write_all(&out) {
                            break 'run Some(lost(err));
                        }
                        if options.local_echo {
                            let shown = super::telnet::local_echo(&bytes);
                            if !shown.is_empty() && output_tx.blocking_send(ShellOutput::Data(shown)).is_err() {
                                break 'run None;
                            }
                        }
                    }
                    Ok(ShellInput::Break) => {
                        if let Err(err) = link.send_break() {
                            break 'run Some(lost(err));
                        }
                    }
                    Ok(ShellInput::Resize { .. }) => {}
                    Ok(ShellInput::Close) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        break 'run Some(ShellEnd::Exited { status: None });
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            match link.read(&mut buf) {
                Ok(0) => {}
                Ok(n) => {
                    if output_tx.blocking_send(ShellOutput::Data(buf[..n].to_vec())).is_err() {
                        break None;
                    }
                }
                Err(err) => break Some(lost(err)),
            }
        };
        // The port closes here, so the next pane (or a reconnect) can open it.
        drop(link);
        if let Some(end) = end {
            let _ = output_tx.blocking_send(ShellOutput::Closed(end));
        }
    });
    (input_tx, output_rx)
}

/// The real ports.
pub struct WindowsSerialPorts;

impl SerialPorts for WindowsSerialPorts {
    fn list(&self) -> Result<Vec<ComPort>> {
        list_ports()
    }

    fn open(&self, port: &str, options: &SerialOptions) -> Result<Box<dyn SerialLink>> {
        let port = crate::sessions::kinds::com_port_name(port)?;
        open_port(&port, options)
    }
}

#[cfg(windows)]
fn list_ports() -> Result<Vec<ComPort>> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"HARDWARE\DEVICEMAP\SERIALCOMM") {
        Ok(key) => key,
        // No COM port at all: Windows makes the key only when one is there.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    let mut ports = Vec::new();
    for value in key.enum_values() {
        let Ok((device, data)) = value else { continue };
        let name = data.to_string();
        let name = name.trim_matches(char::from(0)).trim();
        if let Ok(name) = crate::sessions::kinds::com_port_name(name) {
            ports.push(ComPort { name, device });
        }
    }
    Ok(sorted(ports))
}

#[cfg(not(windows))]
fn list_ports() -> Result<Vec<ComPort>> {
    Ok(Vec::new())
}

#[cfg(windows)]
fn open_port(port: &str, options: &SerialOptions) -> Result<Box<dyn SerialLink>> {
    win::open(port, options)
}

#[cfg(not(windows))]
fn open_port(_port: &str, _options: &SerialOptions) -> Result<Box<dyn SerialLink>> {
    Err(crate::error::CoreError::NotImplemented("serial ports outside Windows"))
}

#[cfg(windows)]
mod win {
    use windows::core::HSTRING;
    use windows::Win32::Devices::Communication::{
        ClearCommBreak, GetCommState, PurgeComm, SetCommBreak, SetCommState, SetCommTimeouts, COMMTIMEOUTS, DCB,
        DCB_PARITY, DCB_STOP_BITS, PURGE_RXCLEAR, PURGE_TXCLEAR,
    };
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
    };

    use super::{SerialLink, BREAK_LENGTH, READ_WAIT};
    use crate::error::{CoreError, Result};
    use crate::sessions::kinds::{FlowControl, Parity, SerialOptions, StopBits};

    struct Port {
        handle: HANDLE,
    }

    // A HANDLE is a kernel object's number; the port is used from one thread at a time.
    unsafe impl Send for Port {}

    impl Drop for Port {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateFileW and is closed once, here.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }

    fn io(err: windows::core::Error) -> std::io::Error {
        std::io::Error::other(err.message())
    }

    impl SerialLink for Port {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut read = 0u32;
            // SAFETY: a synchronous read into `buf` on our own handle.
            unsafe { ReadFile(self.handle, Some(buf), Some(&mut read), None) }.map_err(io)?;
            Ok(read as usize)
        }

        fn write_all(&mut self, mut data: &[u8]) -> std::io::Result<()> {
            while !data.is_empty() {
                let mut written = 0u32;
                // SAFETY: a synchronous write of `data` on our own handle.
                unsafe { WriteFile(self.handle, Some(data), Some(&mut written), None) }.map_err(io)?;
                if written == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the device took nothing for a while (flow control?)",
                    ));
                }
                data = &data[written as usize..];
            }
            Ok(())
        }

        fn send_break(&mut self) -> std::io::Result<()> {
            // SAFETY: our own handle.
            unsafe { SetCommBreak(self.handle) }.map_err(io)?;
            std::thread::sleep(BREAK_LENGTH);
            // SAFETY: our own handle.
            unsafe { ClearCommBreak(self.handle) }.map_err(io)
        }
    }

    /// The DCB's flags for these settings (the bitfield after `BaudRate`): binary mode, parity checking when there
    /// is parity, DTR and RTS on unless they do the handshake.
    pub(super) fn dcb_flags(options: &SerialOptions) -> u32 {
        const BINARY: u32 = 1;
        const PARITY: u32 = 1 << 1;
        const OUTX_CTS: u32 = 1 << 2;
        const OUTX_DSR: u32 = 1 << 3;
        const DTR_ENABLE: u32 = 1 << 4;
        const DTR_HANDSHAKE: u32 = 2 << 4;
        const TX_CONTINUE_ON_XOFF: u32 = 1 << 7;
        const OUTX: u32 = 1 << 8;
        const INX: u32 = 1 << 9;
        const RTS_ENABLE: u32 = 1 << 12;
        const RTS_HANDSHAKE: u32 = 2 << 12;
        let mut flags = BINARY;
        if options.parity != Parity::None {
            flags |= PARITY;
        }
        flags |= match options.flow_control {
            FlowControl::None => DTR_ENABLE | RTS_ENABLE,
            FlowControl::XonXoff => DTR_ENABLE | RTS_ENABLE | OUTX | INX | TX_CONTINUE_ON_XOFF,
            FlowControl::RtsCts => DTR_ENABLE | RTS_HANDSHAKE | OUTX_CTS,
            FlowControl::DsrDtr => DTR_HANDSHAKE | RTS_ENABLE | OUTX_DSR,
        };
        flags
    }

    pub(super) fn open(port: &str, options: &SerialOptions) -> Result<Box<dyn SerialLink>> {
        // `\\.\COM12`: ports above COM9 only open this way. `port` is a checked COM port name.
        let path = HSTRING::from(format!(r"\\.\{port}"));
        // SAFETY: opens a device by a name made here; the handle is owned by `Port`.
        let handle = unsafe {
            CreateFileW(
                &path,
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|err| {
            let why = match err.code().0 as u32 & 0xFFFF {
                2 | 3 => "it isn't there (unplugged?)".to_owned(),
                5 => "another program has it open".to_owned(),
                _ => err.message(),
            };
            CoreError::SerialPort(format!("{port} can't be opened: {why}"))
        })?;
        let link = Port { handle };
        let refused = |what: &str, err: windows::core::Error| {
            CoreError::SerialPort(format!("{port} refused {what}: {}", err.message()))
        };
        let mut dcb = DCB {
            DCBlength: std::mem::size_of::<DCB>() as u32,
            ..DCB::default()
        };
        // SAFETY: fills `dcb` for our own handle.
        unsafe { GetCommState(link.handle, &mut dcb) }.map_err(|e| refused("its settings", e))?;
        dcb.BaudRate = options.speed;
        dcb.ByteSize = options.data_bits;
        dcb.Parity = DCB_PARITY(match options.parity {
            Parity::None => 0,
            Parity::Odd => 1,
            Parity::Even => 2,
            Parity::Mark => 3,
            Parity::Space => 4,
        });
        dcb.StopBits = DCB_STOP_BITS(match options.stop_bits {
            StopBits::One => 0,
            StopBits::OnePointFive => 1,
            StopBits::Two => 2,
        });
        // The flags above bit 14 are reserved: kept as Windows had them.
        dcb._bitfield = (dcb._bitfield & !0x7FFF) | dcb_flags(options);
        dcb.XonChar = 0x11;
        dcb.XoffChar = 0x13;
        dcb.XonLim = 2048;
        dcb.XoffLim = 512;
        // SAFETY: our own handle and a filled DCB.
        unsafe { SetCommState(link.handle, &dcb) }.map_err(|e| refused(&options.frame(), e))?;
        let timeouts = COMMTIMEOUTS {
            ReadIntervalTimeout: u32::MAX,
            ReadTotalTimeoutMultiplier: u32::MAX,
            ReadTotalTimeoutConstant: READ_WAIT.as_millis() as u32,
            WriteTotalTimeoutMultiplier: 0,
            WriteTotalTimeoutConstant: 5000,
        };
        // SAFETY: our own handle.
        unsafe { SetCommTimeouts(link.handle, &timeouts) }.map_err(|e| refused("its timeouts", e))?;
        // SAFETY: our own handle; drops what waited from before.
        let _ = unsafe { PurgeComm(link.handle, PURGE_RXCLEAR | PURGE_TXCLEAR) };
        Ok(Box::new(link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_sort_by_number() {
        let port = |n: &str| ComPort {
            name: n.into(),
            device: String::new(),
        };
        let names: Vec<String> = sorted(vec![port("COM10"), port("COM3"), port("COM1"), port("COM3")])
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(names, ["COM1", "COM3", "COM10"]);
    }

    #[cfg(windows)]
    #[test]
    fn the_dcb_flags_follow_the_flow_control() {
        use crate::sessions::kinds::FlowControl;
        let flags = |flow| {
            win::dcb_flags(&SerialOptions {
                flow_control: flow,
                ..SerialOptions::default()
            })
        };
        assert_eq!(flags(FlowControl::None), 1 | (1 << 4) | (1 << 12));
        assert_eq!(flags(FlowControl::RtsCts), 1 | (1 << 2) | (1 << 4) | (2 << 12));
        assert_eq!(flags(FlowControl::DsrDtr), 1 | (1 << 3) | (2 << 4) | (1 << 12));
        assert_ne!(flags(FlowControl::XonXoff) & (1 << 8), 0);
        let parity = win::dcb_flags(&SerialOptions {
            parity: crate::sessions::kinds::Parity::Even,
            ..SerialOptions::default()
        });
        assert_ne!(parity & 2, 0);
    }
}
