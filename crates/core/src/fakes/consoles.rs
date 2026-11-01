//! SS-12 fakes: a launcher that records each `.rdp` file and viewer command instead of starting it, and COM ports
//! in memory. No test starts `mstsc.exe` or a viewer, or opens a real COM port.

use std::collections::HashMap;
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::adapters::launcher::{ConsoleLauncher, Launch, LaunchedWindow};
use crate::adapters::serial::{ComPort, SerialLink, SerialPorts, READ_WAIT};
use crate::error::{CoreError, Result};
use crate::locks;
use crate::sessions::kinds::SerialOptions;

/// Records what would start. Each window stays "open" until [`FakeLauncher::close_all`] (or `close`).
#[derive(Clone, Default)]
pub struct FakeLauncher {
    inner: Arc<LauncherInner>,
}

#[derive(Default)]
struct LauncherInner {
    launched: Mutex<Vec<Launch>>,
    windows: Mutex<Vec<watch::Sender<bool>>>,
    failing: Mutex<Option<String>>,
}

struct FakeWindow(watch::Receiver<bool>);

#[async_trait]
impl LaunchedWindow for FakeWindow {
    async fn wait(mut self: Box<Self>) {
        while !*self.0.borrow_and_update() {
            if self.0.changed().await.is_err() {
                return;
            }
        }
    }
}

impl FakeLauncher {
    /// Everything launched so far, in order.
    pub fn launched(&self) -> Vec<Launch> {
        locks::lock(&self.inner.launched).clone()
    }

    /// The `.rdp` files' text, in order.
    pub fn rdp_files(&self) -> Vec<String> {
        self.launched()
            .into_iter()
            .filter_map(|l| match l {
                Launch::Rdp { file, .. } => Some(file),
                Launch::Viewer { .. } => None,
            })
            .collect()
    }

    /// Waits until `n` programs were launched, for at most `wait`.
    pub async fn wait_for(&self, n: usize, wait: Duration) -> Vec<Launch> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let launched = self.launched();
            if launched.len() >= n || tokio::time::Instant::now() >= deadline {
                return launched;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The `n`th window (from 0) closes.
    pub fn close(&self, n: usize) {
        if let Some(window) = locks::lock(&self.inner.windows).get(n) {
            let _ = window.send(true);
        }
    }

    /// Every window closes.
    pub fn close_all(&self) {
        for window in locks::lock(&self.inner.windows).iter() {
            let _ = window.send(true);
        }
    }

    /// From now on nothing starts, with this message.
    pub fn set_failing(&self, message: Option<&str>) {
        *locks::lock(&self.inner.failing) = message.map(str::to_owned);
    }
}

#[async_trait]
impl ConsoleLauncher for FakeLauncher {
    async fn launch(&self, launch: Launch) -> Result<Box<dyn LaunchedWindow>> {
        if let Some(message) = locks::lock(&self.inner.failing).clone() {
            return Err(CoreError::Console(message));
        }
        locks::lock(&self.inner.launched).push(launch);
        let (tx, rx) = watch::channel(false);
        locks::lock(&self.inner.windows).push(tx);
        Ok(Box::new(FakeWindow(rx)))
    }
}

/// A device on a fake COM port: what it was sent, and what it sends back.
#[derive(Clone)]
pub struct FakeSerialDevice {
    inner: Arc<DeviceInner>,
}

struct DeviceInner {
    name: String,
    received: Mutex<Vec<u8>>,
    breaks: Mutex<u32>,
    /// Echoes what it gets, as a router's console does.
    echo: Mutex<bool>,
    /// The open link's side: bytes for it to read.
    to_link: Mutex<Option<std_mpsc::Sender<Vec<u8>>>>,
    unplugged: Mutex<bool>,
    /// The settings it was last opened with.
    opened_with: Mutex<Option<SerialOptions>>,
    /// How long closing the port takes.
    release_delay: Mutex<Duration>,
}

impl FakeSerialDevice {
    /// Everything it was sent.
    pub fn received(&self) -> Vec<u8> {
        locks::lock(&self.inner.received).clone()
    }

    /// How many breaks it saw.
    pub fn breaks(&self) -> u32 {
        *locks::lock(&self.inner.breaks)
    }

    pub fn set_echo(&self, echo: bool) {
        *locks::lock(&self.inner.echo) = echo;
    }

    /// Sends bytes to whoever has the port open; false when nobody has.
    pub fn send(&self, bytes: &[u8]) -> bool {
        locks::lock(&self.inner.to_link)
            .as_ref()
            .is_some_and(|tx| tx.send(bytes.to_vec()).is_ok())
    }

    pub fn is_open(&self) -> bool {
        locks::lock(&self.inner.to_link).is_some()
    }

    /// The settings the port was last opened with.
    pub fn opened_with(&self) -> Option<SerialOptions> {
        *locks::lock(&self.inner.opened_with)
    }

    /// Closing the port takes this long from now on (a write held up by flow control), so it stays taken meanwhile.
    pub fn set_release_delay(&self, delay: Duration) {
        *locks::lock(&self.inner.release_delay) = delay;
    }

    /// The adapter is pulled out: an open link fails, and opening fails until it is plugged in again.
    pub fn unplug(&self, unplugged: bool) {
        *locks::lock(&self.inner.unplugged) = unplugged;
    }

    /// Waits until it received `text`, for at most `wait`.
    pub async fn wait_for(&self, text: &[u8], wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if self.received().windows(text.len()).any(|w| w == text) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

struct FakeLink {
    device: FakeSerialDevice,
    from_device: std_mpsc::Receiver<Vec<u8>>,
    /// What the device sent that didn't fit in the last read.
    pending: Vec<u8>,
}

impl SerialLink for FakeLink {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if *locks::lock(&self.device.inner.unplugged) {
            return Err(std::io::Error::other("the device is not connected"));
        }
        if self.pending.is_empty() {
            match self.from_device.recv_timeout(READ_WAIT) {
                Ok(bytes) => self.pending = bytes,
                Err(_) => return Ok(0),
            }
        }
        let n = self.pending.len().min(buf.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }

    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        if *locks::lock(&self.device.inner.unplugged) {
            return Err(std::io::Error::other("the device is not connected"));
        }
        locks::lock(&self.device.inner.received).extend_from_slice(data);
        if *locks::lock(&self.device.inner.echo) {
            let echoed: Vec<u8> = data
                .iter()
                .flat_map(|b| if *b == b'\r' { b"\r\n".to_vec() } else { vec![*b] })
                .collect();
            self.pending.extend(echoed);
        }
        Ok(())
    }

    fn send_break(&mut self) -> std::io::Result<()> {
        *locks::lock(&self.device.inner.breaks) += 1;
        Ok(())
    }
}

impl Drop for FakeLink {
    /// Lets go of the port, after [`FakeSerialDevice::set_release_delay`] (a write held up by flow control).
    fn drop(&mut self) {
        let delay = *locks::lock(&self.device.inner.release_delay);
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        locks::lock(&self.device.inner.to_link).take();
    }
}

/// COM ports in memory, opened one program at a time like Windows'.
#[derive(Clone, Default)]
pub struct FakeSerialPorts {
    devices: Arc<Mutex<HashMap<String, FakeSerialDevice>>>,
}

impl FakeSerialPorts {
    /// Adds a port (`COM3`) and returns its device.
    pub fn with_port(&self, name: &str) -> FakeSerialDevice {
        let device = FakeSerialDevice {
            inner: Arc::new(DeviceInner {
                name: name.to_owned(),
                received: Mutex::default(),
                breaks: Mutex::default(),
                echo: Mutex::new(false),
                to_link: Mutex::default(),
                unplugged: Mutex::new(false),
                opened_with: Mutex::default(),
                release_delay: Mutex::default(),
            }),
        };
        locks::lock(&self.devices).insert(name.to_ascii_uppercase(), device.clone());
        device
    }
}

impl SerialPorts for FakeSerialPorts {
    fn list(&self) -> Result<Vec<ComPort>> {
        let ports = locks::lock(&self.devices)
            .values()
            .map(|d| ComPort {
                name: d.inner.name.clone(),
                device: format!(r"\Device\FakeSerial{}", d.inner.name.trim_start_matches("COM")),
            })
            .collect();
        Ok(crate::adapters::serial::sorted(ports))
    }

    fn open(&self, port: &str, options: &SerialOptions) -> Result<Box<dyn SerialLink>> {
        let device = locks::lock(&self.devices)
            .get(&port.to_ascii_uppercase())
            .cloned()
            .ok_or_else(|| CoreError::SerialPort(format!("{port} can't be opened: it isn't there (unplugged?)")))?;
        if *locks::lock(&device.inner.unplugged) {
            return Err(CoreError::SerialPort(format!(
                "{port} can't be opened: it isn't there (unplugged?)"
            )));
        }
        let mut to_link = locks::lock(&device.inner.to_link);
        if to_link.is_some() {
            return Err(CoreError::SerialPort(format!(
                "{port} can't be opened: another program has it open"
            )));
        }
        let (tx, rx) = std_mpsc::channel();
        *to_link = Some(tx);
        drop(to_link);
        *locks::lock(&device.inner.opened_with) = Some(*options);
        Ok(Box::new(FakeLink {
            device,
            from_device: rx,
            pending: Vec::new(),
        }))
    }
}
