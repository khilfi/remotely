//! SS-03 (R9): wakes the terminals that wait to reconnect when Windows resumes from sleep or this PC
//! gets a new IP address (Wi-Fi or a VPN came back), so a laptop opened at a customer site reconnects
//! at once instead of after its backoff. Connected terminals are left alone, and each woken one waits
//! a short random moment first, so panes behind one jump host don't all log in at the same instant
//! (`Terminals::wake_reconnects`).
//!
//! Windows calls back on its own threads; a callback only sends a note on a channel. A task lets the
//! notes settle for [`SETTLE`] (one adapter coming up reports several addresses, a resume is followed
//! by the network) and then wakes the terminals once.

use std::sync::Arc;
use std::time::Duration;

use remotely_core::terminal::WakeReason;
use remotely_core::Core;
use tokio::sync::mpsc;

/// Notes that arrive within this long of each other wake the terminals once.
const SETTLE: Duration = Duration::from_secs(2);

/// Starts listening for resume and new-address notifications for as long as the app runs.
pub fn watch(core: Arc<Core>) {
    let (tx, mut rx) = mpsc::unbounded_channel::<WakeReason>();
    #[cfg(windows)]
    win::register(tx);
    #[cfg(not(windows))]
    drop(tx);
    tauri::async_runtime::spawn(async move {
        while let Some(first) = rx.recv().await {
            let mut reason = first;
            loop {
                match tokio::time::timeout(SETTLE, rx.recv()).await {
                    // A resume says more than the network change that follows it.
                    Ok(Some(next)) => reason = reason.or(next),
                    Ok(None) => return,
                    Err(_) => break,
                }
            }
            let woken = core.terminals.wake_reconnects(reason);
            tracing::info!(
                reason = reason.as_str(),
                terminals = woken,
                "woke terminals waiting to reconnect"
            );
        }
    });
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    use remotely_core::terminal::WakeReason;
    use tokio::sync::mpsc::UnboundedSender;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows::Win32::NetworkManagement::IpHelper::{
        MibAddInstance, NotifyUnicastIpAddressChange, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;
    use windows::Win32::System::Power::{PowerRegisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS};
    use windows::Win32::UI::WindowsAndMessaging::{
        DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND,
    };

    /// Registers both callbacks. Their context (the channel) and the registrations live as long as
    /// the app, so they are leaked on purpose. A registration Windows refuses is logged and skipped:
    /// terminals still reconnect on their own schedule.
    pub(super) fn register(tx: UnboundedSender<WakeReason>) {
        let context = Box::into_raw(Box::new(tx)).cast::<c_void>();
        let params = Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(on_power),
            Context: context,
        }));
        let mut power = std::ptr::null_mut::<c_void>();
        // SAFETY: `params` and the context it points to are never freed, as the registration needs.
        let result = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                HANDLE(std::ptr::from_mut(params).cast()),
                &mut power,
            )
        };
        if result != ERROR_SUCCESS {
            tracing::warn!(code = result.0, "could not listen for Windows resuming from sleep");
        }
        let mut network = HANDLE::default();
        // SAFETY: as above, the context outlives the registration.
        let result =
            unsafe { NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), Some(context), false, &mut network) };
        if result != ERROR_SUCCESS {
            tracing::warn!(code = result.0, "could not listen for network changes");
        }
    }

    /// SAFETY (both callbacks): Windows passes back the context given at registration, a leaked
    /// `UnboundedSender`, which is never freed.
    unsafe fn sender<'a>(context: *const c_void) -> Option<&'a UnboundedSender<WakeReason>> {
        // SAFETY: see above.
        unsafe { context.cast::<UnboundedSender<WakeReason>>().as_ref() }
    }

    unsafe extern "system" fn on_power(context: *const c_void, kind: u32, _setting: *const c_void) -> u32 {
        if kind == PBT_APMRESUMEAUTOMATIC || kind == PBT_APMRESUMESUSPEND {
            // SAFETY: see `sender`.
            if let Some(tx) = unsafe { sender(context) } {
                let _ = tx.send(WakeReason::Resumed);
            }
        }
        ERROR_SUCCESS.0
    }

    unsafe extern "system" fn on_address(
        context: *const c_void,
        _row: *const MIB_UNICASTIPADDRESS_ROW,
        kind: MIB_NOTIFICATION_TYPE,
    ) {
        // An address that went away gives a waiting terminal nothing new to reach.
        if kind == MibAddInstance {
            // SAFETY: see `sender`.
            if let Some(tx) = unsafe { sender(context) } {
                let _ = tx.send(WakeReason::NetworkChanged);
            }
        }
    }
}
