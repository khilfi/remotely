//! VM-30: a VirtualBox boot or install that hangs under Hyper-V. G7's hand check 4 saw a Windows Server 2022
//! clone stand at the firmware's logo with no disk writes for 17 minutes, until a reset by hand; S3 saw the same hang
//! at an install's restarts, with vCPU 0's run time (`/TM/CPU/00/cNsTotal` in `VBoxManage debugvm <vm> statistics`)
//! no longer moving. G6's hang reset knows only an install's points on its serial log, and a Linux clone has no serial
//! port at all, so the deploy watches that counter: one that stands still for [`super::DeployTuning::hang_silence`]
//! (3 minutes) while nothing else moved gets `controlvm reset`. A running guest, idle or not, moves it with the wall
//! clock (seen: 15 s every 15 s), so a counter that can't be read resets nothing, and neither does a VM that isn't
//! running (paused by the user, or by VirtualBox when the host's disk is full). One count of resets per VM, this
//! watch's and G6's known points' together, at most `max_hang_resets`; a refused reset is noted once.
//!
//! It runs only while the deploy waits anyway (item 1 of PR 101's review: the watch itself adds no time): in G6's
//! install watcher for every VirtualBox install (a Windows clone's first boot, Setup from an ISO, a golden image's
//! build) and in a Linux clone's wait for its address. A reset does: that wait starts again after it, so a clone that
//! hangs at every boot waits at most (1 + `max_hang_resets`) times the wait, and its note says "of its last reset". A VirtualBox reset counts in
//! `/VirtualBox/VMInfo/ResetCounter` as the guest's own do. Every Windows hang seen but one (S3; this package's three) stood at
//! one of Setup's restarts, which the hung guest hadn't counted: the reset finished that restart and was counted once,
//! so the install watcher counts it as Setup's (taking Remotely's resets off would wait for a restart that happened).

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::{Deployer, SHORT};
use crate::domain::PowerState;

/// vCPU 0's run time in nanoseconds, as VirtualBox's statistics name it.
pub const VCPU0_RUN_TIME: &str = "/TM/CPU/00/cNsTotal";

/// The counter named `name` in `VBoxManage debugvm <vm> statistics` output (one XML element per counter, its value in
/// `val` or `c`, whatever the attributes' order). `None` when it isn't there or isn't a number.
pub fn counter(xml: &str, name: &str) -> Option<u64> {
    let wanted = format!("name=\"{name}\"");
    xml.split('<')
        .find(|element| element.contains(&wanted))
        .and_then(|element| {
            ["val", "c"].iter().find_map(|attr| {
                let at = element.find(&format!(" {attr}=\""))? + attr.len() + 3;
                let end = element[at..].find('"')? + at;
                element[at..end].trim().parse().ok()
            })
        })
}

/// One VM's boot or install as watched so far.
#[derive(Debug, Default)]
pub(super) struct BootWatch {
    /// The counter's last value and when it last moved.
    last: Option<(u64, tokio::time::Instant)>,
    /// The resets this VM got for a hang, by this watch or G6's known points: together at most `max_hang_resets`.
    pub(super) resets: u32,
    /// Whether a reset that VirtualBox refused was noted already (once is enough).
    failed_noted: bool,
}

impl BootWatch {
    /// Starts the stillness clock again (after another reset, or while the VM isn't running).
    pub(super) fn restart(&mut self) {
        self.last = None;
    }
}

/// What a round of the watch did.
#[derive(Debug)]
pub(super) enum Hang {
    /// The VM was reset; its note.
    Reset(String),
    /// VirtualBox refused the reset; its note (said once).
    ResetFailed(String),
}

impl Deployer {
    /// One round of the watch (see the module): reads vCPU 0's counter and resets the VM once it has stood still for
    /// `hang_silence` while `quiet` (nothing else showed progress meanwhile), the VM is running (a paused VM's counter
    /// stands still too: its clock starts again) and the job isn't cancelled. `what` names what was reset in the note
    /// ("its first boot", "the install").
    pub(super) async fn first_boot_round(
        &self,
        key: &str,
        watch: &mut BootWatch,
        quiet: bool,
        what: &str,
        token: &CancellationToken,
    ) -> Option<Hang> {
        let tuning = self.tuning();
        if watch.resets >= tuning.max_hang_resets || token.is_cancelled() {
            return None;
        }
        let args = vec![
            "debugvm".to_owned(),
            key.to_owned(),
            "statistics".to_owned(),
            "--pattern".to_owned(),
            VCPU0_RUN_TIME.to_owned(),
        ];
        let read = tokio::select! {
            _ = token.cancelled() => return None,
            read = self.vbox(args, SHORT) => read,
        };
        let now = tokio::time::Instant::now();
        let Some(value) = read.ok().and_then(|xml| counter(&xml, VCPU0_RUN_TIME)) else {
            watch.restart();
            return None;
        };
        let still = match watch.last {
            Some((last, since)) if last == value => now.duration_since(since),
            _ => {
                watch.last = Some((value, now));
                return None;
            }
        };
        if still < tuning.hang_silence || !quiet {
            return None;
        }
        let still = about_minutes(still);
        self.reset_hung(
            key,
            watch,
            token,
            format!("reset {what} once vCPU 0 had stood still for {still} (VirtualBox under Hyper-V)"),
            format!("vCPU 0 stood still for {still}, but VirtualBox refused to reset {what}"),
        )
        .await
    }

    /// Resets a hung VM (this watch's, or G6's known points' in the install watcher), counted in `watch.resets`: only
    /// within `max_hang_resets`, only a VM VirtualBox says is running (item 4 of PR 101's review: a paused VM stands
    /// still too; its clock starts again) and only while the job isn't cancelled (item 8). `done` is the reset's note,
    /// `refused` the start of a refused one's, which is said once (item 7; re-review low 4 for the known points).
    pub(super) async fn reset_hung(
        &self,
        key: &str,
        watch: &mut BootWatch,
        token: &CancellationToken,
        done: String,
        refused: String,
    ) -> Option<Hang> {
        if watch.resets >= self.tuning().max_hang_resets || token.is_cancelled() {
            return None;
        }
        let running = tokio::select! {
            _ = token.cancelled() => return None,
            info = self.hypervisors.virtualbox().vm_info(key) => {
                info.is_ok_and(|i| i.power_state() == PowerState::Running)
            }
        };
        watch.restart();
        if !running || token.is_cancelled() {
            return None;
        }
        let reset = self
            .vbox(vec!["controlvm".into(), key.into(), "reset".into()], SHORT)
            .await;
        match reset {
            Ok(_) => {
                watch.resets += 1;
                Some(Hang::Reset(done))
            }
            Err(err) => {
                tracing::warn!(error = %err, "a VM that hung couldn't be reset");
                if watch.failed_noted {
                    return None;
                }
                watch.failed_noted = true;
                Some(Hang::ResetFailed(format!("{refused} ({err})")))
            }
        }
    }
}

/// `d` as "about N minutes", N rounded to the nearest minute (at least 1).
pub(super) fn about_minutes(d: Duration) -> String {
    let m = ((d.as_millis() + 30_000) / 60_000).max(1);
    format!("about {m} minute{}", if m == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_is_read_whatever_its_elements_look_like() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<Statistics>\n<U64 val=\"84211934400\" unit=\"ns\" name=\"/TM/CPU/00/cNsTotal\"/>\n<U64 val=\"9\" unit=\"ns\" name=\"/TM/CPU/01/cNsTotal\"/>\n</Statistics>\n";
        assert_eq!(counter(xml, VCPU0_RUN_TIME), Some(84_211_934_400));
        assert_eq!(counter(xml, "/TM/CPU/01/cNsTotal"), Some(9));
        // Another element kind, the name first.
        let other = "<Statistics><Counter name=\"/TM/CPU/00/cNsTotal\" unit=\"ns\" c=\"42\"/></Statistics>";
        assert_eq!(counter(other, VCPU0_RUN_TIME), Some(42));
        // Not there, not a number, or a VirtualBox error text: nothing.
        assert_eq!(counter("<Statistics>\n</Statistics>\n", VCPU0_RUN_TIME), None);
        assert_eq!(
            counter("<U64 val=\"x\" name=\"/TM/CPU/00/cNsTotal\"/>", VCPU0_RUN_TIME),
            None
        );
        assert_eq!(
            counter(
                "VBoxManage: error: Machine 'x' is not currently running",
                VCPU0_RUN_TIME
            ),
            None
        );
        // A longer name that starts the same isn't it.
        assert_eq!(
            counter("<U64 val=\"1\" name=\"/TM/CPU/00/cNsTotalStat\"/>", VCPU0_RUN_TIME),
            None
        );
    }
}
