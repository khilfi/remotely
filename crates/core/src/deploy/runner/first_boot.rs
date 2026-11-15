//! VM-30: a clone's first boot that hangs on VirtualBox under Hyper-V. G7's hand check saw a Windows Server 2022 clone
//! stand at the firmware's logo with no disk writes for 17 minutes, until a reset by hand; S3 saw the same hang at an
//! install's restarts, with vCPU 0's run time (`/TM/CPU/00/cNsTotal` in `VBoxManage debugvm <vm> statistics`) no
//! longer moving. G6's hang reset knows only an install's points on its serial log, and a Linux clone has no serial
//! port at all, so a clone's first boot is watched by that counter: one that stands still for
//! [`super::DeployTuning::hang_silence`] (3 minutes) gets `controlvm reset`, at most `max_hang_resets` times. A guest
//! that runs, idle or not, moves it (its timer wakes vCPU 0 many times a second), so a counter that can't be read
//! resets nothing.
//!
//! The watch runs while the deploy waits for the clone anyway (a Windows clone's install watcher, a Linux clone's
//! wait for its address) and, for a VirtualBox clone it wouldn't wait for, for [`super::DeployTuning::first_boot_watch`].

use std::time::Duration;

use super::{Deployer, SHORT};

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

/// One clone's first boot as watched so far.
#[derive(Debug, Default)]
pub(super) struct BootWatch {
    /// The counter's last value and when it last moved.
    last: Option<(u64, tokio::time::Instant)>,
    pub(super) resets: u32,
}

impl Deployer {
    /// One round of the watch (see the module): reads vCPU 0's counter and resets the VM once it has stood still for
    /// `hang_silence`, while `quiet` (nothing else showed progress meanwhile). Returns the note of a reset.
    pub(super) async fn first_boot_round(&self, key: &str, watch: &mut BootWatch, quiet: bool) -> Option<String> {
        let tuning = self.tuning();
        if watch.resets >= tuning.max_hang_resets {
            return None;
        }
        let args = vec![
            "debugvm".to_owned(),
            key.to_owned(),
            "statistics".to_owned(),
            "--pattern".to_owned(),
            VCPU0_RUN_TIME.to_owned(),
        ];
        let now = tokio::time::Instant::now();
        let Some(value) = self
            .vbox(args, SHORT)
            .await
            .ok()
            .and_then(|xml| counter(&xml, VCPU0_RUN_TIME))
        else {
            watch.last = None;
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
        watch.last = None;
        let reset = self
            .vbox(vec!["controlvm".into(), key.into(), "reset".into()], SHORT)
            .await;
        match reset {
            Ok(_) => {
                watch.resets += 1;
                Some(format!(
                    "reset its first boot once vCPU 0 had stood still for {} (VirtualBox under Hyper-V)",
                    minutes(still)
                ))
            }
            Err(err) => {
                tracing::warn!(error = %err, "a clone's hung first boot couldn't be reset");
                None
            }
        }
    }
}

/// `d` in whole minutes, rounded up.
pub(super) fn minutes(d: Duration) -> String {
    let m = d.as_millis().div_ceil(60_000);
    format!("{m} minute{}", if m == 1 { "" } else { "s" })
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
