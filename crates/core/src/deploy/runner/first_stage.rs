//! VM-30: a Windows Setup reset in the middle of its first stage (windowsPE). The hang watch ([`super::first_boot`])
//! resets a VirtualBox VM whose vCPU 0 stands still. Nearly every Windows hang seen stood at one of Setup's restarts,
//! and the reset finished that restart. PR 101's hand check 6 saw both vCPUs stop mid-way through windowsPE instead,
//! before Setup had made the disk bootable: after the reset the firmware started the install ISO again, and Setup
//! asked "It looks like you started an upgrade and booted from installation media ... click Yes ... click No" and
//! waited until the install's time limit. Hand check 8 reset a build there on purpose and answered No (the N key, the
//! message box's mnemonic): the question closed, and Setup's window then showed its spinner and did nothing (no disk
//! writes, no reads of the ISO, no network) for 15 minutes. Setup can't get past it, so the install fails at once.
//!
//! So when the hang watch resets a Windows Setup from an ISO before Setup's first restart was counted (VirtualBox's
//! reset counter read 0), the watcher looks for Setup going on: a restart counted beyond the reset, words on the serial
//! port (the EFI firmware's escapes at each boot don't count), or the guest writing to its disks
//! (`debugvm <vm> statistics --pattern /Public/Storage/*BytesWritten`, every disk's `BytesWritten` summed; the count
//! keeps across a reset). A restart or a line means Setup went on from the disk: the watch ends. Writes only start its
//! clock again (Setup writes a little as it starts). Nothing written for [`super::DeployTuning::setup_stuck`] of rounds
//! in which vCPU 0 moved (a hung or paused guest is the hang watch's) fails the install, saying why, instead of at its
//! time limit; the failure's screenshot shows the question. A round whose disk writes can't be read decides nothing,
//! so a VirtualBox without those statistics is never failed by this. Once per install.
//!
//! A hang at Setup's first restart after all is not mistaken for it: Windows starts from the disk, and specialize and
//! OOBE write to it all along until the next restart is counted.

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{Deployer, SHORT};

/// What Setup asks after a reset in the middle of its first stage.
pub const UPGRADE_QUESTION: &str = "It looks like you started an upgrade and booted from installation media";

/// VirtualBox's statistics for what the guest wrote to each disk (`/Public/Storage/AHCI0/Port0/BytesWritten`, one per
/// attached disk; shown once a disk was written to).
pub const DISK_WRITES: &str = "/Public/Storage/*BytesWritten";

/// The bytes written to every disk in `debugvm <vm> statistics` output: the sum of each `/Public/Storage/...` counter
/// ending in `BytesWritten`, `None` when there is none.
pub fn disk_writes(xml: &str) -> Option<u64> {
    let mut found = None;
    for element in xml.split('<') {
        let Some(at) = element.find("name=\"") else { continue };
        let name = element[at + 6..].split('"').next().unwrap_or_default();
        if !(name.starts_with("/Public/Storage/") && name.ends_with("/BytesWritten")) {
            continue;
        }
        let value = ["c", "val"].iter().find_map(|attr| {
            let at = element.find(&format!(" {attr}=\""))? + attr.len() + 3;
            let end = element[at..].find('"')? + at;
            element[at..end].trim().parse::<u64>().ok()
        });
        if let Some(value) = value {
            found = Some(found.unwrap_or(0u64).saturating_add(value));
        }
    }
    found
}

/// A Windows Setup from an ISO that the hang watch reset before Setup's first restart (see the module).
#[derive(Debug)]
pub(super) struct FirstStageReset {
    /// The reset count once the reset is counted (the count before it, plus one).
    counted: u32,
    /// The disk writes last read.
    writes: Option<u64>,
    /// Since when nothing moved while the guest ran and its writes could be read.
    still_since: Instant,
    over: bool,
}

impl FirstStageReset {
    /// The hang watch reset Setup when the reset counter read `count` (0: Setup's first restart wasn't counted).
    pub(super) fn after_reset(count: u32) -> Self {
        Self {
            counted: count + 1,
            writes: None,
            still_since: Instant::now(),
            over: false,
        }
    }
}

impl Deployer {
    /// One round (see the module). `count` is VirtualBox's reset count now, `grew` whether words reached the serial log
    /// this round and `runs` whether vCPU 0 moved at its last read. `Some(why)` when the install fails.
    pub(super) async fn first_stage_round(
        &self,
        key: &str,
        reset: &mut FirstStageReset,
        count: u32,
        grew: bool,
        runs: bool,
        token: &CancellationToken,
    ) -> Option<String> {
        if reset.over || token.is_cancelled() {
            return None;
        }
        if count > reset.counted || grew {
            // A restart beyond the reset, or a line from the installed system: Setup went on from the disk.
            reset.over = true;
            return None;
        }
        let args = vec![
            "debugvm".to_owned(),
            key.to_owned(),
            "statistics".to_owned(),
            "--pattern".to_owned(),
            DISK_WRITES.to_owned(),
        ];
        let read = tokio::select! {
            _ = token.cancelled() => return None,
            read = self.vbox(args, SHORT) => read,
        };
        let writes = read.ok().as_deref().and_then(disk_writes);
        let now = Instant::now();
        let wrote = match (reset.writes, writes) {
            (Some(before), Some(after)) => after != before,
            _ => true,
        };
        if writes.is_some() {
            reset.writes = writes;
        }
        // Writes (or none to compare), or a hung or paused guest (the hang watch's): the clock starts again.
        if wrote || !runs {
            reset.still_since = now;
            return None;
        }
        let still = now.duration_since(reset.still_since);
        if still < self.tuning().setup_stuck {
            return None;
        }
        reset.over = true;
        Some(format!(
            "Setup was reset in the middle of its first stage (windowsPE), before its disk could start Windows, so the VM started the install ISO again, and Setup has written nothing to the disk for {} since: it waits at \"{UPGRADE_QUESTION}\", which it doesn't get past (answering No leaves it idle). Delete the VM and deploy it again",
            super::first_boot::about_minutes(still)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_disks_writes_are_summed() {
        // As VirtualBox 7.2 prints them (hand check 8), with vCPU 0's counter in the same answer.
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<Statistics>\n<Counter c=\"9313299968\" unit=\"bytes\" vis=\"used\" name=\"/Public/Storage/AHCI0/Port0/BytesWritten\"/>\n<U64 val=\"893453325861\" unit=\"ns\" name=\"/TM/CPU/00/cNsTotal\"/>\n</Statistics>\n";
        assert_eq!(disk_writes(xml), Some(9_313_299_968));
        let two = "<Statistics><Counter c=\"10\" name=\"/Public/Storage/AHCI0/Port0/BytesWritten\"/><Counter c=\"5\" name=\"/Public/Storage/NVMe0/Port1/BytesWritten\"/><Counter c=\"7\" name=\"/Public/Storage/AHCI0/Port1/BytesRead\"/></Statistics>";
        assert_eq!(disk_writes(two), Some(15));
        // None written yet (VirtualBox shows a counter once it is used), or an error: nothing to compare.
        assert_eq!(
            disk_writes("<?xml version=\"1.0\"?>\n<Statistics>\n</Statistics>\n"),
            None
        );
        assert_eq!(
            disk_writes("VBoxManage: error: Machine 'x' is not currently running"),
            None
        );
        assert_eq!(
            disk_writes("<Counter c=\"x\" name=\"/Public/Storage/AHCI0/Port0/BytesWritten\"/>"),
            None
        );
    }
}
