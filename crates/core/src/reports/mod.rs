//! 0.7.0 F6: what an engineer hands over at the end of an engagement. Three exports of one workspace each (rule 8: every
//! read takes the `ctx` the shell passes, the shown workspace's at the time of the call):
//!
//! * **FD-05 inventory to Excel** ([`inventory`], [`xlsx`]): VMs, hosts, networks, health checks and, on request,
//!   installed packages, from what is stored; "Read again first" reads the SSH hosts now.
//! * **BX-12 Ansible inventory** ([`ansible`]): YAML or INI from BX-01's targets, grouped by folder, tag, environment
//!   and workspace, never a secret.
//! * **FD-08 handover pack** ([`pack`]): a zip with one self-contained `index.html` (cover, inventory, the topology
//!   diagram, what was done in the chosen dates, the checks' uptime, the notes marked for it), `inventory.xlsx` and a
//!   CSV per table.
//!
//! All three only read: no tier, nothing on the bus, allowed by the read-only lock (FD-03), like the audit log's and
//! FD-07's exports. Each is audited `data_exported` once written. The file's place comes from the shell's save dialog
//! (never from the window), is refused inside a Git working tree ([`save_guard`]) and is written through a `.part`
//! that takes its name only when it is whole. Every text cell is [`table::clean`]ed (secrets redacted), so no password,
//! key or token in a name, tag, note or output reaches a file.

pub mod activity;
pub mod ansible;
pub mod html;
pub mod inventory;
pub mod pack;
pub mod table;
pub mod topology;
pub mod xlsx;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

use crate::bulk::{BulkRuns, TargetPicks};
use crate::domain::{Context, Environment};
use crate::error::{CoreError, Result};
use crate::host_details::HostDetails;
use crate::host_networks::HostNetworks;
use crate::notes::Notes;
use crate::save_guard::{self, Saved};
use crate::sessions::{SessionKind, SessionRecord};
use crate::store::{self, NewAuditEntry, Store};

pub use ansible::{AnsibleFormat, GroupBy};
pub use inventory::{InventoryOptions, ReadControl, ReadProgress, ReadSummary};

/// Times in a report, in the offset of the PC that made it (the window gives it, as `Date` sees it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportClock {
    offset: UtcOffset,
}

impl ReportClock {
    /// `minutes` east of UTC (UTC+08:00 is 480); out of range is UTC.
    pub fn new(minutes: i32) -> Self {
        let offset = minutes
            .checked_mul(60)
            .and_then(|s| UtcOffset::from_whole_seconds(s).ok())
            .unwrap_or(UtcOffset::UTC);
        Self { offset }
    }

    /// `UTC`, `UTC+08:00`, `UTC-05:00`.
    pub fn zone(&self) -> String {
        if self.offset.is_utc() {
            return "UTC".into();
        }
        let (h, m, _) = self.offset.as_hms();
        let sign = if self.offset.is_negative() { '-' } else { '+' };
        format!("UTC{sign}{:02}:{:02}", h.unsigned_abs(), m.unsigned_abs())
    }

    fn format(&self, t: OffsetDateTime) -> String {
        let t = t.to_offset(self.offset);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute()
        )
    }

    /// `2026-11-01 18:04` for RFC 3339 text; text that isn't a time as it is.
    pub fn at(&self, rfc3339: &str) -> String {
        match OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339) {
            Ok(t) => self.format(t),
            Err(_) => rfc3339.to_owned(),
        }
    }

    /// The same for Unix milliseconds.
    pub fn at_ms(&self, ms: i64) -> String {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
            .map(|t| self.format(t))
            .unwrap_or_default()
    }

    /// `1 Nov 2026`.
    pub fn date_ms(&self, ms: i64) -> String {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
            .map(|t| {
                let t = t.to_offset(self.offset);
                let month = match u8::from(t.month()) {
                    1 => "Jan",
                    2 => "Feb",
                    3 => "Mar",
                    4 => "Apr",
                    5 => "May",
                    6 => "Jun",
                    7 => "Jul",
                    8 => "Aug",
                    9 => "Sep",
                    10 => "Oct",
                    11 => "Nov",
                    _ => "Dec",
                };
                format!("{} {month} {}", t.day(), t.year())
            })
            .unwrap_or_default()
    }

    /// `2026-11-01` for a file name.
    fn file_date(&self, ms: i64) -> String {
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
            .map(|t| {
                let t = t.to_offset(self.offset);
                format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
            })
            .unwrap_or_default()
    }

    /// `secs` before the RFC 3339 time `at` (when a host booted: its read less its uptime).
    pub fn before(&self, at: &str, secs: u64) -> Option<String> {
        let t = OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339).ok()?;
        let back = t.checked_sub(time::Duration::seconds(i64::try_from(secs).ok()?))?;
        Some(self.format(back))
    }
}

/// Unix milliseconds now.
fn now_ms() -> i64 {
    i64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

/// Unix milliseconds as RFC 3339 text in UTC, as the store keeps times.
fn rfc3339_ms(ms: i64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .ok_or_else(|| CoreError::InvalidInput("Choose dates between 1970 and 9999.".into()))
}

/// What each export is, for its file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReportKind {
    Inventory,
    Ansible,
    Handover,
}

/// `remotely-inventory-Acme-Lab-2026-11-01.xlsx`: the workspace's words joined by `-`, safe for any file system.
/// FD-03: `None` while presenting (`remotely-inventory-2026-11-01.xlsx`): the save dialog is Windows' own, out of the
/// masker's reach, and a workspace may be named after a customer.
pub fn file_name(kind: ReportKind, workspace: Option<&str>, date: &str, extension: &str) -> String {
    let what = match kind {
        ReportKind::Inventory => "inventory",
        ReportKind::Ansible => "ansible",
        ReportKind::Handover => "handover",
    };
    let Some(workspace) = workspace else {
        return format!("remotely-{what}-{date}.{extension}");
    };
    let words: Vec<String> = workspace
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect();
    let workspace: String = if words.is_empty() {
        "workspace".into()
    } else {
        words.join("-").chars().take(40).collect()
    };
    format!("remotely-{what}-{workspace}-{date}.{extension}")
}

/// The file a save dialog's answer names, with the first of `extensions` added when the name has none of them (a name
/// given an extension here never replaces a file the dialog didn't ask about).
pub fn chosen_path(chosen: &Path, extensions: &[&str]) -> Result<std::path::PathBuf> {
    let ok = |e: &std::ffi::OsStr| extensions.iter().any(|x| e.eq_ignore_ascii_case(x));
    if chosen.extension().is_some_and(ok) {
        return Ok(chosen.to_owned());
    }
    let extension = extensions.first().copied().unwrap_or("txt");
    let mut path = chosen.to_owned();
    let name = path
        .file_name()
        .map(|n| format!("{}.{extension}", n.to_string_lossy()))
        .ok_or_else(|| CoreError::InvalidInput("Choose a file name.".into()))?;
    path.set_file_name(name);
    if path.exists() {
        return Err(CoreError::InvalidInput(format!(
            "{} is there already. Choose another name, or choose that file itself to replace it.",
            path.display()
        )));
    }
    Ok(path)
}

/// What the dialogs show before anything is made.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportsOverview {
    pub workspace: String,
    /// The handover pack's "prepared by" until one is typed.
    pub prepared_by: Option<String>,
    pub vms: usize,
    pub sessions: usize,
    pub ssh_sessions: usize,
    pub checks: usize,
    /// FD-06: notes marked for the handover pack.
    pub handover_notes: usize,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct InventoryRequest {
    #[serde(flatten)]
    pub options: InventoryOptions,
    /// The window's offset from UTC in minutes (east positive), for the times in the file.
    pub utc_offset_minutes: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryExport {
    pub path: String,
    pub vms: usize,
    pub hosts: usize,
    pub networks: usize,
    pub checks: usize,
    pub packages: Option<usize>,
    pub read: Option<ReadSummary>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AnsibleRequest {
    /// BX-01's picks; none picked is every SSH session of the workspace.
    pub picks: TargetPicks,
    pub format: AnsibleFormat,
    pub group_by: GroupBy,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnsiblePreview {
    /// The file as it would be written.
    pub text: String,
    pub hosts: usize,
    pub groups: usize,
    /// What was left out, and why.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnsibleExport {
    pub path: String,
    pub hosts: usize,
    pub groups: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HandoverRequest {
    /// The first day's start and the day after the last one's start, in Unix ms (local days, from the window).
    pub from_ms: i64,
    pub to_ms: i64,
    pub utc_offset_minutes: i32,
    pub prepared_by: String,
    /// Jobs' outputs in the page (each capped); off by default.
    pub include_outputs: bool,
    /// What the pack's inventory reads now.
    pub inventory: InventoryOptions,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverPreview {
    pub jobs: usize,
    pub other_changes: usize,
    pub notes: usize,
    pub checks: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverExport {
    pub path: String,
    pub jobs: usize,
    pub notes: usize,
    /// The zip's members.
    pub files: Vec<String>,
    pub read: Option<ReadSummary>,
}

/// The longest range a pack covers.
pub const MAX_RANGE_DAYS: i64 = 366;
/// A "prepared by" holds at most this many characters.
pub const MAX_PREPARED_BY: usize = 120;

/// The exports.
pub struct Reports {
    store: Store,
    details: HostDetails,
    networks: HostNetworks,
    notes: Notes,
    bulk: BulkRuns,
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned())
}

impl Reports {
    pub fn new(store: Store, details: HostDetails, networks: HostNetworks, notes: Notes, bulk: BulkRuns) -> Self {
        Self {
            store,
            details,
            networks,
            notes,
            bulk,
        }
    }

    /// The counts the dialogs show, and the workspace's name.
    pub async fn overview(&self, ctx: &Context) -> Result<ReportsOverview> {
        let sessions = self.store.list_sessions(ctx).await?;
        Ok(ReportsOverview {
            workspace: self.store.workspace_name(ctx).await?,
            prepared_by: self.store.user_display_name(ctx).await?,
            vms: self.store.list_vms(ctx).await?.len(),
            ssh_sessions: sessions.iter().filter(|s| matches!(s.kind, SessionKind::Ssh)).count(),
            sessions: sessions.len(),
            checks: self.store.count_checks(ctx).await?,
            handover_notes: self.notes.for_handover(ctx).await?.len(),
        })
    }

    /// The name the save dialog offers; without the workspace while `presenting` (FD-03).
    pub async fn file_name(
        &self,
        ctx: &Context,
        kind: ReportKind,
        format: AnsibleFormat,
        utc_offset_minutes: i32,
        presenting: bool,
    ) -> Result<String> {
        let workspace = self.store.workspace_name(ctx).await?;
        let date = ReportClock::new(utc_offset_minutes).file_date(now_ms());
        let extension = match kind {
            ReportKind::Inventory => "xlsx",
            ReportKind::Ansible => format.extension(),
            ReportKind::Handover => "zip",
        };
        Ok(file_name(
            kind,
            (!presenting).then_some(workspace.as_str()),
            &date,
            extension,
        ))
    }

    async fn audit(&self, ctx: &Context, action: &str, detail: &str) -> Result<()> {
        self.store
            .append_audit(
                ctx,
                NewAuditEntry {
                    event: "data_exported",
                    action,
                    tier: None,
                    job_id: None,
                    targets: &[],
                    approval: None,
                    result: None,
                    detail: Some(detail),
                },
            )
            .await?;
        Ok(())
    }

    fn sources(&self) -> inventory::Sources<'_> {
        inventory::Sources {
            store: &self.store,
            details: &self.details,
            networks: &self.networks,
        }
    }

    /// FD-05: the inventory to `path` as an Excel workbook. Audited. `Cancelled`, with nothing written, once
    /// `control` is cancelled.
    pub async fn export_inventory(
        &self,
        ctx: &Context,
        path: &Path,
        request: InventoryRequest,
        made_by: &str,
        control: &ReadControl,
    ) -> Result<InventoryExport> {
        save_guard::refuse_repository(path, Saved::Inventory)?;
        let clock = ReportClock::new(request.utc_offset_minutes);
        let workspace = self.store.workspace_name(ctx).await?;
        let data = inventory::collect(&self.sources(), ctx, request.options, &clock, now_ms(), control).await?;
        control.check()?;
        let title = format!("Inventory: {workspace}, made with {made_by}");
        let sheets: Vec<table::Sheet> = data.sheets().into_iter().cloned().collect();
        let bytes = tokio::task::spawn_blocking(move || {
            let refs: Vec<&table::Sheet> = sheets.iter().collect();
            xlsx::workbook(&title, &refs)
        })
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the Excel file could not be made: {err}")))??;
        // Checked again: the folder could have become a working tree while the hosts were read.
        save_guard::refuse_repository(path, Saved::Inventory)?;
        write_bytes(path, bytes).await?;
        let report = InventoryExport {
            path: path.display().to_string(),
            vms: data.vms.rows.len(),
            hosts: data.hosts.rows.len(),
            networks: data.networks.rows.len(),
            checks: data.checks.rows.len(),
            packages: data.packages.as_ref().map(|p| p.rows.len()),
            read: data.read.clone(),
            notes: data.notes.clone(),
        };
        let mut detail = format!(
            "{}, {}, {}, {}",
            plural(report.vms, "VM"),
            plural(report.hosts, "host"),
            plural(report.networks, "network"),
            plural(report.checks, "health check")
        );
        if let Some(read) = &report.read {
            detail.push_str(&format!(", {} of {} SSH hosts read again", read.read, read.asked));
        }
        if let Some(p) = report.packages {
            detail.push_str(&format!(", {}", plural(p, "package")));
        }
        detail.push_str(&format!(", to {}", file_label(path)));
        self.audit(ctx, "Exported the inventory to Excel", &detail).await?;
        Ok(report)
    }

    /// BX-12: the inventory of the picked sessions (every SSH session when none is picked).
    async fn ansible_inventory(&self, ctx: &Context, request: &AnsibleRequest) -> Result<ansible::Inventory> {
        let all = self.store.list_sessions(ctx).await?;
        let folders = self.store.list_session_folders(ctx).await?;
        let workspace = self.store.workspace_name(ctx).await?;
        let picks_empty = request.picks == TargetPicks::default();
        let (ids, mut notes): (Vec<Uuid>, Vec<String>) = if picks_empty {
            let others = all.iter().filter(|s| !matches!(s.kind, SessionKind::Ssh)).count();
            let mut notes = Vec::new();
            if others > 0 {
                notes.push(format!(
                    "{} of other kinds (remote desktop, VNC, Telnet, serial) left out: the inventory takes SSH sessions.",
                    plural(others, "session")
                ));
            }
            (
                all.iter()
                    .filter(|s| matches!(s.kind, SessionKind::Ssh))
                    .map(|s| s.id)
                    .collect(),
                notes,
            )
        } else {
            let resolved = self.bulk.resolve(ctx, &request.picks).await?;
            let mut notes = resolved.notes;
            for vm in &resolved.vms_without_session {
                notes.push(format!("{}: no session reaches this VM, so it was left out.", vm.name));
            }
            for vm in &resolved.vms_unconfirmed {
                notes.push(format!(
                    "{}: its session {} was linked by its address and isn't confirmed yet, so it was left out.",
                    vm.name, vm.session_name
                ));
            }
            (resolved.hosts.iter().map(|h| h.session_id).collect(), notes)
        };
        let by_id: HashMap<Uuid, &SessionRecord> = all.iter().map(|s| (s.id, s)).collect();
        let mut seen = HashSet::new();
        let hosts: Vec<&SessionRecord> = ids
            .iter()
            .filter(|id| seen.insert(**id))
            .filter_map(|id| by_id.get(id).copied())
            .collect();
        let vms: HashMap<String, ansible::LinkedVm> = self
            .store
            .list_vms(ctx)
            .await?
            .into_iter()
            .map(|vm| {
                let linked = ansible::LinkedVm {
                    protected: vm.protected,
                    prod: vm.environment == Environment::Prod,
                };
                (vm.id, linked)
            })
            .collect();
        let made_at = ReportClock::new(0).at_ms(now_ms());
        let mut inventory = ansible::build(
            &hosts,
            &all,
            &folders,
            &vms,
            &workspace,
            request.group_by,
            &format!("{made_at} UTC"),
        );
        notes.append(&mut inventory.notes);
        inventory.notes = notes.iter().map(|n| table::clean(n)).collect();
        Ok(inventory)
    }

    /// BX-12: the file as it would be written, for the dialog.
    pub async fn ansible_preview(&self, ctx: &Context, request: &AnsibleRequest) -> Result<AnsiblePreview> {
        let inventory = self.ansible_inventory(ctx, request).await?;
        let (text, notes) = ansible::render(&inventory, request.format);
        Ok(AnsiblePreview {
            text,
            hosts: inventory.hosts.len(),
            groups: inventory.groups.len(),
            notes,
        })
    }

    /// BX-12: the inventory to `path`. Audited.
    pub async fn export_ansible(&self, ctx: &Context, path: &Path, request: &AnsibleRequest) -> Result<AnsibleExport> {
        save_guard::refuse_repository(path, Saved::Ansible)?;
        let inventory = self.ansible_inventory(ctx, request).await?;
        if inventory.hosts.is_empty() {
            return Err(CoreError::InvalidInput(
                "No SSH session can go in the inventory: pick sessions, or VMs linked to one.".into(),
            ));
        }
        let (text, notes) = ansible::render(&inventory, request.format);
        write_bytes(path, text.into_bytes()).await?;
        let format = match request.format {
            AnsibleFormat::Yaml => "YAML",
            AnsibleFormat::Ini => "INI",
        };
        let detail = format!(
            "{} in {} ({format}), to {}",
            plural(inventory.hosts.len(), "host"),
            plural(inventory.groups.len(), "group"),
            file_label(path)
        );
        self.audit(ctx, "Exported an Ansible inventory", &detail).await?;
        Ok(AnsibleExport {
            path: path.display().to_string(),
            hosts: inventory.hosts.len(),
            groups: inventory.groups.len(),
            notes,
        })
    }

    fn checked_range(request: &HandoverRequest) -> Result<(String, String)> {
        if request.to_ms <= request.from_ms {
            return Err(CoreError::InvalidInput(
                "The last day can't be before the first.".into(),
            ));
        }
        if request.to_ms - request.from_ms > (MAX_RANGE_DAYS + 1) * 86_400_000 {
            return Err(CoreError::InvalidInput(format!(
                "A handover pack covers at most {MAX_RANGE_DAYS} days."
            )));
        }
        Ok((rfc3339_ms(request.from_ms)?, rfc3339_ms(request.to_ms)?))
    }

    async fn activity(&self, ctx: &Context, request: &HandoverRequest) -> Result<Vec<activity::Group>> {
        let (from, to) = Self::checked_range(request)?;
        let jobs = self.store.jobs_between(ctx, &from, &to).await?;
        // An approval's entries come before its job: read from an approval's life before the range.
        let early = rfc3339_ms(request.from_ms - 30 * 60 * 1000)?;
        let audit = self.store.audit_between(ctx, &early, &to).await?;
        let from_ms = request.from_ms;
        Ok(activity::group(jobs, &audit)
            .into_iter()
            .filter(|g| g.is_job() || g.at_ms >= from_ms)
            .collect())
    }

    /// Each listed job's targets, by job id. With `outputs`, each target's output is read one at a time, only while
    /// the pack's cap on outputs ([`pack::MAX_OUTPUTS_CHARS`]) isn't reached: a year of bulk runs is never read whole.
    /// True with them when a target's output was left unread.
    async fn job_targets(
        &self,
        ctx: &Context,
        groups: &[activity::Group],
        outputs: bool,
        control: &ReadControl,
    ) -> Result<(HashMap<String, Vec<store::JobTargetRecord>>, bool)> {
        let size = |t: &Option<String>| {
            t.as_deref()
                .map_or(0, |t| t.chars().count().min(pack::MAX_OUTPUT_CHARS))
        };
        let mut targets = HashMap::new();
        let mut left = pack::MAX_OUTPUTS_CHARS;
        let mut unread = false;
        for g in groups.iter().filter(|g| g.is_job()).take(pack::MAX_JOBS_SHOWN) {
            control.check()?;
            let Ok(id) = Uuid::parse_str(&g.key) else { continue };
            let mut list = self.store.job_targets_brief(ctx, id).await?;
            if outputs {
                for target in &mut list {
                    if left == 0 {
                        unread |= target.stdout_bytes.unwrap_or(0) > 0 || target.stderr_bytes.unwrap_or(0) > 0;
                        continue;
                    }
                    let Some(full) = self.store.job_target(ctx, id, &target.target_key).await? else {
                        continue;
                    };
                    left = left.saturating_sub(size(&full.output) + size(&full.stderr));
                    *target = full;
                }
            }
            targets.insert(g.key.clone(), list);
        }
        Ok((targets, unread))
    }

    /// FD-08: what the pack would hold, for the dialog.
    pub async fn handover_preview(&self, ctx: &Context, request: &HandoverRequest) -> Result<HandoverPreview> {
        let groups = self.activity(ctx, request).await?;
        Ok(HandoverPreview {
            jobs: groups.iter().filter(|g| g.is_job()).count(),
            other_changes: groups.iter().filter(|g| activity::worth_listing(g)).count(),
            notes: self.notes.for_handover(ctx).await?.len(),
            checks: self.store.count_checks(ctx).await?,
        })
    }

    /// FD-08: the handover pack to `path`. Audited. `Cancelled`, with nothing written, once `control` is cancelled.
    pub async fn export_handover(
        &self,
        ctx: &Context,
        path: &Path,
        request: &HandoverRequest,
        made_by: &str,
        control: &ReadControl,
    ) -> Result<HandoverExport> {
        save_guard::refuse_repository(path, Saved::Handover)?;
        let prepared_by = table::clean(&request.prepared_by);
        if prepared_by.chars().count() > MAX_PREPARED_BY {
            return Err(CoreError::InvalidInput(format!(
                "\"Prepared by\" can be at most {MAX_PREPARED_BY} characters."
            )));
        }
        let groups = self.activity(ctx, request).await?;
        let clock = ReportClock::new(request.utc_offset_minutes);
        let made_at = now_ms();
        let workspace = self.store.workspace_name(ctx).await?;
        let inventory = inventory::collect(&self.sources(), ctx, request.inventory, &clock, made_at, control).await?;
        let (targets, outputs_unread) = self.job_targets(ctx, &groups, request.include_outputs, control).await?;
        control.check()?;
        let uptime = self.store.check_uptime(ctx, request.from_ms, request.to_ms).await?;
        let notes = self.notes.for_handover(ctx).await?;
        let nics: Vec<topology::VmNics<'_>> = inventory
            .nics
            .iter()
            .map(|(key, (hypervisor, nics))| topology::VmNics {
                vmx_path: key,
                hypervisor: *hypervisor,
                nics,
            })
            .collect();
        let graph = topology::build(&inventory.vm_records, &nics, &inventory.sessions);
        let svg = topology::svg(&graph);
        let parts = pack::PackParts {
            workspace: &workspace,
            prepared_by: &prepared_by,
            made_by,
            made_at_ms: made_at,
            from_ms: request.from_ms,
            to_ms: request.to_ms - 1,
            clock: &clock,
            inventory: &inventory,
            groups: &groups,
            targets: &targets,
            include_outputs: request.include_outputs,
            outputs_unread,
            uptime: &uptime,
            notes: &notes,
            topology_svg: svg.as_deref(),
        };
        let html = pack::index_html(&parts);
        let activity_sheet = pack::activity_sheet(&groups, &clock);
        let uptime_sheet = pack::uptime_sheet(&uptime);
        let mut csvs: Vec<pack::PackFile> = inventory
            .sheets()
            .into_iter()
            .chain([&activity_sheet, &uptime_sheet])
            .map(|s| pack::PackFile {
                name: s.csv_name(),
                bytes: s.csv().into_bytes(),
            })
            .collect();
        let sheets: Vec<table::Sheet> = inventory.sheets().into_iter().cloned().collect();
        let title = format!("Inventory: {workspace}, made with {made_by}");
        let path_owned = path.to_owned();
        let jobs = groups.iter().filter(|g| g.is_job()).count();
        let files = tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let refs: Vec<&table::Sheet> = sheets.iter().collect();
            let book = xlsx::workbook(&title, &refs)?;
            let mut files = vec![
                pack::PackFile {
                    name: "index.html".into(),
                    bytes: html.into_bytes(),
                },
                pack::PackFile {
                    name: "inventory.xlsx".into(),
                    bytes: book,
                },
            ];
            files.append(&mut csvs);
            save_guard::refuse_repository(&path_owned, Saved::Handover)?;
            pack::write_zip(&path_owned, &files)?;
            Ok(files.into_iter().map(|f| f.name).collect())
        })
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the handover pack could not be made: {err}")))??;
        let mut detail = format!(
            "{} from {} to {}, {}, {}",
            plural(jobs, "job"),
            clock.date_ms(request.from_ms),
            clock.date_ms(request.to_ms - 1),
            plural(notes.len(), "note"),
            plural(inventory.hosts.rows.len() + inventory.vms.rows.len(), "inventory row")
        );
        if request.include_outputs {
            detail.push_str(", with outputs");
        }
        detail.push_str(&format!(", to {}", file_label(path)));
        self.audit(ctx, "Saved a handover pack", &detail).await?;
        Ok(HandoverExport {
            path: path.display().to_string(),
            jobs,
            notes: notes.len(),
            files,
            read: inventory.read.clone(),
        })
    }
}

/// Writes `bytes` to `path` through a `.part` beside it.
async fn write_bytes(path: &Path, bytes: Vec<u8>) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    save_guard::write_atomically(path, |mut file| async move {
        file.write_all(&bytes).await?;
        file.flush().await?;
        file.sync_all().await?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_read_in_the_window_s_offset() {
        let utc = ReportClock::new(0);
        assert_eq!(utc.at("2026-11-01T10:05:00Z"), "2026-11-01 10:05");
        assert_eq!(utc.zone(), "UTC");
        let kl = ReportClock::new(480);
        assert_eq!(kl.at("2026-11-01T20:05:00.123456Z"), "2026-11-02 04:05");
        assert_eq!(kl.zone(), "UTC+08:00");
        assert_eq!(ReportClock::new(-330).zone(), "UTC-05:30");
        assert_eq!(ReportClock::new(i32::MAX).zone(), "UTC", "out of range");
        assert_eq!(utc.at("garbage"), "garbage");
        assert_eq!(utc.date_ms(1_793_491_200_000), "1 Nov 2026");
        assert_eq!(
            utc.before("2026-11-01T10:00:00Z", 3600).as_deref(),
            Some("2026-11-01 09:00")
        );
    }

    #[test]
    fn file_names_hold_the_workspace_s_words() {
        assert_eq!(
            file_name(ReportKind::Inventory, Some("Acme: Lab/2"), "2026-11-01", "xlsx"),
            "remotely-inventory-Acme-Lab-2-2026-11-01.xlsx"
        );
        assert_eq!(
            file_name(ReportKind::Handover, Some("\u{202E}"), "2026-11-01", "zip"),
            "remotely-handover-workspace-2026-11-01.zip"
        );
        assert_eq!(
            file_name(ReportKind::Ansible, Some("Kunde \u{e9}t\u{e9}"), "d", "yml"),
            "remotely-ansible-Kunde-\u{e9}t\u{e9}-d.yml"
        );
        assert_eq!(
            file_name(ReportKind::Inventory, None, "2026-11-01", "xlsx"),
            "remotely-inventory-2026-11-01.xlsx",
            "while presenting"
        );
    }

    #[test]
    fn a_range_must_run_forward_and_be_at_most_a_year() {
        let mut r = HandoverRequest {
            from_ms: 1_000,
            to_ms: 500,
            ..HandoverRequest::default()
        };
        assert!(Reports::checked_range(&r).is_err());
        r.to_ms = r.from_ms + 400 * 86_400_000;
        assert!(Reports::checked_range(&r).is_err());
        r.to_ms = r.from_ms + 86_400_000;
        assert!(Reports::checked_range(&r).is_ok());
    }

    #[test]
    fn requests_read_as_the_window_sends_them() {
        let inventory: InventoryRequest =
            serde_json::from_str(r#"{"readAgain":true,"updates":false,"packages":true,"utcOffsetMinutes":480}"#)
                .unwrap();
        assert!(inventory.options.read_again && inventory.options.packages && !inventory.options.updates);
        assert_eq!(inventory.utc_offset_minutes, 480);
        let ansible: AnsibleRequest = serde_json::from_str(
            r#"{"picks":{"sessionIds":["00000000-0000-0000-0000-000000000001"]},"format":"ini","groupBy":{"folder":false,"tag":true,"environment":false,"workspace":true}}"#,
        )
        .unwrap();
        assert_eq!(ansible.format, AnsibleFormat::Ini);
        assert_eq!(ansible.picks.session_ids.len(), 1);
        assert!(!ansible.group_by.folder && ansible.group_by.workspace);
        let handover: HandoverRequest = serde_json::from_str(
            r#"{"fromMs":1,"toMs":2,"utcOffsetMinutes":-300,"preparedBy":"Alice","includeOutputs":true,"inventory":{"readAgain":false,"updates":false,"packages":false}}"#,
        )
        .unwrap();
        assert!(handover.include_outputs);
        assert_eq!(handover.utc_offset_minutes, -300);
        assert_eq!(handover.prepared_by, "Alice");
    }

    #[test]
    fn a_chosen_name_gets_the_extension_without_replacing_anything() {
        let temp = std::env::temp_dir().join(format!("remotely-chosen-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&temp).unwrap();
        assert_eq!(
            chosen_path(&temp.join("a.XLSX"), &["xlsx"]).unwrap(),
            temp.join("a.XLSX")
        );
        assert_eq!(chosen_path(&temp.join("a"), &["xlsx"]).unwrap(), temp.join("a.xlsx"));
        assert_eq!(
            chosen_path(&temp.join("h.yaml"), &["yml", "yaml"]).unwrap(),
            temp.join("h.yaml")
        );
        assert_eq!(
            chosen_path(&temp.join("h.txt"), &["yml", "yaml"]).unwrap(),
            temp.join("h.txt.yml")
        );
        std::fs::write(temp.join("taken.zip"), b"x").unwrap();
        assert!(
            chosen_path(&temp.join("taken"), &["zip"]).is_err(),
            "taken.zip was never asked about"
        );
        let _ = std::fs::remove_dir_all(temp);
    }
}
