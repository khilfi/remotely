//! FD-08: the handover pack's `index.html` and its zip. The page is one file that prints to PDF from any browser:
//! a cover (workspace, dates, prepared by), the inventory, the topology diagram as an `<img>` of a `data:` SVG, what was
//! done in the dates, the checks' uptime, and the notes marked for it. No script and nothing fetched (the CSP in
//! [`super::html::page`] says so to the browser too); every text escaped after [`super::table::clean`] redacted it.
//! Beside it in the zip: `inventory.xlsx` and a CSV per table (A10's rules).

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use super::activity::{event_label, result_label, tier_label, worth_listing, Group};
use super::html::{escape, page, simple_table, table};
use super::inventory::{InventoryData, ReadSummary};
use super::table::{clean, clean_lines, col, Cell, Sheet};
use super::ReportClock;
use crate::error::{CoreError, Result};
use crate::notes::{Note, NoteKind};
use crate::save_guard::AtomicFile;
use crate::store::{CheckUptime, JobTargetRecord};

/// A job target's output kept at most, in characters (stdout and stderr each).
pub const MAX_OUTPUT_CHARS: usize = 20_000;
/// Every output in the pack together, at most.
pub const MAX_OUTPUTS_CHARS: usize = 4_000_000;
/// Jobs the pack lists at most (oldest first); the CSV lists them all.
pub const MAX_JOBS_SHOWN: usize = 2_000;

/// What the page is made of.
pub struct PackParts<'a> {
    pub workspace: &'a str,
    pub prepared_by: &'a str,
    /// "Remotely 0.7.0".
    pub made_by: &'a str,
    pub made_at_ms: i64,
    pub from_ms: i64,
    /// The last day shown, in Unix ms (the range's end less a moment).
    pub to_ms: i64,
    pub clock: &'a ReportClock,
    pub inventory: &'a InventoryData,
    pub groups: &'a [Group],
    /// By job id; with their output only when `include_outputs`, and then only up to [`MAX_OUTPUTS_CHARS`] or so.
    pub targets: &'a HashMap<String, Vec<JobTargetRecord>>,
    pub include_outputs: bool,
    /// Some targets' outputs weren't read: the cap was reached.
    pub outputs_unread: bool,
    pub uptime: &'a [CheckUptime],
    pub notes: &'a [(Note, String)],
    pub topology_svg: Option<&'a str>,
}

/// The pack's "what was done" as a sheet: one row per job.
pub fn activity_sheet(groups: &[Group], clock: &ReportClock) -> Sheet {
    let mut sheet = Sheet::new(
        "activity",
        "What was done",
        &[
            col("Began", 17.0),
            col("Finished", 17.0),
            col("What", 40.0),
            col("Tier", 9.0),
            col("Targets", 30.0),
            col("Result", 12.0),
            col("Succeeded", 10.0),
            col("Failed", 8.0),
            col("Change ID", 14.0),
            col("Reason", 30.0),
            col("Approved", 17.0),
        ],
    );
    for g in groups.iter().filter(|g| g.is_job()) {
        let job = g.job.as_ref();
        sheet.push(vec![
            Cell::text(clock.at_ms(g.at_ms)),
            Cell::opt_text(job.and_then(|j| j.finished_at.as_deref()).map(|t| clock.at(t))),
            Cell::text(&g.title),
            Cell::text(g.tier.as_deref().map(tier_label).unwrap_or("")),
            Cell::text(g.targets.join(", ")),
            Cell::opt_text(job.map(|j| result_label(&j.status))),
            Cell::opt_int(job.map(|j| j.targets_succeeded)),
            Cell::opt_int(job.map(|j| j.targets_failed)),
            Cell::opt_text(job.and_then(|j| j.change_id.as_deref())),
            Cell::opt_text(g.approval.as_ref().and_then(|a| a.reason.as_deref())),
            Cell::opt_text(g.approval.as_ref().map(|a| clock.at(&a.approved_at))),
        ]);
    }
    sheet
}

/// The checks' uptime over the dates.
pub fn uptime_sheet(uptime: &[CheckUptime]) -> Sheet {
    let mut sheet = Sheet::new(
        "uptime",
        "Uptime",
        &[
            col("Check", 30.0),
            col("Up", 8.0),
            col("Down", 8.0),
            col("Unknown", 9.0),
            col("Uptime (%)", 11.0),
        ],
    );
    for u in uptime {
        sheet.push(vec![
            Cell::text(&u.name),
            Cell::int(u.up),
            Cell::int(u.down),
            Cell::int(u.unknown),
            Cell::opt_number(u.uptime),
        ]);
    }
    sheet
}

fn section(id: &str, title: &str, body: &str) -> String {
    format!("<section id=\"{id}\">\n<h2>{}</h2>\n{body}</section>\n", escape(title))
}

fn para(text: &str, class: &str) -> String {
    if class.is_empty() {
        format!("<p>{}</p>\n", escape(text))
    } else {
        format!("<p class=\"{class}\">{}</p>\n", escape(text))
    }
}

fn list(items: &[String]) -> String {
    let mut out = String::from("<ul>\n");
    for item in items {
        out.push_str(&format!("<li>{}</li>\n", escape(&clean(item))));
    }
    out.push_str("</ul>\n");
    out
}

fn read_text(read: &ReadSummary) -> String {
    format!(
        "Read again before this was made: {} of {} hosts.",
        read.read, read.asked
    )
}

fn inventory_section(parts: &PackParts<'_>) -> String {
    let inv = parts.inventory;
    let mut body = para(
        "The same tables in full are in inventory.xlsx and the CSV files beside this page.",
        "muted",
    );
    if let Some(read) = &inv.read {
        body.push_str(&para(&read_text(read), "muted"));
        if !read.problems.is_empty() {
            body.push_str(&list(&read.problems));
        }
    }
    let parts_list: [(&str, &Sheet, &[&str]); 4] = [
        (
            "VMs",
            &inv.vms,
            &[
                "Name",
                "State",
                "Guest OS",
                "vCPU",
                "RAM (GB)",
                "Disk size (GB)",
                "Addresses",
                "Environment",
                "Tags",
            ],
        ),
        (
            "Hosts",
            &inv.hosts,
            &[
                "Name",
                "Kind",
                "Host",
                "User",
                "OS",
                "vCPUs",
                "RAM (GB)",
                "Listening ports",
                "Pending updates",
                "Facts read",
            ],
        ),
        ("Networks", &inv.networks, &[]),
        (
            "Health checks",
            &inv.checks,
            &["Name", "Checks", "Target", "Every", "Last result", "Last run"],
        ),
    ];
    for (title, sheet, columns) in parts_list {
        body.push_str(&format!("<h3>{}</h3>\n", escape(title)));
        match table(sheet, columns) {
            Some(t) => body.push_str(&t),
            None => body.push_str(&para("None.", "muted")),
        }
    }
    if !inv.notes.is_empty() {
        body.push_str(&list(&inv.notes));
    }
    section("inventory", "Inventory", &body)
}

fn topology_section(svg: Option<&str>) -> String {
    let body = match svg {
        Some(svg) => {
            let data = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
            format!(
                "<figure class=\"topology\"><img alt=\"Network diagram: this PC, its networks, the VMs on them and the sessions that reach them\" src=\"data:image/svg+xml;base64,{data}\"></figure>\n"
            )
        }
        None => para(
            "There are no VMs or sessions to draw, or too many to draw legibly.",
            "muted",
        ),
    };
    section("topology", "Network diagram", &body)
}

fn job_html(g: &Group, parts: &PackParts<'_>, outputs_left: &mut usize, cut: &mut bool) -> String {
    let clock = parts.clock;
    let mut out = String::from("<div class=\"job\">\n");
    out.push_str(&format!("<h3>{}</h3>\n", escape(&clean(&g.title))));
    let mut line = vec![clock.at_ms(g.at_ms)];
    if let Some(tier) = g.tier.as_deref().map(tier_label).filter(|t| !t.is_empty()) {
        line.push(format!("{tier} tier"));
    }
    if let Some(job) = &g.job {
        line.push(result_label(&job.status));
        line.push(format!(
            "{} of {} targets succeeded",
            job.targets_succeeded, job.targets_total
        ));
    } else if let Some(result) = &g.result {
        line.push(result_label(result));
    }
    out.push_str(&para(&line.join(" · "), "small muted"));
    if !g.targets.is_empty() {
        out.push_str(&para(&format!("Targets: {}", clean(&g.targets.join(", "))), ""));
    }
    if let Some(a) = &g.approval {
        let mut approved = vec![format!("Approved {}", clock.at(&a.approved_at))];
        if let Some(change) = g
            .job
            .as_ref()
            .and_then(|j| j.change_id.as_deref())
            .or(a.change_id.as_deref())
        {
            approved.push(format!("change ID {}", clean(change)));
        }
        if let Some(reason) = a.reason.as_deref().filter(|r| !r.trim().is_empty()) {
            approved.push(format!("reason: {}", clean(reason)));
        }
        if let Some(standing) = &a.standing {
            approved.push(format!("under the standing approval of {}", clean(&standing.label)));
        }
        if a.safety_snapshot {
            approved.push("a safety snapshot first".into());
        }
        out.push_str(&para(&approved.join("; "), ""));
    } else if let Some(change) = g.job.as_ref().and_then(|j| j.change_id.as_deref()) {
        out.push_str(&para(&format!("Change ID {}", clean(change)), ""));
    }
    if !g.entries.is_empty() {
        let rows: Vec<Vec<String>> = g
            .entries
            .iter()
            .map(|e| {
                vec![
                    clock.at(&e.ts),
                    event_label(&e.event),
                    e.result.as_deref().map(result_label).unwrap_or_default(),
                    clean(e.detail.as_deref().unwrap_or("")),
                ]
            })
            .collect();
        out.push_str(&simple_table(&["When", "Step", "Result", "Detail"], &rows));
    }
    if let Some(targets) = parts.targets.get(&g.key).filter(|t| !t.is_empty()) {
        let rows: Vec<Vec<String>> = targets
            .iter()
            .map(|t| {
                vec![
                    clean(&t.target_name),
                    result_label(&t.status),
                    t.exit_code.map(|c| c.to_string()).unwrap_or_default(),
                    clean(t.error.as_deref().unwrap_or("")),
                ]
            })
            .collect();
        out.push_str(&simple_table(&["Target", "Result", "Exit code", "Error"], &rows));
        if parts.include_outputs {
            for t in targets {
                for (what, text) in [("output", t.output.as_deref()), ("errors", t.stderr.as_deref())] {
                    let Some(text) = text.filter(|t| !t.trim().is_empty()) else {
                        continue;
                    };
                    if *outputs_left == 0 {
                        *cut = true;
                        continue;
                    }
                    let (shown, was_cut) = clean_lines(text, MAX_OUTPUT_CHARS.min(*outputs_left));
                    *outputs_left = outputs_left.saturating_sub(shown.chars().count());
                    let more = if was_cut || t.output_truncated { " (cut)" } else { "" };
                    out.push_str(&format!(
                        "<p class=\"small\">{} {what}{more}:</p>\n<pre>{}</pre>\n",
                        escape(&clean(&t.target_name)),
                        escape(&shown)
                    ));
                }
            }
        }
    }
    out.push_str("</div>\n");
    out
}

fn activity_section(parts: &PackParts<'_>) -> String {
    let clock = parts.clock;
    let jobs: Vec<&Group> = parts.groups.iter().filter(|g| g.is_job()).collect();
    let others: Vec<&Group> = parts.groups.iter().filter(|g| worth_listing(g)).collect();
    let mut body = para(
        &format!(
            "{} from {} to {} (times in {}). Outputs are {}.",
            plural(jobs.len(), "job"),
            clock.date_ms(parts.from_ms),
            clock.date_ms(parts.to_ms),
            clock.zone(),
            if parts.include_outputs { "included" } else { "left out" }
        ),
        "muted",
    );
    if jobs.is_empty() {
        body.push_str(&para("Nothing was run on VMs or hosts in these dates.", ""));
    }
    let mut outputs_left = MAX_OUTPUTS_CHARS;
    let mut cut = false;
    for g in jobs.iter().take(MAX_JOBS_SHOWN) {
        body.push_str(&job_html(g, parts, &mut outputs_left, &mut cut));
    }
    if jobs.len() > MAX_JOBS_SHOWN {
        body.push_str(&para(
            &format!(
                "The first {MAX_JOBS_SHOWN} jobs are shown; activity.csv lists all {}.",
                jobs.len()
            ),
            "muted",
        ));
    }
    if cut || parts.outputs_unread {
        body.push_str(&para(
            "Some outputs were left out: the pack holds at most 4 million characters of them.",
            "muted",
        ));
    }
    if !others.is_empty() {
        body.push_str("<h3>Other changes</h3>\n");
        let rows: Vec<Vec<String>> = others
            .iter()
            .map(|g| {
                let e = &g.entries[0];
                vec![
                    clock.at(&e.ts),
                    event_label(&e.event),
                    clean(&e.action),
                    clean(&g.targets.join(", ")),
                    e.result.as_deref().map(result_label).unwrap_or_default(),
                ]
            })
            .collect();
        body.push_str(&simple_table(&["When", "What", "Action", "Targets", "Result"], &rows));
    }
    section("activity", "What was done", &body)
}

fn uptime_section(parts: &PackParts<'_>) -> String {
    let body = if parts.uptime.is_empty() {
        para("No health checks in this workspace.", "muted")
    } else {
        let mut b = para(
            &format!(
                "Runs that passed, from {} to {}; runs Remotely could not make are counted apart.",
                parts.clock.date_ms(parts.from_ms),
                parts.clock.date_ms(parts.to_ms)
            ),
            "muted",
        );
        if let Some(t) = table(&uptime_sheet(parts.uptime), &[]) {
            b.push_str(&t);
        }
        b
    };
    section("uptime", "Health check uptime", &body)
}

fn notes_section(parts: &PackParts<'_>) -> String {
    let mut body = String::new();
    if parts.notes.is_empty() {
        body.push_str(&para("No notes are marked for the handover pack.", "muted"));
    }
    for (note, html) in parts.notes {
        let kind = match note.kind {
            NoteKind::Session => "Session",
            NoteKind::Vm => "VM",
            NoteKind::Folder => "Folder",
        };
        body.push_str(&format!(
            "<article class=\"note\">\n<h3>{}</h3>\n{}<div class=\"note-body\">\n{html}</div>\n</article>\n",
            escape(&clean(&note.title)),
            para(
                &format!("{kind} · updated {}", parts.clock.at(&note.updated_at)),
                "small muted"
            )
        ));
    }
    section("notes", "Notes", &body)
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 {
        format!("1 {word}")
    } else {
        format!("{n} {word}s")
    }
}

/// The page.
pub fn index_html(parts: &PackParts<'_>) -> String {
    let clock = parts.clock;
    let workspace = clean(parts.workspace);
    let dates = format!("{} to {}", clock.date_ms(parts.from_ms), clock.date_ms(parts.to_ms));
    let mut body = String::new();
    body.push_str("<header class=\"cover\">\n");
    body.push_str(&format!("<h1>Handover: {}</h1>\n", escape(&workspace)));
    body.push_str(&para(&dates, "muted"));
    body.push_str("<dl>\n");
    for (term, value) in [
        ("Workspace", workspace.clone()),
        ("Dates", dates.clone()),
        ("Prepared by", clean(parts.prepared_by)),
        (
            "Made",
            format!("{} with {}", clock.at_ms(parts.made_at_ms), clean(parts.made_by)),
        ),
        ("Times", clock.zone()),
    ] {
        body.push_str(&format!("<dt>{}</dt><dd>{}</dd>\n", escape(term), escape(&value)));
    }
    body.push_str("</dl>\n</header>\n");
    body.push_str(
        "<nav><h2>Contents</h2><ol>\
<li><a href=\"#inventory\">Inventory</a></li>\
<li><a href=\"#topology\">Network diagram</a></li>\
<li><a href=\"#activity\">What was done</a></li>\
<li><a href=\"#uptime\">Health check uptime</a></li>\
<li><a href=\"#notes\">Notes</a></li></ol></nav>\n",
    );
    body.push_str(&inventory_section(parts));
    body.push_str(&topology_section(parts.topology_svg));
    body.push_str(&activity_section(parts));
    body.push_str(&uptime_section(parts));
    body.push_str(&notes_section(parts));
    body.push_str(&para(
        "No passwords, keys or vault items are in this pack. Anything that looked like one was replaced with [redacted].",
        "small muted",
    ));
    page(&format!("Handover: {workspace}"), &body)
}

/// One file of the zip.
pub struct PackFile {
    pub name: String,
    pub bytes: Vec<u8>,
}

fn zip_error(err: zip::result::ZipError) -> CoreError {
    match err {
        zip::result::ZipError::Io(io) => CoreError::Io(io),
        other => CoreError::InvalidInput(format!("the handover pack's zip could not be written: {other}")),
    }
}

/// Writes the zip at `path` through a `.part` beside it, which takes its name only once every file is in (blocking:
/// run it on a blocking thread). Any failure leaves nothing behind.
pub fn write_zip(path: &Path, files: &[PackFile]) -> Result<()> {
    let file = AtomicFile::create(path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::default_for_write())
        .unix_permissions(0o644);
    for f in files {
        zip.start_file(f.name.as_str(), options).map_err(zip_error)?;
        zip.write_all(&f.bytes)?;
    }
    let file = zip.finish().map_err(zip_error)?;
    file.commit()
}
