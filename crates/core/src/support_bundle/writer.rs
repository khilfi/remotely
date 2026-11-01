//! FD-04: a job's open bundle: its zip, written as each host gives a file (into `<name>.part` beside the chosen
//! path, which takes the name only once the manifest is in: [`crate::save_guard::AtomicFile`]); the caps (a file,
//! a host, the bundle); and what goes into `manifest.json`. A bundle of up to 1 GB is never held in memory: each
//! file goes into the zip as it comes, on a blocking thread, one at a time.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

use super::presets::{self, PresetId};
use super::spec::{
    safe_name, unique, BundleItem, BundleSpec, COMMAND_LIMIT_SECS, FILE_LIMIT_SECS, MAX_BUNDLE_BYTES, MAX_FILE_BYTES,
    MAX_HOST_BYTES,
};
use crate::domain::{now_rfc3339, Target};
use crate::error::{CoreError, Result};
use crate::export::redact_secrets;
use crate::locks;
use crate::save_guard::AtomicFile;

/// The manifest's own format, for whoever reads bundles with a script.
pub const MANIFEST_FORMAT: u32 = 1;
/// The manifest's name at the zip's root.
pub const MANIFEST_NAME: &str = "manifest.json";

/// One item of one host, as the manifest says it went.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRecord {
    /// `command` or `file`.
    pub kind: &'static str,
    /// The command (secrets redacted), or the file's path on the host.
    pub source: String,
    /// Its file in the zip; `None` when nothing was saved.
    pub file: Option<String>,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub duration_ms: Option<u64>,
    /// Bytes saved.
    pub bytes: u64,
    /// The whole output or file on the host, when more than was saved.
    pub original_bytes: Option<u64>,
    /// Hex SHA-256 of the saved file.
    pub sha256: Option<String>,
    /// Places Remotely replaced with `[redacted]`: a vault secret of the run, or what looks like a password, token or
    /// private key.
    pub redacted: usize,
    /// What was cut and why.
    pub cut: Option<String>,
    /// Why nothing (or not all of it) was collected.
    pub error: Option<String>,
}

/// One host, as the manifest says it went.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRecord {
    pub name: String,
    /// Its folder in the zip.
    pub folder: String,
    /// `user@host:port`, and the jump hosts on the way.
    pub address: Option<String>,
    /// The address this PC reached (a host reached directly).
    pub peer_ip: Option<String>,
    /// How the job ended for it: succeeded, failed, unknown (timed out), skipped, cancelled.
    pub status: String,
    pub error: Option<String>,
    pub bytes: u64,
    pub items: Vec<ItemRecord>,
    #[serde(skip)]
    key: String,
}

/// The caps, for the manifest and the UI.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Caps {
    pub file_bytes: u64,
    pub host_bytes: u64,
    pub bundle_bytes: u64,
    /// Seconds one command may run, and one file's read take, before the host goes on without it.
    pub command_secs: u64,
    pub file_secs: u64,
}

pub const CAPS: Caps = Caps {
    file_bytes: MAX_FILE_BYTES,
    host_bytes: MAX_HOST_BYTES,
    bundle_bytes: MAX_BUNDLE_BYTES,
    command_secs: COMMAND_LIMIT_SECS,
    file_secs: FILE_LIMIT_SECS,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest<'a> {
    format: u32,
    created_by: String,
    workspace: &'a str,
    job_id: String,
    started_at: &'a str,
    finished_at: String,
    presets: Vec<&'static str>,
    /// What each host was asked for, commands with their secrets redacted.
    items: Vec<BundleItem>,
    sudo: bool,
    caps: Caps,
    bytes: u64,
    files: usize,
    redacted_files: usize,
    /// Everything cut or left out, one line each.
    cut: Vec<String>,
    hosts: &'a [HostRecord],
}

/// Bytes of the bundle's cap held for one file ([`OpenBundle::hold`]). What isn't kept goes back when it is dropped.
pub struct Reservation {
    bundle: Arc<OpenBundle>,
    held: u64,
}

impl Reservation {
    /// The bytes held: at most what the file may keep.
    pub fn granted(&self) -> u64 {
        self.held
    }

    /// Keeps `bytes` of it for good (what the file stored); the rest goes back now.
    pub fn keep(mut self, bytes: u64) {
        self.held = self.held.saturating_sub(bytes);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.held > 0 {
            self.bundle.release(self.held);
        }
    }
}

/// What [`OpenBundle::finish`] saved.
#[derive(Debug, Clone)]
pub struct Saved {
    pub path: PathBuf,
    pub hosts: usize,
    pub files: usize,
    pub bytes: u64,
    pub redacted_files: usize,
    pub cut: usize,
}

/// A job's bundle while it runs.
pub struct OpenBundle {
    output: PathBuf,
    job_id: uuid::Uuid,
    spec: BundleSpec,
    started_at: String,
    zip: Mutex<Option<ZipWriter<AtomicFile>>>,
    /// Bytes given out to files so far, of [`MAX_BUNDLE_BYTES`].
    used: Mutex<u64>,
    hosts: Mutex<Vec<HostRecord>>,
}

impl OpenBundle {
    /// Opens `<output>.part` (blocking) and names each host's folder after it, safe for Windows and once each.
    pub fn create(job_id: uuid::Uuid, spec: &BundleSpec, hosts: &[Target]) -> Result<Self> {
        let output = PathBuf::from(&spec.output);
        if !output.parent().is_some_and(Path::is_dir) {
            return Err(CoreError::InvalidInput(format!(
                "The folder of {} is not there any more.",
                output.display()
            )));
        }
        let file = AtomicFile::create(&output)?;
        let mut taken = HashSet::new();
        taken.insert(MANIFEST_NAME.to_owned());
        let hosts = hosts
            .iter()
            .map(|t| HostRecord {
                name: t.name.clone(),
                folder: unique(&mut taken, &safe_name(&t.name, "host"), ""),
                address: None,
                peer_ip: None,
                status: "pending".into(),
                error: None,
                bytes: 0,
                items: Vec::new(),
                key: t.target.key(),
            })
            .collect();
        Ok(Self {
            output,
            job_id,
            spec: spec.clone(),
            started_at: now_rfc3339(),
            zip: Mutex::new(Some(ZipWriter::new(file))),
            used: Mutex::new(0),
            hosts: Mutex::new(hosts),
        })
    }

    pub fn spec(&self) -> &BundleSpec {
        &self.spec
    }

    pub fn output(&self) -> &Path {
        &self.output
    }

    /// The host's folder in the zip.
    pub fn folder(&self, key: &str) -> Option<String> {
        locks::lock(&self.hosts)
            .iter()
            .find(|h| h.key == key)
            .map(|h| h.folder.clone())
    }

    /// Up to `want` bytes of the bundle's [`MAX_BUNDLE_BYTES`] for one file; 0 once they are all given out.
    pub fn reserve(&self, want: u64) -> u64 {
        let mut used = locks::lock(&self.used);
        let granted = want.min(MAX_BUNDLE_BYTES.saturating_sub(*used));
        *used += granted;
        granted
    }

    /// Gives back what a file did not use of what it reserved.
    pub fn release(&self, bytes: u64) {
        let mut used = locks::lock(&self.used);
        *used = used.saturating_sub(bytes);
    }

    /// [`Self::reserve`] as a guard: whatever becomes of the item (it fails, times out, or its host's work is dropped
    /// by a time limit or a cancel), what it doesn't keep goes back.
    pub fn hold(self: &Arc<Self>, want: u64) -> Reservation {
        Reservation {
            held: self.reserve(want),
            bundle: Arc::clone(self),
        }
    }

    /// Adds a host's file to the zip and its record to the manifest, together, under the zip's lock: the job's end
    /// either sees both or neither, even when the item's own work was dropped meanwhile (blocking: call it on a
    /// blocking thread). The reservation keeps the bytes written; a failed write gives them all back.
    pub fn add_file(
        &self,
        key: &str,
        entry: &str,
        data: &[u8],
        mut record: ItemRecord,
        reservation: Reservation,
    ) -> Result<()> {
        let mut zip = locks::lock(&self.zip);
        let written = match zip.as_mut() {
            Some(zip) => zip
                .start_file(entry, options())
                .map_err(zip_error)
                .and_then(|()| zip.write_all(data).map_err(CoreError::from)),
            None => Err(CoreError::InvalidInput("the bundle was closed".into())),
        };
        if let Err(err) = &written {
            record.error = Some(redact_secrets(&err.to_string()).0);
            self.record_item(key, record);
            return written;
        }
        record.file = Some(entry.to_owned());
        record.bytes = data.len() as u64;
        reservation.keep(record.bytes);
        self.record_item(key, record);
        Ok(())
    }

    /// Notes an item of a host for the manifest.
    pub fn record_item(&self, key: &str, item: ItemRecord) {
        if let Some(host) = locks::lock(&self.hosts).iter_mut().find(|h| h.key == key) {
            host.bytes += item.bytes;
            host.items.push(item);
        }
    }

    /// Notes where a host was reached.
    pub fn record_address(&self, key: &str, address: String, peer_ip: Option<String>) {
        if let Some(host) = locks::lock(&self.hosts).iter_mut().find(|h| h.key == key) {
            host.address = Some(address);
            host.peer_ip = peer_ip;
        }
    }

    /// Notes how the job ended for a host.
    pub fn record_end(&self, key: &str, status: &str, error: Option<&str>) {
        if let Some(host) = locks::lock(&self.hosts).iter_mut().find(|h| h.key == key) {
            host.status = status.to_owned();
            host.error = error.map(|e| redact_secrets(e).0);
        }
    }

    /// The files saved so far.
    pub fn files(&self) -> usize {
        locks::lock(&self.hosts)
            .iter()
            .flat_map(|h| &h.items)
            .filter(|i| i.file.is_some())
            .count()
    }

    /// Writes the manifest, closes the zip and gives it its name (blocking). `None` when no host gave a file: the
    /// half file is removed, and nothing is saved.
    pub fn finish(&self) -> Result<Option<Saved>> {
        let Some(mut zip) = locks::lock(&self.zip).take() else {
            return Ok(None);
        };
        let hosts = locks::lock(&self.hosts).clone();
        let files = hosts.iter().flat_map(|h| &h.items).filter(|i| i.file.is_some()).count();
        if files == 0 {
            // Dropping it removes the `.part`.
            return Ok(None);
        }
        let bytes: u64 = hosts.iter().map(|h| h.bytes).sum();
        let redacted_files = hosts.iter().flat_map(|h| &h.items).filter(|i| i.redacted > 0).count();
        let cut: Vec<String> = hosts
            .iter()
            .flat_map(|h| {
                h.items.iter().filter_map(move |i| {
                    let why = i
                        .cut
                        .as_deref()
                        .or(if i.file.is_none() { i.error.as_deref() } else { None })?;
                    Some(format!("{}: {}: {why}", h.name, i.source))
                })
            })
            .collect();
        let items = self.spec.for_journal().0.items;
        let manifest = Manifest {
            format: MANIFEST_FORMAT,
            created_by: format!("Remotely {}", env!("CARGO_PKG_VERSION")),
            workspace: &self.spec.workspace,
            job_id: self.job_id.to_string(),
            started_at: &self.started_at,
            finished_at: now_rfc3339(),
            presets: self
                .spec
                .presets
                .iter()
                .map(|id: &PresetId| presets::preset(*id).label)
                .collect(),
            items,
            sudo: self.spec.sudo,
            caps: CAPS,
            bytes,
            files,
            redacted_files,
            cut: cut.clone(),
            hosts: &hosts,
        };
        let json = serde_json::to_vec_pretty(&manifest)?;
        zip.start_file(MANIFEST_NAME, options()).map_err(zip_error)?;
        zip.write_all(&json)?;
        let file = zip.finish().map_err(zip_error)?;
        file.commit()?;
        Ok(Some(Saved {
            path: self.output.clone(),
            hosts: hosts
                .iter()
                .filter(|h| h.items.iter().any(|i| i.file.is_some()))
                .count(),
            files,
            bytes,
            redacted_files,
            cut: cut.len(),
        }))
    }

    /// Drops the zip (blocking): its `.part` is removed.
    pub fn discard(&self) {
        drop(locks::lock(&self.zip).take());
    }
}

fn options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::default_for_write())
        .unix_permissions(0o644)
}

fn zip_error(err: zip::result::ZipError) -> CoreError {
    match err {
        zip::result::ZipError::Io(io) => CoreError::Io(io),
        other => CoreError::InvalidInput(format!("the bundle's zip could not be written: {other}")),
    }
}

/// Runs `work` on the bundle on a blocking thread.
pub async fn blocking<T: Send + 'static>(
    bundle: &Arc<OpenBundle>,
    work: impl FnOnce(&OpenBundle) -> Result<T> + Send + 'static,
) -> Result<T> {
    let bundle = Arc::clone(bundle);
    tokio::task::spawn_blocking(move || work(&bundle))
        .await
        .map_err(|err| CoreError::InvalidInput(format!("writing the bundle stopped: {err}")))?
}
