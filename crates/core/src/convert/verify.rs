//! CV-03 Verify: one image, or two (a conversion's source and its output), read and compared. A read: nothing is
//! written, audited or asked.
//!
//! * Sizes: each image's virtual size and what its files take; two images should have the same virtual size.
//! * SHA-256 of every file each image is (a flat VMDK's descriptor and extent each), read on a blocking thread
//!   with progress and cancel. Two images of different formats have different checksums even when the disks are
//!   the same: the checksums are for checking a copy (an upload, a download) against its original.
//! * `qemu-img compare` when qemu-img is installed: whether the guest would see the same bytes. Never on an image
//!   with a parent or a backing file, which qemu-img would open by the path written in it.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::args;
use super::inspect::{inspect, ImageInfo};
use crate::adapters::disk_tools::{DiskTools, Tool, ToolRun};
use crate::error::{CoreError, Result};

/// One file's checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileHash {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// What `qemu-img compare` said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub identical: bool,
    /// qemu-img's own words ("Images are identical.", "Content mismatch at offset 4096!").
    pub said: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub first: ImageInfo,
    pub second: Option<ImageInfo>,
    pub first_hashes: Vec<FileHash>,
    pub second_hashes: Vec<FileHash>,
    /// Both images' virtual sizes are the same (two images given, both sizes read).
    pub same_size: Option<bool>,
    pub comparison: Option<Comparison>,
    /// Why there is no comparison (qemu-img isn't installed, one has a parent...).
    pub no_comparison: Option<String>,
}

/// How far the checksums are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProgress {
    pub done: u64,
    pub total: u64,
}

const CHUNK: usize = 1 << 20;
const PROGRESS_EVERY: Duration = Duration::from_millis(200);
/// `qemu-img compare` reads both disks whole.
const COMPARE_LIMIT: Duration = Duration::from_secs(6 * 60 * 60);

/// The files an image is: the file, and a VMDK's extents in other files (resolved beside it; never a parent's).
fn own_files(info: &ImageInfo) -> Vec<PathBuf> {
    let path = PathBuf::from(&info.path);
    let folder = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut out = vec![path];
    for extent in &info.extents {
        let extent_path = folder.join(extent);
        if crate::untrusted::path_refusal(&extent_path).is_none() && !out.contains(&extent_path) {
            out.push(extent_path);
        }
    }
    out
}

/// SHA-256 of these files, one after another. Blocking.
fn hash_files(
    files: &[PathBuf],
    done: &mut u64,
    total: u64,
    cancel: &CancellationToken,
    progress: &(dyn Fn(VerifyProgress) + Send + Sync),
) -> Result<Vec<FileHash>> {
    let mut out = Vec::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut last = Instant::now();
    for path in files {
        let mut file = std::fs::File::open(path)
            .map_err(|err| CoreError::InvalidInput(format!("{} can't be read: {err}", path.display())))?;
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        loop {
            if cancel.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    return Err(CoreError::InvalidInput(format!(
                        "{} couldn't be read to the end: {err}",
                        path.display()
                    )))
                }
            };
            hasher.update(&buffer[..read]);
            bytes += read as u64;
            *done += read as u64;
            if last.elapsed() >= PROGRESS_EVERY {
                last = Instant::now();
                progress(VerifyProgress { done: *done, total });
            }
        }
        out.push(FileHash {
            path: path.display().to_string(),
            bytes,
            sha256: hex::encode(hasher.finalize()),
        });
    }
    Ok(out)
}

/// Verifies `first` (and `second`): sizes, checksums and, with qemu-img, a comparison.
pub async fn verify(
    tools: &dyn DiskTools,
    first: &Path,
    second: Option<&Path>,
    cancel: CancellationToken,
    progress: std::sync::Arc<dyn Fn(VerifyProgress) + Send + Sync>,
) -> Result<VerifyReport> {
    let first = inspect(first).await?;
    let second = match second {
        Some(path) => Some(inspect(path).await?),
        None => None,
    };
    let first_files = own_files(&first);
    let second_files = second.as_ref().map(own_files).unwrap_or_default();
    let mut total = 0u64;
    for file in first_files.iter().chain(&second_files) {
        total += tokio::fs::metadata(file).await.map(|m| m.len()).unwrap_or(0);
    }
    let token = cancel.clone();
    let reporter = progress.clone();
    let (first_hashes, second_hashes) = tokio::task::spawn_blocking(move || {
        let mut done = 0u64;
        reporter(VerifyProgress { done, total });
        let a = hash_files(&first_files, &mut done, total, &token, reporter.as_ref())?;
        let b = hash_files(&second_files, &mut done, total, &token, reporter.as_ref())?;
        reporter(VerifyProgress { done, total });
        Ok::<_, CoreError>((a, b))
    })
    .await
    .map_err(|err| CoreError::InvalidInput(format!("the checksums stopped: {err}")))??;
    let same_size = match (&second, first.virtual_bytes) {
        (Some(second), Some(a)) => second.virtual_bytes.map(|b| a == b),
        _ => None,
    };
    let (comparison, no_comparison) = match &second {
        None => (None, None),
        Some(second) => compare(tools, &first, second, &cancel).await,
    };
    Ok(VerifyReport {
        first,
        second,
        first_hashes,
        second_hashes,
        same_size,
        comparison,
        no_comparison,
    })
}

async fn compare(
    tools: &dyn DiskTools,
    first: &ImageInfo,
    second: &ImageInfo,
    cancel: &CancellationToken,
) -> (Option<Comparison>, Option<String>) {
    let Some(qemu) = tools.qemu_img() else {
        return (
            None,
            Some("qemu-img isn't installed, so the disks' contents weren't compared (the sizes and checksums are above)".into()),
        );
    };
    if first.has_parent() || second.has_parent() || !first.problems.is_empty() || !second.problems.is_empty() {
        return (
            None,
            Some("one of them has a parent disk or a problem, so qemu-img didn't compare them".into()),
        );
    }
    let args = args::qemu_compare(
        Path::new(&first.path),
        first.format,
        Path::new(&second.path),
        second.format,
    );
    let mut run = ToolRun::new(Tool::QemuImg, &qemu, args, COMPARE_LIMIT, &|_| {});
    run.answers = &[0, 1];
    let ran = tokio::select! {
        biased;
        _ = cancel.cancelled() => return (None, Some("cancelled before qemu-img finished comparing".into())),
        ran = tools.run(run) => ran,
    };
    match ran {
        Ok(output) => {
            let said = output
                .text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('('))
                .collect::<Vec<_>>()
                .join(" ");
            (
                Some(Comparison {
                    identical: output.code == 0,
                    said,
                }),
                None,
            )
        }
        Err(err) => (None, Some(format!("qemu-img couldn't compare them: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::fakes::disk_images::{self as img, TempFolder};
    use crate::fakes::FakeDiskTools;

    #[tokio::test]
    async fn checksums_sizes_and_a_comparison() {
        let dir = TempFolder::new("verify");
        let a = dir.write("a.vhd", &img::vhd_fixed(1 << 20));
        let b = dir.write("b.vdi", &img::vdi(1 << 20, 1));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let progress: Arc<dyn Fn(VerifyProgress) + Send + Sync> = Arc::new(move |p| log.lock().unwrap().push(p));
        let tools = FakeDiskTools::new().with_qemu_img();
        let report = verify(&tools, &a, Some(&b), CancellationToken::new(), progress)
            .await
            .unwrap();
        assert_eq!(report.same_size, Some(true));
        assert_eq!(report.first_hashes.len(), 1);
        assert_eq!(report.first_hashes[0].bytes, (1 << 20) + 512);
        assert_eq!(report.first_hashes[0].sha256.len(), 64);
        assert!(report.comparison.as_ref().unwrap().identical);
        assert!(tools.calls()[0].starts_with("qemu-img compare -p -f vpc -F vdi"));
        let last = *seen.lock().unwrap().last().unwrap();
        assert_eq!(last.done, last.total);

        tools.set_compare_differs(true);
        let report = verify(&tools, &a, Some(&b), CancellationToken::new(), Arc::new(|_| {}))
            .await
            .unwrap();
        assert!(!report.comparison.unwrap().identical);

        // Without qemu-img: sizes and checksums only.
        let report = verify(&FakeDiskTools::new(), &a, Some(&b), CancellationToken::new(), Arc::new(|_| {}))
            .await
            .unwrap();
        assert!(report.comparison.is_none());
        assert!(report.no_comparison.unwrap().contains("isn't installed"));

        // A flat VMDK is its descriptor and its extent.
        dir.write("f-flat.vmdk", &[0u8; 4096]);
        let descriptor = img::vmdk_descriptor("monolithicFlat", &[(8, "FLAT", "f-flat.vmdk")], None);
        let f = dir.write("f.vmdk", descriptor.as_bytes());
        let report = verify(&tools, &f, None, CancellationToken::new(), Arc::new(|_| {}))
            .await
            .unwrap();
        assert_eq!(report.first_hashes.len(), 2);
        assert!(report.second.is_none() && report.comparison.is_none());

        let cancel = CancellationToken::new();
        cancel.cancel();
        let err = verify(&tools, &a, None, cancel, Arc::new(|_| {})).await.unwrap_err();
        assert!(matches!(err, CoreError::Cancelled));
    }
}
