//! VM-21: what an OVA or OVF says about its disks, for the AP-02 preview's disk space: each `<Disk>`'s
//! `ovf:capacity` in its `ovf:capacityAllocationUnits`. An OVA is a tar file whose first member is (by the OVF
//! standard) the `.ovf` descriptor; only that descriptor is read, up to [`MAX_DESCRIPTOR_BYTES`] (A9), never the
//! disks. A path on a share or a device path is refused before the file system sees it (A3).

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::catalog::images::ImageFormat;
use crate::error::{CoreError, Result};
use crate::untrusted;

/// The largest descriptor read (they are a few KB).
pub const MAX_DESCRIPTOR_BYTES: u64 = 4 * 1024 * 1024;
/// Tar members looked at for the descriptor, in case a tool put another file first.
const MAX_MEMBERS: usize = 8;

/// The value of attribute `name` (with or without the `ovf:` prefix) in one element's text.
fn attribute<'a>(element: &'a str, name: &str) -> Option<&'a str> {
    for prefix in ["ovf:", ""] {
        let key = format!("{prefix}{name}=\"");
        let mut from = 0;
        while let Some(at) = element[from..].find(&key) {
            let start = from + at;
            // A whole attribute name: `capacity=` must not match `populatedSize`-like longer names.
            let before = element[..start].chars().last();
            if before.is_none_or(|c| c.is_whitespace()) {
                let value_start = start + key.len();
                let end = element[value_start..].find('"')?;
                return Some(&element[value_start..value_start + end]);
            }
            from = start + key.len();
        }
    }
    None
}

/// Bytes per unit of `ovf:capacityAllocationUnits`: `byte`, `byte * 2^30`, `byte*2^20`... (absent: bytes).
fn unit_bytes(units: Option<&str>) -> Option<u64> {
    let Some(units) = units else {
        return Some(1);
    };
    let squeezed: String = units
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    match squeezed.as_str() {
        "byte" | "bytes" => Some(1),
        "kilobytes" => Some(1 << 10),
        "megabytes" => Some(1 << 20),
        "gigabytes" => Some(1 << 30),
        other => {
            let power = other.strip_prefix("byte*2^")?.parse::<u32>().ok()?;
            (power < 64).then(|| 1u64 << power)
        }
    }
}

/// Each disk's capacity in bytes, in the order the descriptor lists them.
pub fn disk_capacities(descriptor: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut rest = descriptor;
    let next = |text: &str| match (text.find("<Disk"), text.find("<ovf:Disk")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    while let Some(at) = next(rest) {
        let tag = &rest[at..];
        let name_end = tag[1..]
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .map_or(tag.len(), |i| i + 1);
        let end = tag.find('>').map_or(tag.len(), |i| i + 1);
        let name = &tag[1..name_end];
        if name == "Disk" || name == "ovf:Disk" {
            let element = &tag[..end];
            if let (Some(capacity), Some(unit)) = (
                attribute(element, "capacity").and_then(|c| c.trim().parse::<u64>().ok()),
                unit_bytes(attribute(element, "capacityAllocationUnits")),
            ) {
                out.push(capacity.saturating_mul(unit));
            }
        }
        rest = &tag[end.max(1)..];
    }
    out
}

/// An octal tar header field.
fn octal(field: &[u8]) -> Option<u64> {
    let text: String = field
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as char)
        .collect::<String>();
    u64::from_str_radix(text.trim(), 8).ok()
}

fn read_tar_descriptor(file: &mut std::fs::File) -> Result<Option<String>> {
    for _ in 0..MAX_MEMBERS {
        let mut header = [0u8; 512];
        if file.read_exact(&mut header).is_err() || header.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        let name: String = header[..100]
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as char)
            .collect();
        let size = octal(&header[124..136]).unwrap_or(0);
        if name.to_ascii_lowercase().ends_with(".ovf") {
            if size > MAX_DESCRIPTOR_BYTES {
                return Err(CoreError::InvalidInput(
                    "The appliance's OVF descriptor is too large.".into(),
                ));
            }
            let mut text = vec![0u8; size as usize];
            file.read_exact(&mut text)?;
            return Ok(Some(String::from_utf8_lossy(&text).into_owned()));
        }
        let skip = size.div_ceil(512) * 512;
        file.seek(SeekFrom::Current(i64::try_from(skip).unwrap_or(i64::MAX)))?;
    }
    Ok(None)
}

fn read_descriptor_blocking(path: &Path, format: ImageFormat) -> Result<Option<String>> {
    if let Some(refusal) = untrusted::path_refusal(path) {
        return Err(CoreError::InvalidInput(format!(
            "{} {}.",
            path.display(),
            refusal.describe()
        )));
    }
    match format {
        ImageFormat::Ovf => {
            let bytes = untrusted::read_capped_blocking(path, MAX_DESCRIPTOR_BYTES)?;
            Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
        }
        ImageFormat::Ova => {
            let mut file = std::fs::File::open(path)?;
            read_tar_descriptor(&mut file)
        }
        _ => Ok(None),
    }
}

/// The appliance's disks' capacities in bytes; empty when its descriptor can't be found or names none.
pub async fn appliance_disks(path: &str, format: ImageFormat) -> Result<Vec<u64>> {
    let path = PathBuf::from(path);
    let text = tokio::task::spawn_blocking(move || read_descriptor_blocking(&path, format))
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the appliance couldn't be read: {err}")))??;
    Ok(text.as_deref().map(disk_capacities).unwrap_or_default())
}

/// CV-01: the appliance's OVF descriptor (at most [`MAX_DESCRIPTOR_BYTES`]), or `None` when an OVA has none among its
/// first members.
pub async fn appliance_descriptor(path: &str, format: ImageFormat) -> Result<Option<String>> {
    let path = PathBuf::from(path);
    tokio::task::spawn_blocking(move || read_descriptor_blocking(&path, format))
        .await
        .map_err(|err| CoreError::InvalidInput(format!("the appliance couldn't be read: {err}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape VirtualBox 7 and ovftool write (shortened).
    const OVF: &str = r#"<?xml version="1.0"?>
<Envelope ovf:version="1.0" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1">
  <DiskSection>
    <Info>List of the virtual disks used in the package</Info>
    <Disk ovf:capacity="10737418240" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" vbox:uuid="x"/>
    <Disk ovf:capacity="40" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk2" ovf:populatedSize="123"/>
    <ovf:Disk ovf:capacity="512" ovf:capacityAllocationUnits="MegaBytes" ovf:diskId="vmdisk3"/>
  </DiskSection>
  <DiskSectionInfo/>
</Envelope>"#;

    #[test]
    fn disk_capacities_in_their_units() {
        assert_eq!(disk_capacities(OVF), [10 << 30, 40 << 30, 512 << 20]);
        assert!(disk_capacities("<Envelope/>").is_empty());
        assert_eq!(unit_bytes(Some("byte*2^20")), Some(1 << 20));
        assert_eq!(unit_bytes(Some("byte * 2^99")), None);
        assert_eq!(unit_bytes(Some("furlongs")), None);
    }

    fn tar_member(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", data.len());
        header[124..136].copy_from_slice(size.as_bytes());
        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    #[tokio::test]
    async fn an_ova_is_read_up_to_its_descriptor() {
        let dir = std::env::temp_dir().join(format!("remotely-ova-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut ova = tar_member("appliance.mf", b"SHA256(appliance.ovf)= ab\n");
        ova.extend(tar_member("appliance.ovf", OVF.as_bytes()));
        ova.extend(tar_member("appliance-disk1.vmdk", &[7u8; 2000]));
        ova.extend([0u8; 1024]);
        let path = dir.join("appliance.ova");
        std::fs::write(&path, &ova).unwrap();
        let disks = appliance_disks(&path.display().to_string(), ImageFormat::Ova)
            .await
            .unwrap();
        assert_eq!(disks, [10 << 30, 40 << 30, 512 << 20]);
        let ovf = dir.join("appliance.ovf");
        std::fs::write(&ovf, OVF).unwrap();
        assert_eq!(
            appliance_disks(&ovf.display().to_string(), ImageFormat::Ovf)
                .await
                .unwrap()
                .len(),
            3
        );
        // Not a tar at all: no disks known, no error.
        let junk = dir.join("junk.ova");
        std::fs::write(&junk, b"not a tar").unwrap();
        assert!(appliance_disks(&junk.display().to_string(), ImageFormat::Ova)
            .await
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_device_path_is_refused_unopened() {
        let err = appliance_disks("NUL", ImageFormat::Ovf).await.unwrap_err();
        assert!(err.to_string().contains("NUL"), "{err}");
    }
}
