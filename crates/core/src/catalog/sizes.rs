//! VM-19 sizes: what a VM gets, like a cloud provider's instance types. CPU as sockets times cores per
//! socket, RAM, and one or more disks (the first is the boot disk), each thin or thick and on a disk controller
//! (by default the OS profile's).
//!
//! The twelve built-ins ([`BUILT_IN_SIZES`]) are part of the app, as `docs/plan-0.5.md` lists them: read only, not
//! stored, and named by their name (`gp.medium`), which no other size may take. The owner's own sizes are stored
//! (`catalog_sizes`) under a UUID; Duplicate (the UI fills the editor from any size) makes one from a built-in.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

pub const MAX_SIZE_NAME: usize = 40;
pub const MAX_SIZE_DESCRIPTION: usize = 200;
/// Disks one size may have.
pub const MAX_DISKS: usize = 8;
/// Workstation and VirtualBox both run at most 32 vCPUs in one VM.
pub const MAX_VCPUS: u32 = 32;
pub const MIN_MEMORY_MB: u32 = 256;
/// Workstation's largest VM: 128 GB.
pub const MAX_MEMORY_MB: u32 = 128 * 1024;
/// Workstation's largest virtual disk: 8 TB.
pub const MAX_DISK_GB: u32 = 8 * 1024;
/// Own sizes one workspace keeps.
pub const MAX_SIZES: usize = 500;

/// How a disk takes space on this PC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provisioning {
    /// Takes only what the guest writes (the default).
    #[default]
    Thin,
    /// Takes its whole size when it is made.
    Thick,
}

impl Provisioning {
    pub fn as_str(self) -> &'static str {
        match self {
            Provisioning::Thin => "thin",
            Provisioning::Thick => "thick",
        }
    }
}

/// The kind of disk controller. Each OS profile names the one its guest needs, with the hypervisor's own model
/// ([`super::profiles`]); a disk names one only to differ from that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskController {
    Scsi,
    Sata,
    Nvme,
    Ide,
}

impl DiskController {
    pub fn label(self) -> &'static str {
        match self {
            DiskController::Scsi => "SCSI",
            DiskController::Sata => "SATA",
            DiskController::Nvme => "NVMe",
            DiskController::Ide => "IDE",
        }
    }
}

/// One disk of a size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskSpec {
    pub size_gb: u32,
    #[serde(default)]
    pub provisioning: Provisioning,
    /// `None`: the OS profile's controller.
    #[serde(default)]
    pub controller: Option<DiskController>,
}

impl DiskSpec {
    const fn thin(size_gb: u32) -> Self {
        Self {
            size_gb,
            provisioning: Provisioning::Thin,
            controller: None,
        }
    }

    /// `40 GB thin`, `500 GB thick on SATA`.
    pub fn describe(&self) -> String {
        let on = self
            .controller
            .map(|c| format!(" on {}", c.label()))
            .unwrap_or_default();
        format!("{} GB {}{on}", self.size_gb, self.provisioning.as_str())
    }
}

/// A size as the Templates page and deploy see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Size {
    /// A built-in's name (`gp.medium`), or an own size's UUID.
    pub id: String,
    pub name: String,
    /// Part of the app: read only.
    pub built_in: bool,
    pub sockets: u32,
    pub cores_per_socket: u32,
    pub memory_mb: u32,
    /// The first is the boot disk.
    pub disks: Vec<DiskSpec>,
    pub description: Option<String>,
    /// Own sizes only.
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl Size {
    pub fn vcpus(&self) -> u32 {
        self.sockets.saturating_mul(self.cores_per_socket)
    }

    /// Every disk at its full size: what thin disks may grow to.
    pub fn total_disk_gb(&self) -> u64 {
        self.disks.iter().map(|d| u64::from(d.size_gb)).sum()
    }

    /// `2 vCPU, 4 GB RAM, 40 GB thin + 500 GB thin`, for the audit log and previews.
    pub fn describe(&self) -> String {
        let cpu = if self.sockets > 1 {
            format!("{} vCPU ({} x {})", self.vcpus(), self.sockets, self.cores_per_socket)
        } else {
            format!("{} vCPU", self.vcpus())
        };
        let disks: Vec<String> = self.disks.iter().map(DiskSpec::describe).collect();
        format!("{cpu}, {} RAM, {}", memory_text(self.memory_mb), disks.join(" + "))
    }
}

/// `512 MB`, `4 GB`, `1.5 GB`.
pub fn memory_text(mb: u32) -> String {
    if mb < 1024 {
        format!("{mb} MB")
    } else if mb.is_multiple_of(1024) {
        format!("{} GB", mb / 1024)
    } else {
        format!("{:.1} GB", f64::from(mb) / 1024.0)
    }
}

/// What the size editor sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SizeInput {
    pub name: String,
    pub sockets: u32,
    pub cores_per_socket: u32,
    pub memory_mb: u32,
    pub disks: Vec<DiskSpec>,
    #[serde(default)]
    pub description: Option<String>,
}

impl From<&Size> for SizeInput {
    fn from(size: &Size) -> Self {
        Self {
            name: size.name.clone(),
            sockets: size.sockets,
            cores_per_socket: size.cores_per_socket,
            memory_mb: size.memory_mb,
            disks: size.disks.clone(),
            description: size.description.clone(),
        }
    }
}

/// A built-in size, as the plan's table lists it: one socket, the vCPUs as its cores.
struct BuiltIn {
    name: &'static str,
    vcpus: u32,
    memory_mb: u32,
    disks: &'static [DiskSpec],
    good_for: &'static str,
}

const BUILT_INS: [BuiltIn; 12] = [
    BuiltIn {
        name: "gp.nano",
        vcpus: 1,
        memory_mb: 512,
        disks: &[DiskSpec::thin(8)],
        good_for: "Tiny services, test boxes",
    },
    BuiltIn {
        name: "gp.micro",
        vcpus: 1,
        memory_mb: 1024,
        disks: &[DiskSpec::thin(16)],
        good_for: "Jump host, DNS, NTP",
    },
    BuiltIn {
        name: "gp.small",
        vcpus: 1,
        memory_mb: 2 * 1024,
        disks: &[DiskSpec::thin(20)],
        good_for: "Small web or agent host",
    },
    BuiltIn {
        name: "gp.medium",
        vcpus: 2,
        memory_mb: 4 * 1024,
        disks: &[DiskSpec::thin(40)],
        good_for: "General Linux server (the default)",
    },
    BuiltIn {
        name: "gp.large",
        vcpus: 2,
        memory_mb: 8 * 1024,
        disks: &[DiskSpec::thin(60)],
        good_for: "App server, Docker host",
    },
    BuiltIn {
        name: "gp.xlarge",
        vcpus: 4,
        memory_mb: 16 * 1024,
        disks: &[DiskSpec::thin(100)],
        good_for: "Database, CI runner",
    },
    BuiltIn {
        name: "gp.2xlarge",
        vcpus: 8,
        memory_mb: 32 * 1024,
        disks: &[DiskSpec::thin(200)],
        good_for: "Heavy lab, Kubernetes node",
    },
    BuiltIn {
        name: "cpu.large",
        vcpus: 4,
        memory_mb: 4 * 1024,
        disks: &[DiskSpec::thin(40)],
        good_for: "Builds, load generators",
    },
    BuiltIn {
        name: "cpu.xlarge",
        vcpus: 8,
        memory_mb: 8 * 1024,
        disks: &[DiskSpec::thin(60)],
        good_for: "Parallel builds",
    },
    BuiltIn {
        name: "mem.large",
        vcpus: 2,
        memory_mb: 16 * 1024,
        disks: &[DiskSpec::thin(60)],
        good_for: "Caches, in-memory databases",
    },
    BuiltIn {
        name: "mem.xlarge",
        vcpus: 4,
        memory_mb: 32 * 1024,
        disks: &[DiskSpec::thin(100)],
        good_for: "Databases, search",
    },
    BuiltIn {
        name: "disk.large",
        vcpus: 2,
        memory_mb: 4 * 1024,
        disks: &[DiskSpec::thin(40), DiskSpec::thin(500)],
        good_for: "File server, backups, logs",
    },
];

/// The size a new launch template starts with.
pub const DEFAULT_SIZE: &str = "gp.medium";

/// The twelve built-in sizes, in the plan's order.
pub fn built_in_sizes() -> Vec<Size> {
    BUILT_INS
        .iter()
        .map(|b| Size {
            id: b.name.to_owned(),
            name: b.name.to_owned(),
            built_in: true,
            sockets: 1,
            cores_per_socket: b.vcpus,
            memory_mb: b.memory_mb,
            disks: b.disks.to_vec(),
            description: Some(b.good_for.to_owned()),
            created_at: None,
            updated_at: None,
        })
        .collect()
}

/// The built-in size with this name or id (any letter case).
pub fn built_in(id: &str) -> Option<Size> {
    built_in_sizes().into_iter().find(|s| s.id.eq_ignore_ascii_case(id))
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(CoreError::InvalidInput(message.into()))
}

/// A size name: like a cloud instance type, `gp.medium` or `web-small_2`. 1 to [`MAX_SIZE_NAME`] letters, digits,
/// `.`, `-` and `_`, starting with a letter or digit; not a built-in's.
pub fn clean_size_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return invalid("Give the size a name, such as web.small.");
    }
    if name.chars().count() > MAX_SIZE_NAME {
        return invalid(format!("A size's name can be at most {MAX_SIZE_NAME} characters."));
    }
    let starts_well = name.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if !starts_well
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return invalid("A size's name can hold letters, digits, dots, hyphens and underscores, and starts with a letter or digit (like gp.medium).");
    }
    if built_in(name).is_some() {
        return invalid(format!(
            "{name} is a built-in size. Pick another name; Duplicate makes an editable copy of a built-in."
        ));
    }
    Ok(name.to_owned())
}

/// Checks and tidies a size.
pub fn check_size(input: &SizeInput) -> Result<SizeInput> {
    let name = clean_size_name(&input.name)?;
    if input.sockets == 0 || input.cores_per_socket == 0 {
        return invalid("A size needs at least one socket with one core.");
    }
    let vcpus = input.sockets.saturating_mul(input.cores_per_socket);
    if vcpus > MAX_VCPUS {
        return invalid(format!(
            "{} sockets x {} cores is {vcpus} vCPUs; a VM can have at most {MAX_VCPUS}.",
            input.sockets, input.cores_per_socket
        ));
    }
    if !(MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&input.memory_mb) {
        return invalid(format!(
            "RAM must be {} to {}.",
            memory_text(MIN_MEMORY_MB),
            memory_text(MAX_MEMORY_MB)
        ));
    }
    if !input.memory_mb.is_multiple_of(4) {
        return invalid("RAM must be a multiple of 4 MB (Workstation's rule).");
    }
    if input.disks.is_empty() {
        return invalid("A size needs a boot disk.");
    }
    if input.disks.len() > MAX_DISKS {
        return invalid(format!("A size can have at most {MAX_DISKS} disks."));
    }
    if let Some(bad) = input.disks.iter().find(|d| !(1..=MAX_DISK_GB).contains(&d.size_gb)) {
        return invalid(format!("A disk can be 1 to {MAX_DISK_GB} GB, not {} GB.", bad.size_gb));
    }
    let description = clean_description(input.description.as_deref())?;
    Ok(SizeInput {
        name,
        sockets: input.sockets,
        cores_per_socket: input.cores_per_socket,
        memory_mb: input.memory_mb,
        disks: input.disks.clone(),
        description,
    })
}

fn clean_description(text: Option<&str>) -> Result<Option<String>> {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > MAX_SIZE_DESCRIPTION {
        return invalid(format!(
            "A size's description can be at most {MAX_SIZE_DESCRIPTION} characters."
        ));
    }
    if text.chars().any(char::is_control) {
        return invalid("A size's description can't hold line breaks or tabs.");
    }
    Ok(Some(text.to_owned()))
}

/// What changed between two versions of a size, for the audit log.
pub(crate) fn size_changes(before: &Size, after: &SizeInput) -> Vec<String> {
    let mut out = Vec::new();
    if before.name != after.name {
        out.push(format!("renamed to '{}'", after.name));
    }
    let after_size = Size {
        id: before.id.clone(),
        name: after.name.clone(),
        built_in: false,
        sockets: after.sockets,
        cores_per_socket: after.cores_per_socket,
        memory_mb: after.memory_mb,
        disks: after.disks.clone(),
        description: after.description.clone(),
        created_at: None,
        updated_at: None,
    };
    if before.describe() != after_size.describe() {
        out.push(format!("{} -> {}", before.describe(), after_size.describe()));
    }
    if before.description != after.description {
        out.push("description changed".to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_the_twelve_built_ins_of_the_plan() {
        let sizes = built_in_sizes();
        let table: Vec<(&str, u32, u32, Vec<u32>)> = sizes
            .iter()
            .map(|s| {
                (
                    s.name.as_str(),
                    s.vcpus(),
                    s.memory_mb,
                    s.disks.iter().map(|d| d.size_gb).collect(),
                )
            })
            .collect();
        assert_eq!(
            table,
            vec![
                ("gp.nano", 1, 512, vec![8]),
                ("gp.micro", 1, 1024, vec![16]),
                ("gp.small", 1, 2048, vec![20]),
                ("gp.medium", 2, 4096, vec![40]),
                ("gp.large", 2, 8192, vec![60]),
                ("gp.xlarge", 4, 16384, vec![100]),
                ("gp.2xlarge", 8, 32768, vec![200]),
                ("cpu.large", 4, 4096, vec![40]),
                ("cpu.xlarge", 8, 8192, vec![60]),
                ("mem.large", 2, 16384, vec![60]),
                ("mem.xlarge", 4, 32768, vec![100]),
                ("disk.large", 2, 4096, vec![40, 500]),
            ]
        );
        for s in &sizes {
            assert!(s.built_in && s.id == s.name, "{}", s.name);
            assert_eq!(s.sockets, 1, "{}", s.name);
            assert!(s.description.is_some(), "{}", s.name);
            // Thin unless a template says thick; the profile's controller.
            assert!(s
                .disks
                .iter()
                .all(|d| d.provisioning == Provisioning::Thin && d.controller.is_none()));
            // Each one passes the checks an own size must pass, apart from its reserved name.
            let mut input = SizeInput::from(s);
            input.name = format!("copy-{}", s.name);
            check_size(&input).unwrap();
        }
        assert_eq!(built_in("GP.MEDIUM").map(|s| s.name), Some("gp.medium".to_owned()));
        assert_eq!(built_in(DEFAULT_SIZE).map(|s| s.vcpus()), Some(2));
        assert_eq!(
            built_in("disk.large").unwrap().describe(),
            "2 vCPU, 4 GB RAM, 40 GB thin + 500 GB thin"
        );
    }

    fn input(name: &str) -> SizeInput {
        SizeInput {
            name: name.into(),
            sockets: 2,
            cores_per_socket: 2,
            memory_mb: 6144,
            disks: vec![DiskSpec::thin(50)],
            description: Some("  web tier  ".into()),
        }
    }

    #[test]
    fn a_size_is_checked_and_tidied() {
        let ok = check_size(&input(" web.small ")).unwrap();
        assert_eq!(ok.name, "web.small");
        assert_eq!(ok.description.as_deref(), Some("web tier"));
        let bad = [
            (input("gp.medium"), "is a built-in size"),
            (input("GP.Nano"), "is a built-in size"),
            (input(""), "Give the size a name"),
            (input("web small"), "letters, digits"),
            (input(".web"), "letters, digits"),
            (input(&"x".repeat(41)), "at most 40"),
            (
                SizeInput {
                    sockets: 0,
                    ..input("a")
                },
                "at least one socket",
            ),
            (
                SizeInput {
                    sockets: 4,
                    cores_per_socket: 16,
                    ..input("a")
                },
                "at most 32",
            ),
            (
                SizeInput {
                    memory_mb: 128,
                    ..input("a")
                },
                "RAM must be 256 MB to 128 GB",
            ),
            (
                SizeInput {
                    memory_mb: 1026,
                    ..input("a")
                },
                "multiple of 4 MB",
            ),
            (
                SizeInput {
                    disks: vec![],
                    ..input("a")
                },
                "boot disk",
            ),
            (
                SizeInput {
                    disks: vec![DiskSpec::thin(0)],
                    ..input("a")
                },
                "1 to 8192 GB",
            ),
            (
                SizeInput {
                    disks: vec![DiskSpec::thin(9000)],
                    ..input("a")
                },
                "1 to 8192 GB",
            ),
            (
                SizeInput {
                    disks: vec![DiskSpec::thin(10); 9],
                    ..input("a")
                },
                "at most 8 disks",
            ),
            (
                SizeInput {
                    description: Some("two\nlines".into()),
                    ..input("a")
                },
                "line breaks",
            ),
        ];
        for (size, why) in bad {
            let err = check_size(&size).unwrap_err().to_string();
            assert!(err.contains(why), "{}: {err}", size.name);
        }
    }

    #[test]
    fn sizes_describe_themselves() {
        assert_eq!(memory_text(512), "512 MB");
        assert_eq!(memory_text(1536), "1.5 GB");
        assert_eq!(memory_text(32768), "32 GB");
        let thick = DiskSpec {
            size_gb: 100,
            provisioning: Provisioning::Thick,
            controller: Some(DiskController::Nvme),
        };
        assert_eq!(thick.describe(), "100 GB thick on NVMe");
        let before = built_in("gp.medium").unwrap();
        let changes = size_changes(&before, &input("web.small"));
        assert_eq!(
            changes,
            [
                "renamed to 'web.small'",
                "2 vCPU, 4 GB RAM, 40 GB thin -> 4 vCPU (2 x 2), 6 GB RAM, 50 GB thin",
                "description changed"
            ]
        );
    }
}
