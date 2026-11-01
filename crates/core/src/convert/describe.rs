//! CV-01: what a foreign VM's own description says about it: an OVF descriptor, a libvirt domain XML (KVM) or a
//! Proxmox VE `.conf`. Each is untrusted input: read whole up to [`MAX_DESCRIPTION_BYTES`] or refused, parsed by
//! Remotely's own small reader (no entities, no DTDs, nothing fetched), with caps on depth and elements, and only the
//! values an import uses taken from it: name, CPU, memory, firmware, the guest OS's family and each disk. Disk paths
//! in it are never opened as written: a disk is looked for by its file name beside the description.

use serde::Serialize;

use crate::catalog::profiles::GuestFamily;

/// A description is a few KB; anything larger than this is refused unread (A9).
pub const MAX_DESCRIPTION_BYTES: u64 = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_ELEMENTS: usize = 20_000;

/// What a description says.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Described {
    pub name: Option<String>,
    pub vcpus: Option<u32>,
    pub cores_per_socket: Option<u32>,
    pub memory_mb: Option<u32>,
    /// `Some(true)`: UEFI; `Some(false)`: BIOS.
    pub efi: Option<bool>,
    pub family: Option<GuestFamily>,
    /// The guest OS as the description names it.
    pub os: Option<String>,
    pub disks: Vec<DescribedDisk>,
}

/// One disk a description names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribedDisk {
    /// Its file's name (the last part of the path written in the description).
    pub file: String,
    /// The format the description says it is (`qcow2`, `raw`, `vmdk`...), as written.
    pub format: Option<String>,
    pub capacity_bytes: Option<u64>,
}

// ---- A small XML reader --------------------------------------------------------------------------------------

/// One element: its local name (prefix dropped), attributes (local names) and text, and its children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name.eq_ignore_ascii_case(name))
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name.eq_ignore_ascii_case(name))
    }

    /// Every element below this one named `name`, depth first.
    pub fn find_all<'a>(&'a self, name: &str, out: &mut Vec<&'a Element>) {
        for child in &self.children {
            if child.name.eq_ignore_ascii_case(name) {
                out.push(child);
            }
            child.find_all(name, out);
        }
    }

    pub fn text(&self) -> &str {
        self.text.trim()
    }
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_owned()
}

/// `&amp;` and its kin, and `&#NN;` / `&#xNN;`; anything else is kept as written (no entity is ever expanded).
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at..];
        let Some(end) = after.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &after[1..];
            continue;
        };
        let entity = &after[1..end];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = &after[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn parse_attributes(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim();
        let after = rest[eq + 1..].trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let Some(end) = after[1..].find(quote) else {
            break;
        };
        if !name.is_empty() && !name.contains(char::is_whitespace) {
            out.push((local(name), unescape(&after[1..1 + end])));
        }
        rest = &after[1 + end + 1..];
    }
    out
}

/// Parses an XML document into its root element; `None` for something that isn't well enough formed to read.
/// Comments, processing instructions and CDATA are skipped; a DOCTYPE refuses the document (descriptions never
/// need one, and entities are never expanded).
pub fn parse_xml(text: &str) -> Option<Element> {
    parse_xml_limited(
        text,
        XmlLimits {
            depth: MAX_DEPTH,
            elements: MAX_ELEMENTS,
            text: 64 * 1024,
        },
    )
}

/// What [`parse_xml_limited`] reads at most.
#[derive(Debug, Clone, Copy)]
pub struct XmlLimits {
    /// Elements inside each other.
    pub depth: usize,
    /// Elements in all.
    pub elements: usize,
    /// Bytes of text kept per element (the rest is dropped).
    pub text: usize,
}

/// [`parse_xml`] with its own caps (F4: a WinRM answer's output stream runs to a few hundred KB of base64).
pub fn parse_xml_limited(text: &str, limits: XmlLimits) -> Option<Element> {
    let mut stack: Vec<Element> = vec![Element::default()];
    let mut rest = text;
    let mut count = 0usize;
    while let Some(lt) = rest.find('<') {
        let text_part = &rest[..lt];
        if let Some(top) = stack.last_mut() {
            if !text_part.trim().is_empty() && top.text.len() < limits.text {
                top.text.push_str(&unescape(text_part));
            }
        }
        let tag = &rest[lt..];
        if let Some(after) = tag.strip_prefix("<!--") {
            rest = &after[after.find("-->")? + 3..];
            continue;
        }
        if let Some(after) = tag.strip_prefix("<![CDATA[") {
            rest = &after[after.find("]]>")? + 3..];
            continue;
        }
        if tag.starts_with("<!") {
            return None;
        }
        if let Some(after) = tag.strip_prefix("<?") {
            rest = &after[after.find("?>")? + 2..];
            continue;
        }
        let end = tag.find('>')?;
        let inner = &tag[1..end];
        rest = &tag[end + 1..];
        if let Some(name) = inner.strip_prefix('/') {
            let done = stack.pop()?;
            if !local(name.trim()).eq_ignore_ascii_case(&done.name) {
                return None;
            }
            stack.last_mut()?.children.push(done);
            continue;
        }
        count += 1;
        if count > limits.elements || stack.len() > limits.depth {
            return None;
        }
        let self_closing = inner.ends_with('/');
        let inner = inner.trim_end_matches('/');
        let (name, attributes) = match inner.find(char::is_whitespace) {
            Some(at) => (&inner[..at], &inner[at..]),
            None => (inner, ""),
        };
        let element = Element {
            name: local(name),
            attributes: parse_attributes(attributes),
            ..Element::default()
        };
        if self_closing {
            stack.last_mut()?.children.push(element);
        } else {
            stack.push(element);
        }
    }
    if stack.len() != 1 {
        return None;
    }
    stack.pop()?.children.into_iter().next()
}

// ---- What each description says -----------------------------------------------------------------------------

/// The guest's family from the words a description uses for its OS.
pub fn family_of(text: &str) -> Option<GuestFamily> {
    let lower = text.to_ascii_lowercase();
    let windows = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|w| w.starts_with("win"));
    if windows {
        return Some(GuestFamily::Windows);
    }
    let linux = [
        "linux", "ubuntu", "debian", "rhel", "redhat", "centos", "rocky", "alma", "fedora", "suse", "l26", "l24",
    ]
    .iter()
    .any(|w| lower.contains(w));
    linux.then_some(GuestFamily::Linux)
}

fn file_name_of(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).trim().to_owned()
}

/// Bytes per unit of an OVF `AllocationUnits`/`capacityAllocationUnits` (`byte * 2^20`...); absent: bytes.
fn ovf_unit(units: Option<&str>) -> Option<u64> {
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
        "megabytes" | "mb" => Some(1 << 20),
        "gigabytes" | "gb" => Some(1 << 30),
        other => {
            let power = other.strip_prefix("byte*2^")?.parse::<u32>().ok()?;
            (power < 64).then(|| 1u64 << power)
        }
    }
}

/// An OVF descriptor: CPUs (ResourceType 3), memory (4), disks (DiskSection, with their files), firmware (VMware's
/// `firmware` config, VirtualBox's `<Firmware>`) and the OS (`OperatingSystemSection`).
pub fn parse_ovf(text: &str) -> Option<Described> {
    let root = parse_xml(text)?;
    if !root.name.eq_ignore_ascii_case("Envelope") {
        return None;
    }
    let mut out = Described::default();
    let mut systems = Vec::new();
    root.find_all("VirtualSystem", &mut systems);
    let system = systems.first().copied().unwrap_or(&root);
    out.name = system
        .child("Name")
        .map(|n| n.text().to_owned())
        .or_else(|| system.attr("id").map(str::to_owned))
        .filter(|n| !n.is_empty());
    let mut items = Vec::new();
    system.find_all("Item", &mut items);
    let mut storage_items = Vec::new();
    system.find_all("StorageItem", &mut storage_items);
    items.extend(storage_items);
    for item in items {
        let kind = item.child("ResourceType").map(Element::text).unwrap_or("");
        let quantity = item.child("VirtualQuantity").and_then(|q| q.text().parse::<u64>().ok());
        match kind {
            "3" => {
                out.vcpus = quantity.and_then(|q| u32::try_from(q).ok());
                out.cores_per_socket = item.child("CoresPerSocket").and_then(|c| c.text().parse().ok());
            }
            "4" => {
                let unit = ovf_unit(item.child("AllocationUnits").map(Element::text));
                out.memory_mb = match (quantity, unit) {
                    (Some(q), Some(u)) => u32::try_from(q.saturating_mul(u) >> 20).ok(),
                    _ => None,
                };
            }
            _ => {}
        }
    }
    // Files by id, for each disk's file name.
    let mut files = Vec::new();
    root.find_all("File", &mut files);
    let mut disks = Vec::new();
    root.find_all("Disk", &mut disks);
    for disk in disks {
        let file_ref = disk.attr("fileRef").unwrap_or("");
        let file = files
            .iter()
            .find(|f| f.attr("id") == Some(file_ref))
            .and_then(|f| f.attr("href"))
            .map(file_name_of)
            .unwrap_or_default();
        let capacity = disk
            .attr("capacity")
            .and_then(|c| c.trim().parse::<u64>().ok())
            .zip(ovf_unit(disk.attr("capacityAllocationUnits")))
            .map(|(c, u)| c.saturating_mul(u));
        let format = disk.attr("format").map(|f| {
            if f.to_ascii_lowercase().contains("vmdk") {
                "vmdk".to_owned()
            } else {
                f.rsplit(['/', '#']).next().unwrap_or(f).to_owned()
            }
        });
        out.disks.push(DescribedDisk {
            file,
            format,
            capacity_bytes: capacity,
        });
    }
    // Firmware: VMware writes `<vmw:Config vmw:key="firmware" vmw:value="efi"/>`, VirtualBox `<Firmware type="EFI"/>`.
    let mut configs = Vec::new();
    root.find_all("Config", &mut configs);
    if let Some(value) = configs
        .iter()
        .find(|c| c.attr("key") == Some("firmware"))
        .and_then(|c| c.attr("value"))
    {
        out.efi = Some(value.eq_ignore_ascii_case("efi"));
    }
    let mut firmware = Vec::new();
    root.find_all("Firmware", &mut firmware);
    if let Some(kind) = firmware.first().and_then(|f| f.attr("type")) {
        out.efi = Some(kind.to_ascii_uppercase().starts_with("EFI"));
    }
    let mut os = Vec::new();
    root.find_all("OperatingSystemSection", &mut os);
    if let Some(section) = os.first() {
        let named = section
            .child("Description")
            .map(|d| d.text().to_owned())
            .filter(|d| !d.is_empty())
            .or_else(|| section.attr("osType").map(str::to_owned));
        out.family = named
            .as_deref()
            .and_then(family_of)
            .or_else(|| section.attr("osType").and_then(family_of));
        out.os = named;
    }
    Some(out)
}

/// libvirt's `<memory unit=...>` in MB (KiB when no unit is written).
fn libvirt_mb(element: &Element) -> Option<u32> {
    let value: u64 = element.text().parse().ok()?;
    let unit = element.attr("unit").unwrap_or("KiB").to_ascii_lowercase();
    let bytes = match unit.as_str() {
        "b" | "bytes" => value,
        "k" | "kib" => value << 10,
        "kb" => value * 1000,
        "m" | "mib" => value << 20,
        "mb" => value * 1_000_000,
        "g" | "gib" => value << 30,
        "gb" => value * 1_000_000_000,
        _ => return None,
    };
    u32::try_from(bytes >> 20).ok()
}

/// A libvirt domain XML (`virsh dumpxml`): name, memory, vCPUs and topology, firmware (`<os firmware='efi'>` or an
/// OVMF loader), libosinfo's OS id, and each file-backed disk (CD-ROMs left out).
pub fn parse_libvirt(text: &str) -> Option<Described> {
    let root = parse_xml(text)?;
    if !root.name.eq_ignore_ascii_case("domain") {
        return None;
    }
    let mut out = Described {
        name: root
            .child("name")
            .map(|n| n.text().to_owned())
            .filter(|n| !n.is_empty()),
        memory_mb: root.child("memory").and_then(libvirt_mb),
        vcpus: root.child("vcpu").and_then(|v| v.text().parse().ok()),
        ..Described::default()
    };
    if let Some(topology) = root.child("cpu").and_then(|c| c.child("topology")) {
        out.cores_per_socket = topology.attr("cores").and_then(|c| c.parse().ok());
    }
    if let Some(os) = root.child("os") {
        let loader_efi = os
            .child("loader")
            .is_some_and(|l| l.text().to_ascii_lowercase().contains("ovmf") || l.attr("type") == Some("pflash"));
        out.efi = Some(os.attr("firmware") == Some("efi") || loader_efi);
    }
    let mut libosinfo = Vec::new();
    root.find_all("os", &mut libosinfo);
    if let Some(id) = libosinfo.iter().find_map(|o| o.attr("id")) {
        out.family = family_of(id);
        out.os = Some(id.to_owned());
    }
    if let Some(devices) = root.child("devices") {
        for disk in devices.children_named("disk") {
            if disk.attr("device").is_some_and(|d| d != "disk") {
                continue;
            }
            let Some(source) = disk.child("source") else {
                continue;
            };
            let Some(path) = source.attr("file").or_else(|| source.attr("dev")) else {
                continue;
            };
            out.disks.push(DescribedDisk {
                file: file_name_of(path),
                format: disk.child("driver").and_then(|d| d.attr("type")).map(str::to_owned),
                capacity_bytes: None,
            });
        }
    }
    Some(out)
}

/// Proxmox's `size=32G` in bytes.
fn proxmox_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let (number, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(text.len()),
    );
    let value: f64 = number.parse().ok()?;
    let factor = match unit.to_ascii_uppercase().as_str() {
        "" => 1.0,
        "K" => 1024.0,
        "M" => 1024.0 * 1024.0,
        "G" => 1024.0 * 1024.0 * 1024.0,
        "T" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * factor) as u64)
}

/// A Proxmox VE VM's `.conf` (`/etc/pve/qemu-server/<id>.conf`): `name`, `cores`, `sockets`, `memory` (MB),
/// `bios: ovmf`, `ostype`, and each disk (`scsi0: local-lvm:vm-100-disk-0,size=32G`; CD-ROMs left out). Only the
/// VM's own section counts, not its snapshots' (`[name]` sections).
pub fn parse_proxmox(text: &str) -> Option<Described> {
    let mut out = Described::default();
    let mut sockets: Option<u32> = None;
    let mut cores: Option<u32> = None;
    let mut any = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        any = true;
        match key {
            "name" => out.name = Some(value.to_owned()),
            "cores" => cores = value.parse().ok(),
            "sockets" => sockets = value.parse().ok(),
            "vcpus" => out.vcpus = value.parse().ok(),
            "memory" => out.memory_mb = value.parse().ok(),
            "bios" => out.efi = Some(value == "ovmf"),
            "ostype" => {
                out.os = Some(value.to_owned());
                out.family = family_of(value);
            }
            _ => {
                let bus = key.trim_end_matches(|c: char| c.is_ascii_digit());
                let numbered = bus.len() < key.len();
                if numbered && ["scsi", "sata", "virtio", "ide"].contains(&bus) && !value.contains("media=cdrom") {
                    let parts: Vec<&str> = value.split(',').map(str::trim).collect();
                    let volume = parts.first().copied().unwrap_or("");
                    let file = file_name_of(volume.rsplit(':').next().unwrap_or(volume));
                    let size = parts
                        .iter()
                        .find_map(|p| p.strip_prefix("size="))
                        .and_then(proxmox_size);
                    let format = parts.iter().find_map(|p| p.strip_prefix("format=")).map(str::to_owned);
                    if !file.is_empty() && file != "none" {
                        out.disks.push(DescribedDisk {
                            file,
                            format,
                            capacity_bytes: size,
                        });
                    }
                }
            }
        }
    }
    if !any {
        return None;
    }
    let cores = cores.unwrap_or(1).max(1);
    let total = cores.saturating_mul(sockets.unwrap_or(1).max(1));
    out.vcpus = Some(out.vcpus.unwrap_or(total).max(1));
    out.cores_per_socket = Some(cores);
    if out.efi.is_none() {
        out.efi = Some(false);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::disk_images as img;

    #[test]
    fn the_xml_reader_takes_what_descriptions_hold_and_refuses_the_rest() {
        let root = parse_xml(
            "<?xml version='1.0'?><!-- made by hand --><a:root x='1' b:y=\"&lt;2&gt;\"><child>one &amp; two</child><empty/><![CDATA[ignored]]></a:root>",
        )
        .unwrap();
        assert_eq!(root.name, "root");
        assert_eq!(root.attr("y"), Some("<2>"));
        assert_eq!(root.child("child").unwrap().text(), "one & two");
        assert!(root.child("empty").is_some());
        // A DTD (entity tricks), a mismatched tag, too deep, unclosed.
        assert!(parse_xml("<!DOCTYPE x [<!ENTITY a 'b'>]><x>&a;</x>").is_none());
        assert!(parse_xml("<a><b></a>").is_none());
        assert!(parse_xml(&"<a>".repeat(100)).is_none());
        assert!(parse_xml("<a><b>").is_none());
        assert_eq!(unescape("&#65;&#x42;&bogus;&"), "AB&bogus;&");
    }

    #[test]
    fn an_ovf_says_cpu_memory_disks_firmware_and_os() {
        let text = img::ovf(
            "web01",
            4,
            8192,
            true,
            "ubuntu64Guest",
            &[("web01-disk1.vmdk", 40 << 30), ("data.vmdk", 1 << 30)],
        );
        let d = parse_ovf(&text).unwrap();
        assert_eq!(d.name.as_deref(), Some("web01"));
        assert_eq!((d.vcpus, d.memory_mb, d.efi), (Some(4), Some(8192), Some(true)));
        assert_eq!(d.family, Some(GuestFamily::Linux));
        assert_eq!(d.disks.len(), 2);
        assert_eq!(d.disks[0].file, "web01-disk1.vmdk");
        assert_eq!(d.disks[0].capacity_bytes, Some(40 << 30));
        assert_eq!(d.disks[0].format.as_deref(), Some("vmdk"));
        let bios = parse_ovf(&img::ovf("w", 2, 4096, false, "windows2019srv_64Guest", &[])).unwrap();
        assert_eq!(bios.family, Some(GuestFamily::Windows));
        assert_eq!(
            bios.efi, None,
            "BIOS is what an OVF without a firmware setting means: the import decides"
        );
        assert!(parse_ovf("<domain/>").is_none());
    }

    #[test]
    fn a_libvirt_domain_says_its_vm() {
        let text = r#"<domain type='kvm'>
  <name>db01</name>
  <metadata><libosinfo:libosinfo xmlns:libosinfo="http://libosinfo.org/xmlns/libvirt/domain/1.0"><libosinfo:os id="http://rockylinux.org/rocky/9"/></libosinfo:libosinfo></metadata>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>4</vcpu>
  <cpu mode='host-passthrough'><topology sockets='1' cores='4' threads='1'/></cpu>
  <os firmware='efi'><type arch='x86_64' machine='q35'>hvm</type></os>
  <devices>
    <disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='/var/lib/libvirt/images/db01.qcow2'/><target dev='vda' bus='virtio'/></disk>
    <disk type='file' device='cdrom'><source file='/isos/rocky.iso'/></disk>
    <disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='/srv/data/db01-data.img'/></disk>
    <interface type='network'><mac address='52:54:00:12:34:56'/><source network='default'/></interface>
  </devices>
</domain>"#;
        let d = parse_libvirt(text).unwrap();
        assert_eq!(d.name.as_deref(), Some("db01"));
        assert_eq!(
            (d.vcpus, d.cores_per_socket, d.memory_mb),
            (Some(4), Some(4), Some(4096))
        );
        assert_eq!(d.efi, Some(true));
        assert_eq!(d.family, Some(GuestFamily::Linux));
        assert_eq!(
            d.disks
                .iter()
                .map(|d| (d.file.as_str(), d.format.as_deref()))
                .collect::<Vec<_>>(),
            [("db01.qcow2", Some("qcow2")), ("db01-data.img", Some("raw"))]
        );
        let bios = parse_libvirt("<domain><name>x</name><memory unit='MiB'>512</memory><os><loader>/usr/share/OVMF/OVMF_CODE.fd</loader></os></domain>").unwrap();
        assert_eq!((bios.memory_mb, bios.efi), (Some(512), Some(true)));
        assert!(parse_libvirt("<Envelope/>").is_none());
    }

    #[test]
    fn a_proxmox_conf_says_its_vm_but_not_its_snapshots() {
        let text = "boot: order=scsi0;net0\ncores: 2\nsockets: 2\nmemory: 4096\nname: web01\nbios: ovmf\nostype: l26\nefidisk0: local-lvm:vm-100-disk-1,efitype=4m,size=4M\nide2: local:iso/ubuntu.iso,media=cdrom,size=2G\nscsi0: local-lvm:vm-100-disk-0,iothread=1,size=32G\nscsi1: nas:100/vm-100-disk-2.qcow2,size=500G\nnet0: virtio=BC:24:11:00:00:01,bridge=vmbr0\n\n[before-upgrade]\ncores: 8\nscsi2: local-lvm:vm-100-disk-9,size=1G\n";
        let d = parse_proxmox(text).unwrap();
        assert_eq!(d.name.as_deref(), Some("web01"));
        assert_eq!(
            (d.vcpus, d.cores_per_socket, d.memory_mb, d.efi),
            (Some(4), Some(2), Some(4096), Some(true))
        );
        assert_eq!(d.family, Some(GuestFamily::Linux));
        assert_eq!(
            d.disks
                .iter()
                .map(|d| (d.file.as_str(), d.capacity_bytes))
                .collect::<Vec<_>>(),
            [
                ("vm-100-disk-0", Some(32 << 30)),
                ("vm-100-disk-2.qcow2", Some(500 << 30))
            ]
        );
        let windows = parse_proxmox("ostype: win11\nmemory: 8192\n").unwrap();
        assert_eq!(
            (windows.family, windows.vcpus, windows.efi),
            (Some(GuestFamily::Windows), Some(1), Some(false))
        );
        assert!(parse_proxmox("").is_none());
    }
}
