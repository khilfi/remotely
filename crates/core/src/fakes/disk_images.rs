//! CV-01 to CV-03 in tests: small disk images made at run time, in a folder of the system temp folder that is
//! deleted with its [`TempFolder`]. Each has the header of its format, as the real tools write it, so the readers
//! in [`crate::convert::inspect`] read them; the data is zeros (a few MB at most). Never downloaded images, never
//! a network share (docs/plan-0.5.md, "Development safety for 0.5.0").

use std::path::{Path, PathBuf};

/// A folder in the system temp folder, deleted when dropped.
#[derive(Debug)]
pub struct TempFolder {
    path: PathBuf,
}

impl TempFolder {
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("remotely-{tag}-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&path).expect("make a temp folder");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Writes `bytes` to `name` in the folder and returns its path.
    pub fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, bytes).expect("write a test image");
        path
    }
}

impl Drop for TempFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn put_u32_le(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64_le(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn put_u16_le(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32_be(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn put_u64_be(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

/// A VMDK text descriptor. `extents`: (sectors, `SPARSE`/`FLAT`/`VMFS`, file name).
pub fn vmdk_descriptor(create_type: &str, extents: &[(u64, &str, &str)], parent: Option<&str>) -> String {
    let mut text = format!(
        "# Disk DescriptorFile\nversion=1\nencoding=\"windows-1252\"\nCID=fffffffe\nparentCID={}\ncreateType=\"{create_type}\"\n",
        if parent.is_some() { "12345678" } else { "ffffffff" }
    );
    if let Some(parent) = parent {
        text.push_str(&format!("parentFileNameHint=\"{parent}\"\n"));
    }
    text.push_str("\n# Extent description\n");
    for (sectors, kind, file) in extents {
        let offset = if *kind == "SPARSE" { "" } else { " 0" };
        text.push_str(&format!("RW {sectors} {kind} \"{file}\"{offset}\n"));
    }
    text.push_str("\n# The Disk Data Base\n#DDB\n\nddb.adapterType = \"lsilogic\"\nddb.virtualHWVersion = \"21\"\n");
    text
}

/// A monolithic sparse VMDK (`KDMV` header, its descriptor in sector 1) of `virtual_bytes`, named `name` in its
/// own descriptor; `stream` makes it a stream-optimized one.
pub fn vmdk_sparse(name: &str, virtual_bytes: u64, stream: bool) -> Vec<u8> {
    let sectors = virtual_bytes / 512;
    let create = if stream { "streamOptimized" } else { "monolithicSparse" };
    let descriptor = vmdk_descriptor(create, &[(sectors, "SPARSE", name)], None);
    let mut out = vec![0u8; 512 * 24];
    out[0..4].copy_from_slice(b"KDMV");
    put_u32_le(&mut out, 4, if stream { 3 } else { 1 });
    put_u32_le(&mut out, 8, 3);
    put_u64_le(&mut out, 12, sectors);
    put_u64_le(&mut out, 20, 128);
    put_u64_le(&mut out, 28, 1);
    put_u64_le(&mut out, 36, 20);
    out[73] = b'\n';
    out[74] = b' ';
    out[75] = b'\r';
    out[76] = b'\n';
    if stream {
        put_u16_le(&mut out, 77, 1);
    }
    out[512..512 + descriptor.len()].copy_from_slice(descriptor.as_bytes());
    out
}

/// A VDI's header: `kind` 1 dynamic, 2 fixed, 4 differencing.
pub fn vdi(virtual_bytes: u64, kind: u32) -> Vec<u8> {
    let mut out = vec![0u8; 1024];
    let text = b"<<< Oracle VM VirtualBox Disk Image >>>\n";
    out[..text.len()].copy_from_slice(text);
    put_u32_le(&mut out, 0x40, 0xbeda_107f);
    put_u32_le(&mut out, 0x44, 0x0001_0001);
    put_u32_le(&mut out, 0x48, 0x190);
    put_u32_le(&mut out, 0x4c, kind);
    put_u64_le(&mut out, 0x170, virtual_bytes);
    put_u32_le(&mut out, 0x178, 1 << 20);
    out
}

/// A VHD footer: `kind` 2 fixed, 3 dynamic, 4 differencing.
pub fn vhd_footer(virtual_bytes: u64, kind: u32) -> [u8; 512] {
    let mut out = [0u8; 512];
    out[0..8].copy_from_slice(b"conectix");
    put_u32_be(&mut out, 8, 2);
    put_u32_be(&mut out, 12, 0x0001_0000);
    put_u64_be(&mut out, 16, if kind == 2 { u64::MAX } else { 512 });
    out[28..32].copy_from_slice(b"rmly");
    out[36..40].copy_from_slice(b"Wi2k");
    put_u64_be(&mut out, 40, virtual_bytes);
    put_u64_be(&mut out, 48, virtual_bytes);
    put_u32_be(&mut out, 60, kind);
    let sum: u32 = out.iter().map(|b| u32::from(*b)).sum();
    put_u32_be(&mut out, 64, !sum);
    out
}

/// A whole fixed VHD of `virtual_bytes` (zeros, then the footer): a few MB at most in tests.
pub fn vhd_fixed(virtual_bytes: u64) -> Vec<u8> {
    let mut out = vec![0u8; usize::try_from(virtual_bytes).expect("a small test disk")];
    out.extend_from_slice(&vhd_footer(virtual_bytes, 2));
    out
}

/// A dynamic VHD (or a differencing one with `parent`): the footer's copy, its dynamic header, the footer.
pub fn vhd_dynamic(virtual_bytes: u64, parent: bool) -> Vec<u8> {
    let kind = if parent { 4 } else { 3 };
    let footer = vhd_footer(virtual_bytes, kind);
    let mut out = footer.to_vec();
    let mut header = vec![0u8; 1024];
    header[0..8].copy_from_slice(b"cxsparse");
    out.extend_from_slice(&header);
    out.extend_from_slice(&footer);
    out
}

/// A qcow2 v3 header of `virtual_bytes`, naming `backing` as its backing file when given.
pub fn qcow2(virtual_bytes: u64, backing: Option<&str>) -> Vec<u8> {
    let mut out = vec![0u8; 4096];
    out[0..4].copy_from_slice(b"QFI\xfb");
    put_u32_be(&mut out, 4, 3);
    if let Some(name) = backing {
        put_u64_be(&mut out, 8, 0x400);
        put_u32_be(&mut out, 16, name.len() as u32);
        out[0x400..0x400 + name.len()].copy_from_slice(name.as_bytes());
    }
    put_u32_be(&mut out, 20, 16);
    put_u64_be(&mut out, 24, virtual_bytes);
    put_u32_be(&mut out, 96, 4);
    put_u32_be(&mut out, 100, 112);
    out
}

/// A GUID in VHDX's on-disk order (the first three fields little-endian).
fn guid_bytes(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    let mut raw = [0u8; 16];
    for (i, byte) in raw.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("a GUID");
    }
    let mut out = raw;
    out[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    out[4..6].copy_from_slice(&[raw[5], raw[4]]);
    out[6..8].copy_from_slice(&[raw[7], raw[6]]);
    out
}

pub const VHDX_METADATA_REGION: &str = "8B7CA206-4790-4B9A-B8FE-575F050F886E";
pub const VHDX_BAT_REGION: &str = "2DC27766-F623-4200-9D64-115E9BFD4A08";
pub const VHDX_FILE_PARAMETERS: &str = "CAA16737-FA36-4D43-B3B6-33F0AA44E76B";
pub const VHDX_VIRTUAL_DISK_SIZE: &str = "2FA54224-CD1B-4876-B211-5DBED83BF4B8";

/// A VHDX's file identifier, headers, region tables and metadata (4 MB): `fixed` sets "leave blocks
/// allocated", `parent` "has parent" (a differencing disk).
pub fn vhdx(virtual_bytes: u64, fixed: bool, parent: bool) -> Vec<u8> {
    const MB: usize = 1 << 20;
    let mut out = vec![0u8; 4 * MB];
    out[0..8].copy_from_slice(b"vhdxfile");
    for at in [0x10000, 0x20000] {
        out[at..at + 4].copy_from_slice(b"head");
        put_u16_le(&mut out, at + 66, 1);
    }
    for at in [0x30000, 0x40000] {
        out[at..at + 4].copy_from_slice(b"regi");
        put_u32_le(&mut out, at + 8, 2);
        let bat = at + 16;
        out[bat..bat + 16].copy_from_slice(&guid_bytes(VHDX_BAT_REGION));
        put_u64_le(&mut out, bat + 16, (3 * MB) as u64);
        put_u32_le(&mut out, bat + 24, MB as u32);
        put_u32_le(&mut out, bat + 28, 1);
        let meta = at + 48;
        out[meta..meta + 16].copy_from_slice(&guid_bytes(VHDX_METADATA_REGION));
        put_u64_le(&mut out, meta + 16, (2 * MB) as u64);
        put_u32_le(&mut out, meta + 24, MB as u32);
        put_u32_le(&mut out, meta + 28, 1);
    }
    let region = 2 * MB;
    out[region..region + 8].copy_from_slice(b"metadata");
    put_u16_le(&mut out, region + 10, 2);
    let entries = [(VHDX_FILE_PARAMETERS, 0x10000u32, 8u32), (VHDX_VIRTUAL_DISK_SIZE, 0x10008, 8)];
    for (i, (guid, offset, length)) in entries.iter().enumerate() {
        let at = region + 32 + i * 32;
        out[at..at + 16].copy_from_slice(&guid_bytes(guid));
        put_u32_le(&mut out, at + 16, *offset);
        put_u32_le(&mut out, at + 20, *length);
        put_u32_le(&mut out, at + 24, 0b110);
    }
    put_u32_le(&mut out, region + 0x10000, 32 << 20);
    let flags = u32::from(fixed) | (u32::from(parent) << 1);
    put_u32_le(&mut out, region + 0x10004, flags);
    put_u64_le(&mut out, region + 0x10008, virtual_bytes);
    out
}

/// A tar file (an OVA) of these members, in order.
pub fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in members {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000644");
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        let size = format!("{:011o}", data.len());
        header[124..135].copy_from_slice(size.as_bytes());
        header[136..147].copy_from_slice(b"00000000000");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
        let sum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(sum.as_bytes());
        out.extend_from_slice(&header);
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// An OVF descriptor for a VM with these disks (file name, capacity in bytes), as vendors write them.
pub fn ovf(name: &str, cpus: u32, memory_mb: u32, efi: bool, os: &str, disks: &[(&str, u64)]) -> String {
    let mut files = String::new();
    let mut disk_section = String::new();
    let mut items = String::new();
    for (i, (file, capacity)) in disks.iter().enumerate() {
        let n = i + 1;
        files.push_str(&format!("    <File ovf:href=\"{file}\" ovf:id=\"file{n}\"/>\n"));
        disk_section.push_str(&format!(
            "    <Disk ovf:capacity=\"{capacity}\" ovf:capacityAllocationUnits=\"byte\" ovf:diskId=\"vmdisk{n}\" ovf:fileRef=\"file{n}\" ovf:format=\"http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized\"/>\n"
        ));
        items.push_str(&format!(
            "      <Item><rasd:ElementName>Hard Disk {n}</rasd:ElementName><rasd:HostResource>ovf:/disk/vmdisk{n}</rasd:HostResource><rasd:InstanceID>{}</rasd:InstanceID><rasd:ResourceType>17</rasd:ResourceType></Item>\n",
            10 + n
        ));
    }
    let firmware = if efi {
        "      <vmw:Config ovf:required=\"false\" vmw:key=\"firmware\" vmw:value=\"efi\"/>\n"
    } else {
        ""
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Envelope xmlns=\"http://schemas.dmtf.org/ovf/envelope/1\" xmlns:ovf=\"http://schemas.dmtf.org/ovf/envelope/1\" xmlns:rasd=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData\" xmlns:vmw=\"http://www.vmware.com/schema/ovf\">\n  <References>\n{files}  </References>\n  <DiskSection>\n    <Info>Virtual disk information</Info>\n{disk_section}  </DiskSection>\n  <VirtualSystem ovf:id=\"{name}\">\n    <Name>{name}</Name>\n    <OperatingSystemSection ovf:id=\"94\" vmw:osType=\"{os}\">\n      <Description>{os}</Description>\n    </OperatingSystemSection>\n    <VirtualHardwareSection>\n      <Item><rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits><rasd:ElementName>{cpus} virtual CPU(s)</rasd:ElementName><rasd:InstanceID>1</rasd:InstanceID><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>{cpus}</rasd:VirtualQuantity></Item>\n      <Item><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:ElementName>{memory_mb}MB of memory</rasd:ElementName><rasd:InstanceID>2</rasd:InstanceID><rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>{memory_mb}</rasd:VirtualQuantity></Item>\n{items}{firmware}    </VirtualHardwareSection>\n  </VirtualSystem>\n</Envelope>\n"
    )
}

/// A raw disk of `bytes` with an MBR boot signature, so it reads as a disk with a partition table.
pub fn raw_mbr(bytes: u64) -> Vec<u8> {
    let mut out = vec![0u8; usize::try_from(bytes).expect("a small test disk")];
    if out.len() >= 512 {
        out[510] = 0x55;
        out[511] = 0xaa;
    }
    out
}
