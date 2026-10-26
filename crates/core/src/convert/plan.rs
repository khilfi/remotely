//! CV-01 to CV-03, VM-17: which tools turn a source disk into the output asked for, in what steps. Pure, so every
//! route is tested without a tool.
//!
//! The hypervisors' own tools first (docs/plan-0.5.md, "Conversion tools"): `vmware-vdiskmanager` for VMDK outputs
//! (and Workstation's snapshot chains), `VBoxManage` for VDI, VHD and raw ones (and VirtualBox's own disks with
//! their differencing images), and `qemu-img` only for what neither does: reading or writing qcow2 and VHDX. A
//! route needs at most two steps, through a growable VMDK (or VDI) in the job's own work folder.
//!
//! qemu-img never reads a disk with a parent or a backing file: a chain is flattened by the hypervisor that made
//! it first, and a foreign disk with one is refused ([`super::inspect`]), since its parent is a path written in the
//! file.

use serde::Serialize;

use super::formats::{DiskFormat, OutputKind};
use crate::adapters::disk_tools::{Tool, ToolPaths};

/// What the planner knows about a source disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    pub format: DiskFormat,
    /// A snapshot delta, differencing or backed disk: only its whole chain is the disk.
    pub chain: bool,
    /// One of a VirtualBox VM's own disks, registered in VirtualBox: VBoxManage reads its whole chain.
    pub vbox_medium: bool,
}

impl Source {
    pub fn file(format: DiskFormat) -> Self {
        Self {
            format,
            chain: false,
            vbox_medium: false,
        }
    }
}

/// One tool run of a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Step {
    pub tool: Tool,
    /// What it reads: the source, or the step before's output.
    pub from: DiskFormat,
    /// What it writes.
    pub to: OutputKind,
    /// Grows the image it reads to this many bytes first (Azure's whole megabytes), when set.
    pub grow_to: Option<u64>,
}

/// Why no plan could be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoPlan {
    /// qemu-img would do it, and it isn't installed.
    NeedsQemuImg,
    /// These tools would, and aren't here (Workstation's or VirtualBox's).
    NeedsTools(Vec<Tool>),
    /// No tool does it.
    Impossible(String),
}

impl NoPlan {
    pub fn describe(&self, from: DiskFormat, to: OutputKind) -> String {
        match self {
            NoPlan::NeedsQemuImg => format!(
                "{} to {} needs qemu-img, which isn't installed: install QEMU for Windows, or set qemu-img.exe's path in Settings",
                from.label(),
                to.label()
            ),
            NoPlan::NeedsTools(tools) => {
                let names: Vec<&str> = tools.iter().map(|t| t.label()).collect();
                format!(
                    "{} to {} needs {}, which isn't on this PC",
                    from.label(),
                    to.label(),
                    names.join(" and ")
                )
            }
            NoPlan::Impossible(why) => why.clone(),
        }
    }
}

fn reads(tool: Tool, source: Source) -> bool {
    match tool {
        // vdiskmanager reads every VMDK, a snapshot's delta with its whole chain; raw through a flat descriptor.
        Tool::VdiskManager => match source.format {
            DiskFormat::Vmdk => true,
            DiskFormat::Raw => !source.chain,
            _ => false,
        },
        // VBoxManage reads VirtualBox's own disks with their chains, and standalone VDI, VMDK and VHD files;
        // raw through convertfromraw. Its VHDX reader is read-only and refused qemu-img's VHDX (hand check), so
        // VHDX goes through qemu-img.
        Tool::VBoxManage => match source.format {
            DiskFormat::Vdi | DiskFormat::Vmdk | DiskFormat::Vhd => !source.chain || source.vbox_medium,
            DiskFormat::Raw => !source.chain,
            DiskFormat::Vhdx | DiskFormat::Qcow2 => false,
        },
        // Never a chain: its parent would be opened by a path written in the file.
        Tool::QemuImg => !source.chain,
        Tool::Ovftool => false,
    }
}

fn writes(tool: Tool, source: Source, out: OutputKind) -> bool {
    match tool {
        // -t 0, 2, 4, 5; raw is the extent of a -t 2.
        Tool::VdiskManager => {
            matches!(
                out,
                OutputKind::VmdkSparse
                    | OutputKind::VmdkFlat
                    | OutputKind::VmdkStream
                    | OutputKind::VmdkEsx
                    | OutputKind::Raw
            ) && !(source.format == DiskFormat::Raw && out == OutputKind::Raw)
        }
        Tool::VBoxManage => {
            let any = matches!(
                out,
                OutputKind::VdiDynamic
                    | OutputKind::VdiFixed
                    | OutputKind::VhdDynamic
                    | OutputKind::VhdFixed
                    | OutputKind::VmdkSparse
                    | OutputKind::VmdkFlat
                    | OutputKind::VmdkStream
                    | OutputKind::Raw
            );
            // convertfromraw writes VDI, VMDK and VHD.
            any && !(source.format == DiskFormat::Raw && out == OutputKind::Raw)
        }
        // Every layout but ESXi's own (`vmfs`).
        Tool::QemuImg => out != OutputKind::VmdkEsx,
        Tool::Ovftool => false,
    }
}

/// The tools that may write `out`, best first: the hypervisor whose format it is.
fn preference(out: OutputKind) -> &'static [Tool] {
    match out.format() {
        DiskFormat::Vmdk => &[Tool::VdiskManager, Tool::VBoxManage, Tool::QemuImg],
        DiskFormat::Vdi | DiskFormat::Vhd => &[Tool::VBoxManage, Tool::QemuImg],
        DiskFormat::Raw => &[Tool::VBoxManage, Tool::QemuImg, Tool::VdiskManager],
        DiskFormat::Vhdx | DiskFormat::Qcow2 => &[Tool::QemuImg],
    }
}

fn one_step(source: Source, out: OutputKind, tools: &ToolPaths) -> Option<Step> {
    preference(out)
        .iter()
        .copied()
        .find(|tool| tools.has(*tool) && reads(*tool, source) && writes(*tool, source, out))
        .map(|tool| Step {
            tool,
            from: source.format,
            to: out,
            grow_to: None,
        })
}

/// Formats a step in between may be: growable, so they take what the guest wrote, and every tool reads them.
const BETWEEN: [OutputKind; 2] = [OutputKind::VmdkSparse, OutputKind::VdiDynamic];

fn route(source: Source, out: OutputKind, tools: &ToolPaths) -> Option<Vec<Step>> {
    if let Some(step) = one_step(source, out, tools) {
        return Some(vec![step]);
    }
    for mid in BETWEEN {
        let Some(first) = one_step(source, mid, tools) else {
            continue;
        };
        if let Some(second) = one_step(Source::file(mid.format()), out, tools) {
            return Some(vec![first, second]);
        }
    }
    None
}

/// A route that grows the disk to `bytes` on the way: into a growable image a tool can resize (a VDI for
/// VBoxManage, qcow2 for qemu-img), grown, then into `out`.
fn route_growing(source: Source, out: OutputKind, bytes: u64, tools: &ToolPaths) -> Option<Vec<Step>> {
    for mid in [OutputKind::VdiDynamic, OutputKind::Qcow2] {
        let Some(mut first) = route(source, mid, tools) else {
            continue;
        };
        let resizer = if mid == OutputKind::VdiDynamic {
            Tool::VBoxManage
        } else {
            Tool::QemuImg
        };
        if !tools.has(resizer) {
            continue;
        }
        let Some(mut last) = route(Source::file(mid.format()), out, tools) else {
            continue;
        };
        last[0].grow_to = Some(bytes);
        first.append(&mut last);
        return Some(first);
    }
    None
}

/// The steps that turn `source` into `out` with the tools here. `grow_to`: the disk must be this many bytes
/// (Azure's whole megabytes) and isn't yet.
pub fn plan(source: Source, out: OutputKind, grow_to: Option<u64>, tools: &ToolPaths) -> Result<Vec<Step>, NoPlan> {
    let found = |tools: &ToolPaths| match grow_to {
        Some(bytes) => route_growing(source, out, bytes, tools),
        None => route(source, out, tools),
    };
    if let Some(steps) = found(tools) {
        return Ok(steps);
    }
    if source.chain && !source.vbox_medium && source.format != DiskFormat::Vmdk {
        return Err(NoPlan::Impossible(format!(
            "a differencing {} can't be converted alone: convert the whole chain where it was made",
            source.format.label()
        )));
    }
    let mut with_qemu = tools.clone();
    with_qemu.qemu_img = Some(std::path::PathBuf::from("qemu-img.exe"));
    if !tools.has(Tool::QemuImg) && found(&with_qemu).is_some() {
        return Err(NoPlan::NeedsQemuImg);
    }
    let all = ToolPaths::all();
    match found(&all) {
        Some(steps) => {
            let mut missing: Vec<Tool> = steps.iter().map(|s| s.tool).filter(|t| !tools.has(*t)).collect();
            if steps.iter().any(|s| s.grow_to.is_some()) && !tools.has(Tool::VBoxManage) && !tools.has(Tool::QemuImg) {
                missing.push(Tool::VBoxManage);
            }
            missing.dedup();
            Err(NoPlan::NeedsTools(missing))
        }
        None => Err(NoPlan::Impossible(format!(
            "no tool turns this {} into {}",
            source.format.label(),
            out.label()
        ))),
    }
}

/// The plan in words, for the dialog and the job's note: "VBoxManage (VHD to VDI)", "qemu-img, then vmware-vdiskmanager".
pub fn describe(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|s| format!("{} ({} to {})", s.tool.label(), s.from.label(), s.to.label()))
        .collect::<Vec<_>>()
        .join(", then ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools(qemu: bool, vmware: bool, vbox: bool) -> ToolPaths {
        let all = ToolPaths::all();
        ToolPaths {
            qemu_img: all.qemu_img.filter(|_| qemu),
            vdiskmanager: all.vdiskmanager.filter(|_| vmware),
            vboxmanage: all.vboxmanage.filter(|_| vbox),
            ovftool: all.ovftool.filter(|_| vmware),
        }
    }

    fn tools_of(steps: &[Step]) -> Vec<Tool> {
        steps.iter().map(|s| s.tool).collect()
    }

    #[test]
    fn the_hypervisors_own_tools_come_first() {
        let every = tools(true, true, true);
        let file = Source::file;
        let run = |from: DiskFormat, to: OutputKind| tools_of(&plan(file(from), to, None, &every).unwrap());
        assert_eq!(run(DiskFormat::Vmdk, OutputKind::VmdkStream), [Tool::VdiskManager]);
        assert_eq!(run(DiskFormat::Vhd, OutputKind::VdiDynamic), [Tool::VBoxManage]);
        assert_eq!(run(DiskFormat::Vdi, OutputKind::VmdkSparse), [Tool::VBoxManage]);
        assert_eq!(run(DiskFormat::Vmdk, OutputKind::VhdFixed), [Tool::VBoxManage]);
        assert_eq!(run(DiskFormat::Raw, OutputKind::VdiFixed), [Tool::VBoxManage]);
        assert_eq!(run(DiskFormat::Raw, OutputKind::VmdkSparse), [Tool::VdiskManager]);
        // qcow2 and VHDX: qemu-img, on either side.
        assert_eq!(run(DiskFormat::Qcow2, OutputKind::VmdkSparse), [Tool::QemuImg]);
        assert_eq!(run(DiskFormat::Vmdk, OutputKind::Qcow2), [Tool::QemuImg]);
        assert_eq!(run(DiskFormat::Vhdx, OutputKind::VdiDynamic), [Tool::QemuImg]);
        assert_eq!(run(DiskFormat::Vdi, OutputKind::VhdxDynamic), [Tool::QemuImg]);
        // ESXi's own layout is vdiskmanager's alone: two steps from what it can't read.
        assert_eq!(
            run(DiskFormat::Qcow2, OutputKind::VmdkEsx),
            [Tool::QemuImg, Tool::VdiskManager]
        );
        assert_eq!(
            run(DiskFormat::Vdi, OutputKind::VmdkEsx),
            [Tool::VBoxManage, Tool::VdiskManager]
        );
    }

    #[test]
    fn chains_are_flattened_by_the_hypervisor_that_made_them() {
        let every = tools(true, true, true);
        let workstation_delta = Source {
            format: DiskFormat::Vmdk,
            chain: true,
            vbox_medium: false,
        };
        let steps = plan(workstation_delta, OutputKind::Qcow2, None, &every).unwrap();
        assert_eq!(tools_of(&steps), [Tool::VdiskManager, Tool::QemuImg]);
        assert_eq!(steps[0].to, OutputKind::VmdkSparse);
        assert_eq!(
            tools_of(&plan(workstation_delta, OutputKind::VhdFixed, None, &every).unwrap()),
            [Tool::VdiskManager, Tool::VBoxManage]
        );
        let vbox_diff = Source {
            format: DiskFormat::Vdi,
            chain: true,
            vbox_medium: true,
        };
        assert_eq!(
            tools_of(&plan(vbox_diff, OutputKind::VhdxDynamic, None, &every).unwrap()),
            [Tool::VBoxManage, Tool::QemuImg]
        );
        assert_eq!(
            tools_of(&plan(vbox_diff, OutputKind::VmdkEsx, None, &every).unwrap()),
            [Tool::VBoxManage, Tool::VdiskManager]
        );
        // A foreign differencing disk: no tool reads its chain.
        let foreign = Source {
            format: DiskFormat::Vhd,
            chain: true,
            vbox_medium: false,
        };
        assert!(matches!(
            plan(foreign, OutputKind::VdiDynamic, None, &every),
            Err(NoPlan::Impossible(_))
        ));
    }

    #[test]
    fn without_qemu_img_the_ui_can_say_what_needs_it() {
        let no_qemu = tools(false, true, true);
        assert_eq!(
            plan(Source::file(DiskFormat::Qcow2), OutputKind::VdiDynamic, None, &no_qemu),
            Err(NoPlan::NeedsQemuImg)
        );
        assert_eq!(
            plan(Source::file(DiskFormat::Vmdk), OutputKind::VhdxDynamic, None, &no_qemu),
            Err(NoPlan::NeedsQemuImg)
        );
        assert!(NoPlan::NeedsQemuImg
            .describe(DiskFormat::Qcow2, OutputKind::VdiDynamic)
            .contains("qemu-img"));
        // Workstation alone still converts VMDKs, raw images and its chains.
        let workstation = tools(false, true, false);
        assert_eq!(
            tools_of(
                &plan(
                    Source::file(DiskFormat::Raw),
                    OutputKind::VmdkStream,
                    None,
                    &workstation
                )
                .unwrap()
            ),
            [Tool::VdiskManager]
        );
        assert_eq!(
            tools_of(&plan(Source::file(DiskFormat::Vmdk), OutputKind::Raw, None, &workstation).unwrap()),
            [Tool::VdiskManager]
        );
        assert_eq!(
            plan(
                Source::file(DiskFormat::Vdi),
                OutputKind::VmdkSparse,
                None,
                &workstation
            ),
            Err(NoPlan::NeedsQemuImg)
        );
        // ESXi's layout from a VDI with VirtualBox and qemu-img but no Workstation: vdiskmanager is missing.
        let no_vmware = tools(true, false, true);
        assert_eq!(
            plan(Source::file(DiskFormat::Vdi), OutputKind::VmdkEsx, None, &no_vmware),
            Err(NoPlan::NeedsTools(vec![Tool::VdiskManager]))
        );
        assert!(NoPlan::NeedsTools(vec![Tool::VdiskManager])
            .describe(DiskFormat::Vdi, OutputKind::VmdkEsx)
            .contains("vmware-vdiskmanager"));
    }

    #[test]
    fn growing_to_whole_megabytes_goes_through_an_image_a_tool_resizes() {
        let vbox = tools(false, false, true);
        let steps = plan(
            Source::file(DiskFormat::Vmdk),
            OutputKind::VhdFixed,
            Some(1 << 30),
            &vbox,
        )
        .unwrap();
        assert_eq!(tools_of(&steps), [Tool::VBoxManage, Tool::VBoxManage]);
        assert_eq!(steps[0].to, OutputKind::VdiDynamic);
        assert_eq!(steps[1].grow_to, Some(1 << 30));
        let qemu = tools(true, false, false);
        let steps = plan(
            Source::file(DiskFormat::Qcow2),
            OutputKind::VhdFixed,
            Some(1 << 30),
            &qemu,
        )
        .unwrap();
        assert_eq!(tools_of(&steps), [Tool::QemuImg, Tool::QemuImg]);
        assert_eq!(steps[0].to, OutputKind::Qcow2);
        assert_eq!(
            describe(&steps),
            "qemu-img (qcow2 to qcow2), then qemu-img (qcow2 to VHD, fixed)"
        );
    }
}
