//! CV-01 to CV-03, VM-17 (R5): conversion. Remotely reads and writes other hypervisors' VM and disk formats
//! (Hyper-V, KVM/QEMU, Proxmox, ESXi, Azure and other clouds); it never manages those hypervisors.
//!
//! * [`formats`]: the disk formats ([`formats::DiskFormat`]) and what a conversion writes ([`formats::OutputKind`]).
//! * [`inspect`]: CV-03 Inspect, from each format's header (MO-13's readers, and VHDX and qcow2 here).
//! * [`plan`] and [`args`]: which tools convert what (the hypervisors' own first, qemu-img for qcow2 and VHDX
//!   only when the owner installed it) and their command lines.

pub mod args;
pub mod describe;
pub mod formats;
pub mod import;
pub mod inspect;
pub mod plan;
pub mod runner;
pub mod service;
pub mod spec;
pub mod targets;
pub mod verify;

pub use self::runner::{ConvertActions, Converter};
pub use self::spec::{ConvertSpec, ExportSpec, ExportTarget};
