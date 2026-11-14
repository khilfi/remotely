//! VM-21, VM-22, VM-10 (R2): deploy. A launch template, or every value chosen by hand (Custom), becomes new VMs:
//! a clone of a golden VM, a cloud image with cloud-init first-boot setup, an ISO install or an OVA/OVF import;
//! and the VMs picked on the VMs page can be cloned in bulk.
//!
//! * [`spec`]: [`DeploySpec`], what the bus approves and the job runs.
//! * [`cloud_init`] and [`seed`]: VM-22's first boot (Workstation's `guestinfo`, VirtualBox's NoCloud seed).
//! * [`vmx`]: a new Workstation VM's `.vmx`.
//!
//! Everything that changes a VM is a [`crate::command_bus::Command::Deploy`] on the bus (Medium for 1 to 4 VMs,
//! High for 5 or more; a Prod label moves it up one). The job makes one VM per step through [`DeployActions`]; a
//! cancel or a failure removes only what that step made (its own folder, the VM it registered), never anything
//! that was there before.

pub mod cloud_init;
pub mod install;
pub mod iso;
pub mod ovf;
pub mod preview;
pub mod runner;
pub mod seed;
pub mod service;
pub mod spec;
pub mod virtualbox;
pub mod vmx;
pub mod watch;
pub mod workstation;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub use self::spec::{
    DeployOrigin, DeploySource, DeploySpec, DeployVm, DiskPlan, FirstBootSpec, ProfileSpec, SizeSpec,
};
use crate::domain::Context;
use crate::error::Result;

/// How many VMs of one deploy are made at once: each copies or writes whole disks.
pub const PARALLEL_VMS: usize = 2;
/// VM-29: how many VMs of an unattended install deploy are made and watched at once: each writes only a blank disk,
/// then waits for its installer (S2: ten at once through Workstation's NAT took 20 to 30 minutes).
pub const PARALLEL_INSTALLS: usize = 10;

/// A step's progress: overall percent (0 to 100) and what it does now, in words.
pub type DeployProgress<'a> = dyn Fn(f64, &str) + Send + Sync + 'a;

/// What the job runner calls for each new VM of a [`DeploySpec`].
#[async_trait]
pub trait DeployActions: Send + Sync {
    /// Makes `vm`, then its after-deploy steps. Returns what the job's audit entry says about it (where it is,
    /// its IP, what the after-deploy steps did or why they didn't). A failure or a cancel before the VM is made
    /// removes what this call made for it, and is the error; an after-deploy step that doesn't work is reported
    /// in the note, never a failure. VM-29: an unattended install is watched until it is done; one that fails or
    /// runs out of time is the error, and its VM is kept for a look.
    async fn deploy_vm(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &DeploySpec,
        vm: &DeployVm,
        progress: &DeployProgress<'_>,
        token: &CancellationToken,
    ) -> Result<String>;

    /// VM-30: one golden image version's VM: made and installed as a deploy's (G6), made generic, shut down, its
    /// install CDs, serial port and NAT rule taken out, and snapshotted powered off. A failure before the VM is made
    /// removes what this call made; a later one keeps the VM for a look and is the error.
    async fn build_image(
        &self,
        _ctx: &Context,
        _job_id: Uuid,
        _spec: &crate::golden::BuildSpec,
        _progress: &DeployProgress<'_>,
        _token: &CancellationToken,
    ) -> Result<crate::golden::Built> {
        Err(crate::error::CoreError::NotImplemented("golden image builds"))
    }
}
