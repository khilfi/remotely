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
pub mod ovf;
pub mod preview;
pub mod seed;
pub mod spec;
pub mod vmx;

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

/// What the job runner calls for each new VM of a [`DeploySpec`].
#[async_trait]
pub trait DeployActions: Send + Sync {
    /// Makes `vm`, then its after-deploy steps. Returns what the job's audit entry says about it (where it is,
    /// its IP, what the after-deploy steps did or why they didn't). A failure or a cancel before the VM is made
    /// removes what this call made for it, and is the error; an after-deploy step that doesn't work is reported
    /// in the note, never a failure.
    async fn deploy_vm(
        &self,
        ctx: &Context,
        job_id: Uuid,
        spec: &DeploySpec,
        vm: &DeployVm,
        token: &CancellationToken,
    ) -> Result<String>;
}
