//! VM-30 (0.8.0 G7): golden image builds. "Build an image" installs one VM from an install config through G6's
//! unattended deploy (what is approved is what runs: the build VM's whole [`crate::deploy::DeploySpec`] is in the
//! command), makes it generic ([`generic`]), shuts it down, snapshots it powered off and registers it as a version of
//! a VM-20 golden image. Each build is a new VM, `<image>-v<N>`; the image always points at its newest version, so
//! launch templates that use it deploy that one. An old version's VM is deleted only by the image's retention (the
//! newest `keep` stay) and never while a linked clone depends on it (VM-04's guard, the R3 delete's own).
//!
//! * [`spec`]: the recipe an image keeps, and [`BuildSpec`], what [`crate::command_bus::Command::ImageBuild`] carries.
//! * [`generic`]: the scripts that make Linux and Windows generic, and how their reports read.
//! * [`service`]: [`GoldenImages`] (`Core.golden`): check, build, rebuild, build settings, versions; and the job's side
//!   ([`ImageBuildActions`]): registering a version and the retention.
//!
//! "Golden image builds (G7)" in CLAUDE.md says what was decided and why.

pub mod generic;
mod service;
pub mod spec;

pub use self::service::{
    BuildCheck, BuildGuard, BuildPreview, BuildRequest, BuildTarget, Built, GoldenImages, ImageBuildActions,
    ImageVersion, StandingCheck, StillApproved, VersionState,
};
pub use self::spec::{BuildDetails, BuildOs, BuildRecipe, BuildSpec, PruneVm, SignIn};

/// Why 0.8.0 builds no Windows image and deploys no clone of one Remotely built (the owner deferred them on 14 Nov 2026):
/// the hand checks' builds sealed, but their clones never read their answer file after sysprep and stopped at OOBE.
pub const WINDOWS_DEFERRED: &str =
    "Windows golden images come in a later release: a clone of a sysprepped image doesn't read its answer file yet.";

/// Whether this core builds Windows golden images and deploys their clones: never in 0.8.0 ([`WINDOWS_DEFERRED`]). The
/// catalogue keeps it, shared by its clones and [`GoldenImages`]; only tests of the kept Windows seal and clone code
/// turn it on (`fakes`).
#[derive(Clone, Default)]
pub struct WindowsImages {
    #[cfg(feature = "fakes")]
    allowed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl WindowsImages {
    pub fn allowed(&self) -> bool {
        #[cfg(feature = "fakes")]
        {
            self.allowed.load(std::sync::atomic::Ordering::SeqCst)
        }
        #[cfg(not(feature = "fakes"))]
        {
            false
        }
    }

    /// Tests only: builds and deploys Windows golden images as the later release will.
    #[cfg(feature = "fakes")]
    pub fn set_allowed_for_tests(&self, allowed: bool) {
        self.allowed.store(allowed, std::sync::atomic::Ordering::SeqCst);
    }
}
