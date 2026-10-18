//! One adapter per outside system, so a Workstation, SSH or Windows change touches one module.
//! Each sits behind a trait; [`crate::fakes`] has a fake of each for tests.

pub mod dns;
pub mod exec_output;
pub mod github;
pub mod host_counters;
pub mod remote;
pub mod updater;
pub mod vmware;
