//! One adapter per outside system, so a Workstation, SSH or Windows change touches one module.
//! Each sits behind a trait; [`crate::fakes`] has a fake of each for tests.

pub mod exec_output;
pub mod host_counters;
pub mod network;
pub mod remote;
pub mod updater;
pub mod vmware;
