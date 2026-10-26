//! One adapter per outside system, so a Workstation, VirtualBox, SSH or Windows change touches one
//! module. Each sits behind a trait; [`crate::fakes`] has a fake of each for tests. VM-18:
//! [`hypervisor`] routes each VM to Workstation or VirtualBox by its key.

pub mod containers;
pub mod disk_tools;
pub mod exec_output;
pub mod github;
pub mod host_counters;
pub mod host_networks;
pub mod hypervisor;
pub mod network;
pub mod paging;
pub mod remote;
pub mod updater;
pub mod virtualbox;
pub mod vm_hardware;
pub mod vmware;
pub mod vmx_file;
