//! BX-08 Library: common Linux commands for day-to-day IT admin work and troubleshooting, built in
//! and grouped. Most only read. Which ones change something or are dangerous is not written here: the
//! policy engine decides it from the user's current rules ([`super::Snippets::library`]), so the marks
//! always match what a bulk run or MultiExec would ask for.
//!
//! The library has two sections ([`LibrarySection`]):
//! * **Area** groups browse by topic (system info, disk, network, services, security, databases, ...).
//!   Every command is defined once here, in [`LIBRARY`], with a stable id (`disk.free`) and an area
//!   group.
//! * **Troubleshoot** groups ([`TROUBLESHOOT`]) are symptom runbooks ("host is slow", "disk is full")
//!   that list, in the order to run them, ids of commands from the area groups. So one command can
//!   show up in a symptom group and in its area group.
//!
//! Commands are Linux only and aim to be right for RHEL/Rocky/Alma 8 and 9, Ubuntu 22.04 and 24.04 and
//! Debian 12; where distros differ (apt vs dnf, ufw vs firewalld) both are given. None hangs or opens a
//! pager (`--no-pager`, `top -b -n 1`, bounded `ping -c`, `--max-time`/`timeout`). Entries that need a
//! tool not always installed (sysstat, smartmontools, mtr, iotop, ...) say so.

use serde::Serialize;

/// Which of the two sections of the panel a group belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LibrarySection {
    /// Symptom runbooks, shown first.
    Troubleshoot,
    /// Groups by topic.
    Area,
}

impl LibrarySection {
    pub fn label(self) -> &'static str {
        match self {
            LibrarySection::Troubleshoot => "Troubleshoot",
            LibrarySection::Area => "By area",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LibraryGroup {
    // Troubleshoot section (symptoms).
    SlowHost,
    OutOfMemory,
    DiskFull,
    CantReachService,
    DnsFails,
    ServiceWontStart,
    CantLoginSsh,
    ClockWrong,
    CertExpired,
    PackageBroken,
    // Area section.
    SystemInfo,
    Disk,
    StorageLvm,
    StorageSan,
    Memory,
    Processes,
    Network,
    Services,
    Logs,
    PackagesApt,
    PackagesDnf,
    Users,
    Security,
    Certificates,
    Firewall,
    WebServers,
    Databases,
    Scheduling,
    TimeSync,
    Identity,
    VmwareGuest,
    Docker,
    Podman,
    Kubernetes,
    Helm,
}

impl LibraryGroup {
    /// In the order the panel shows them: the Troubleshoot section first, then the area groups.
    pub const ALL: [LibraryGroup; 35] = [
        LibraryGroup::SlowHost,
        LibraryGroup::OutOfMemory,
        LibraryGroup::DiskFull,
        LibraryGroup::CantReachService,
        LibraryGroup::DnsFails,
        LibraryGroup::ServiceWontStart,
        LibraryGroup::CantLoginSsh,
        LibraryGroup::ClockWrong,
        LibraryGroup::CertExpired,
        LibraryGroup::PackageBroken,
        LibraryGroup::SystemInfo,
        LibraryGroup::Disk,
        LibraryGroup::StorageLvm,
        LibraryGroup::StorageSan,
        LibraryGroup::Memory,
        LibraryGroup::Processes,
        LibraryGroup::Network,
        LibraryGroup::Services,
        LibraryGroup::Logs,
        LibraryGroup::PackagesApt,
        LibraryGroup::PackagesDnf,
        LibraryGroup::Users,
        LibraryGroup::Security,
        LibraryGroup::Certificates,
        LibraryGroup::Firewall,
        LibraryGroup::WebServers,
        LibraryGroup::Databases,
        LibraryGroup::Scheduling,
        LibraryGroup::TimeSync,
        LibraryGroup::Identity,
        LibraryGroup::VmwareGuest,
        LibraryGroup::Docker,
        LibraryGroup::Podman,
        LibraryGroup::Kubernetes,
        LibraryGroup::Helm,
    ];

    pub fn section(self) -> LibrarySection {
        use LibraryGroup::*;
        match self {
            SlowHost | OutOfMemory | DiskFull | CantReachService | DnsFails | ServiceWontStart | CantLoginSsh
            | ClockWrong | CertExpired | PackageBroken => LibrarySection::Troubleshoot,
            _ => LibrarySection::Area,
        }
    }

    pub fn label(self) -> &'static str {
        use LibraryGroup::*;
        match self {
            SlowHost => "Host is slow",
            OutOfMemory => "Out of memory",
            DiskFull => "Disk is full",
            CantReachService => "Can't reach a service",
            DnsFails => "DNS fails",
            ServiceWontStart => "Service won't start",
            CantLoginSsh => "Can't log in over SSH",
            ClockWrong => "Clock is wrong",
            CertExpired => "Certificate expired or failing",
            PackageBroken => "Package manager broken",
            SystemInfo => "System info",
            Disk => "Disk and filesystems",
            StorageLvm => "Storage: LVM and RAID",
            StorageSan => "Storage: SMART, SAN and shares",
            Memory => "Memory",
            Processes => "CPU and processes",
            Network => "Network",
            Services => "Services (systemd)",
            Logs => "Logs (journalctl)",
            PackagesApt => "Packages (apt)",
            PackagesDnf => "Packages (dnf/yum)",
            Users => "Users and groups",
            Security => "Security and access",
            Certificates => "TLS certificates",
            Firewall => "Firewall",
            WebServers => "Web servers (nginx, Apache)",
            Databases => "Databases (MySQL, PostgreSQL)",
            Scheduling => "Cron and timers",
            TimeSync => "Time sync (NTP/chrony)",
            Identity => "Identity (AD/LDAP, SSSD)",
            VmwareGuest => "VMware Tools (guest)",
            Docker => "Docker",
            Podman => "Podman",
            Kubernetes => "Kubernetes",
            Helm => "Helm",
        }
    }
}

/// One built-in command, as written here. Every entry lives in an area group; symptom groups reference
/// entries by [`BuiltIn::id`].
pub struct BuiltIn {
    /// Stable, for the UI's keys: `disk.free`.
    pub id: &'static str,
    pub group: LibraryGroup,
    pub name: &'static str,
    pub command: &'static str,
    pub description: &'static str,
}

const fn entry(
    id: &'static str,
    group: LibraryGroup,
    name: &'static str,
    command: &'static str,
    description: &'static str,
) -> BuiltIn {
    BuiltIn {
        id,
        group,
        name,
        command,
        description,
    }
}

/// A symptom runbook: a Troubleshoot group and the ids of the commands to run, in order.
pub struct Symptom {
    pub group: LibraryGroup,
    pub steps: &'static [&'static str],
}

use LibraryGroup::*;

#[rustfmt::skip]
pub const LIBRARY: &[BuiltIn] = &[
    // ============================ System info ============================
    entry("system.os", SystemInfo, "OS release", "cat /etc/os-release", "Distribution name and version."),
    entry("system.kernel", SystemInfo, "Kernel and architecture", "uname -a", "Kernel version, host name and CPU architecture."),
    entry("system.host", SystemInfo, "Host name and OS", "hostnamectl status", "Host name, OS, kernel, and the machine's chassis and virtualization."),
    entry("system.uptime", SystemInfo, "Uptime and load", "uptime", "How long the host has run, logged-in users and the 1, 5 and 15 minute load."),
    entry("system.lastboot", SystemInfo, "Boot time", "uptime -s", "The date and time the host last booted."),
    entry("system.time", SystemInfo, "Date, time zone and NTP", "timedatectl", "Local and UTC time, time zone, and whether the clock is synchronized."),
    entry("system.virt", SystemInfo, "Virtualization", "systemd-detect-virt", "The hypervisor or container the host runs in (vmware, kvm, docker, none)."),
    entry("system.who", SystemInfo, "Who is logged in", "w", "Logged-in users, where from, and what they run."),
    entry("system.cpu", SystemInfo, "CPU details", "lscpu", "CPU model, cores, threads, sockets and caches."),
    entry("system.mem", SystemInfo, "Memory size", "free -h", "Total, used, free and available memory and swap."),
    entry("system.pci", SystemInfo, "PCI devices", "lspci", "Network cards, disk controllers and other PCI devices."),
    entry("system.usb", SystemInfo, "USB devices", "lsusb", "Devices on the USB buses."),
    entry("system.lshw", SystemInfo, "Hardware summary", "sudo lshw -short", "One line per hardware device (lshw; may not be installed)."),
    entry("system.modules", SystemInfo, "Loaded kernel modules", "lsmod", "Kernel modules loaded now, with their sizes and users."),
    entry("system.cmdline", SystemInfo, "Kernel boot options", "cat /proc/cmdline", "The options the kernel booted with."),
    entry("system.selinux", SystemInfo, "SELinux mode", "getenforce", "Enforcing, Permissive or Disabled."),
    entry("system.locale", SystemInfo, "Locale", "localectl status", "System locale, keymap and console settings."),
    entry("system.default-target", SystemInfo, "Default boot target", "systemctl get-default", "The target the system boots into (graphical or multi-user)."),
    entry("system.boottime", SystemInfo, "Startup time", "systemd-analyze time", "How long the firmware, loader and userspace took at the last boot."),
    entry("system.critical-chain", SystemInfo, "Boot critical chain", "systemd-analyze critical-chain --no-pager", "The chain of units that held up the last boot."),
    entry("system.sysctl", SystemInfo, "Kernel parameters", "sudo sysctl -a", "Every kernel (sysctl) parameter and its value."),
    entry("system.env", SystemInfo, "Environment variables", "env | sort", "The shell's environment, sorted by name."),
    entry("system.reboot", SystemInfo, "Reboot the host", "sudo systemctl reboot", "Restarts the host now. Every session to it drops."),

    // ============================ Disk and filesystems ============================
    entry("disk.free", Disk, "Free space", "df -hT", "Size, use and free space of each mounted filesystem, with its type."),
    entry("disk.inodes", Disk, "Free inodes", "df -i", "Inode use per filesystem: full inodes stop new files even with space left."),
    entry("disk.devices", Disk, "Block devices", "lsblk -f", "Disks, partitions and LVM volumes with filesystems, labels and mount points."),
    entry("disk.mounts", Disk, "Mounted filesystems", "findmnt --real", "Real (not virtual) filesystems and where they are mounted."),
    entry("disk.mount-all", Disk, "All mounts", "findmnt", "Every mount, virtual filesystems included, as a tree."),
    entry("disk.fstab", Disk, "Mounts at boot", "cat /etc/fstab", "Filesystems mounted at boot."),
    entry("disk.biggest", Disk, "Biggest folders", "sudo du -xh --max-depth=1 {{path:/var}} 2>/dev/null | sort -h | tail -20", "The 20 largest folders directly under a path, on the same filesystem."),
    entry("disk.usage-tree", Disk, "Folder sizes two deep", "sudo du -xh --max-depth=2 {{path:/var}} 2>/dev/null | sort -h | tail -30", "The 30 largest folders up to two levels under a path, same filesystem."),
    entry("disk.biggest-files", Disk, "Biggest files", "sudo du -xah {{path:/var}} 2>/dev/null | sort -h | tail -20", "The 20 largest files and folders under a path, on the same filesystem."),
    entry("disk.largest-logs", Disk, "Largest files in /var/log", "sudo du -ah /var/log 2>/dev/null | sort -rh | head -20", "The 20 largest log files."),
    entry("disk.io", Disk, "Disk I/O", "iostat -xz 1 3", "Reads, writes, waits and utilization per device, three samples a second apart (sysstat)."),
    entry("disk.deleted", Disk, "Deleted files still open", "sudo lsof +L1", "Files deleted while a process holds them open: their space is not free until it closes them."),
    entry("disk.open-by-dir", Disk, "What has files open under a path", "sudo lsof +D {{path:/var/log}} 2>/dev/null | head -40", "Processes with files open anywhere under a folder."),
    entry("disk.mount-errors", Disk, "Filesystem errors in dmesg", "sudo dmesg -T --level=err,warn 2>/dev/null | grep -iE -e ext4 -e xfs -e 'i/o error' -e remount -e 'read-only' | tail -40", "Recent filesystem and I/O error messages from the kernel."),
    entry("disk.uuids", Disk, "Filesystem UUIDs", "sudo blkid", "UUIDs, labels and types of block devices."),
    entry("disk.by-id", Disk, "Disks by stable name", "ls -l /dev/disk/by-id", "Each disk's stable /dev/disk/by-id name and the device it points to."),
    entry("disk.swap", Disk, "Swap in use", "swapon --show", "Swap files and partitions, their size and how much is used."),
    entry("disk.ncdu", Disk, "Browse disk usage", "sudo ncdu -x {{path:/}}", "Walk a filesystem's usage interactively, staying on one filesystem (ncdu; may not be installed)."),

    // ============================ Storage: LVM and RAID ============================
    entry("lvm.pvs", StorageLvm, "Physical volumes", "sudo pvs", "Each LVM physical volume: device, volume group, size and free space."),
    entry("lvm.vgs", StorageLvm, "Volume groups", "sudo vgs", "Each volume group: size, free space and how many volumes and disks it has."),
    entry("lvm.lvs", StorageLvm, "Logical volumes", "sudo lvs", "Each logical volume: name, group, size and how full a thin or snapshot volume is."),
    entry("lvm.lvs-devices", StorageLvm, "Logical volumes on their devices", "sudo lvs -a -o +devices", "Logical volumes, including internal ones, and the devices under each."),
    entry("lvm.pvdisplay", StorageLvm, "Physical volume detail", "sudo pvdisplay", "Full detail of each physical volume."),
    entry("lvm.vgdisplay", StorageLvm, "Volume group detail", "sudo vgdisplay", "Full detail of each volume group, with its free extents."),
    entry("lvm.lvdisplay", StorageLvm, "Logical volume detail", "sudo lvdisplay", "Full detail of each logical volume."),
    entry("lvm.vg-free", StorageLvm, "Free space per group", "sudo vgs -o vg_name,vg_size,vg_free,vg_free_count", "Free space and free extents in each volume group, to see if an LV can grow."),
    entry("lvm.scan", StorageLvm, "Scan for physical volumes", "sudo pvscan", "Scans the disks for LVM physical volumes."),
    entry("lvm.lvextend", StorageLvm, "Extend a logical volume", "sudo lvextend -L +{{size:1G}} {{lv:/dev/vg0/root}}", "Grows a logical volume by a size. Does not grow the filesystem on it."),
    entry("lvm.resize", StorageLvm, "Extend an LV and its filesystem", "sudo lvextend -r -L +{{size:1G}} {{lv:/dev/vg0/root}}", "Grows a logical volume and the filesystem on it (ext4/XFS, online)."),
    entry("lvm.fsgrow-xfs", StorageLvm, "Grow an XFS filesystem", "sudo xfs_growfs {{mount:/}}", "Grows a mounted XFS filesystem to fill its device."),
    entry("lvm.fsgrow-ext", StorageLvm, "Grow an ext4 filesystem", "sudo resize2fs {{device:/dev/vg0/root}}", "Grows an ext2/3/4 filesystem to fill its device."),
    entry("lvm.mdstat", StorageLvm, "Software RAID state", "cat /proc/mdstat", "Software RAID (md) arrays and their sync or rebuild progress."),
    entry("lvm.mddetail", StorageLvm, "RAID array detail", "sudo mdadm --detail {{array:/dev/md0}}", "State, level, devices and rebuild status of a software RAID array."),
    entry("lvm.mdexamine", StorageLvm, "RAID member detail", "sudo mdadm --examine {{device:/dev/sda1}}", "The RAID superblock stored on one member device."),

    // ============================ Storage: SMART, SAN and shares ============================
    entry("san.smart-health", StorageSan, "Disk SMART health", "sudo smartctl -H {{device:/dev/sda}}", "Overall SMART health (PASSED or FAILED) of a disk (smartmontools)."),
    entry("san.smart-all", StorageSan, "Disk SMART detail", "sudo smartctl -a {{device:/dev/sda}}", "All SMART attributes, the error log and the self-test log of a disk."),
    entry("san.smart-attrs", StorageSan, "SMART attributes", "sudo smartctl -A {{device:/dev/sda}}", "SMART attributes, with reallocated, pending and uncorrectable sector counts."),
    entry("san.smart-scan", StorageSan, "Disks SMART can see", "sudo smartctl --scan", "The devices smartctl is able to query."),
    entry("san.smart-test", StorageSan, "Start a SMART self-test", "sudo smartctl -t short {{device:/dev/sda}}", "Starts a short self-test on a disk; read its result later with the SMART detail check."),
    entry("san.multipath", StorageSan, "Multipath map", "sudo multipath -ll", "Multipath devices, their paths and each path's status."),
    entry("san.iscsi-sessions", StorageSan, "iSCSI sessions", "sudo iscsiadm -m session -P 3", "Active iSCSI sessions and their targets, in detail."),
    entry("san.iscsi-nodes", StorageSan, "iSCSI targets", "sudo iscsiadm -m node", "The iSCSI target nodes this host knows."),
    entry("san.nfs-mounts", StorageSan, "NFS mounts", "findmnt -t nfs,nfs4", "Mounted NFS filesystems, their servers and options."),
    entry("san.nfs-exports", StorageSan, "Exports on a NFS server", "showmount -e {{server:nfs01.test}}", "The exports a NFS server offers (showmount)."),
    entry("san.nfs-stat", StorageSan, "NFS client stats", "nfsstat -c", "NFS client operation counts, to spot retransmits (nfsstat)."),
    entry("san.cifs-mounts", StorageSan, "SMB/CIFS mounts", "findmnt -t cifs", "Mounted SMB/CIFS filesystems and their options."),
    entry("san.smb-shares", StorageSan, "List SMB shares", "smbclient -L {{server:fs01.test}} -N", "The shares a SMB server offers, queried anonymously (smbclient)."),
    entry("san.xfs-info", StorageSan, "XFS geometry", "sudo xfs_info {{mount:/}}", "Block sizes and geometry of a mounted XFS filesystem."),
    entry("san.ext-info", StorageSan, "ext4 superblock", "sudo dumpe2fs -h {{device:/dev/sda1}}", "An ext2/3/4 superblock: features, mount count and check interval (dumpe2fs)."),
    entry("san.fsck-check", StorageSan, "Check an ext filesystem read-only", "sudo e2fsck -fn {{device:/dev/sdb1}}", "Checks an UNMOUNTED ext filesystem without changing it (-n). Never run it on a mounted one."),

    // ============================ Memory ============================
    entry("memory.free", Memory, "Memory and swap", "free -h", "Total, used, free and available memory and swap."),
    entry("memory.available", Memory, "Available memory", "grep -E -e MemAvailable -e MemFree -e SwapFree -e Dirty -e Writeback /proc/meminfo", "How much memory is really available, plus dirty pages still to be written."),
    entry("memory.vmstat", Memory, "Memory activity", "vmstat 1 5", "Memory, swapping, I/O and CPU, five samples a second apart."),
    entry("memory.top", Memory, "Top memory users", "ps aux --sort=-%mem | head -15", "The processes using the most memory."),
    entry("memory.meminfo", Memory, "Memory details", "cat /proc/meminfo", "The kernel's full memory counters."),
    entry("memory.pressure", Memory, "Memory pressure (PSI)", "cat /proc/pressure/memory", "How long tasks stalled waiting for memory (pressure stall info, kernel 4.20+)."),
    entry("memory.slab", Memory, "Kernel slab usage", "sudo slabtop -o -s c", "Kernel slab caches by size, one snapshot (-o)."),
    entry("memory.smem", Memory, "Per-process memory (PSS)", "smem -rs pss 2>/dev/null | head -20", "Processes by proportional memory, sharing counted once (smem; may not be installed)."),
    entry("memory.swaps", Memory, "Swap devices", "cat /proc/swaps", "Swap files and partitions in use."),
    entry("memory.swappiness", Memory, "Swappiness", "cat /proc/sys/vm/swappiness", "How readily the kernel swaps (0 = avoid, 100 = eager)."),
    entry("memory.hugepages", Memory, "Huge pages", "grep -i huge /proc/meminfo", "Huge page counts and sizes."),
    entry("memory.oom", Memory, "Out-of-memory kills", "sudo journalctl -k --no-pager 2>/dev/null | grep -i -e 'out of memory' -e oom-kill | tail -40", "Processes the kernel killed for lack of memory."),
    entry("memory.dropcaches", Memory, "Free the page cache", "sudo sh -c 'sync; echo 3 > /proc/sys/vm/drop_caches'", "Writes dirty pages, then drops clean caches to free memory. Safe, but caches refill on use."),
    entry("memory.earlyoom", Memory, "earlyoom status", "systemctl status earlyoom --no-pager", "Whether earlyoom, which kills before the kernel does, is running (if installed)."),

    // ============================ CPU and processes ============================
    entry("cpu.info", Processes, "CPU details", "lscpu", "CPU model, cores, threads, sockets and caches."),
    entry("cpu.count", Processes, "CPU count", "nproc", "Processing units available to this shell."),
    entry("cpu.load", Processes, "Load average", "cat /proc/loadavg", "Load over 1, 5 and 15 minutes, and running and total processes."),
    entry("cpu.top", Processes, "Top snapshot", "top -b -n 1 | head -25", "One snapshot of top: load, CPU, memory and the busiest processes."),
    entry("cpu.busiest", Processes, "Top CPU users", "ps aux --sort=-%cpu | head -15", "The processes using the most CPU."),
    entry("cpu.per-cpu", Processes, "Use per CPU", "mpstat -P ALL 1 3", "User, system, I/O wait and idle time per CPU, three samples (sysstat)."),
    entry("cpu.top-io", Processes, "Top I/O processes", "sudo iotop -b -n 2 -o -k 2>/dev/null | head -25", "Processes doing disk I/O, two snapshots (iotop; may not be installed)."),
    entry("cpu.pidstat", Processes, "Per-process CPU and I/O", "pidstat -dru 1 3", "CPU, memory and disk per process, three samples (sysstat)."),
    entry("cpu.pressure", Processes, "CPU pressure (PSI)", "cat /proc/pressure/cpu", "How long tasks stalled waiting for CPU (pressure stall info)."),
    entry("cpu.io-pressure", Processes, "I/O pressure (PSI)", "cat /proc/pressure/io", "How long tasks stalled waiting for I/O (pressure stall info)."),
    entry("cpu.tree", Processes, "Process tree", "ps axjf", "Every process under its parent."),
    entry("cpu.find", Processes, "Find a process", "pgrep -a {{name}}", "Process IDs and command lines matching a name."),
    entry("cpu.uninterruptible", Processes, "Stuck (D state) processes", "ps -eo stat,pid,ppid,comm | grep '^D'", "Processes in uninterruptible sleep, usually blocked on I/O."),
    entry("cpu.zombies", Processes, "Zombie processes", "ps -eo stat,pid,ppid,cmd | grep '^Z'", "Processes that ended but whose parent has not collected them."),
    entry("cpu.threads", Processes, "Most threads", "ps -eo nlwp,pid,comm --sort=-nlwp | head -15", "The processes with the most threads."),
    entry("cpu.limits", Processes, "A process's limits", "cat /proc/{{pid}}/limits", "The resource limits (open files, memory, ...) a process runs with."),
    entry("cpu.openfiles", Processes, "A process's open files", "sudo lsof -p {{pid}}", "The files, sockets and devices a process has open."),
    entry("cpu.strace", Processes, "Trace a process briefly", "sudo timeout 5 strace -fp {{pid}} 2>&1 | head -50", "Five seconds of a process's system calls (strace; blocks the process while tracing)."),
    entry("cpu.renice", Processes, "Lower a process's priority", "sudo renice +10 -p {{pid}}", "Makes a process yield CPU to others (higher nice is lower priority)."),
    entry("cpu.kill", Processes, "Stop a process", "kill {{pid}}", "Asks a process to end (SIGTERM)."),
    entry("cpu.killname", Processes, "Stop processes by name", "pkill {{name}}", "Asks every process matching a name to end (SIGTERM)."),

    // ============================ Network ============================
    entry("network.addresses", Network, "IP addresses", "ip -br a", "Each interface, its state and addresses, one line each."),
    entry("network.routes", Network, "Routes", "ip route", "The routing table, with the default gateway."),
    entry("network.default-route", Network, "Default gateway", "ip route show default", "The default route and the gateway traffic leaves through."),
    entry("network.route-to", Network, "Route to a host", "ip route get {{ip}}", "Which interface and gateway reach an address."),
    entry("network.iface-stats", Network, "Interface counters", "ip -s link show {{iface:eth0}}", "Bytes, packets, errors and drops on one interface."),
    entry("network.listening", Network, "Listening ports", "sudo ss -tulpn", "TCP and UDP ports open for connections, with their processes."),
    entry("network.port", Network, "Who listens on a port", "sudo ss -tulpn | grep :{{port:443}}", "The process listening on a port."),
    entry("network.connections", Network, "Open connections", "ss -tan state established", "Established TCP connections."),
    entry("network.estab", Network, "Connections to a host", "ss -tanp state established dst {{ip}}", "Established TCP connections to one address, with their processes."),
    entry("network.summary", Network, "Socket summary", "ss -s", "Totals of sockets by type and state."),
    entry("network.neighbours", Network, "Neighbours (ARP)", "ip neigh show", "MAC addresses seen on the local networks."),
    entry("network.traffic", Network, "Traffic per interface", "cat /proc/net/dev", "Bytes, packets, errors and drops per interface since boot."),
    entry("network.dns", Network, "DNS servers", "cat /etc/resolv.conf", "The name servers and search domains the host uses."),
    entry("network.hosts", Network, "Hosts file", "cat /etc/hosts", "Names resolved locally, before DNS."),
    entry("network.resolve", Network, "Resolve a name", "dig +short {{name}}", "The addresses a name resolves to."),
    entry("network.dns-dig", Network, "Query a DNS server", "dig @{{server}} {{name}} +short", "Resolve a name against a chosen DNS server."),
    entry("network.dns-reverse", Network, "Reverse DNS", "dig -x {{ip}} +short", "The name an address resolves back to."),
    entry("network.dns-trace", Network, "Trace a DNS lookup", "dig +trace {{name}}", "Follows a name from the root servers down, to find where resolution breaks."),
    entry("network.dns-resolvectl", Network, "systemd-resolved status", "resolvectl status", "Per-link DNS servers and search domains (systemd-resolved)."),
    entry("network.getent-host", Network, "Resolve the way programs do", "getent hosts {{name}}", "Resolve a name through nsswitch (hosts file, DNS, mDNS), as applications see it."),
    entry("network.ping", Network, "Ping a host", "ping -c 4 {{host}}", "Four pings: reachability and round-trip time."),
    entry("network.trace", Network, "Path to a host (tracepath)", "tracepath {{host}}", "Each hop on the way to a host, and the path MTU."),
    entry("network.traceroute", Network, "Traceroute", "traceroute -n {{host}}", "Each hop to a host, by address (traceroute; may not be installed)."),
    entry("network.mtr", Network, "mtr report", "mtr -rwznc 10 {{host}}", "A 10-cycle traceroute with loss and latency per hop (mtr; may not be installed)."),
    entry("network.tcpprobe", Network, "Test a TCP port", "nc -vz -w 5 {{host}} {{port:443}}", "Whether a TCP port accepts connections (netcat; times out after 5 s)."),
    entry("network.curl-time", Network, "Time an HTTP request", "curl -o /dev/null -sS --max-time 10 -w 'dns:%{time_namelookup}s connect:%{time_connect}s tls:%{time_appconnect}s ttfb:%{time_starttransfer}s total:%{time_total}s code:%{http_code}\\n' {{url:https://host.test}}", "Where the time goes in an HTTP(S) request: DNS, connect, TLS, first byte."),
    entry("network.curl-head", Network, "HTTP response headers", "curl -sSI --max-time 10 {{url:https://host.test}}", "The status line and headers of an HTTP(S) response."),
    entry("network.curl-resolve", Network, "Test a site against a chosen IP", "curl -sS -o /dev/null -w '%{http_code}\\n' --max-time 10 --resolve {{host}}:443:{{ip}} https://{{host}}/", "Fetch a site forcing which IP it resolves to, to test one backend."),
    entry("network.iface-detail", Network, "Interface settings", "sudo ethtool {{iface:eth0}}", "Link speed, duplex and negotiation of an interface (ethtool)."),
    entry("network.nmcli", Network, "NetworkManager status", "nmcli -o general status; nmcli -o device status", "Overall and per-device NetworkManager state (nmcli)."),
    entry("network.tcpdump", Network, "Capture packets (bounded)", "sudo timeout 10 tcpdump -nni {{iface:eth0}} -c 50 {{filter:port 443}}", "Up to 50 packets or 10 seconds on an interface, matching a filter. Prints, writes nothing."),
    entry("network.conntrack", Network, "Tracked connections", "sudo conntrack -L 2>/dev/null | head -40", "Connections the kernel is tracking, for NAT and firewalls (conntrack-tools)."),

    // ============================ Services (systemd) ============================
    entry("services.failed", Services, "Failed services", "systemctl --failed", "Units that failed to start or crashed."),
    entry("services.running", Services, "Running services", "systemctl list-units --type=service --state=running", "Services running now."),
    entry("services.status", Services, "Service status", "systemctl status {{service}} --no-pager", "State, main process, memory and the last log lines of a service."),
    entry("services.show", Services, "Service properties", "systemctl show {{service}} --no-pager", "Every property of a unit, including restart counts and limits."),
    entry("services.enabled", Services, "Starts at boot?", "systemctl is-enabled {{service}}", "Whether a service starts at boot."),
    entry("services.files", Services, "Installed services", "systemctl list-unit-files --type=service", "Every service unit and whether it is enabled."),
    entry("services.deps", Services, "Service dependencies", "systemctl list-dependencies {{service}}", "What a unit needs and what needs it."),
    entry("services.timers", Services, "Timers", "systemctl list-timers --all", "Scheduled timers, when they last ran and run next."),
    entry("services.unit", Services, "Show a unit file", "systemctl cat {{service}}", "A service's unit file and its drop-ins."),
    entry("services.boot", Services, "Slow starts at boot", "systemd-analyze blame | head -20", "The units that took longest to start at the last boot."),
    entry("services.start", Services, "Start a service", "sudo systemctl start {{service}}", "Starts a service now."),
    entry("services.stop", Services, "Stop a service", "sudo systemctl stop {{service}}", "Stops a service now; its connections drop."),
    entry("services.restart", Services, "Restart a service", "sudo systemctl restart {{service}}", "Stops and starts a service: its connections drop."),
    entry("services.reload", Services, "Reload a service", "sudo systemctl reload {{service}}", "Asks a service to read its configuration again, without a restart."),
    entry("services.enable", Services, "Enable at boot", "sudo systemctl enable --now {{service}}", "Starts a service and makes it start at boot."),
    entry("services.disable", Services, "Disable at boot", "sudo systemctl disable --now {{service}}", "Stops a service and stops it starting at boot."),
    entry("services.mask", Services, "Mask a service", "sudo systemctl mask {{service}}", "Blocks a service from starting at all until it is unmasked."),
    entry("services.reset-failed", Services, "Clear failed state", "sudo systemctl reset-failed {{service}}", "Clears a unit's failed state and its restart-rate limit so it can start again."),
    entry("services.daemon-reload", Services, "Reload unit files", "sudo systemctl daemon-reload", "Re-reads unit files after you add or change one."),

    // ============================ Logs (journalctl) ============================
    entry("logs.errors", Logs, "Errors since boot", "journalctl -b -p err --no-pager", "Messages of priority error and worse since the last boot."),
    entry("logs.service", Logs, "A service's log", "journalctl -u {{service}} -n {{lines:200}} --no-pager", "The last lines a service logged."),
    entry("logs.follow", Logs, "Follow a service's log", "journalctl -u {{service}} -f", "New log lines of a service as they come; Ctrl+C stops."),
    entry("logs.recent", Logs, "Everything recently", "journalctl --since '{{since:1 hour ago}}' --no-pager", "All messages since a time, such as '1 hour ago' or '2026-10-19 08:00'."),
    entry("logs.priority", Logs, "By priority", "journalctl -b -p {{priority:warning}} --no-pager | tail -100", "Messages at a priority or worse since boot (emerg, alert, crit, err, warning, notice, info, debug)."),
    entry("logs.grep", Logs, "Search the journal", "journalctl --no-pager 2>/dev/null | grep -i {{text}} | tail -50", "The last journal lines matching a word."),
    entry("logs.kernel", Logs, "Kernel messages", "journalctl -k -n 100 --no-pager", "The last kernel messages: hardware, drivers, out-of-memory kills."),
    entry("logs.dmesg", Logs, "Kernel ring buffer", "sudo dmesg -T | tail -80", "The kernel ring buffer with human times (dmesg)."),
    entry("logs.ssh", Logs, "SSH logins", "journalctl -u ssh -u sshd -n 100 --no-pager", "The SSH server's log: logins, failures and disconnects."),
    entry("logs.boots", Logs, "Boots", "journalctl --list-boots", "Boots the journal holds, newest last."),
    entry("logs.usage", Logs, "Journal size", "journalctl --disk-usage", "Disk space the journal uses."),
    entry("logs.vacuum", Logs, "Shrink the journal to a size", "sudo journalctl --vacuum-size={{size:500M}}", "Deletes old journal files to bring the journal under a size."),
    entry("logs.vacuum-time", Logs, "Drop journal older than", "sudo journalctl --vacuum-time={{age:7d}}", "Deletes journal entries older than an age (such as 7d or 2weeks)."),

    // ============================ Packages (apt) ============================
    entry("apt.upgradable", PackagesApt, "Updates available", "apt list --upgradable", "Packages with a newer version (as of the last apt update)."),
    entry("apt.installed", PackagesApt, "Is a package installed?", "dpkg -l | grep -i {{package}}", "Installed packages whose name matches."),
    entry("apt.policy", PackagesApt, "Package versions", "apt-cache policy {{package}}", "Installed and candidate versions of a package, and their repositories."),
    entry("apt.search", PackagesApt, "Search packages", "apt-cache search {{text}}", "Packages whose name or description matches."),
    entry("apt.depends", PackagesApt, "Package dependencies", "apt-cache depends {{package}}", "What a package depends on."),
    entry("apt.owner", PackagesApt, "Which package has a file", "dpkg -S {{path}}", "The package that installed a file."),
    entry("apt.verify", PackagesApt, "Verify a package's files", "dpkg -V {{package}}", "Files of a package that changed since it was installed."),
    entry("apt.audit", PackagesApt, "Half-installed packages", "dpkg -C", "Packages left half-installed or half-configured."),
    entry("apt.held", PackagesApt, "Held packages", "apt-mark showhold", "Packages pinned to their current version."),
    entry("apt.manual", PackagesApt, "Manually installed", "apt-mark showmanual | head -50", "Packages installed on purpose, not pulled in as dependencies."),
    entry("apt.sources", PackagesApt, "Repositories", "grep -rhE '^[^#]' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null", "The apt repositories configured on this host."),
    entry("apt.last", PackagesApt, "Recent apt actions", "grep -h -e ' install ' -e ' remove ' -e ' upgrade ' /var/log/dpkg.log 2>/dev/null | tail -30", "Recent installs, removals and upgrades from the dpkg log."),
    entry("apt.update", PackagesApt, "Refresh package lists", "sudo apt update", "Downloads the repositories' package lists."),
    entry("apt.upgrade", PackagesApt, "Install updates", "sudo apt upgrade", "Upgrades installed packages; asks before it starts."),
    entry("apt.full-upgrade", PackagesApt, "Full upgrade", "sudo apt full-upgrade", "Upgrades, removing packages where needed; asks before it starts."),
    entry("apt.install", PackagesApt, "Install a package", "sudo apt install {{package}}", "Installs a package and what it needs."),
    entry("apt.remove", PackagesApt, "Remove a package", "sudo apt remove {{package}}", "Removes a package but keeps its configuration files."),
    entry("apt.autoremove", PackagesApt, "Remove unused packages", "sudo apt autoremove", "Removes packages that nothing needs any more; asks first."),
    entry("apt.fix-broken", PackagesApt, "Fix broken dependencies", "sudo apt-get -f install", "Tries to finish half-installed packages and fix dependencies; asks first."),
    entry("apt.clean", PackagesApt, "Free the package cache", "sudo apt clean", "Deletes downloaded .deb files from the cache."),

    // ============================ Packages (dnf/yum) ============================
    entry("dnf.updates", PackagesDnf, "Updates available", "dnf check-update", "Packages with a newer version in the repositories."),
    entry("dnf.security", PackagesDnf, "Security updates", "dnf updateinfo list security", "Updates that fix security issues."),
    entry("dnf.installed", PackagesDnf, "Installed packages", "rpm -qa | sort", "Every installed package, sorted."),
    entry("dnf.info", PackagesDnf, "Package details", "dnf info {{package}}", "Version, repository and description of a package."),
    entry("dnf.search", PackagesDnf, "Search packages", "dnf search {{text}}", "Packages whose name or summary matches."),
    entry("dnf.provides", PackagesDnf, "Which package provides a file", "dnf provides {{path}}", "The package that provides a file or capability."),
    entry("dnf.owner", PackagesDnf, "Which package has a file", "rpm -qf {{path}}", "The installed package that owns a file."),
    entry("dnf.repoquery", PackagesDnf, "Query the repositories", "dnf repoquery {{package}}", "Versions of a package available across the repositories."),
    entry("dnf.deps", PackagesDnf, "Package dependencies", "dnf repoquery --requires --resolve {{package}}", "The packages a package depends on, resolved."),
    entry("dnf.groups", PackagesDnf, "Package groups", "dnf grouplist", "The package groups available and installed."),
    entry("dnf.verify", PackagesDnf, "Verify a package's files", "rpm -V {{package}}", "Files of a package that changed since it was installed."),
    entry("dnf.checksig", PackagesDnf, "Verify a package signature", "rpm -K {{file}}", "Checks the GPG signature and digest of an .rpm file."),
    entry("dnf.repos", PackagesDnf, "Repositories", "dnf repolist", "The enabled repositories."),
    entry("dnf.history", PackagesDnf, "Install history", "dnf history list", "Past installs, upgrades and removals."),
    entry("dnf.needs-restart", PackagesDnf, "What needs a restart", "needs-restarting -s; needs-restarting -r", "Services, and whether the host, need a restart after updates (dnf-utils)."),
    entry("dnf.yum-installed", PackagesDnf, "Installed packages (yum)", "yum list installed", "Every installed package, on hosts with yum only."),
    entry("dnf.upgrade", PackagesDnf, "Install updates", "sudo dnf upgrade", "Upgrades installed packages; asks before it starts."),
    entry("dnf.install", PackagesDnf, "Install a package", "sudo dnf install {{package}}", "Installs a package and what it needs."),
    entry("dnf.remove", PackagesDnf, "Remove a package", "sudo dnf remove {{package}}", "Removes a package and packages that depended only on it."),
    entry("dnf.autoremove", PackagesDnf, "Remove unused packages", "sudo dnf autoremove", "Removes packages that were pulled in as dependencies and are no longer needed."),
    entry("dnf.downgrade", PackagesDnf, "Downgrade a package", "sudo dnf downgrade {{package}}", "Installs the previous version of a package."),
    entry("dnf.distrosync", PackagesDnf, "Sync to repo versions", "sudo dnf distro-sync", "Brings every package to the version the repositories offer."),
    entry("dnf.makecache", PackagesDnf, "Refresh metadata", "sudo dnf makecache", "Downloads fresh repository metadata."),
    entry("dnf.clean", PackagesDnf, "Clean the cache", "sudo dnf clean all", "Deletes cached repository metadata and packages."),

    // ============================ Users and groups ============================
    entry("users.me", Users, "Who am I", "id", "Your user, its ID and groups."),
    entry("users.of", Users, "A user's groups", "id {{user}}", "A user's ID and groups."),
    entry("users.all", Users, "All accounts", "getent passwd | cut -d: -f1,3,7 | sort -t: -k2 -n", "Every account with its UID and login shell, by UID."),
    entry("users.logins", Users, "Accounts that can log in", "grep -v -e nologin -e /bin/false /etc/passwd", "Users with a login shell."),
    entry("users.group", Users, "Members of a group", "getent group {{group}}", "A group's ID and members (local or from the directory)."),
    entry("users.sudoers", Users, "Who can sudo", "getent group sudo wheel 2>/dev/null", "Members of the sudo and wheel groups."),
    entry("users.expiry", Users, "Password expiry", "sudo chage -l {{user}}", "When a user's password was changed and when it expires."),
    entry("users.locked", Users, "Locked accounts", "sudo grep -E '^[^:]+:[!*]' /etc/shadow | cut -d: -f1", "Accounts whose password is locked (! or * in /etc/shadow)."),
    entry("users.last", Users, "Last logins", "last -n 20", "The 20 latest logins and reboots."),
    entry("users.failed", Users, "Failed logins", "sudo lastb -n 20", "The 20 latest failed login attempts."),
    entry("users.sessions", Users, "Logged-in sessions", "loginctl list-sessions", "Current login sessions (loginctl)."),
    entry("users.session-detail", Users, "A session's detail", "loginctl session-status {{session}}", "What a login session is running, and from where."),
    entry("users.lslogins", Users, "Accounts and last login", "lslogins", "Every account with its last login and whether it can log in (util-linux)."),
    entry("users.sudo-log", Users, "Recent sudo use", "sudo journalctl _COMM=sudo -n 50 --no-pager 2>/dev/null; sudo grep -h sudo /var/log/auth.log 2>/dev/null | tail -30", "Recent sudo commands, from the journal or auth.log."),
    entry("users.add", Users, "Add a user", "sudo useradd -m {{user}}", "Creates a user with a home folder (no password yet)."),
    entry("users.add-to-group", Users, "Add a user to a group", "sudo usermod -aG {{group}} {{user}}", "Adds a group to a user's groups; it applies at their next login."),
    entry("users.lock", Users, "Lock an account", "sudo usermod -L {{user}}", "Locks an account's password so it cannot log in with it."),
    entry("users.deluser", Users, "Remove a user", "sudo userdel {{user}}", "Removes a user, leaving their home folder."),

    // ============================ Security and access ============================
    entry("sec.selinux-mode", Security, "SELinux mode", "getenforce", "Enforcing, Permissive or Disabled."),
    entry("sec.selinux-status", Security, "SELinux status", "sestatus", "SELinux status, the loaded policy and per-mount modes (sestatus)."),
    entry("sec.selinux-booleans", Security, "SELinux booleans that are on", "getsebool -a 2>/dev/null | grep ' on$'", "SELinux booleans currently enabled."),
    entry("sec.selinux-denials", Security, "Recent SELinux denials", "sudo ausearch -m avc,user_avc -ts recent 2>/dev/null | tail -60", "Recent SELinux access denials from the audit log."),
    entry("sec.selinux-denials-report", Security, "SELinux denials today", "sudo ausearch -m avc -ts today 2>/dev/null | aureport -a 2>/dev/null | tail -40", "A summary of today's SELinux denials."),
    entry("sec.setenforce", Security, "Switch SELinux to permissive", "sudo setenforce 0", "Puts SELinux in permissive mode until reboot: it logs denials but does not block."),
    entry("sec.restorecon", Security, "Restore file labels", "sudo restorecon -Rv {{path}}", "Resets SELinux labels on a path to the policy default."),
    entry("sec.apparmor-status", Security, "AppArmor status", "sudo aa-status", "AppArmor profiles and whether each enforces or complains (aa-status)."),
    entry("sec.apparmor-denials", Security, "AppArmor denials", "sudo dmesg -T 2>/dev/null | grep -i apparmor | tail -40", "Recent AppArmor denials from the kernel buffer."),
    entry("sec.sudo-rights", Security, "A user's sudo rights", "sudo -l -U {{user}}", "What a user may run with sudo."),
    entry("sec.sudoers-check", Security, "Check sudoers syntax", "sudo visudo -c", "Validates /etc/sudoers and its drop-ins without editing them."),
    entry("sec.sshd-config", Security, "Effective sshd config", "sudo sshd -T 2>/dev/null | sort", "Every effective sshd setting after includes and matches (sshd -T)."),
    entry("sec.sshd-test", Security, "Test sshd config", "sudo sshd -t", "Validates the sshd config and reports errors, without restarting it."),
    entry("sec.sshd-keyauth", Security, "sshd login settings", "sudo sshd -T 2>/dev/null | grep -iE -e passwordauth -e permitroot -e pubkeyauth -e challenge -e kbdinteractive", "The sshd settings that decide how logins are allowed."),
    entry("sec.failed-logins", Security, "Failed SSH logins", "sudo journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep -iE -e failed -e invalid | tail -40", "Recent failed or invalid SSH login attempts."),
    entry("sec.auth-log", Security, "Authentication log", "sudo journalctl -t sshd -t sudo -t su --no-pager -n 80 2>/dev/null; sudo tail -n 80 /var/log/auth.log /var/log/secure 2>/dev/null", "Recent authentication events, from the journal or auth.log/secure."),
    entry("sec.fail2ban-status", Security, "fail2ban status", "sudo fail2ban-client status", "The fail2ban jails that are active."),
    entry("sec.fail2ban-jail", Security, "A fail2ban jail", "sudo fail2ban-client status {{jail:sshd}}", "A jail's banned addresses and failure counts."),
    entry("sec.fail2ban-unban", Security, "Unban an address", "sudo fail2ban-client set {{jail:sshd}} unbanip {{ip}}", "Removes a ban for one address in a jail."),
    entry("sec.auditd-status", Security, "auditd status", "sudo systemctl status auditd --no-pager", "Whether the audit daemon is running."),
    entry("sec.auditd-rules", Security, "Audit rules", "sudo auditctl -l", "The audit rules loaded now."),
    entry("sec.audit-summary", Security, "Audit summary", "sudo aureport 2>/dev/null | head -40", "A summary of the audit log: logins, denials and changes."),
    entry("sec.listening", Security, "Listening services (attack surface)", "sudo ss -tulpnH | sort", "Every port open for connections and the process behind it."),

    // ============================ TLS certificates ============================
    entry("cert.file", Certificates, "Inspect a certificate file", "openssl x509 -in {{path:/etc/ssl/certs/cert.pem}} -noout -subject -issuer -dates", "Subject, issuer and validity dates of a certificate file."),
    entry("cert.text", Certificates, "Full certificate detail", "openssl x509 -in {{path:/etc/ssl/certs/cert.pem}} -noout -text", "Everything in a certificate: extensions, SANs and key info."),
    entry("cert.fingerprint", Certificates, "Certificate fingerprint", "openssl x509 -in {{path:/etc/ssl/certs/cert.pem}} -noout -fingerprint -sha256", "The SHA-256 fingerprint of a certificate."),
    entry("cert.expiry", Certificates, "When a server's cert expires", "echo | openssl s_client -connect {{host}}:{{port:443}} -servername {{host}} 2>/dev/null | openssl x509 -noout -subject -dates", "Subject and validity dates of the certificate a TLS server presents."),
    entry("cert.enddate", Certificates, "Server cert end date", "echo | openssl s_client -connect {{host}}:{{port:443}} -servername {{host}} 2>/dev/null | openssl x509 -noout -enddate", "Just the expiry date of a TLS server's certificate."),
    entry("cert.chain", Certificates, "Server's certificate chain", "echo | openssl s_client -connect {{host}}:{{port:443}} -servername {{host}} -showcerts 2>/dev/null | grep -E -e 'subject=' -e 'issuer='", "The subjects and issuers in the chain a TLS server sends, to spot a missing intermediate."),
    entry("cert.verify", Certificates, "Verify a cert against a CA", "openssl verify -CAfile {{ca:/etc/ssl/certs/ca-bundle.crt}} {{path:/etc/ssl/certs/cert.pem}}", "Whether a certificate validates against a CA bundle."),
    entry("cert.connect-tls12", Certificates, "Test a TLS version", "echo | openssl s_client -connect {{host}}:{{port:443}} -tls1_2 2>/dev/null | grep -E -e Protocol -e Cipher", "Whether a server accepts TLS 1.2 and which cipher it picks."),
    entry("cert.csr", Certificates, "Inspect a CSR", "openssl req -in {{path:/tmp/request.csr}} -noout -text -verify", "The subject, SANs and signature of a certificate signing request."),
    entry("cert.ca-dir", Certificates, "System CA bundle", "ls -l /etc/ssl/certs /etc/pki/tls/certs 2>/dev/null | head -40", "The folders that hold the system's trusted CA certificates."),
    entry("cert.update-trust", Certificates, "Rebuild the CA trust store", "sudo update-ca-trust extract 2>/dev/null || sudo update-ca-certificates", "Rebuilds the system CA trust store after you add or remove a CA."),

    // ============================ Firewall ============================
    entry("firewall.ufw", Firewall, "ufw status", "sudo ufw status verbose", "Whether ufw is on, its defaults and rules."),
    entry("firewall.firewalld", Firewall, "firewalld zone", "sudo firewall-cmd --list-all", "The default zone's services, ports and rules."),
    entry("firewall.firewalld-state", Firewall, "Is firewalld running?", "sudo firewall-cmd --state", "running or not running."),
    entry("firewall.firewalld-zones", Firewall, "All firewalld zones", "sudo firewall-cmd --list-all-zones", "Every firewalld zone and its rules."),
    entry("firewall.firewalld-services", Firewall, "firewalld known services", "sudo firewall-cmd --get-services | tr ' ' '\\n' | head -40", "The predefined services firewalld can allow by name."),
    entry("firewall.iptables", Firewall, "iptables rules", "sudo iptables -L -n -v --line-numbers", "Each chain's rules, with counters and numbers."),
    entry("firewall.iptables-nat", Firewall, "iptables NAT rules", "sudo iptables -L -t nat -n -v --line-numbers", "The NAT table's rules, for port forwards and masquerading."),
    entry("firewall.nft", Firewall, "nftables rules", "sudo nft list ruleset", "The whole nftables rule set."),
    entry("firewall.nft-tables", Firewall, "nftables tables", "sudo nft list tables", "The nftables tables that exist."),
    entry("firewall.ufw-allow", Firewall, "Open a port (ufw)", "sudo ufw allow {{port}}/tcp", "Allows incoming TCP connections to a port."),
    entry("firewall.ufw-reload", Firewall, "Reload ufw", "sudo ufw reload", "Re-applies the ufw rules."),
    entry("firewall.firewalld-allow", Firewall, "Open a port (firewalld)", "sudo firewall-cmd --add-port={{port}}/tcp", "Allows a TCP port in the default zone until the next reload (add --permanent to keep it)."),
    entry("firewall.firewalld-reload", Firewall, "Reload firewalld", "sudo firewall-cmd --reload", "Applies the permanent firewalld rules now."),

    // ============================ Web servers (nginx, Apache) ============================
    entry("web.which", WebServers, "Which web server runs", "systemctl status nginx httpd apache2 --no-pager 2>/dev/null | grep -E -e 'Loaded:' -e 'Active:' | head", "Which of nginx, httpd and apache2 is installed and running."),
    entry("web.nginx-test", WebServers, "Test nginx config", "sudo nginx -t", "Checks the nginx config for errors without reloading it."),
    entry("web.nginx-dump", WebServers, "Dump nginx config", "sudo nginx -T 2>&1 | head -120", "The full effective nginx config, includes expanded."),
    entry("web.nginx-version", WebServers, "nginx version and modules", "nginx -V 2>&1", "The nginx version and how it was built."),
    entry("web.nginx-status", WebServers, "nginx service status", "systemctl status nginx --no-pager", "Whether nginx is running, and its last log lines."),
    entry("web.nginx-errors", WebServers, "nginx error log", "sudo tail -n 80 /var/log/nginx/error.log", "The last nginx error log lines."),
    entry("web.nginx-access", WebServers, "nginx access log", "sudo tail -n 80 /var/log/nginx/access.log", "The last nginx access log lines."),
    entry("web.nginx-reload", WebServers, "Reload nginx", "sudo systemctl reload nginx", "Re-reads the nginx config without dropping connections."),
    entry("web.apache-test", WebServers, "Test Apache config", "sudo apachectl configtest 2>/dev/null || sudo apache2ctl configtest || sudo httpd -t", "Checks the Apache config for errors (apachectl, apache2ctl or httpd)."),
    entry("web.apache-vhosts", WebServers, "Apache virtual hosts", "sudo apachectl -S 2>/dev/null || sudo apache2ctl -S || sudo httpd -S", "The virtual hosts Apache serves and which config defines each."),
    entry("web.apache-modules", WebServers, "Apache modules", "sudo apachectl -M 2>/dev/null || sudo apache2ctl -M || sudo httpd -M", "The modules Apache has loaded."),
    entry("web.apache-status", WebServers, "Apache service status", "systemctl status apache2 httpd --no-pager 2>/dev/null", "Whether Apache is running, and its last log lines."),
    entry("web.apache-errors", WebServers, "Apache error log", "sudo tail -n 80 /var/log/apache2/error.log /var/log/httpd/error_log 2>/dev/null", "The last Apache error log lines."),
    entry("web.apache-reload", WebServers, "Reload Apache", "sudo systemctl reload apache2 2>/dev/null || sudo systemctl reload httpd", "Re-reads the Apache config without dropping connections."),
    entry("web.local-check", WebServers, "Fetch the local site", "curl -sSI --max-time 5 http://localhost/", "The response headers from the web server on localhost."),
    entry("web.ports", WebServers, "Web ports listening", "sudo ss -tulpn | grep -E -e ':80 ' -e ':443 ' -e ':8080 ' -e ':8443 '", "What is listening on the common web ports."),

    // ============================ Databases (MySQL, PostgreSQL) ============================
    entry("db.mysql-status", Databases, "MySQL/MariaDB service", "systemctl status mariadb mysql --no-pager 2>/dev/null", "Whether MariaDB or MySQL is running, and its last log lines."),
    entry("db.mysql-ping", Databases, "Is MySQL up", "sudo mysqladmin ping 2>/dev/null", "Whether the MySQL/MariaDB server answers (mysqladmin)."),
    entry("db.mysql-stat", Databases, "MySQL status counters", "sudo mysqladmin status 2>/dev/null", "Uptime, threads, questions and slow queries at a glance."),
    entry("db.mysql-extended", Databases, "MySQL global status", "sudo mysqladmin extended-status 2>/dev/null | head -60", "The server's global status counters."),
    entry("db.mysql-proclist", Databases, "MySQL process list", "sudo mysqladmin processlist 2>/dev/null", "The queries running now."),
    entry("db.mysql-vars", Databases, "MySQL key variables", "sudo mysqladmin variables 2>/dev/null | grep -iE -e max_connections -e buffer_pool -e datadir -e version -e read_only", "Important server settings: connections, buffer pool, data dir, version."),
    entry("db.mysql-version", Databases, "MySQL/MariaDB version", "mysql --version 2>/dev/null; mariadb --version 2>/dev/null", "The client (and usually server) version."),
    entry("db.mysql-datadir", Databases, "MySQL data size", "sudo du -sh /var/lib/mysql 2>/dev/null", "How much disk the MySQL/MariaDB data directory uses."),
    entry("db.mysql-logs", Databases, "MySQL error log", "sudo tail -n 80 /var/log/mysql/error.log 2>/dev/null; sudo journalctl -u mariadb -u mysql --no-pager -n 80 2>/dev/null", "The last MySQL/MariaDB error log lines."),
    entry("db.pg-status", Databases, "PostgreSQL service", "systemctl status postgresql --no-pager 2>/dev/null", "Whether PostgreSQL is running, and its last log lines."),
    entry("db.pg-ready", Databases, "Is PostgreSQL up", "pg_isready", "Whether PostgreSQL is accepting connections (pg_isready)."),
    entry("db.pg-version", Databases, "PostgreSQL version", "psql --version 2>/dev/null", "The PostgreSQL client version."),
    entry("db.pg-clusters", Databases, "PostgreSQL clusters", "pg_lsclusters 2>/dev/null", "The PostgreSQL clusters, their versions, ports and state (Debian/Ubuntu)."),
    entry("db.pg-activity", Databases, "PostgreSQL activity", "sudo -u postgres psql -c 'SELECT pid, usename, state, wait_event, query FROM pg_stat_activity ORDER BY state;' 2>/dev/null", "The sessions connected to PostgreSQL and what each is doing."),
    entry("db.pg-conns", Databases, "PostgreSQL connection count", "sudo -u postgres psql -tc 'SELECT count(*), max_conn FROM pg_stat_activity, (SELECT setting::int AS max_conn FROM pg_settings WHERE name=$$max_connections$$) s GROUP BY max_conn;' 2>/dev/null", "How many connections are in use against the limit."),
    entry("db.pg-datadir", Databases, "PostgreSQL data size", "sudo du -sh /var/lib/pgsql /var/lib/postgresql 2>/dev/null", "How much disk the PostgreSQL data directory uses."),
    entry("db.pg-logs", Databases, "PostgreSQL log", "sudo journalctl -u postgresql --no-pager -n 80 2>/dev/null; sudo tail -n 80 /var/lib/pgsql/data/log/*.log 2>/dev/null", "The last PostgreSQL log lines."),

    // ============================ Cron and timers ============================
    entry("cron.user", Scheduling, "Your cron jobs", "crontab -l 2>/dev/null", "The crontab of the current user."),
    entry("cron.user-of", Scheduling, "A user's cron jobs", "sudo crontab -l -u {{user}} 2>/dev/null", "Another user's crontab."),
    entry("cron.system", Scheduling, "System crontab", "cat /etc/crontab", "The system-wide crontab."),
    entry("cron.d", Scheduling, "Cron drop-ins", "ls -l /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly 2>/dev/null", "The scripts and files in the system cron folders."),
    entry("cron.anacron", Scheduling, "anacron schedule", "cat /etc/anacrontab 2>/dev/null", "The anacron jobs, for machines that are not always on."),
    entry("cron.timers", Scheduling, "systemd timers", "systemctl list-timers --all --no-pager", "Every systemd timer, when it last ran and runs next."),
    entry("cron.timer-status", Scheduling, "A timer's status", "systemctl status {{timer:logrotate.timer}} --no-pager", "A timer's state and the unit it triggers."),
    entry("cron.at", Scheduling, "at queue", "atq 2>/dev/null", "One-off jobs queued with at."),
    entry("cron.log", Scheduling, "Cron activity", "sudo journalctl -t CRON -t cron --no-pager -n 60 2>/dev/null; sudo grep -h CRON /var/log/syslog 2>/dev/null | tail -40", "Recent cron runs, from the journal or syslog."),

    // ============================ Time sync (NTP/chrony) ============================
    entry("time.status", TimeSync, "Clock and sync", "timedatectl", "Local and UTC time, time zone, and whether the clock is synchronized."),
    entry("time.sync", TimeSync, "Time sync status", "timedatectl timesync-status 2>/dev/null", "The server systemd-timesyncd uses and the current offset."),
    entry("time.timezone", TimeSync, "Time zone", "timedatectl show -p Timezone --value 2>/dev/null", "The configured time zone."),
    entry("time.chrony-tracking", TimeSync, "chrony tracking", "chronyc tracking 2>/dev/null", "chrony's current offset, stratum and drift."),
    entry("time.chrony-sources", TimeSync, "chrony sources", "chronyc sources -v 2>/dev/null", "The time sources chrony uses and their state."),
    entry("time.chrony-stats", TimeSync, "chrony source stats", "chronyc sourcestats 2>/dev/null", "How steady each chrony source is."),
    entry("time.chrony-activity", TimeSync, "chrony activity", "chronyc activity 2>/dev/null", "How many sources are online, offline and unreachable."),
    entry("time.ntpq", TimeSync, "ntpd peers", "ntpq -p -n 2>/dev/null", "The peers ntpd uses and their offsets (classic ntpd)."),
    entry("time.offset", TimeSync, "Clock offset", "chronyc tracking 2>/dev/null | grep -iE -e offset -e stratum -e leap", "chrony's offset, stratum and leap status at a glance."),
    entry("time.hwclock", TimeSync, "Hardware clock", "sudo hwclock --show 2>/dev/null", "The time the hardware (RTC) clock holds."),
    entry("time.set-ntp", TimeSync, "Turn on NTP sync", "sudo timedatectl set-ntp true", "Enables automatic clock sync (timesyncd or chrony)."),
    entry("time.makestep", TimeSync, "Step the clock now", "sudo chronyc makestep 2>/dev/null", "Tells chrony to jump the clock straight to the right time instead of slewing."),

    // ============================ Identity (AD/LDAP, SSSD) ============================
    entry("id.realm", Identity, "Joined domains", "realm list 2>/dev/null", "The AD or IPA domains this host is joined to, and the login settings."),
    entry("id.realm-discover", Identity, "Discover a domain", "realm discover {{domain:example.test}} 2>/dev/null", "What a domain offers and what joining it would need."),
    entry("id.sssd-status", Identity, "SSSD service", "systemctl status sssd --no-pager", "Whether SSSD, which talks to AD/LDAP, is running."),
    entry("id.sssd-domains", Identity, "SSSD domains", "sudo sssctl domain-list 2>/dev/null", "The domains SSSD is configured for."),
    entry("id.sssd-domain-status", Identity, "A SSSD domain's status", "sudo sssctl domain-status {{domain:example.test}} 2>/dev/null", "Whether a SSSD domain is online and which server it uses."),
    entry("id.sssd-config-check", Identity, "Check SSSD config", "sudo sssctl config-check 2>/dev/null", "Reports mistakes in the SSSD configuration."),
    entry("id.user-lookup", Identity, "Look up a directory user", "getent passwd {{user}}", "Resolve a user through SSSD/LDAP, as the system sees them."),
    entry("id.user-groups", Identity, "A directory user's groups", "id {{user}}", "A directory user's ID and group memberships."),
    entry("id.klist", Identity, "Kerberos tickets", "klist 2>/dev/null", "The Kerberos tickets held now."),
    entry("id.adcli", Identity, "AD computer account", "adcli info {{domain:example.test}} 2>/dev/null", "What adcli can learn about an AD domain."),
    entry("id.nsswitch", Identity, "NSS lookup order", "grep -E -e '^passwd:' -e '^group:' -e '^hosts:' /etc/nsswitch.conf", "Where the system looks up users, groups and hosts, and in what order."),
    entry("id.sssd-logs", Identity, "SSSD log", "sudo journalctl -u sssd --no-pager -n 80 2>/dev/null; sudo tail -n 80 /var/log/sssd/*.log 2>/dev/null", "The last SSSD log lines."),
    entry("id.sss-cache", Identity, "Clear the SSSD cache", "sudo sss_cache -E 2>/dev/null", "Invalidates the SSSD cache so the next lookup refreshes from the directory."),
    entry("id.realm-join", Identity, "Join a domain", "sudo realm join {{domain:example.test}} -U {{user}}", "Joins the host to an AD/IPA domain (prompts for the password)."),

    // ============================ VMware Tools (guest) ============================
    entry("vmtools.status", VmwareGuest, "open-vm-tools service", "systemctl status vmtoolsd open-vm-tools --no-pager 2>/dev/null", "Whether VMware Tools (vmtoolsd / open-vm-tools) is running in the guest."),
    entry("vmtools.version", VmwareGuest, "VMware Tools version", "vmware-toolbox-cmd -v 2>/dev/null", "The installed VMware Tools version."),
    entry("vmtools.timesync", VmwareGuest, "Guest time sync", "vmware-toolbox-cmd timesync status 2>/dev/null", "Whether the guest syncs its clock from the ESXi/Workstation host."),
    entry("vmtools.stat-host", VmwareGuest, "Host time", "vmware-toolbox-cmd stat hosttime 2>/dev/null", "The time the hypervisor host reports."),
    entry("vmtools.stat-speed", VmwareGuest, "Host CPU speed", "vmware-toolbox-cmd stat speed 2>/dev/null", "The host CPU speed the guest sees."),
    entry("vmtools.stat-mem", VmwareGuest, "Balloon and swap", "vmware-toolbox-cmd stat balloon 2>/dev/null; vmware-toolbox-cmd stat swap 2>/dev/null", "Memory the host has reclaimed from this guest through ballooning or swap."),
    entry("vmtools.devices", VmwareGuest, "Virtual devices", "vmware-toolbox-cmd device list 2>/dev/null", "The guest's connectable virtual devices."),
    entry("vmtools.pkg", VmwareGuest, "open-vm-tools package", "rpm -q open-vm-tools 2>/dev/null; dpkg -l open-vm-tools 2>/dev/null", "The installed open-vm-tools package version."),
    entry("vmtools.processes", VmwareGuest, "VMware guest processes", "ps -ef | grep -E -e '[v]mtoolsd' -e '[v]mware'", "The VMware helper processes running in the guest."),

    // ============================ Docker ============================
    entry("docker.ps", Docker, "Running containers", "docker ps", "Containers running now, with their images, ports and names."),
    entry("docker.ps-all", Docker, "All containers", "docker ps -a", "Every container, stopped ones too."),
    entry("docker.names", Docker, "Container names and states", r"docker ps -a --format '{{.Names}}\t{{.Status}}'", "One line per container: name and status."),
    entry("docker.images", Docker, "Images", "docker images", "Images on this host and their sizes."),
    entry("docker.logs", Docker, "Container logs", "docker logs --tail {{lines:200}} {{container}}", "The last lines a container wrote."),
    entry("docker.follow", Docker, "Follow container logs", "docker logs -f --tail 50 {{container}}", "New log lines of a container as they come; Ctrl+C stops."),
    entry("docker.stats", Docker, "Resource use", "docker stats --no-stream", "CPU, memory, network and disk I/O per container, once."),
    entry("docker.top", Docker, "Processes in a container", "docker top {{container}}", "The processes running inside a container."),
    entry("docker.inspect", Docker, "Inspect a container", "docker inspect {{container}}", "A container's full configuration and state, as JSON."),
    entry("docker.port", Docker, "A container's ports", "docker port {{container}}", "The port mappings of a container."),
    entry("docker.df", Docker, "Disk use", "docker system df", "Space used by images, containers, volumes and the build cache."),
    entry("docker.info", Docker, "Docker info", "docker info", "The daemon's storage driver, runtimes, resources and warnings."),
    entry("docker.version", Docker, "Docker version", "docker version", "The client and daemon versions."),
    entry("docker.networks", Docker, "Networks", "docker network ls", "Docker networks and their drivers."),
    entry("docker.volumes", Docker, "Volumes", "docker volume ls", "Docker volumes on this host."),
    entry("docker.compose", Docker, "Compose services", "docker compose ps", "The services of the Compose project in this folder."),
    entry("docker.compose-logs", Docker, "Compose logs", "docker compose logs --tail {{lines:200}}", "The last lines from the Compose project's services."),
    entry("docker.restart", Docker, "Restart a container", "docker restart {{container}}", "Stops and starts a container."),
    entry("docker.shell", Docker, "Shell in a container", "docker exec -it {{container}} sh", "Opens a shell inside a running container."),
    entry("docker.prune", Docker, "Remove unused data", "docker system prune", "Deletes stopped containers, unused networks, dangling images and the build cache; asks first."),

    // ============================ Podman ============================
    entry("podman.ps", Podman, "Running containers", "podman ps", "Containers running now."),
    entry("podman.ps-all", Podman, "All containers", "podman ps -a", "Every container, stopped ones too."),
    entry("podman.images", Podman, "Images", "podman images", "Images on this host and their sizes."),
    entry("podman.logs", Podman, "Container logs", "podman logs --tail {{lines:200}} {{container}}", "The last lines a container wrote."),
    entry("podman.stats", Podman, "Resource use", "podman stats --no-stream", "CPU, memory and I/O per container, once."),
    entry("podman.inspect", Podman, "Inspect a container", "podman inspect {{container}}", "A container's full configuration and state, as JSON."),
    entry("podman.top", Podman, "Processes in a container", "podman top {{container}}", "The processes running inside a container."),
    entry("podman.info", Podman, "Podman info", "podman info", "Podman's storage, runtimes and host details."),
    entry("podman.version", Podman, "Podman version", "podman version", "The Podman version."),
    entry("podman.pods", Podman, "Pods", "podman pod ps", "The pods on this host and their containers."),
    entry("podman.volumes", Podman, "Volumes", "podman volume ls", "Podman volumes on this host."),
    entry("podman.df", Podman, "Disk use", "podman system df", "Space used by images, containers and volumes."),
    entry("podman.restart", Podman, "Restart a container", "podman restart {{container}}", "Stops and starts a container."),
    entry("podman.prune", Podman, "Remove unused data", "podman system prune", "Deletes stopped containers, unused networks and dangling images; asks first."),

    // ============================ Kubernetes ============================
    entry("k8s.nodes", Kubernetes, "Nodes", "kubectl get nodes -o wide", "Nodes, their state, versions and addresses."),
    entry("k8s.pods", Kubernetes, "Pods", "kubectl get pods -A -o wide", "Pods in every namespace, with their nodes."),
    entry("k8s.unhealthy", Kubernetes, "Pods not running", "kubectl get pods -A --field-selector=status.phase!=Running", "Pods pending, failed or in another state than Running."),
    entry("k8s.services", Kubernetes, "Services", "kubectl get svc -A", "Services in every namespace, with their types and cluster IPs."),
    entry("k8s.deployments", Kubernetes, "Deployments", "kubectl get deploy -A", "Deployments and how many replicas are ready."),
    entry("k8s.namespaces", Kubernetes, "Namespaces", "kubectl get ns", "The namespaces in the cluster."),
    entry("k8s.pvc", Kubernetes, "Persistent volume claims", "kubectl get pvc -A", "Persistent volume claims and whether each is bound."),
    entry("k8s.configmaps", Kubernetes, "ConfigMaps", "kubectl get configmap -A", "ConfigMaps in every namespace."),
    entry("k8s.describe", Kubernetes, "Describe a pod", "kubectl describe pod {{pod}} -n {{namespace:default}}", "A pod's containers, state, events and why it is not ready."),
    entry("k8s.node-detail", Kubernetes, "Describe a node", "kubectl describe node {{node}}", "A node's capacity, conditions, pods and events."),
    entry("k8s.logs", Kubernetes, "Pod logs", "kubectl logs {{pod}} -n {{namespace:default}} --tail={{lines:200}}", "The last lines a pod's container wrote."),
    entry("k8s.logs-previous", Kubernetes, "Previous container logs", "kubectl logs {{pod}} -n {{namespace:default}} -p --tail={{lines:200}}", "The logs of a container's previous run, to see why it crashed."),
    entry("k8s.events", Kubernetes, "Recent events", "kubectl get events -A --sort-by=.lastTimestamp", "Cluster events, newest last."),
    entry("k8s.top", Kubernetes, "Resource use", "kubectl top pods -A", "CPU and memory per pod (needs metrics-server)."),
    entry("k8s.api-resources", Kubernetes, "API resources", "kubectl api-resources", "The kinds of object this cluster knows and their short names."),
    entry("k8s.can-i", Kubernetes, "What may I do", "kubectl auth can-i --list -n {{namespace:default}}", "What the current context is allowed to do in a namespace."),
    entry("k8s.contexts", Kubernetes, "Contexts", "kubectl config get-contexts", "The clusters kubectl knows, and the current one."),
    entry("k8s.config-view", Kubernetes, "kubeconfig", "kubectl config view", "The merged kubeconfig, with secrets hidden."),
    entry("k8s.cluster", Kubernetes, "Cluster info", "kubectl cluster-info", "Addresses of the control plane and core services."),
    entry("k8s.rollout-status", Kubernetes, "Rollout status", "kubectl rollout status deployment/{{deployment}} -n {{namespace:default}}", "Whether a deployment's rollout has finished."),
    entry("k8s.rollout-history", Kubernetes, "Rollout history", "kubectl rollout history deployment/{{deployment}} -n {{namespace:default}}", "A deployment's revisions, to roll back to one."),
    entry("k8s.restart", Kubernetes, "Restart a deployment", "kubectl rollout restart deployment/{{deployment}} -n {{namespace:default}}", "Replaces a deployment's pods one by one."),
    entry("k8s.scale", Kubernetes, "Scale a deployment", "kubectl scale deployment/{{deployment}} --replicas={{count:3}} -n {{namespace:default}}", "Changes how many replicas a deployment runs."),
    entry("k8s.delete-pod", Kubernetes, "Delete a pod", "kubectl delete pod {{pod}} -n {{namespace:default}}", "Deletes a pod; its controller starts a new one, if it has one."),

    // ============================ Helm ============================
    entry("helm.list", Helm, "Releases", "helm list -A", "Helm releases in every namespace and their status."),
    entry("helm.status", Helm, "Release status", "helm status {{release}} -n {{namespace:default}}", "A release's status, revision and notes."),
    entry("helm.history", Helm, "Release history", "helm history {{release}} -n {{namespace:default}}", "A release's revisions, to roll back to one."),
    entry("helm.values", Helm, "Release values", "helm get values {{release}} -n {{namespace:default}}", "The values a release was installed with."),
    entry("helm.manifest", Helm, "Release manifest", "helm get manifest {{release}} -n {{namespace:default}}", "The Kubernetes objects a release rendered."),
    entry("helm.repos", Helm, "Repositories", "helm repo list", "The chart repositories configured."),
    entry("helm.search", Helm, "Search charts", "helm search repo {{text}}", "Charts in the configured repositories whose name matches."),
    entry("helm.version", Helm, "Helm version", "helm version", "The Helm client version."),
    entry("helm.rollback", Helm, "Roll back a release", "helm rollback {{release}} {{revision}} -n {{namespace:default}}", "Returns a release to an earlier revision."),
];

/// Symptom runbooks: each lists, in order, the ids of the area commands to run. An id may appear in
/// several symptom groups and always also appears in its own area group.
#[rustfmt::skip]
pub const TROUBLESHOOT: &[Symptom] = &[
    Symptom { group: SlowHost, steps: &[
        "system.uptime", "cpu.load", "cpu.top", "cpu.busiest", "memory.free",
        "cpu.pressure", "cpu.io-pressure", "memory.pressure", "disk.io", "cpu.top-io",
        "cpu.uninterruptible", "cpu.per-cpu", "memory.oom",
    ] },
    Symptom { group: OutOfMemory, steps: &[
        "memory.free", "memory.top", "memory.oom", "memory.meminfo", "memory.pressure",
        "memory.swaps", "memory.slab", "cpu.busiest", "memory.dropcaches",
    ] },
    Symptom { group: DiskFull, steps: &[
        "disk.free", "disk.inodes", "disk.biggest", "disk.largest-logs", "disk.biggest-files",
        "disk.deleted", "logs.usage", "disk.open-by-dir", "logs.vacuum", "docker.df",
    ] },
    Symptom { group: CantReachService, steps: &[
        "network.ping", "network.default-route", "network.routes", "network.listening", "network.port",
        "network.tcpprobe", "services.status", "network.iface-stats", "firewall.ufw", "firewall.firewalld",
        "sec.listening",
    ] },
    Symptom { group: DnsFails, steps: &[
        "network.dns", "network.resolve", "network.dns-dig", "network.dns-reverse", "network.dns-trace",
        "network.getent-host", "network.dns-resolvectl", "network.hosts",
    ] },
    Symptom { group: ServiceWontStart, steps: &[
        "services.status", "logs.service", "services.show", "services.unit", "sec.selinux-denials",
        "disk.free", "services.daemon-reload", "services.reset-failed", "services.restart",
    ] },
    Symptom { group: CantLoginSsh, steps: &[
        "sec.sshd-test", "sec.sshd-config", "sec.failed-logins", "network.port", "sec.fail2ban-status",
        "users.expiry", "sec.selinux-denials", "disk.free",
    ] },
    Symptom { group: ClockWrong, steps: &[
        "time.status", "time.sync", "time.chrony-tracking", "time.chrony-sources", "time.ntpq",
        "time.offset", "time.set-ntp", "time.makestep",
    ] },
    Symptom { group: CertExpired, steps: &[
        "cert.expiry", "cert.enddate", "cert.chain", "cert.verify", "cert.file",
        "cert.connect-tls12", "time.status",
    ] },
    Symptom { group: PackageBroken, steps: &[
        "apt.audit", "apt.fix-broken", "apt.held", "apt.clean", "apt.update",
        "dnf.verify", "dnf.clean", "dnf.makecache",
    ] },
];
