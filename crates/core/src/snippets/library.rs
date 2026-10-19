//! BX-08 Library: common Linux commands, built in and grouped. Most only read. Which ones change
//! something or are dangerous is not written here: the policy engine decides it from the user's
//! current rules ([`super::Snippets::library`]), so the marks always match what a bulk run or
//! MultiExec would ask for.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LibraryGroup {
    SystemInfo,
    Disk,
    Memory,
    Processes,
    Network,
    Services,
    Logs,
    PackagesApt,
    PackagesDnf,
    Users,
    Firewall,
    Docker,
    Kubernetes,
}

impl LibraryGroup {
    /// In the order the panel shows them.
    pub const ALL: [LibraryGroup; 13] = [
        LibraryGroup::SystemInfo,
        LibraryGroup::Disk,
        LibraryGroup::Memory,
        LibraryGroup::Processes,
        LibraryGroup::Network,
        LibraryGroup::Services,
        LibraryGroup::Logs,
        LibraryGroup::PackagesApt,
        LibraryGroup::PackagesDnf,
        LibraryGroup::Users,
        LibraryGroup::Firewall,
        LibraryGroup::Docker,
        LibraryGroup::Kubernetes,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LibraryGroup::SystemInfo => "System info",
            LibraryGroup::Disk => "Disk and filesystems",
            LibraryGroup::Memory => "Memory",
            LibraryGroup::Processes => "CPU and processes",
            LibraryGroup::Network => "Network",
            LibraryGroup::Services => "Services (systemd)",
            LibraryGroup::Logs => "Logs (journalctl)",
            LibraryGroup::PackagesApt => "Packages (apt)",
            LibraryGroup::PackagesDnf => "Packages (dnf/yum)",
            LibraryGroup::Users => "Users and groups",
            LibraryGroup::Firewall => "Firewall",
            LibraryGroup::Docker => "Docker",
            LibraryGroup::Kubernetes => "Kubernetes",
        }
    }
}

/// One built-in command, as written here.
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

use LibraryGroup::*;

#[rustfmt::skip]
pub const LIBRARY: &[BuiltIn] = &[
    // ---- System info
    entry("system.os", SystemInfo, "OS release", "cat /etc/os-release", "Distribution name and version."),
    entry("system.kernel", SystemInfo, "Kernel and architecture", "uname -a", "Kernel version, host name and CPU architecture."),
    entry("system.host", SystemInfo, "Host name and OS", "hostnamectl status", "Host name, OS, kernel, and the machine's chassis and virtualization."),
    entry("system.uptime", SystemInfo, "Uptime and load", "uptime", "How long the host has run, logged-in users and the 1, 5 and 15 minute load."),
    entry("system.time", SystemInfo, "Date, time zone and NTP", "timedatectl", "Local and UTC time, time zone, and whether the clock is synchronized."),
    entry("system.virt", SystemInfo, "Virtualization", "systemd-detect-virt", "The hypervisor or container the host runs in (vmware, kvm, docker, none)."),
    entry("system.who", SystemInfo, "Who is logged in", "w", "Logged-in users, where from, and what they run."),
    entry("system.pci", SystemInfo, "PCI devices", "lspci", "Network cards, disk controllers and other PCI devices."),
    entry("system.selinux", SystemInfo, "SELinux mode", "getenforce", "Enforcing, Permissive or Disabled."),
    entry("system.env", SystemInfo, "Environment variables", "env | sort", "The shell's environment, sorted by name."),
    entry("system.reboot", SystemInfo, "Reboot the host", "sudo systemctl reboot", "Restarts the host now. Every session to it drops."),
    // ---- Disk and filesystems
    entry("disk.free", Disk, "Free space", "df -hT", "Size, use and free space of each mounted filesystem, with its type."),
    entry("disk.inodes", Disk, "Free inodes", "df -i", "Inode use per filesystem: full inodes stop new files even with space left."),
    entry("disk.devices", Disk, "Block devices", "lsblk -f", "Disks, partitions and LVM volumes with filesystems, labels and mount points."),
    entry("disk.mounts", Disk, "Mounted filesystems", "findmnt --real", "Real (not virtual) filesystems and where they are mounted."),
    entry("disk.fstab", Disk, "Mounts at boot", "cat /etc/fstab", "Filesystems mounted at boot."),
    entry("disk.biggest", Disk, "Biggest folders", "sudo du -xh --max-depth=1 {{path:/var}} 2>/dev/null | sort -h | tail -20", "The 20 largest folders directly under a path, on the same filesystem."),
    entry("disk.io", Disk, "Disk I/O", "iostat -xz 1 3", "Reads, writes, waits and utilization per device, three samples a second apart (sysstat)."),
    entry("disk.deleted", Disk, "Deleted files still open", "sudo lsof +L1", "Files deleted while a process holds them open: their space is not free until it closes them."),
    entry("disk.uuids", Disk, "Filesystem UUIDs", "sudo blkid", "UUIDs, labels and types of block devices."),
    // ---- Memory
    entry("memory.free", Memory, "Memory and swap", "free -h", "Total, used, free and available memory and swap."),
    entry("memory.vmstat", Memory, "Memory activity", "vmstat 1 5", "Memory, swapping, I/O and CPU, five samples a second apart."),
    entry("memory.top", Memory, "Top memory users", "ps aux --sort=-%mem | head -15", "The processes using the most memory."),
    entry("memory.meminfo", Memory, "Memory details", "cat /proc/meminfo", "The kernel's full memory counters."),
    entry("memory.swaps", Memory, "Swap devices", "cat /proc/swaps", "Swap files and partitions in use."),
    entry("memory.oom", Memory, "Out-of-memory kills", "journalctl -k --no-pager | grep -i -e 'out of memory' -e oom-kill", "Processes the kernel killed for lack of memory."),
    // ---- CPU and processes
    entry("cpu.info", Processes, "CPU details", "lscpu", "CPU model, cores, threads, sockets and caches."),
    entry("cpu.count", Processes, "CPU count", "nproc", "Processing units available."),
    entry("cpu.load", Processes, "Load average", "cat /proc/loadavg", "Load over 1, 5 and 15 minutes, and running and total processes."),
    entry("cpu.top", Processes, "Top snapshot", "top -b -n 1 | head -25", "One snapshot of top: load, CPU, memory and the busiest processes."),
    entry("cpu.busiest", Processes, "Top CPU users", "ps aux --sort=-%cpu | head -15", "The processes using the most CPU."),
    entry("cpu.per-cpu", Processes, "Use per CPU", "mpstat -P ALL 1 3", "User, system, I/O wait and idle time per CPU, three samples (sysstat)."),
    entry("cpu.tree", Processes, "Process tree", "ps axjf", "Every process under its parent."),
    entry("cpu.find", Processes, "Find a process", "pgrep -a {{name}}", "Process IDs and command lines matching a name."),
    entry("cpu.zombies", Processes, "Zombie processes", "ps -eo stat,pid,ppid,cmd | grep '^Z'", "Processes that ended but their parent has not collected them."),
    entry("cpu.kill", Processes, "Stop a process", "kill {{pid}}", "Asks a process to end (SIGTERM)."),
    // ---- Network
    entry("network.addresses", Network, "IP addresses", "ip -br a", "Each interface, its state and addresses, one line each."),
    entry("network.routes", Network, "Routes", "ip route", "The routing table, with the default gateway."),
    entry("network.route-to", Network, "Route to a host", "ip route get {{ip}}", "Which interface and gateway reach an address."),
    entry("network.listening", Network, "Listening ports", "sudo ss -tulpn", "TCP and UDP ports open for connections, with their processes."),
    entry("network.connections", Network, "Open connections", "ss -tan state established", "Established TCP connections."),
    entry("network.neighbours", Network, "Neighbours (ARP)", "ip neigh show", "MAC addresses seen on the local networks."),
    entry("network.traffic", Network, "Traffic per interface", "cat /proc/net/dev", "Bytes, packets, errors and drops per interface since boot."),
    entry("network.dns", Network, "DNS servers", "cat /etc/resolv.conf", "The name servers and search domains the host uses."),
    entry("network.hosts", Network, "Hosts file", "cat /etc/hosts", "Names resolved locally, before DNS."),
    entry("network.resolve", Network, "Resolve a name", "dig +short {{name}}", "The addresses a name resolves to."),
    entry("network.ping", Network, "Ping a host", "ping -c 4 {{host}}", "Four pings: reachability and round-trip time."),
    entry("network.trace", Network, "Path to a host", "tracepath {{host}}", "Each hop on the way to a host, and the path MTU."),
    // ---- Services (systemd)
    entry("services.failed", Services, "Failed services", "systemctl --failed", "Units that failed to start or crashed."),
    entry("services.running", Services, "Running services", "systemctl list-units --type=service --state=running", "Services running now."),
    entry("services.status", Services, "Service status", "systemctl status {{service}} --no-pager", "State, main process, memory and the last log lines of a service."),
    entry("services.enabled", Services, "Starts at boot?", "systemctl is-enabled {{service}}", "Whether a service starts at boot."),
    entry("services.files", Services, "Installed services", "systemctl list-unit-files --type=service", "Every service unit and whether it is enabled."),
    entry("services.timers", Services, "Timers", "systemctl list-timers --all", "Scheduled timers, when they last ran and run next."),
    entry("services.unit", Services, "Show a unit file", "systemctl cat {{service}}", "A service's unit file and its drop-ins."),
    entry("services.boot", Services, "Slow starts at boot", "systemd-analyze blame | head -20", "The units that took longest to start at the last boot."),
    entry("services.restart", Services, "Restart a service", "sudo systemctl restart {{service}}", "Stops and starts a service: its connections drop."),
    entry("services.reload", Services, "Reload a service", "sudo systemctl reload {{service}}", "Asks a service to read its configuration again, without a restart."),
    // ---- Logs (journalctl)
    entry("logs.errors", Logs, "Errors since boot", "journalctl -b -p err --no-pager", "Messages of priority error and worse since the last boot."),
    entry("logs.service", Logs, "A service's log", "journalctl -u {{service}} -n {{lines:200}} --no-pager", "The last lines a service logged."),
    entry("logs.follow", Logs, "Follow a service's log", "journalctl -u {{service}} -f", "New log lines of a service as they come; Ctrl+C stops."),
    entry("logs.recent", Logs, "Everything recently", "journalctl --since '{{since:1 hour ago}}' --no-pager", "All messages since a time, such as '1 hour ago' or '2026-10-19 08:00'."),
    entry("logs.kernel", Logs, "Kernel messages", "journalctl -k -n 100 --no-pager", "The last kernel messages: hardware, drivers, out-of-memory kills."),
    entry("logs.ssh", Logs, "SSH logins", "journalctl -u ssh -u sshd -n 100 --no-pager", "The SSH server's log: logins, failures and disconnects."),
    entry("logs.boots", Logs, "Boots", "journalctl --list-boots", "Boots the journal holds, newest last."),
    entry("logs.usage", Logs, "Journal size", "journalctl --disk-usage", "Disk space the journal uses."),
    // ---- Packages (apt)
    entry("apt.upgradable", PackagesApt, "Updates available", "apt list --upgradable", "Packages with a newer version (as of the last apt update)."),
    entry("apt.installed", PackagesApt, "Is a package installed?", "dpkg -l | grep -i {{package}}", "Installed packages whose name matches."),
    entry("apt.policy", PackagesApt, "Package versions", "apt-cache policy {{package}}", "Installed and candidate versions of a package, and their repositories."),
    entry("apt.owner", PackagesApt, "Which package has a file", "dpkg -S {{path}}", "The package that installed a file."),
    entry("apt.update", PackagesApt, "Refresh package lists", "sudo apt update", "Downloads the repositories' package lists."),
    entry("apt.upgrade", PackagesApt, "Install updates", "sudo apt upgrade", "Upgrades installed packages; asks before it starts."),
    entry("apt.install", PackagesApt, "Install a package", "sudo apt install {{package}}", "Installs a package and what it needs."),
    // ---- Packages (dnf/yum)
    entry("dnf.updates", PackagesDnf, "Updates available", "dnf check-update", "Packages with a newer version in the repositories."),
    entry("dnf.installed", PackagesDnf, "Installed packages", "rpm -qa | sort", "Every installed package, sorted."),
    entry("dnf.info", PackagesDnf, "Package details", "dnf info {{package}}", "Version, repository and description of a package."),
    entry("dnf.owner", PackagesDnf, "Which package has a file", "rpm -qf {{path}}", "The package that installed a file."),
    entry("dnf.repos", PackagesDnf, "Repositories", "dnf repolist", "The enabled repositories."),
    entry("dnf.history", PackagesDnf, "Install history", "dnf history list", "Past installs, upgrades and removals."),
    entry("dnf.yum-installed", PackagesDnf, "Installed packages (yum)", "yum list installed", "Every installed package, on hosts with yum only."),
    entry("dnf.upgrade", PackagesDnf, "Install updates", "sudo dnf upgrade", "Upgrades installed packages; asks before it starts."),
    entry("dnf.install", PackagesDnf, "Install a package", "sudo dnf install {{package}}", "Installs a package and what it needs."),
    // ---- Users and groups
    entry("users.me", Users, "Who am I", "id", "Your user, its ID and groups."),
    entry("users.of", Users, "A user's groups", "id {{user}}", "A user's ID and groups."),
    entry("users.logins", Users, "Accounts that can log in", "grep -v -e nologin -e /bin/false /etc/passwd", "Users with a login shell."),
    entry("users.group", Users, "Members of a group", "getent group {{group}}", "A group's ID and members (local or from the directory)."),
    entry("users.expiry", Users, "Password expiry", "sudo chage -l {{user}}", "When a user's password was changed and when it expires."),
    entry("users.last", Users, "Last logins", "last -n 20", "The 20 latest logins and reboots."),
    entry("users.failed", Users, "Failed logins", "sudo lastb -n 20", "The 20 latest failed logins."),
    entry("users.add", Users, "Add a user", "sudo useradd -m {{user}}", "Creates a user with a home folder (no password yet)."),
    entry("users.add-to-group", Users, "Add a user to a group", "sudo usermod -aG {{group}} {{user}}", "Adds a group to a user's groups; it applies at their next login."),
    // ---- Firewall
    entry("firewall.ufw", Firewall, "ufw status", "sudo ufw status verbose", "Whether ufw is on, its defaults and rules."),
    entry("firewall.firewalld", Firewall, "firewalld zone", "sudo firewall-cmd --list-all", "The default zone's services, ports and rules."),
    entry("firewall.firewalld-state", Firewall, "Is firewalld running?", "sudo firewall-cmd --state", "running or not running."),
    entry("firewall.iptables", Firewall, "iptables rules", "sudo iptables -L -n -v --line-numbers", "Each chain's rules, with counters and numbers."),
    entry("firewall.nft", Firewall, "nftables rules", "sudo nft list ruleset", "The whole nftables rule set."),
    entry("firewall.ufw-allow", Firewall, "Open a port (ufw)", "sudo ufw allow {{port}}/tcp", "Allows incoming TCP connections to a port."),
    entry("firewall.firewalld-allow", Firewall, "Open a port (firewalld)", "sudo firewall-cmd --add-port={{port}}/tcp", "Allows a TCP port in the default zone until the next reload (add --permanent to keep it)."),
    // ---- Docker
    entry("docker.ps", Docker, "Running containers", "docker ps", "Containers running now, with their images, ports and names."),
    entry("docker.ps-all", Docker, "All containers", "docker ps -a", "Every container, stopped ones too."),
    entry("docker.names", Docker, "Container names and states", r"docker ps -a --format '{{.Names}}\t{{.Status}}'", "One line per container: name and status."),
    entry("docker.images", Docker, "Images", "docker images", "Images on this host and their sizes."),
    entry("docker.logs", Docker, "Container logs", "docker logs --tail {{lines:200}} {{container}}", "The last lines a container wrote."),
    entry("docker.follow", Docker, "Follow container logs", "docker logs -f --tail 50 {{container}}", "New log lines of a container as they come; Ctrl+C stops."),
    entry("docker.stats", Docker, "Resource use", "docker stats --no-stream", "CPU, memory, network and disk I/O per container, once."),
    entry("docker.inspect", Docker, "Inspect a container", "docker inspect {{container}}", "A container's full configuration and state, as JSON."),
    entry("docker.df", Docker, "Disk use", "docker system df", "Space used by images, containers, volumes and the build cache."),
    entry("docker.networks", Docker, "Networks", "docker network ls", "Docker networks and their drivers."),
    entry("docker.compose", Docker, "Compose services", "docker compose ps", "The services of the Compose project in this folder."),
    entry("docker.restart", Docker, "Restart a container", "docker restart {{container}}", "Stops and starts a container."),
    entry("docker.shell", Docker, "Shell in a container", "docker exec -it {{container}} sh", "Opens a shell inside a running container."),
    entry("docker.prune", Docker, "Remove unused data", "docker system prune", "Deletes stopped containers, unused networks, dangling images and the build cache; asks first."),
    // ---- Kubernetes
    entry("k8s.nodes", Kubernetes, "Nodes", "kubectl get nodes -o wide", "Nodes, their state, versions and addresses."),
    entry("k8s.pods", Kubernetes, "Pods", "kubectl get pods -A -o wide", "Pods in every namespace, with their nodes."),
    entry("k8s.unhealthy", Kubernetes, "Pods not running", "kubectl get pods -A --field-selector=status.phase!=Running", "Pods pending, failed or in another state than Running."),
    entry("k8s.describe", Kubernetes, "Describe a pod", "kubectl describe pod {{pod}} -n {{namespace:default}}", "A pod's containers, state, events and why it is not ready."),
    entry("k8s.logs", Kubernetes, "Pod logs", "kubectl logs {{pod}} -n {{namespace:default}} --tail={{lines:200}}", "The last lines a pod's container wrote."),
    entry("k8s.events", Kubernetes, "Recent events", "kubectl get events -A --sort-by=.lastTimestamp", "Cluster events, newest last."),
    entry("k8s.top", Kubernetes, "Resource use", "kubectl top pods -A", "CPU and memory per pod (needs metrics-server)."),
    entry("k8s.contexts", Kubernetes, "Contexts", "kubectl config get-contexts", "The clusters kubectl knows, and the current one."),
    entry("k8s.cluster", Kubernetes, "Cluster info", "kubectl cluster-info", "Addresses of the control plane and core services."),
    entry("k8s.restart", Kubernetes, "Restart a deployment", "kubectl rollout restart deployment/{{deployment}} -n {{namespace:default}}", "Replaces a deployment's pods one by one."),
    entry("k8s.delete-pod", Kubernetes, "Delete a pod", "kubectl delete pod {{pod}} -n {{namespace:default}}", "Deletes a pod; its controller starts a new one, if it has one."),
];
