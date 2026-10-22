// MO-13, MO-14, MO-15: pure helpers for the host details views (tested in host-details.test.ts): the one-line
// summaries, CPU and virtualization wording, where a read ran, the commands the Admin tab offers to copy (never
// run from Remotely), and the latest value of a chart series for its legend.

import type {
  CollectedBy,
  CpuInfo,
  HostService,
  ListeningPort,
  ReadVia,
  ServiceManager,
  UpdatesReport,
} from "@/lib/api";

/** Binary units like Windows shows them, rounded for a one-line summary: 8 GB, 1.5 GB, 512 MB. */
export function summaryBytes(bytes: number): string {
  const gb = bytes / 1024 ** 3;
  if (gb >= 10) return `${Math.round(gb)} GB`;
  if (gb >= 1)
    return `${Number.isInteger(Math.round(gb * 2) / 2) ? Math.round(gb) : (Math.round(gb * 2) / 2).toFixed(1)} GB`;
  return `${Math.round(bytes / 1024 ** 2)} MB`;
}

/** "4 vCPU · 8 GB · Ubuntu 24.04" (a VM), "8 CPU · 32 GB · RHEL 9.4" (a host); empty when nothing is known. */
export function specsSummary(
  kind: "vm" | "host",
  cpus: number | null,
  memoryBytes: number | null,
  os: string | null,
): string {
  return [cpus ? `${cpus} ${kind === "vm" ? "vCPU" : "CPU"}` : null, memoryBytes ? summaryBytes(memoryBytes) : null, os]
    .filter(Boolean)
    .join(" · ");
}

/** "2 sockets × 2 cores × 1 thread" when the layout is known; the logical CPUs otherwise. */
export function cpuLayout(cpu: CpuInfo): string | null {
  const parts: string[] = [];
  const n = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;
  if (cpu.sockets) parts.push(n(cpu.sockets, "socket"));
  if (cpu.coresPerSocket) parts.push(n(cpu.coresPerSocket, "core"));
  if (cpu.threadsPerCore) parts.push(n(cpu.threadsPerCore, "thread"));
  const logical = cpu.logicalCpus ? n(cpu.logicalCpus, "logical CPU") : null;
  if (parts.length === 0) return logical;
  return logical ? `${logical} (${parts.join(" × ")})` : parts.join(" × ");
}

/** systemd-detect-virt's names, as people say them. */
const VIRT: Record<string, string> = {
  none: "None (bare metal)",
  vmware: "VMware",
  oracle: "VirtualBox",
  kvm: "KVM",
  qemu: "QEMU",
  microsoft: "Hyper-V",
  xen: "Xen",
  amazon: "AWS (Nitro)",
  docker: "Docker container",
  podman: "Podman container",
  lxc: "LXC container",
  "lxc-libvirt": "LXC container",
  wsl: "WSL",
  openvz: "OpenVZ",
  parallels: "Parallels",
  bhyve: "bhyve",
};

export function virtualizationName(value: string | null): string | null {
  if (!value) return null;
  return VIRT[value.toLowerCase()] ?? value;
}

/** Where a read ran, as a short clause. */
export function viaText(via: ReadVia): string {
  switch (via) {
    case "terminal":
      return "over the open terminal's connection";
    case "dashboard":
      return "over the dashboard's connection";
    case "ownConnection":
      return "over a connection Remotely keeps for a few minutes";
  }
}

/** What read stored facts. */
export function collectedByText(by: CollectedBy): string {
  switch (by) {
    case "terminal":
      return "when a terminal connected";
    case "dashboard":
      return "by the dashboard";
    case "refresh":
      return "on Refresh";
  }
}

/** The address part of a listener: `0.0.0.0`, `[::]` (IPv6 in brackets), `*`. */
export function portIp(port: ListeningPort): string {
  return port.ip.includes(":") ? `[${port.ip}]` : port.ip;
}

/** `0.0.0.0:22`, `[::]:22`, `127.0.0.53%lo:53`. */
export function portAddress(port: ListeningPort): string {
  return `${portIp(port)}${port.interface ? `%${port.interface}` : ""}:${port.port}`;
}

/** Listens beyond this machine (not loopback only). */
export function listensOutside(port: ListeningPort): boolean {
  const ip = port.ip.toLowerCase();
  return !(ip.startsWith("127.") || ip === "::1" || ip === "localhost");
}

/** Shell-quotes a word only when it needs it. */
function word(text: string): string {
  return /^[\w@%+=:,./-]+$/.test(text) ? text : `'${text.replace(/'/g, `'\\''`)}'`;
}

/** The usual fix for a failed or stuck service: copied, never run by Remotely. */
export function restartCommand(manager: ServiceManager, service: HostService): string {
  switch (manager) {
    case "openRc":
      return `sudo rc-service ${word(service.name)} restart`;
    case "sysV":
      return `sudo service ${word(service.name)} restart`;
    default:
      return `sudo systemctl restart ${word(service.name)}`;
  }
}

/** Where to look first: the service's recent log. */
export function logsCommand(manager: ServiceManager, service: HostService): string | null {
  if (manager === "systemd" || manager === "unknown") {
    return `sudo journalctl -u ${word(service.name)} -n 100 --no-pager`;
  }
  return null;
}

export function killCommand(pid: number): string {
  return `kill ${pid}`;
}

/** Installs what is pending: copied, never run by Remotely. */
export function upgradeCommand(report: UpdatesReport): string | null {
  switch (report.manager) {
    case "apt":
      return "sudo apt update && sudo apt upgrade";
    case "dnf":
      return "sudo dnf upgrade";
    default:
      return null;
  }
}

/** The last value that is not empty, for a chart's legend when nothing is hovered. */
export function latestValue(values: (number | null)[]): number | null {
  for (let i = values.length - 1; i >= 0; i--) {
    const v = values[i];
    if (v !== null && v !== undefined) return v;
  }
  return null;
}

/** Days since a Unix time, for "apt's lists were refreshed 3 days ago". */
export function daysSince(unixSecs: number, nowMs: number = Date.now()): number {
  return Math.max(0, Math.floor((nowMs / 1000 - unixSecs) / 86_400));
}
