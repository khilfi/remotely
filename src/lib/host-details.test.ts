/// <reference types="node" />
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  cpuLayout,
  daysSince,
  killCommand,
  latestValue,
  listensOutside,
  logsCommand,
  portAddress,
  portIp,
  restartCommand,
  specsSummary,
  summaryBytes,
  upgradeCommand,
  viaText,
  virtualizationName,
} from "./host-details.ts";
import type { CpuInfo, HostService, ListeningPort, UpdatesReport } from "./api.ts";

const GB = 1024 ** 3;

test("the dashboard's one-line summary", () => {
  assert.equal(specsSummary("vm", 4, 8 * GB, "Ubuntu 24.04"), "4 vCPU · 8 GB · Ubuntu 24.04");
  assert.equal(specsSummary("host", 8, 32 * GB, "RHEL 9.4"), "8 CPU · 32 GB · RHEL 9.4");
  assert.equal(specsSummary("host", null, 7.75 * GB, null), "8 GB");
  assert.equal(specsSummary("vm", null, null, null), "");
  assert.equal(summaryBytes(1.5 * GB), "1.5 GB");
  assert.equal(summaryBytes(3.84 * GB), "4 GB");
  assert.equal(summaryBytes(512 * 1024 ** 2), "512 MB");
  assert.equal(summaryBytes(15.6 * GB), "16 GB");
});

test("CPU layout and virtualization in words", () => {
  const cpu = (c: Partial<CpuInfo>): CpuInfo => ({
    model: null,
    vendor: null,
    logicalCpus: null,
    sockets: null,
    coresPerSocket: null,
    threadsPerCore: null,
    maxMhz: null,
    ...c,
  });
  assert.equal(
    cpuLayout(cpu({ logicalCpus: 8, sockets: 1, coresPerSocket: 4, threadsPerCore: 2 })),
    "8 logical CPUs (1 socket × 4 cores × 2 threads)",
  );
  assert.equal(cpuLayout(cpu({ logicalCpus: 2 })), "2 logical CPUs");
  assert.equal(cpuLayout(cpu({})), null);
  assert.equal(virtualizationName("oracle"), "VirtualBox");
  assert.equal(virtualizationName("none"), "None (bare metal)");
  assert.equal(virtualizationName("something-new"), "something-new");
  assert.equal(virtualizationName(null), null);
  assert.equal(viaText("terminal"), "over the open terminal's connection");
});

test("listening addresses read like ss prints them", () => {
  const port = (ip: string, p: number, iface: string | null = null): ListeningPort => ({
    protocol: "tcp",
    ip,
    port: p,
    interface: iface,
    processes: [],
    pids: [],
  });
  assert.equal(portAddress(port("0.0.0.0", 22)), "0.0.0.0:22");
  assert.equal(portAddress(port("::", 22)), "[::]:22");
  assert.equal(portAddress(port("127.0.0.53", 53, "lo")), "127.0.0.53%lo:53");
  assert.equal(portIp(port("::", 22)), "[::]");
  assert.equal(listensOutside(port("0.0.0.0", 22)), true);
  assert.equal(listensOutside(port("127.0.0.1", 5432)), false);
  assert.equal(listensOutside(port("::1", 631)), false);
});

test("commands to copy for the usual fixes, quoted where they need it", () => {
  const svc = (name: string): HostService => ({ name, description: null, state: "failed", sub: "failed" });
  assert.equal(restartCommand("systemd", svc("nginx.service")), "sudo systemctl restart nginx.service");
  assert.equal(
    restartCommand("systemd", svc("postgresql@16-main.service")),
    "sudo systemctl restart postgresql@16-main.service",
  );
  assert.equal(restartCommand("openRc", svc("sshd")), "sudo rc-service sshd restart");
  assert.equal(restartCommand("sysV", svc("odd name")), "sudo service 'odd name' restart");
  assert.equal(logsCommand("systemd", svc("nginx.service")), "sudo journalctl -u nginx.service -n 100 --no-pager");
  assert.equal(logsCommand("sysV", svc("nginx")), null);
  assert.equal(killCommand(3000), "kill 3000");
  const report = (manager: UpdatesReport["manager"]): UpdatesReport => ({
    manager,
    packages: [],
    securityCount: 0,
    listsRefreshedUnix: null,
    error: null,
  });
  assert.equal(upgradeCommand(report("apt")), "sudo apt update && sudo apt upgrade");
  assert.equal(upgradeCommand(report("dnf")), "sudo dnf upgrade");
  assert.equal(upgradeCommand(report(null)), null);
});

test("a chart legend shows the latest reading when nothing is hovered", () => {
  assert.equal(latestValue([1, 2, null]), 2);
  assert.equal(latestValue([null, null]), null);
  assert.equal(latestValue([]), null);
  assert.equal(daysSince(1_000_000, (1_000_000 + 3 * 86_400 + 5) * 1000), 3);
});
