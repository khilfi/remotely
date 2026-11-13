// VM-32 address pools: the editor's form and its checks (the core's, so the dialog says what is wrong before saving; the
// core checks again), and the Address pools tab's wording. Pure, tested in address-pools.test.ts.

import type { Hypervisor, TemplateNetwork } from "./api.ts";
import type { AddressLease, AddressPool, AddressPoolInput } from "./address-pools-api.ts";

/** The core's limits (crate::address_pools). */
export const MAX_NAME_CHARS = 60;
export const MAX_RANGE = 4096;
export const MAX_DNS = 3;
export const MAX_NOTES = 1000;
export const MIN_PREFIX = 8;
export const MAX_PREFIX = 30;
export const MAX_NETWORK_NAME = 64;
export const MAX_VMNET = 19;

export const NETWORK_KIND_LABEL: Record<TemplateNetwork["kind"], string> = {
  nat: "NAT",
  hostOnly: "Host-only",
  bridged: "Bridged",
  vmnet: "Custom vmnet",
  natNetwork: "NAT network",
  internal: "Internal network",
};

/** A dotted IPv4 address as a number, or null. Leading zeros are refused, as the core refuses them. */
export function parseIpv4(text: string): number | null {
  const parts = text.trim().split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

export function formatIpv4(value: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(value / 2 ** shift) % 256).join(".");
}

/** The subnet mask of a prefix length, as a number. */
function maskOf(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff - (2 ** (32 - prefix) - 1)) >>> 0;
}

function subnetOf(value: number, prefix: number): number {
  return (value & maskOf(prefix)) >>> 0;
}

/** Why an address can't be on a network (0.0.0.0, loopback, link-local, multicast, reserved), or null. */
function unusable(value: number): boolean {
  const first = Math.floor(value / 2 ** 24);
  const second = Math.floor(value / 2 ** 16) % 256;
  return value === 0 || first === 127 || (first === 169 && second === 254) || first >= 224;
}

type Parsed = { value: number } | { error: string };

function parseAddress(what: string, text: string): Parsed {
  const trimmed = text.trim();
  if (!trimmed) return { error: `Give the ${what}.` };
  const value = parseIpv4(trimmed);
  if (value === null) {
    if (trimmed.includes(":")) return { error: `The ${what} is an IPv6 address: address pools are IPv4 only.` };
    return { error: `The ${what} '${trimmed}' isn't an IPv4 address, such as 192.0.2.10.` };
  }
  if (unusable(value)) return { error: `The ${what} ${formatIpv4(value)} can't be used on a network.` };
  return { value };
}

/** The editor's fields as typed. */
export interface PoolForm {
  name: string;
  hypervisor: Hypervisor;
  network: TemplateNetwork;
  firstIp: string;
  lastIp: string;
  prefix: string;
  gateway: string;
  /** Three boxes; empty ones are left out. */
  dns: [string, string, string];
  notes: string;
}

export const EMPTY_POOL_FORM: PoolForm = {
  name: "",
  hypervisor: "vmware",
  network: { kind: "nat" },
  firstIp: "",
  lastIp: "",
  prefix: "24",
  gateway: "",
  dns: ["", "", ""],
  notes: "",
};

/** The form of a saved pool. */
export function poolForm(pool: AddressPoolInput): PoolForm {
  const dns = pool.dnsServers;
  return {
    name: pool.name,
    hypervisor: pool.hypervisor,
    network: pool.network,
    firstIp: pool.firstIp,
    lastIp: pool.lastIp,
    prefix: String(pool.prefix),
    gateway: pool.gateway ?? "",
    dns: [dns[0] ?? "", dns[1] ?? "", dns[2] ?? ""],
    notes: pool.notes ?? "",
  };
}

function checkNetwork(network: TemplateNetwork, hypervisor: Hypervisor): string | null {
  if (network.kind === "vmnet") {
    if (hypervisor !== "vmware") return "A custom vmnet is Workstation's; pick a network VirtualBox has.";
    if (!Number.isInteger(network.number) || network.number < 0 || network.number > MAX_VMNET)
      return `Workstation's custom networks are vmnet0 to vmnet${MAX_VMNET}.`;
  }
  if (network.kind === "natNetwork" || network.kind === "internal") {
    if (hypervisor !== "virtualbox") return "That network is VirtualBox's; pick a network Workstation has.";
    const name = network.name.trim();
    if (!name || name.length > MAX_NETWORK_NAME)
      return `A VirtualBox network's name is 1 to ${MAX_NETWORK_NAME} characters.`;
    if (!/^[A-Za-z0-9 ._-]+$/.test(name))
      return "A VirtualBox network's name can hold letters, digits, spaces, dots, hyphens and underscores.";
  }
  return null;
}

/** The input the core gets, with the range's size and what it can hand out; or the first problem. */
export function parsePoolForm(
  form: PoolForm,
  taken: readonly string[] = [],
): { input: AddressPoolInput; size: number; usable: number } | { error: string } {
  const name = form.name.trim();
  if (!name) return { error: "Give the address pool a name." };
  if ([...name].length > MAX_NAME_CHARS)
    return { error: `An address pool's name can be at most ${MAX_NAME_CHARS} characters.` };
  if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(name))
    return { error: "An address pool's name can't hold line breaks, tabs or invisible characters." };
  if (taken.some((t) => t.toLowerCase() === name.toLowerCase()))
    return { error: `There is an address pool named '${name}' already.` };
  const networkError = checkNetwork(form.network, form.hypervisor);
  if (networkError) return { error: networkError };
  const prefix = Number(form.prefix.trim().replace(/^\//, ""));
  if (!Number.isInteger(prefix) || prefix < MIN_PREFIX || prefix > MAX_PREFIX)
    return { error: `The prefix length is /${MIN_PREFIX} to /${MAX_PREFIX}.` };
  const first = parseAddress("first address", form.firstIp);
  if ("error" in first) return first;
  const last = parseAddress("last address", form.lastIp);
  if ("error" in last) return last;
  const [from, to] = [first.value, last.value];
  const [firstText, lastText] = [formatIpv4(from), formatIpv4(to)];
  if (from > to) return { error: `The first address ${firstText} comes after the last ${lastText}.` };
  const subnet = subnetOf(from, prefix);
  if (subnetOf(to, prefix) !== subnet)
    return { error: `${firstText} and ${lastText} are in different /${prefix} subnets: a pool is one subnet.` };
  const broadcast = subnet + 2 ** (32 - prefix) - 1;
  if (from === subnet)
    return {
      error: `${firstText} is the subnet's own address (${firstText}/${prefix}): start at ${formatIpv4(subnet + 1)} or later.`,
    };
  if (to === broadcast)
    return { error: `${lastText} is the subnet's broadcast address: end at ${formatIpv4(broadcast - 1)} or earlier.` };
  const size = to - from + 1;
  if (size > MAX_RANGE)
    return { error: `A pool spans at most ${MAX_RANGE} addresses; ${firstText} to ${lastText} is ${size}.` };
  let gateway: number | null = null;
  if (form.gateway.trim()) {
    const parsed = parseAddress("gateway", form.gateway);
    if ("error" in parsed) return parsed;
    if (subnetOf(parsed.value, prefix) !== subnet || parsed.value === subnet || parsed.value === broadcast)
      return {
        error: `The gateway ${formatIpv4(parsed.value)} isn't an address of ${formatIpv4(subnet)}/${prefix}, the pool's subnet.`,
      };
    gateway = parsed.value;
  }
  const dns: number[] = [];
  for (const text of form.dns.filter((d) => d.trim())) {
    const parsed = parseAddress("DNS server", text);
    if ("error" in parsed) return parsed;
    if (!dns.includes(parsed.value)) dns.push(parsed.value);
  }
  if (dns.length > MAX_DNS) return { error: `A pool gives its VMs at most ${MAX_DNS} DNS servers.` };
  const notes = form.notes.trim();
  if ([...notes].length > MAX_NOTES) return { error: `Notes can be at most ${MAX_NOTES} characters.` };
  const reserved = new Set([...(gateway === null ? [] : [gateway]), ...dns].filter((v) => v >= from && v <= to));
  const network: TemplateNetwork =
    form.network.kind === "natNetwork" || form.network.kind === "internal"
      ? { kind: form.network.kind, name: form.network.name.trim() }
      : form.network;
  return {
    input: {
      name,
      hypervisor: form.hypervisor,
      network,
      firstIp: firstText,
      lastIp: lastText,
      prefix,
      gateway: gateway === null ? null : formatIpv4(gateway),
      dnsServers: dns.map(formatIpv4),
      notes: notes || null,
    },
    size,
    usable: size - reserved.size,
  };
}

/** "3 of 41 used". */
export function usedText(pool: Pick<AddressPool, "used" | "usable">): string {
  return `${pool.used} of ${pool.usable} used`;
}

/** "41 addresses, 40 to hand out" under the editor's range. */
export function sizeText(size: number, usable: number): string {
  const all = size === 1 ? "1 address" : `${size} addresses`;
  return usable === size ? all : `${all}, ${usable} to hand out`;
}

export function leaseStateLabel(lease: Pick<AddressLease, "state">): string {
  return lease.state === "assigned" ? "The VM's" : "Being deployed";
}

/** Why Delete is off for a pool, or null. */
export function deletePoolReason(readOnly: string | null, pool: Pick<AddressPool, "used">): string | null {
  if (readOnly) return readOnly;
  if (pool.used === 0) return null;
  return pool.used === 1
    ? "A VM holds one of its addresses: delete the VM first, or free the address if the VM is gone"
    : `VMs hold ${pool.used} of its addresses: delete the VMs first, or free the addresses of VMs that are gone`;
}

/** Why "Free the address" is off for a lease, or null. */
export function freeReason(readOnly: string | null, lease: AddressLease): string | null {
  if (readOnly) return readOnly;
  if (lease.canFree) return null;
  return lease.state === "assigned"
    ? `${lease.vmName} is still on the VMs page: deleting the VM frees its address`
    : `A deploy is making ${lease.vmName} with it now`;
}
