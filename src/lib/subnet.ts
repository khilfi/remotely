// FD-09: the Toolbox's subnet calculator, all in the window (nothing is sent anywhere). IPv4 and IPv6: a CIDR (or an
// IPv4 address and mask) to its network, mask, wildcard, broadcast, first and last host and counts, and a split into
// smaller subnets. IPv6 addresses are written as RFC 5952 says (lower case, the longest run of zeros as "::").
// Tested in subnet.test.ts.

export interface SubnetInfo {
  family: 4 | 6;
  /** The network as CIDR: "192.0.2.0/24". */
  cidr: string;
  /** The address as typed (written out again). */
  address: string;
  prefix: number;
  network: string;
  /** IPv4 only: "255.255.255.0". */
  mask: string | null;
  /** IPv4 only: "0.0.0.255". */
  wildcard: string | null;
  /** IPv4 only, and not for /31 and /32 (RFC 3021: their addresses are all hosts). */
  broadcast: string | null;
  /** IPv4: the first usable host; IPv6: the first address. */
  first: string;
  last: string;
  /** Addresses in the subnet. */
  addresses: bigint;
  /** IPv4: usable hosts (the network and broadcast left out, but for /31 and /32); IPv6: every address. */
  hosts: bigint;
}

export type SubnetResult = { ok: true; info: SubnetInfo } | { ok: false; error: string };

const V4_BITS = 32;
const V6_BITS = 128;

function bits(family: 4 | 6): number {
  return family === 4 ? V4_BITS : V6_BITS;
}

function all(family: 4 | 6): bigint {
  return (1n << BigInt(bits(family))) - 1n;
}

/** A dotted IPv4 address as a number, or null. */
export function parseV4(text: string): bigint | null {
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    // A leading zero is read as octal by some tools: refuse it rather than guess.
    if (part.length > 1 && part.startsWith("0")) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

export function formatV4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => String((value >> shift) & 255n)).join(".");
}

/** An IPv6 address (with "::", an IPv4 tail, or a zone after "%") as a number, or null. */
export function parseV6(input: string): bigint | null {
  let text = input.trim().toLowerCase();
  if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
  const zone = text.indexOf("%");
  if (zone >= 0) text = text.slice(0, zone);
  if (!text.includes(":")) return null;
  let tail: number[] = [];
  const lastColon = text.lastIndexOf(":");
  const after = text.slice(lastColon + 1);
  if (after.includes(".")) {
    const v4 = parseV4(after);
    if (v4 === null) return null;
    tail = [Number((v4 >> 16n) & 0xffffn), Number(v4 & 0xffffn)];
    text = text.slice(0, lastColon + 1) + "0:0";
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string): string[] | null => {
    if (part === "") return [];
    const list = part.split(":");
    return list.every((g) => /^[0-9a-f]{1,4}$/.test(g)) ? list : null;
  };
  const head = groups(halves[0]);
  const rest = halves.length === 2 ? groups(halves[1]) : [];
  if (head === null || rest === null) return null;
  let words: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    words = [...head, ...Array<string>(missing).fill("0"), ...rest];
  } else {
    words = head;
  }
  if (words.length !== 8) return null;
  let numbers = words.map((w) => parseInt(w, 16));
  if (tail.length === 2) numbers = [...numbers.slice(0, 6), ...tail];
  return numbers.reduce((acc, n) => (acc << 16n) | BigInt(n), 0n);
}

/** RFC 5952: lower case, no leading zeros, the longest run of two or more zero groups (the first, on a tie) as "::". */
export function formatV6(value: bigint): string {
  const words: number[] = [];
  for (let i = 7; i >= 0; i--) words.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  let best = -1;
  let bestLength = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLength && j - i >= 2) {
      best = i;
      bestLength = j - i;
    }
    i = j;
  }
  const hex = words.map((w) => w.toString(16));
  if (best < 0) return hex.join(":");
  const head = hex.slice(0, best).join(":");
  const tail = hex.slice(best + bestLength).join(":");
  return `${head}::${tail}`;
}

function format(family: 4 | 6, value: bigint): string {
  return family === 4 ? formatV4(value) : formatV6(value);
}

function maskOf(family: 4 | 6, prefix: number): bigint {
  const width = bits(family);
  return prefix === 0 ? 0n : (all(family) >> BigInt(width - prefix)) << BigInt(width - prefix);
}

/** The prefix length of a contiguous IPv4 mask ("255.255.255.0" is 24), or null. */
export function prefixOfMask(mask: string): number | null {
  const value = parseV4(mask);
  if (value === null) return null;
  for (let prefix = 0; prefix <= V4_BITS; prefix++) {
    if (maskOf(4, prefix) === value) return prefix;
  }
  return null;
}

/** Reads "192.0.2.10/24", "192.0.2.10 255.255.255.0", "192.0.2.10/255.255.255.0", "2001:db8::/48" or an address alone (/32, /128). */
export function calculate(input: string): SubnetResult {
  const text = input.trim();
  if (!text) return { ok: false, error: "Type an address with its prefix, like 192.0.2.0/24." };
  const [addressText, prefixText, ...extra] = text.split(/\s*\/\s*|\s+/);
  if (extra.length > 0) return { ok: false, error: `"${text}" isn't an address and a prefix.` };
  const v4 = parseV4(addressText);
  const v6 = v4 === null ? parseV6(addressText) : null;
  if (v4 === null && v6 === null) return { ok: false, error: `"${addressText}" isn't an IPv4 or IPv6 address.` };
  const family: 4 | 6 = v4 !== null ? 4 : 6;
  const value = (v4 ?? v6) as bigint;
  let prefix: number;
  if (prefixText === undefined || prefixText === "") {
    prefix = bits(family);
  } else if (/^\d{1,3}$/.test(prefixText)) {
    prefix = Number(prefixText);
    if (prefix > bits(family)) {
      return { ok: false, error: `An IPv${family} prefix is 0 to ${bits(family)}.` };
    }
  } else if (family === 4 && prefixText.includes(".")) {
    const fromMask = prefixOfMask(prefixText);
    if (fromMask === null) return { ok: false, error: `"${prefixText}" isn't a subnet mask.` };
    prefix = fromMask;
  } else {
    return { ok: false, error: `"${prefixText}" isn't a prefix length.` };
  }
  return { ok: true, info: describe(family, value, prefix) };
}

function describe(family: 4 | 6, value: bigint, prefix: number): SubnetInfo {
  const width = bits(family);
  const mask = maskOf(family, prefix);
  const network = value & mask;
  const last = network | (all(family) ^ mask);
  const addresses = 1n << BigInt(width - prefix);
  let first = network;
  let lastHost = last;
  let hosts = addresses;
  let broadcast: string | null = null;
  if (family === 4 && prefix <= 30) {
    first = network + 1n;
    lastHost = last - 1n;
    hosts = addresses - 2n;
    broadcast = formatV4(last);
  }
  return {
    family,
    cidr: `${format(family, network)}/${prefix}`,
    address: format(family, value),
    prefix,
    network: format(family, network),
    mask: family === 4 ? formatV4(mask) : null,
    wildcard: family === 4 ? formatV4(all(4) ^ mask) : null,
    broadcast,
    first: format(family, first),
    last: format(family, lastHost),
    addresses,
    hosts,
  };
}

/** The most subnets a split lists; the count is still given in full. */
export const MAX_SPLIT_LISTED = 256;

export type SplitResult =
  { ok: true; total: bigint; subnets: string[]; listedAll: boolean } | { ok: false; error: string };

/** The subnet split into subnets of `prefix` (longer than its own), the first MAX_SPLIT_LISTED of them listed. */
export function split(info: SubnetInfo, prefix: number): SplitResult {
  const width = bits(info.family);
  if (!Number.isInteger(prefix) || prefix <= info.prefix || prefix > width) {
    return { ok: false, error: `Choose a prefix from ${info.prefix + 1} to ${width}.` };
  }
  const network = (info.family === 4 ? parseV4(info.network) : parseV6(info.network)) as bigint;
  const total = 1n << BigInt(prefix - info.prefix);
  const step = 1n << BigInt(width - prefix);
  const subnets: string[] = [];
  for (let i = 0n; i < total && subnets.length < MAX_SPLIT_LISTED; i++) {
    subnets.push(`${format(info.family, network + i * step)}/${prefix}`);
  }
  return { ok: true, total, subnets, listedAll: BigInt(subnets.length) === total };
}

/** A count with thousands separators, or as a power of two once it is too long to read ("2^64"). */
export function countText(count: bigint): string {
  if (count < 10n ** 15n) return count.toLocaleString("en-US");
  let power = 0;
  let rest = count;
  while (rest > 1n && rest % 2n === 0n) {
    rest /= 2n;
    power++;
  }
  return rest === 1n ? `2^${power}` : count.toString();
}
