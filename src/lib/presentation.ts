// FD-03 presentation mode: what to show instead of IP addresses, host names, user names and the Windows user name
// in local paths while the screen is shared. Pure functions over strings (tested in presentation.test.ts); the DOM
// masker (presentation-dom.ts), the terminal panes (terminal-session.ts) and QL-07's Windows notifications use them,
// so every value on screen goes through the same rules.
//
// Two ways a value is recognised:
// - By field: values the UI gets in fields named like `host`, `username` or `ipAddress` (see `learnFields`, which the
//   IPC wrappers in api.ts call on every answer) become known values, masked wherever they appear as a whole word.
//   Elements and inputs marked `data-mask` hold one such value, masked whatever it looks like.
// - By pattern in free text: IPv4, IPv6 (compressed forms too), FQDN-like names (a known top-level domain, or three
//   labels or more, and not a file name), user@host, Windows profile paths (C:\Users\<name>) and /home/<name>.
//   MO-13: MAC addresses (`00:0c:29:ab:cd:ef` or with hyphens) too: a VM's adapters name them.
//
// Each value gets a stand-in for the app's run: `host-3`, `user-2`, `ip-5`, numbered in the order they are first
// masked. Stand-ins say nothing about the value they replace (no hashing), and the mapping lives in this module's
// memory only: never saved, logged or shown. Plain labels that don't look like a host (a session called "Customer A
// bastion") stay as they are. Loopback and "any" addresses (127.0.0.1, ::1, 0.0.0.0, localhost) say nothing about a
// customer and stay too, so a tunnel's "listening on 127.0.0.1:8080" still reads right.
//
// The terminal needs the masked text to take exactly as many cells as the real text (`TerminalMasker`), so its
// stand-ins keep the value's width: `ip-5······` for 192.0.2.10, `u2···` for alice.
//
// FD-02: workspace names may be customer names, so they are masked too (`workspace-1`): in elements marked
// `data-mask="workspace"` whatever they look like, and as a phrase anywhere else once the UI learnt them
// (`learnWorkspace`, from the workspace list; names may hold spaces). A name of fewer than three letters or a plain
// word like "Default" or "Lab" is masked only in its own field.

export type MaskKind = "host" | "ip" | "user" | "mac" | "workspace";

/** A value the masker learnt, masked from now on wherever it appears as a whole word. */
export interface Learned {
  kind: "host" | "user" | "workspace";
  value: string;
}

/** A part of a text to show differently: [start, end) in the original string, and the stand-in for it. */
export interface Replacement {
  start: number;
  end: number;
  kind: MaskKind;
  text: string;
}

/** Shown in the terminal after a short stand-in, so the masked value keeps the real one's width. */
export const PAD = "·";

/**
 * Accounts and words that name nobody in particular. They are still masked in their own field and in user@host, but
 * not as a bare word in free text, where they are mostly plain English or the same on every Linux host.
 */
const GENERIC = new Set(
  (
    "root admin administrator user users guest test tester ubuntu debian centos fedora rocky alma pi vagrant ec2-user " +
    "oracle postgres mysql git nobody daemon operator support service default local localhost localdomain server " +
    "host home data system public private demo dev prod staging lab backup web db app api www mail ftp ssh vm all " +
    "none null unknown remote shared"
  ).split(" "),
);

/** Windows profile folders that belong to nobody. */
const SHARED_PROFILES = new Set(["public", "default", "default user", "all users", "defaultapppool"]);

/** File name extensions: a name ending in one is a file, not a host (README.md, nginx.conf, web01.example.com.log). */
const FILE_EXTENSIONS = new Set(
  (
    "txt log md json yaml yml xml html htm css scss less js mjs cjs ts tsx jsx map py pyc rs go java class jar war c h " +
    "cc cpp hpp cs fs vb rb pl pm php sh bash zsh fish ps ps1 psm1 bat cmd conf cfg cnf ini toml lock env gz tgz bz2 " +
    "xz zst zip rar tar deb rpm apk msi exe dll so dylib lib out bin img iso vmdk vmx vmxf vmsd vmss vmem nvram png " +
    "jpg jpeg gif svg ico webp bmp pdf doc docx xls xlsx ppt pptx csv tsv sig asc pem crt cer key pub der p12 pfx csr " +
    "sql db sqlite sqlite3 bak tmp old orig swp service socket timer target mount properties gradle mod sum dat cache " +
    "pid sock repo list tf tfvars hcl j2 tpl tmpl erb ejs vue svelte wasm whl egg gem rst adoc tex mo po rules sum " +
    "patch diff gpg kdbx ova ovf vhd vhdx qcow2 tsbuildinfo"
  ).split(" "),
);

/**
 * Top-level domains a host name ends in: the common generic ones and suffixes used inside companies. Any two-letter
 * label that is not a file extension also counts (the country codes).
 */
const TLDS = new Set(
  (
    "com net org edu gov mil int info biz name pro mobi app dev page cloud online site tech store shop blog xyz top " +
    "club live news email host website space link click systems network solutions services company global group " +
    "local lan internal intranet intra corp home private localdomain domain test example invalid localhost arpa priv " +
    "office lab prod staging stage qa uat dmz mgmt infra consul svc cluster cloudapp azure amazonaws"
  ).split(" "),
);

const IPV4_PART = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = `${IPV4_PART}(?:\\.${IPV4_PART}){3}`;
const IPV4_RE = new RegExp(`(?<![\\w.])${IPV4}(?![\\w]|\\.\\d)`, "g");
const IPV4_EXACT = new RegExp(`^${IPV4}$`);
/** A run of hex groups and colons (at least two), maybe ending in an IPv4 address and a zone; checked by `parseIpv6`. */
const IPV6_RE = new RegExp(
  `(?<![\\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:${IPV4}|[0-9A-Fa-f]{1,4})?(?:%[\\w.-]+)?(?![\\w:])`,
  "g",
);
const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
const FQDN_RE = new RegExp(
  `(?<![\\w.@-])(?:${LABEL}\\.)+[A-Za-z][A-Za-z0-9-]{0,61}[A-Za-z0-9](?![\\w-]|\\.[A-Za-z0-9])`,
  "g",
);
/** user@host, user@1.2.3.4 or user@[2001:db8::1]. */
const USER_AT_RE = new RegExp(
  `(?<![\\w.+%-])([A-Za-z0-9_][A-Za-z0-9._+-]{0,63})@(\\[[0-9A-Fa-f:.]+(?:%[\\w.-]+)?\\]|${LABEL}(?:\\.${LABEL})*)(?![\\w-])`,
  "g",
);
/**
 * C:\Users\<name>\…, \\?\C:\Users\…, C:/Users/… and /Users/<name>. A name followed by a separator may hold spaces
 * ("Alice B"); one at the end of the path may not.
 */
const PROFILE_RE =
  /(?:\b[A-Za-z]:|(?<![\w.]))[\\/]+(?:Users|Documents and Settings)[\\/]+([^\\/:*?"<>|\r\n\t]{1,64}?(?=[\\/])|[^\s\\/:*?"<>|,;)'`]{1,64})/gi;
/** /home/<name> on a Linux host. */
const HOME_RE = /(?<![\w.~-])\/home\/([A-Za-z0-9_][A-Za-z0-9._-]{0,63})(?![\w-])/g;
const STAND_IN_RE = /^(?:host|ip|user|mac|workspace)-\d+$/;
/**
 * FD-04: a support bundle's file name, `remotely-bundle-<workspace>-<UTC time>.zip`, and 0.7.0 F6's exports',
 * `remotely-<inventory|ansible|handover>-<workspace>-<YYYY-MM-DD>.<ext>`. The workspace's name is in them as its words
 * joined by hyphens (`workspaceSlug`), which the phrase matcher can't see, so this finds it by its place.
 */
const BUNDLE_NAME_RE =
  /(?<![\p{L}\p{N}_.-])(remotely-(?:bundle|inventory|ansible|handover)-)([\p{L}\p{N}-]{1,80}?)-(?:\d{8}T\d{6}Z|\d{4}-\d{2}-\d{2}(?=\.))/gu;
/** MO-13: six hex pairs split by colons or by hyphens (not mixed). */
const MAC_RE = /(?<![\w:.-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:.-])/g;

function escapeRegExp(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The address's hex groups, expanded to eight; null when it is not an IPv6 address. */
export function parseIpv6(text: string): number[] | null {
  let s = text;
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(":") || !/\d/.test(s)) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const groups = (part: string): number[] | null => {
    if (part === "") return [];
    const out: number[] = [];
    const pieces = part.split(":");
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i] ?? "";
      if (i === pieces.length - 1 && IPV4_EXACT.test(piece)) {
        const [a, b, c, d] = piece.split(".").map(Number) as [number, number, number, number];
        out.push((a << 8) | b, (c << 8) | d);
      } else if (/^[0-9A-Fa-f]{1,4}$/.test(piece)) {
        out.push(parseInt(piece, 16));
      } else {
        return null;
      }
    }
    return out;
  };
  const head = groups(halves[0] ?? "");
  if (!head) return null;
  if (halves.length === 1) return head.length === 8 ? head : null;
  const tail = groups(halves[1] ?? "");
  if (!tail || head.length + tail.length > 7) return null;
  return [...head, ...new Array<number>(8 - head.length - tail.length).fill(0), ...tail];
}

/** The usual short form (lower case, longest run of zero groups as ::), so one address gets one stand-in. */
export function canonicalIpv6(groups: number[]): string {
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i > 1) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

/** An IPv4 or IPv6 address (brackets and a zone allowed). */
export function isIp(value: string): boolean {
  const v = value.replace(/^\[|\]$/g, "");
  return IPV4_EXACT.test(v) || parseIpv6(v) !== null;
}

/** Addresses that say nothing about anyone's network: loopback, "any", and localhost. */
export function isLocalAddress(value: string): boolean {
  const v = value
    .replace(/^\[|\]$/g, "")
    .toLowerCase()
    .replace(/\.$/, "");
  if (v === "localhost" || v === "localhost.localdomain" || v === "ip6-localhost" || v === "ip6-loopback") return true;
  // MO-14: `*` and `::` are ss's "any address" (`*:80`, `[::]:22`).
  if (v === "*" || v === "::") return true;
  if (IPV4_EXACT.test(v)) return v.startsWith("127.") || v === "0.0.0.0";
  const groups = parseIpv6(v);
  if (!groups) return false;
  const zeros = groups.slice(0, 7).every((g) => g === 0);
  return zeros && (groups[7] === 0 || groups[7] === 1);
}

/**
 * How much of a dotted name is a host name: the whole name, a leading part (web01.example.com of
 * web01.example.com.log), or nothing (index.html, app.min.js, v1.2.3).
 */
export function hostPart(name: string): string | null {
  const labels = name.split(".");
  while (labels.length > 2 && FILE_EXTENSIONS.has((labels[labels.length - 1] ?? "").toLowerCase())) labels.pop();
  if (labels.length < 2) return null;
  const last = (labels[labels.length - 1] ?? "").toLowerCase();
  if (!/^[a-z][a-z0-9-]*[a-z0-9]$/.test(last) || /\d/.test(last)) return null;
  if (FILE_EXTENSIONS.has(last)) return null;
  const host = labels.join(".");
  if (TLDS.has(last) || last.length === 2) return host;
  return labels.length >= 3 ? host : null;
}

/**
 * FD-04: a workspace's name as a support bundle's file name holds it (the core's `default_file_name`): its words
 * (letters and digits) joined by hyphens, at most 40 characters.
 */
export function workspaceSlug(name: string): string {
  const words = name.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  return Array.from(words.join("-")).slice(0, 40).join("");
}

/** A value found in a text; `value` gets its stand-in only once the candidates are chosen, so they number in order. */
type Part = { start: number; end: number; kind: MaskKind; value: string };
type Candidate = { start: number; end: number; parts: Part[] };

export class Masker {
  private readonly standIns = new Map<string, string>();
  private readonly issued = new Set<string>();
  private readonly counts: Record<MaskKind, number> = { host: 0, ip: 0, user: 0, mac: 0, workspace: 0 };
  /** Known values masked as bare words, by kind. */
  private readonly known: Record<"host" | "user" | "workspace", Set<string>> = {
    host: new Set(),
    user: new Set(),
    workspace: new Set(),
  };
  private matchers: { re: RegExp; kind: "host" | "user" | "workspace" }[] | null = null;
  private readonly listeners = new Set<(learned: Learned) => void>();

  /** Called with each new known value, so text already on screen that holds it can be masked again. */
  onChange(listener: (learned: Learned) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** A stand-in this masker handed out (so masking twice changes nothing). */
  isStandIn(text: string): boolean {
    return this.issued.has(text);
  }

  /** The stand-in for a value: the same one every time during the app's run. */
  standIn(kind: MaskKind, value: string): string {
    if (this.issued.has(value)) return value;
    const key = `${kind}:${normalize(kind, value)}`;
    let shown = this.standIns.get(key);
    if (!shown) {
      this.counts[kind] += 1;
      shown = `${kind}-${this.counts[kind]}`;
      this.standIns.set(key, shown);
      this.issued.add(shown);
    }
    return shown;
  }

  /**
   * A value the UI got in a host, IP or user field. IP addresses need no learning (the patterns find them all); the
   * rest are masked from now on wherever they appear as a whole word. Returns whether it was new.
   */
  learn(kind: MaskKind, raw: string | null | undefined): boolean {
    if (kind === "workspace") return this.learnWorkspace(raw);
    // MAC addresses need no learning either: the pattern finds them all.
    if (kind === "mac") return false;
    const value = raw?.trim().replace(/\.$/, "");
    if (!value || value.length > 253 || /\s/.test(value) || this.issued.has(value)) return false;
    if (STAND_IN_RE.test(value)) return false;
    if (kind !== "user" && (isIp(value) || isLocalAddress(value))) return false;
    const as = kind === "user" ? "user" : "host";
    if (value.length < 3 || GENERIC.has(value.toLowerCase())) return false;
    const set = this.known[as];
    const key = as === "host" ? value.toLowerCase() : value;
    if (set.has(key)) return false;
    set.add(key);
    this.matchers = null;
    const learned: Learned = { kind: as, value };
    this.listeners.forEach((l) => l(learned));
    return true;
  }

  /**
   * FD-02: a workspace's name, masked from now on wherever it appears as a phrase (any letter case). Short names and
   * plain words are left to their own fields. Returns whether it was new.
   */
  learnWorkspace(raw: string | null | undefined): boolean {
    const value = raw?.trim().replace(/\s+/g, " ");
    if (!value || value.length < 3 || value.length > 120 || this.issued.has(value)) return false;
    if (STAND_IN_RE.test(value) || GENERIC.has(value.toLowerCase())) return false;
    const key = value.toLowerCase();
    if (this.known.workspace.has(key)) return false;
    this.known.workspace.add(key);
    this.matchers = null;
    const learned: Learned = { kind: "workspace", value };
    this.listeners.forEach((l) => l(learned));
    return true;
  }

  /**
   * A whole value of one kind, whatever it looks like: a user name, or a host or IP field, which may come as
   * `user@host:port`, `host:port` or `[2001:db8::1]:22`. Text with spaces is masked like free text.
   */
  field(kind: MaskKind | "address", value: string): string {
    const trimmed = value.trim();
    if (trimmed === "" || this.issued.has(trimmed)) return value;
    // FD-02: a workspace's name is one value, spaces and all.
    if (kind === "workspace") {
      const lead = value.slice(0, value.indexOf(trimmed));
      const trail = value.slice(lead.length + trimmed.length);
      return `${lead}${this.standIn("workspace", trimmed)}${trail}`;
    }
    if (/\s/.test(trimmed)) return this.text(value);
    const lead = value.slice(0, value.indexOf(trimmed));
    const trail = value.slice(lead.length + trimmed.length);
    if (kind === "user" || kind === "mac") return `${lead}${this.standIn(kind, trimmed)}${trail}`;
    let rest = trimmed;
    let user = "";
    const at = rest.lastIndexOf("@");
    if (at > 0) {
      const name = rest.slice(0, at);
      user = `${this.issued.has(name) ? name : this.standIn("user", name)}@`;
      rest = rest.slice(at + 1);
    }
    const bracketed = /^\[([^\]]+)\](:\d+)?$/.exec(rest);
    if (bracketed) return `${lead}${user}[${this.hostValue(bracketed[1] ?? "")}]${bracketed[2] ?? ""}${trail}`;
    if (parseIpv6(rest)) return `${lead}${user}${this.hostValue(rest)}${trail}`;
    const port = /:\d+$/.exec(rest)?.[0] ?? "";
    return `${lead}${user}${this.hostValue(rest.slice(0, rest.length - port.length))}${port}${trail}`;
  }

  /** A host or IP address on its own. */
  private hostValue(host: string): string {
    if (host === "" || this.issued.has(host) || isLocalAddress(host)) return host;
    return isIp(host) ? this.standIn("ip", ipKey(host)) : this.standIn("host", host);
  }

  /** The text with every value it recognises replaced by its stand-in. */
  text(text: string): string {
    const reps = this.ranges(text);
    if (reps.length === 0) return text;
    let out = "";
    let at = 0;
    for (const r of reps) {
      out += text.slice(at, r.start) + r.text;
      at = r.end;
    }
    return out + text.slice(at);
  }

  /** What `text` replaces, in order and without overlaps. */
  ranges(text: string): Replacement[] {
    if (text.length < 3) return [];
    const found: Candidate[] = [];
    this.profiles(text, found);
    this.homes(text, found);
    this.userAtHost(text, found);
    this.macs(text, found);
    this.ipv6(text, found);
    this.ipv4(text, found);
    this.names(text, found);
    this.bundleNames(text, found);
    this.knownWords(text, found);
    if (found.length === 0) return [];
    found.sort((a, b) => a.start - b.start || b.end - a.end);
    const out: Replacement[] = [];
    let end = 0;
    for (const c of found) {
      if (c.start < end) continue;
      for (const p of c.parts)
        out.push({ start: p.start, end: p.end, kind: p.kind, text: this.standIn(p.kind, p.value) });
      end = c.end;
    }
    return out;
  }

  private profiles(text: string, found: Candidate[]) {
    for (const m of text.matchAll(PROFILE_RE)) {
      const name = m[1] ?? "";
      if (SHARED_PROFILES.has(name.toLowerCase()) || this.issued.has(name)) continue;
      const start = (m.index ?? 0) + m[0].length - name.length;
      this.learn("user", name);
      found.push({
        start: m.index ?? 0,
        end: start + name.length,
        parts: [{ start, end: start + name.length, kind: "user", value: name }],
      });
    }
  }

  private homes(text: string, found: Candidate[]) {
    for (const m of text.matchAll(HOME_RE)) {
      const name = m[1] ?? "";
      if (this.issued.has(name)) continue;
      const start = (m.index ?? 0) + m[0].length - name.length;
      found.push({
        start: m.index ?? 0,
        end: start + name.length,
        parts: [{ start, end: start + name.length, kind: "user", value: name }],
      });
    }
  }

  private userAtHost(text: string, found: Candidate[]) {
    for (const m of text.matchAll(USER_AT_RE)) {
      const user = m[1] ?? "";
      const host = m[2] ?? "";
      const at = m.index ?? 0;
      // pkg@1.2.3 is a version, not a host.
      if (/^[\d.]+$/.test(host) && !IPV4_EXACT.test(host)) continue;
      // MO-14: a systemd template unit (postgresql@16-main.service, getty@tty1.service) names a file, not a host.
      const last = host.includes(".") ? (host.split(".").pop() ?? "").toLowerCase() : "";
      if (FILE_EXTENSIONS.has(last) && !TLDS.has(last)) continue;
      const parts: Part[] = [];
      if (!this.issued.has(user)) {
        parts.push({ start: at, end: at + user.length, kind: "user", value: user });
      }
      const hostStart = at + user.length + 1;
      const bare = host.replace(/^\[|\]$/g, "");
      if (!this.issued.has(host) && !isLocalAddress(bare)) {
        if (isIp(bare)) {
          // Inside the brackets of [2001:db8::1], the brackets stay.
          const inner = host.startsWith("[") ? 1 : 0;
          parts.push({
            start: hostStart + inner,
            end: hostStart + host.length - inner,
            kind: "ip",
            value: ipKey(bare),
          });
        } else {
          parts.push({ start: hostStart, end: hostStart + host.length, kind: "host", value: host });
        }
      }
      found.push({ start: at, end: at + m[0].length, parts });
    }
  }

  private macs(text: string, found: Candidate[]) {
    for (const m of text.matchAll(MAC_RE)) {
      const start = m.index ?? 0;
      found.push({
        start,
        end: start + m[0].length,
        parts: [{ start, end: start + m[0].length, kind: "mac", value: m[0] }],
      });
    }
  }

  private ipv6(text: string, found: Candidate[]) {
    for (const m of text.matchAll(IPV6_RE)) {
      const groups = parseIpv6(m[0]);
      if (!groups || isLocalAddress(m[0])) continue;
      const start = m.index ?? 0;
      found.push({
        start,
        end: start + m[0].length,
        parts: [{ start, end: start + m[0].length, kind: "ip", value: ipKey(m[0]) }],
      });
    }
  }

  private ipv4(text: string, found: Candidate[]) {
    for (const m of text.matchAll(IPV4_RE)) {
      if (isLocalAddress(m[0])) continue;
      const start = m.index ?? 0;
      found.push({
        start,
        end: start + m[0].length,
        parts: [{ start, end: start + m[0].length, kind: "ip", value: m[0] }],
      });
    }
  }

  private names(text: string, found: Candidate[]) {
    for (const m of text.matchAll(FQDN_RE)) {
      const host = hostPart(m[0]);
      if (!host || isLocalAddress(host) || this.issued.has(host)) continue;
      const start = m.index ?? 0;
      found.push({
        start,
        end: start + host.length,
        parts: [{ start, end: start + host.length, kind: "host", value: host }],
      });
    }
  }

  /**
   * FD-04: the workspace in a support bundle's file name, whether or not the name is known yet: a known workspace's
   * name gets its own stand-in, so the file name and the top bar show the same one.
   */
  private bundleNames(text: string, found: Candidate[]) {
    for (const m of text.matchAll(BUNDLE_NAME_RE)) {
      const slug = m[2] ?? "";
      if (this.issued.has(slug)) continue;
      const known = [...this.known.workspace].find((w) => workspaceSlug(w).toLowerCase() === slug.toLowerCase());
      const at = m.index ?? 0;
      const start = at + (m[1] ?? "").length;
      found.push({
        start: at,
        end: start + slug.length,
        parts: [{ start, end: start + slug.length, kind: "workspace", value: known ?? slug }],
      });
    }
  }

  private knownWords(text: string, found: Candidate[]) {
    for (const { re, kind } of this.wordMatchers()) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        if (this.issued.has(m[0])) continue;
        const start = m.index ?? 0;
        found.push({
          start,
          end: start + m[0].length,
          parts: [{ start, end: start + m[0].length, kind, value: m[0] }],
        });
      }
    }
  }

  /**
   * One regular expression per kind and letter case: host names with a digit, dot, hyphen or underscore match in any
   * letter case (DNS ignores it); letter-only ones and user names only as written, so a host called "gateway" leaves
   * "Gateway" in a sentence alone.
   */
  private wordMatchers() {
    if (this.matchers) return this.matchers;
    const build = (values: string[], flags: string) => {
      if (values.length === 0) return null;
      const sorted = [...values].sort((a, b) => b.length - a.length).map(escapeRegExp);
      return new RegExp(`(?<![A-Za-z0-9_.-])(?:${sorted.join("|")})(?![A-Za-z0-9_-]|\\.[A-Za-z0-9])`, flags);
    };
    const hosts = [...this.known.host];
    const distinctive = hosts.filter((h) => /[\d._-]/.test(h));
    const plain = hosts.filter((h) => !/[\d._-]/.test(h));
    const out: { re: RegExp; kind: "host" | "user" | "workspace" }[] = [];
    const hostAny = build(distinctive, "gi");
    const hostExact = build(plain, "g");
    const users = build([...this.known.user], "g");
    // FD-02: workspace names in any letter case, the spaces in them matching any run of spaces.
    const workspaces = build([...this.known.workspace], "gi");
    if (workspaces) {
      out.push({ re: new RegExp(workspaces.source.replace(/ /g, "\\s+"), "gi"), kind: "workspace" });
    }
    if (hostAny) out.push({ re: hostAny, kind: "host" });
    if (hostExact) out.push({ re: hostExact, kind: "host" });
    if (users) out.push({ re: users, kind: "user" });
    this.matchers = out;
    return out;
  }
}

function ipKey(value: string): string {
  const groups = parseIpv6(value);
  return groups ? canonicalIpv6(groups) : value;
}

function normalize(kind: MaskKind, value: string): string {
  if (kind === "user") return value;
  if (kind === "ip") return ipKey(value.replace(/^\[|\]$/g, ""));
  if (kind === "mac") return value.toLowerCase().replace(/-/g, ":");
  if (kind === "workspace") return value.toLowerCase().replace(/\s+/g, " ");
  return value.toLowerCase().replace(/\.$/, "");
}

/**
 * BX-08: a command's `{{variable}}` named like a host, address or user holds one, so its input shows dots while
 * presenting (`{{host}}`, `{{target_ip}}`, `{{dbServer}}`, `{{user}}`; not `{{zip}}` or `{{service}}`).
 */
export function namesAHost(variable: string): boolean {
  const words = variable
    .replace(/([a-z\d])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/);
  return words.some((w) =>
    /^(ip|ipv4|ipv6|ips|host|hosts|hostname|fqdn|addr|address|server|domain|node|user|username|login|bastion|jump)\d*$/.test(
      w,
    ),
  );
}

/** Field names in IPC answers that hold a host, an IP address, a user, or `user@host:port`. */
const FIELD_KINDS: Record<string, MaskKind | "address"> = {
  host: "host",
  hostname: "host",
  lastHostname: "host",
  destHost: "host",
  jumpHost: "host",
  ip: "ip",
  ipAddress: "ip",
  mac: "mac",
  macAddress: "mac",
  lastIp: "ip",
  peerIp: "ip",
  guestIp: "ip",
  hostIp: "ip",
  username: "user",
  user: "user",
  address: "address",
  // FD-02: the workspace an FD-07 file was exported from.
  workspace: "workspace",
  // FD-09: the Toolbox's certificate's server name, a DNS lookup's name, and (a list) the names a certificate shows.
  serverName: "host",
  queryName: "host",
  hosts: "host",
};

/**
 * Learns the host, IP and user fields anywhere in an IPC answer or event (objects and arrays, a few levels deep), so
 * the values are masked wherever they show. Cheap enough to run on every answer.
 */
export function learnFields(masker: Masker, value: unknown, depth = 0): void {
  if (depth > 6 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) learnFields(masker, item, depth + 1);
    return;
  }
  for (const [key, field] of Object.entries(value as Record<string, unknown>)) {
    const kind = Object.prototype.hasOwnProperty.call(FIELD_KINDS, key) ? FIELD_KINDS[key] : undefined;
    if (typeof field === "string") {
      if (!kind) continue;
      if (kind === "address") learnAddress(masker, field);
      else masker.learn(kind, field);
    } else if (kind && Array.isArray(field) && field.every((item) => typeof item === "string")) {
      // A list of one kind of value (FD-09's `hosts`).
      for (const item of field as string[]) {
        if (kind === "address") learnAddress(masker, item);
        else masker.learn(kind, item);
      }
    } else if (field && typeof field === "object") {
      learnFields(masker, field, depth + 1);
    }
  }
}

/** `alice@web01.example.com:2222`, `web01:22` or `192.0.2.10`. */
export function learnAddress(masker: Masker, address: string) {
  let rest = address.trim();
  const at = rest.lastIndexOf("@");
  if (at > 0) {
    masker.learn("user", rest.slice(0, at));
    rest = rest.slice(at + 1);
  }
  const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(rest);
  if (bracket) return masker.learn("ip", bracket[1]);
  if (parseIpv6(rest)) return masker.learn("ip", rest);
  masker.learn("host", rest.replace(/:\d+$/, ""));
}

// ---- the terminal ----

/** Fits a stand-in into exactly `width` cells: padded with `PAD`, or shortened (host-12 -> h-12 -> h12). */
export function fitWidth(standIn: string, kind: MaskKind, width: number): string {
  if (width <= 0) return "";
  const n = /-(\d+)$/.exec(standIn)?.[1] ?? "";
  const short = kind === "host" ? "h" : kind === "user" ? "u" : kind === "mac" ? "m" : kind === "workspace" ? "w" : "i";
  for (const candidate of [standIn, `${short}-${n}`, `${short}${n}`]) {
    if (candidate.length <= width) return candidate + PAD.repeat(width - candidate.length);
  }
  return PAD.repeat(width);
}

/** Characters a host, address, user@host or path is made of: a word of them may still be arriving. */
const WORDISH = /[A-Za-z0-9._:%@\\/+[\]~-]/;
/** Held back at most this long (characters of text) waiting for the rest of a value. */
const MAX_HELD = 512;

type Token = { kind: "text" | "style" | "control"; raw: string };

/**
 * Splits terminal output into printable text, style changes (SGR, `ESC [ … m`, which may sit inside a value) and
 * everything else (controls and other escape sequences, which end a value). `complete` is where an escape sequence
 * that has not fully arrived starts (the end when none).
 */
function tokenize(s: string): { tokens: Token[]; complete: number } {
  const tokens: Token[] = [];
  let i = 0;
  let text = "";
  const push = (kind: Token["kind"], raw: string) => {
    if (text) tokens.push({ kind: "text", raw: text });
    text = "";
    tokens.push({ kind, raw });
  };
  while (i < s.length) {
    const c = s.charCodeAt(i);
    if (c === 0x1b) {
      const end = escapeEnd(s, i);
      if (end < 0) {
        if (text) tokens.push({ kind: "text", raw: text });
        return { tokens, complete: i };
      }
      const raw = s.slice(i, end);
      // ESC [ params m: a style change (SGR).
      push(raw[1] === "[" && /^..[0-9;:]*m$/.test(raw) ? "style" : "control", raw);
      i = end;
    } else if (c < 0x20 || c === 0x7f || (c >= 0x80 && c <= 0x9f)) {
      push("control", s[i] ?? "");
      i++;
    } else {
      text += s[i];
      i++;
    }
  }
  if (text) tokens.push({ kind: "text", raw: text });
  return { tokens, complete: s.length };
}

/** Where the escape sequence starting at `i` ends (exclusive), or -1 when it has not all arrived yet. */
function escapeEnd(s: string, i: number): number {
  const next = s[i + 1];
  if (next === undefined) return -1;
  if (next === "[") {
    for (let j = i + 2; j < s.length; j++) {
      const c = s.charCodeAt(j);
      if (c >= 0x40 && c <= 0x7e) return j + 1;
      if (c < 0x20 || c > 0x7e) return j; // malformed: ends here
    }
    return -1;
  }
  if (next === "]" || next === "P" || next === "X" || next === "^" || next === "_") {
    for (let j = i + 2; j < s.length; j++) {
      if (s[j] === "\x07" && next === "]") return j + 1;
      if (s[j] === "\x1b") {
        if (j + 1 >= s.length) return -1;
        if (s[j + 1] === "\\") return j + 2;
      }
    }
    return -1;
  }
  // ESC, intermediates (space to /), then a final byte.
  let j = i + 1;
  while (j < s.length && s.charCodeAt(j) >= 0x20 && s.charCodeAt(j) <= 0x2f) j++;
  if (j >= s.length) return -1;
  return j + 1;
}

/**
 * Masks terminal output as it arrives, for the terminal on screen only (what the host gets, and copies, saves and logs,
 * keep the real text). Stand-ins take exactly the cells of what they replace, so the screen's layout, line wraps and
 * cursor positions stay as the host drew them. A value may be split across reads and have style changes inside it;
 * the last word of a read is held back until the next read or `flush` (the pane flushes after a few milliseconds).
 */
export class TerminalMasker {
  private held = "";
  private readonly masker: Masker;

  constructor(masker: Masker) {
    this.masker = masker;
  }

  /** Some output is held back waiting for the rest of a value. */
  get holding(): boolean {
    return this.held !== "";
  }

  /** The masked text that can be shown now. */
  push(chunk: string): string {
    const s = this.held + chunk;
    const { tokens, complete } = tokenize(s);
    // The last run of text and styles may go on in the next read: hold back its last word.
    let keepFrom = complete;
    let plainHeld = 0;
    let offset = 0;
    const starts = tokens.map((t) => {
      const at = offset;
      offset += t.raw.length;
      return at;
    });
    for (let k = tokens.length - 1; k >= 0; k--) {
      const t = tokens[k] as Token;
      if (t.kind === "control") break;
      if (t.kind === "style") {
        keepFrom = starts[k] as number;
        continue;
      }
      let j = t.raw.length;
      while (j > 0 && WORDISH.test(t.raw[j - 1] ?? "")) j--;
      plainHeld += t.raw.length - j;
      if (j > 0) {
        keepFrom = (starts[k] as number) + j;
        break;
      }
      keepFrom = starts[k] as number;
    }
    // A trailing style change on its own needs nothing held.
    if (plainHeld === 0) keepFrom = complete;
    if (plainHeld > MAX_HELD) keepFrom = complete;
    this.held = s.slice(keepFrom);
    return this.maskRuns(s.slice(0, keepFrom));
  }

  /** Everything held back, masked as it is. */
  flush(): string {
    const s = this.held;
    this.held = "";
    return this.maskRuns(s);
  }

  /** Masks a whole text (a restored screen, a message of the app's own). */
  mask(text: string): string {
    return this.maskRuns(text);
  }

  private maskRuns(s: string): string {
    if (s === "") return s;
    const { tokens, complete } = tokenize(s);
    let out = "";
    let run: Token[] = [];
    const flushRun = () => {
      if (run.length > 0) out += this.maskRun(run);
      run = [];
    };
    for (const t of tokens) {
      if (t.kind === "control") {
        flushRun();
        out += t.raw;
      } else {
        run.push(t);
      }
    }
    flushRun();
    return out + s.slice(complete);
  }

  private maskRun(run: Token[]): string {
    const plain = run
      .filter((t) => t.kind === "text")
      .map((t) => t.raw)
      .join("");
    const reps = this.masker.ranges(plain);
    if (reps.length === 0) return run.map((t) => t.raw).join("");
    // Each replaced character of the plain text gets the character at the same place in the fitted stand-in.
    const shown = plain.split("");
    for (const r of reps) {
      const fitted = fitWidth(r.text, r.kind, r.end - r.start);
      for (let k = r.start; k < r.end; k++) shown[k] = fitted[k - r.start] ?? PAD;
    }
    let pos = 0;
    let out = "";
    for (const t of run) {
      if (t.kind === "style") {
        out += t.raw;
        continue;
      }
      out += shown.slice(pos, pos + t.raw.length).join("");
      pos += t.raw.length;
    }
    return out;
  }
}

/** The masker the whole UI shares while the app runs. */
export const masker = new Masker();
