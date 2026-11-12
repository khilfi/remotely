// VM-28 install configs in the window, as pure functions (tested in install-configs.test.ts): each kind's name and
// what it is for, a blank file per kind, copy names, the vault picks and variables a file needs, problem summaries,
// and which configs fit a launch template's image.

import type {
  ConfigProblem,
  InstallConfig,
  InstallConfigInput,
  InstallKind,
  SecretRef,
  SecretRefKind,
  UsedPlaceholders,
  VariableDef,
} from "./install-configs-api.ts";

export const KIND_ORDER: InstallKind[] = ["autoinstall", "kickstart", "preseed", "unattend", "cloudInit"];

export const KIND_LABEL: Record<InstallKind, string> = {
  autoinstall: "Ubuntu autoinstall",
  kickstart: "Kickstart",
  preseed: "Debian preseed",
  cloudInit: "cloud-init user data",
  unattend: "Windows unattend",
};

/** What each kind installs, in a line. */
export const KIND_HINT: Record<InstallKind, string> = {
  autoinstall: "Ubuntu Server from its ISO.",
  kickstart: "RHEL, Rocky, Alma, Oracle Linux, Fedora or CentOS Stream from their ISO.",
  preseed: "Debian from its ISO.",
  cloudInit: "A cloud image's first boot: users, keys and packages.",
  unattend: "Windows Server from its ISO, with WinRM over HTTPS turned on.",
};

export const MAX_CONFIG_NAME = 60;

/** A file to start a blank config from: the least each installer reads without stopping. */
export const BLANK_BODY: Record<InstallKind, string> = {
  autoinstall: [
    "#cloud-config",
    "autoinstall:",
    "  version: 1",
    "  identity:",
    '    hostname: "{{hostname}}"',
    "    username: sysadmin",
    '    password: "{{password.admin}}"',
    "  ssh:",
    "    install-server: true",
    "",
  ].join("\n"),
  kickstart: [
    "text",
    "lang en_US.UTF-8",
    "timezone Etc/UTC --utc",
    'network --bootproto=dhcp --device=link --activate --hostname="{{hostname}}"',
    "rootpw --lock",
    'user --name=sysadmin --groups=wheel --iscrypted --password="{{password.admin}}"',
    "autopart --type=lvm",
    "reboot",
    "",
  ].join("\n"),
  preseed: [
    "d-i debian-installer/locale string en_US.UTF-8",
    "d-i netcfg/get_hostname string {{hostname}}",
    "d-i passwd/root-login boolean false",
    "d-i passwd/username string sysadmin",
    "d-i passwd/user-password-crypted password {{password.admin}}",
    "d-i pkgsel/include string openssh-server",
    "d-i finish-install/reboot_in_progress note",
    "",
  ].join("\n"),
  cloudInit: ["#cloud-config", 'hostname: "{{hostname}}"', "users:", "  - name: sysadmin", ""].join("\n"),
  unattend: [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<unattend xmlns="urn:schemas-microsoft-com:unattend">',
    '  <settings pass="specialize">',
    '    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64">',
    "      <ComputerName>{{hostname}}</ComputerName>",
    "    </component>",
    "  </settings>",
    "</unattend>",
    "",
  ].join("\n"),
};

export function blankConfig(kind: InstallKind): InstallConfigInput {
  return { name: "", kind, body: BLANK_BODY[kind], variables: [], secrets: [], notes: null };
}

/** A copy of a config (a starter's, say) to edit, under a name not taken. */
export function copyOf(config: InstallConfig, taken: string[]): InstallConfigInput {
  return {
    name: copyName(config.name, taken),
    kind: config.kind,
    body: config.body,
    variables: config.variables.map((v) => ({ ...v })),
    secrets: config.secrets.map((s) => ({ ...s, secretId: config.builtIn ? null : s.secretId })),
    notes: config.notes,
  };
}

/** "Name (copy)", "Name (copy 2)"... within the length a name may have. */
export function copyName(name: string, taken: string[]): string {
  const lower = new Set(taken.map((t) => t.toLowerCase()));
  for (let n = 1; n < 1000; n++) {
    const suffix = n === 1 ? " (copy)" : ` (copy ${n})`;
    const candidate = `${name.slice(0, MAX_CONFIG_NAME - suffix.length)}${suffix}`;
    if (!lower.has(candidate.toLowerCase())) return candidate;
  }
  return name;
}

/** A reference's name from free text, such as a user's name: lower case letters, digits and `_`. */
export function refSlug(text: string): string {
  const slug = text
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^[^a-z]+/, "")
    .replace(/_+$/, "")
    .slice(0, 32);
  return slug || "admin";
}

export function placeholder(kind: SecretRefKind, name: string): string {
  return kind === "password" ? `{{password.${name}}}` : `{{ssh_key.${name}}}`;
}

/** The name in `{{password.<name>}}` or `{{ssh_key.<name>}}`, when the text is one. */
export function refOf(text: string | null | undefined, kind: SecretRefKind): string | null {
  const prefix = kind === "password" ? "password." : "ssh_key.";
  const m = /^\{\{\s*([a-z_.0-9]+)\s*\}\}$/.exec((text ?? "").trim());
  if (!m || !m[1].startsWith(prefix)) return null;
  return m[1].slice(prefix.length) || null;
}

/** Every reference the file uses, with its pick if made; unused picks follow, so nothing picked is lost. */
export function syncSecrets(used: UsedPlaceholders, secrets: SecretRef[]): (SecretRef & { used: boolean })[] {
  const out: (SecretRef & { used: boolean })[] = [];
  const add = (kind: SecretRefKind, name: string) => {
    const pick = secrets.find((s) => s.kind === kind && s.name === name);
    out.push({ name, kind, secretId: pick?.secretId ?? null, used: true });
  };
  used.passwords.forEach((n) => add("password", n));
  used.sshKeys.forEach((n) => add("sshKey", n));
  for (const s of secrets) {
    if (!out.some((o) => o.kind === s.kind && o.name === s.name)) out.push({ ...s, used: false });
  }
  return out;
}

/** The file's own variables: those declared, then those the file uses without a declaration (to add). */
export function missingVariables(used: UsedPlaceholders, variables: VariableDef[]): string[] {
  return used.variables.filter((name) => !variables.some((v) => v.name === name));
}

export function errorsOf(problems: ConfigProblem[]): ConfigProblem[] {
  return problems.filter((p) => p.severity === "error");
}

/** "2 errors · 1 warning", or "No problems". */
export function problemSummary(problems: ConfigProblem[]): string {
  const errors = errorsOf(problems).length;
  const warnings = problems.length - errors;
  const parts = [
    errors ? `${errors} error${errors === 1 ? "" : "s"}` : null,
    warnings ? `${warnings} warning${warnings === 1 ? "" : "s"}` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" · ") : "No problems";
}

/** Why a config can't deploy, for its badge's tooltip; null when it can. */
export function configReason(config: Pick<InstallConfig, "problems">): string | null {
  const first = errorsOf(config.problems)[0];
  if (!first) return null;
  return first.line ? `Line ${first.line}: ${first.message}` : first.message;
}

/** A disk layout's need, such as "41 GB". */
export function diskText(mb: number | null): string | null {
  if (mb === null) return null;
  return `${Math.ceil(mb / 1024)} GB`;
}

/** Words a list field takes, split on commas, spaces and new lines. */
export function parseWords(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((w) => w.trim())
    .filter(Boolean);
}

/** One command a line; blank lines dropped at the end only. */
export function parseLines(text: string): string[] {
  const lines = text.split("\n");
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
  return lines;
}

/** Whether an own config can go with a template's image: its kind installs from that image, for that OS family. */
export function fitsImage(
  config: Pick<InstallConfig, "kind" | "builtIn">,
  image: { kind: string; family: string | undefined },
): boolean {
  if (config.builtIn) return false;
  const fromIso = config.kind !== "cloudInit";
  if (fromIso !== (image.kind === "iso")) return false;
  if (image.family === undefined) return true;
  return (config.kind === "unattend") === (image.family === "windows");
}

/** The line a character offset of the file is on, from 1. */
export function lineAt(text: string, offset: number): number {
  return text.slice(0, offset).split("\n").length;
}

/** The character offsets a line (from 1) starts and ends at. */
export function lineRange(text: string, line: number): [number, number] {
  let start = 0;
  for (let i = 1; i < line; i++) {
    const next = text.indexOf("\n", start);
    if (next < 0) return [text.length, text.length];
    start = next + 1;
  }
  const end = text.indexOf("\n", start);
  return [start, end < 0 ? text.length : end];
}
