// VM-28 install configs: the types the core sends and the IPC wrappers. Edits are the app's own data (audited, no
// approval tier, refused by the read-only lock); the check, the form and the preview only read. A config never holds a
// secret: a password is `{{password.<name>}}`, picked from the vault, and the preview masks it.

import { invoke } from "@/lib/api";

export type InstallKind = "autoinstall" | "kickstart" | "preseed" | "cloudInit" | "unattend";
export type SecretRefKind = "password" | "sshKey";

export interface VariableDef {
  name: string;
  default: string | null;
}

/** A `{{password.<name>}}` or `{{ssh_key.<name>}}` and the vault item it is, once picked. */
export interface SecretRef {
  name: string;
  kind: SecretRefKind;
  secretId: string | null;
}

export interface InstallConfigInput {
  name: string;
  kind: InstallKind;
  body: string;
  variables: VariableDef[];
  secrets: SecretRef[];
  notes: string | null;
}

export type Severity = "error" | "warning";

export interface ConfigProblem {
  severity: Severity;
  line: number | null;
  message: string;
}

export interface InstallConfig extends InstallConfigInput {
  /** A UUID, or a starter's own id. */
  id: string;
  builtIn: boolean;
  createdAt: string | null;
  updatedAt: string | null;
  problems: ConfigProblem[];
  diskNeedMb: number | null;
}

export type FormField =
  | "hostname"
  | "locale"
  | "keyboard"
  | "timezone"
  | "storage"
  | "network"
  | "users"
  | "ssh"
  | "packages"
  | "updates"
  | "proxy"
  | "mirror"
  | "lateCommands";

export type StorageLayout = "lvm" | "plain" | "custom";
export type Swap = { kind: "auto" } | { kind: "none" } | { kind: "sizeMb"; mb: number };
export type NetworkForm =
  { kind: "dhcp" } | { kind: "static"; address: string; prefix: number; gateway: string | null; dns: string[] };
export type Updates = "none" | "security" | "all";

export interface UserForm {
  name: string;
  /** `{{password.<name>}}`, or null for a locked password. */
  password: string | null;
  sshKeys: string[];
  sudo: boolean;
}

export interface InstallForm {
  hostname: string | null;
  locale: string | null;
  keyboard: string | null;
  timezone: string | null;
  storage: { layout: StorageLayout; swap: Swap } | null;
  network: NetworkForm | null;
  users: UserForm[];
  ssh: { installServer: boolean; passwordLogins: boolean } | null;
  packages: string[];
  updates: Updates | null;
  proxy: string | null;
  mirror: string | null;
  lateCommands: string[];
}

export interface FieldState {
  field: FormField;
  editable: boolean;
  note: string | null;
}

export interface FormRead {
  form: InstallForm;
  fields: FieldState[];
  maxUsers: number | null;
  /** Why the form can't read the file yet: edit the file. */
  unreadable: string | null;
}

export interface UsedPlaceholders {
  builtIns: string[];
  variables: string[];
  passwords: string[];
  sshKeys: string[];
}

export interface ConfigCheck {
  problems: ConfigProblem[];
  form: FormRead;
  used: UsedPlaceholders;
  diskNeedMb: number | null;
}

/** The VM a preview renders for; the rest takes samples. */
export interface PreviewVm {
  hostname?: string | null;
  ip?: string | null;
  n?: number | null;
  template?: string | null;
  values?: Record<string, string>;
}

export const installConfigsApi = {
  list: () => invoke<InstallConfig[]>("install_configs"),
  check: (input: InstallConfigInput, sizeId: string | null) =>
    invoke<ConfigCheck>("install_config_check", { input, sizeId }),
  applyForm: (kind: InstallKind, body: string, form: InstallForm) =>
    invoke<string>("install_config_apply_form", { kind, body, form }),
  preview: (input: InstallConfigInput, vm: PreviewVm) => invoke<string>("install_config_preview", { input, vm }),
  add: (input: InstallConfigInput) => invoke<InstallConfig>("install_config_add", { input }),
  update: (id: string, input: InstallConfigInput) => invoke<InstallConfig>("install_config_update", { id, input }),
  remove: (id: string) => invoke<void>("install_config_delete", { id }),
};
