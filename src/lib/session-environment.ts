// UX-12: the environment that applies to a session, and where it comes from when it isn't the session's own. The core
// already decides it: a session's own environment, else its folders' (QL-16, `SessionRecord.environment` with
// `inherited.environment` naming the folder), and Prod when it reaches a Prod VM (BX-01, `find_session_target`), since
// a command over SSH changes the VM as much as a VM action would. This file only says it in words, the same way in the
// session list, the tree, the terminal tabs and the editor, so a Medium approval is never a surprise. Pure, so it is
// tested on its own (session-environment.test.ts).

import type { Environment } from "./api.ts";

/** What this needs of a saved session (a `SessionRecord`). */
export interface EnvironmentOfSession {
  /** What applies from the session and its folders. */
  environment: Environment;
  inherited: { environment: { name: string } | null };
  /** The VM it reaches. */
  vmId: string | null;
}

/** What this needs of a VM (a `VmRecord`). */
export interface EnvironmentOfVm {
  id: string;
  displayName: string;
  environment: Environment;
}

/** Where an environment comes from when the session doesn't set it itself. */
export type EnvironmentSource = { kind: "folder"; name: string } | { kind: "vm"; name: string };

export interface AppliedEnvironment {
  environment: Environment;
  /** null: the session's own (or none at all). */
  from: EnvironmentSource | null;
}

export const ENVIRONMENT_NAMES: Record<Environment, string> = {
  none: "None",
  lab: "Lab",
  staging: "Staging",
  prod: "Prod",
};

/** The environment that applies to a session: its own or its folder's, raised to Prod by a Prod VM it reaches. */
export function appliedEnvironment(
  session: EnvironmentOfSession,
  vms: ReadonlyMap<string, EnvironmentOfVm>,
): AppliedEnvironment {
  const vm = session.vmId ? vms.get(session.vmId) : undefined;
  if (vm?.environment === "prod" && session.environment !== "prod") {
    return { environment: "prod", from: { kind: "vm", name: vm.displayName } };
  }
  const folder = session.inherited.environment;
  if (folder && session.environment !== "none") {
    return { environment: session.environment, from: { kind: "folder", name: folder.name } };
  }
  return { environment: session.environment, from: null };
}

/** "from VM db-01", "from folder Production"; empty for the session's own. */
export function sourceText(from: EnvironmentSource | null): string {
  if (!from) return "";
  return from.kind === "vm" ? `from VM ${from.name}` : `from folder ${from.name}`;
}

/** "Prod · from VM db-01", "Lab · from folder Dev", "Staging", or "None". */
export function environmentText(applied: AppliedEnvironment): string {
  const name = ENVIRONMENT_NAMES[applied.environment];
  return applied.from ? `${name} · ${sourceText(applied.from)}` : name;
}

/** The VMs by id, for `appliedEnvironment`. */
export function vmsById<T extends EnvironmentOfVm>(vms: readonly T[]): Map<string, T> {
  return new Map(vms.map((vm) => [vm.id, vm]));
}
