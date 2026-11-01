// UX-04: the session editor shows the basics first (name, host, port, user, login, folder, environment) and folds the
// rest under Advanced. Folded, Advanced says in one line what is set inside it, so nothing is hidden by surprise.
// UX-12: under Environment, one line says which environment applies and where it comes from. Pure, so it is tested
// on its own (session-editor.test.ts).

import type { Environment, SessionProtocol } from "./api.ts";
import { ENVIRONMENT_NAMES, environmentText, type AppliedEnvironment } from "./session-environment.ts";

/**
 * The line under the editor's Environment: what applies and where from ("Prod · from VM db-01: actions on it move up
 * one approval tier."), what the session's own choice overrides, or what an environment does.
 */
export function environmentNote(
  applied: AppliedEnvironment,
  /** A folder's environment the session's own choice overrides. */
  overrides: { environment: Environment; folder: string } | null,
): string {
  const prod = applied.environment === "prod";
  const tier = "actions on it move up one approval tier";
  if (applied.from) return prod ? `${environmentText(applied)}: ${tier}.` : `${environmentText(applied)}.`;
  if (overrides) {
    const text = `Overrides ${ENVIRONMENT_NAMES[overrides.environment]} from folder ${overrides.folder}`;
    return prod ? `${text}; ${tier}.` : `${text}.`;
  }
  return prod ? `Prod: ${tier}.` : "Shown on its tab and rows. Prod raises the approval tier.";
}

export interface AdvancedValues {
  /** SS-12: the kind's own fields in a line ("full screen · clipboard"), for a session that is not SSH. */
  kind?: string | null;
  /** SS-12: which kind, so an empty Advanced names what it holds for that kind. */
  protocol?: SessionProtocol;
  /** The jump host that applies (chosen, or from a folder), by name. */
  jumpHost: string | null;
  /** The VM it reaches, by name. */
  vm: string | null;
  startupCommand: boolean;
  /** The prompt hook: null as in Settings. */
  promptHook: boolean | null;
  portForwards: number;
  colour: boolean;
  tags: number;
}

/** "Jump host bastion · VM db-01 · startup command · 2 port forwards · colour · 3 tags", or what Advanced holds. */
export function advancedSummary(values: AdvancedValues): string {
  const parts: string[] = [];
  if (values.kind) parts.push(values.kind);
  if (values.jumpHost) parts.push(`Jump host ${values.jumpHost}`);
  if (values.vm) parts.push(`VM ${values.vm}`);
  if (values.startupCommand) parts.push("startup command");
  if (values.promptHook !== null) parts.push(`prompt hook ${values.promptHook ? "on" : "off"}`);
  if (values.portForwards > 0)
    parts.push(`${values.portForwards} port ${values.portForwards === 1 ? "forward" : "forwards"}`);
  if (values.colour) parts.push("colour");
  if (values.tags > 0) parts.push(`${values.tags} ${values.tags === 1 ? "tag" : "tags"}`);
  if (parts.length === 0) {
    switch (values.protocol ?? "ssh") {
      case "ssh":
        return "Jump host, VM, startup command, port forwards, colour and tags";
      case "rdp":
        return "Screen, what is shared, jump host, colour and tags";
      case "vnc":
        return "View only, jump host, colour and tags";
      case "telnet":
        return "Line ending, colour and tags";
      case "serial":
        return "Line settings, colour and tags";
      case "winrm":
        return "Connection, sign-in, certificate, VM, colour and tags";
    }
  }
  const text = parts.join(" · ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
