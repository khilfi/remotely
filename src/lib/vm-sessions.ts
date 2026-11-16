// QL-29: SSH sessions made from VMs. Which VMs still need one (no SSH session linked), how a draft's login and what
// it lacks read in the preview, and what saving several said. The core makes the drafts and saves them
// (`api.vmSessionDrafts`, `api.createVmSessions`). Tested in vm-sessions.test.ts.

import type { SessionAuth, SessionDraft, VmSessionDraft, VmSessionMade } from "./api.ts";

/** The parts of a saved session these helpers read. */
export interface LinkedSession {
  name: string;
  vmId: string | null;
  protocol: string;
}

/** The SSH sessions linked to the VM (automatically or by hand). */
export function linkedSshSessions<S extends LinkedSession>(vmId: string, sessions: readonly S[]): S[] {
  return sessions.filter((s) => s.vmId === vmId && s.protocol === "ssh");
}

/** The VMs that have no SSH session linked: Create SSH session goes to these. */
export function vmsWithoutSsh<V extends { id: string }>(vms: readonly V[], sessions: readonly LinkedSession[]): V[] {
  const linked = new Set(sessions.filter((s) => s.vmId !== null && s.protocol === "ssh").map((s) => s.vmId));
  return vms.filter((v) => !linked.has(v.id));
}

/** How a draft logs in, for the preview. `keyLabel` names a vault key by id. */
export function loginText(auth: SessionAuth, keyLabel: (id: string) => string | undefined): string {
  if (auth.method === "key") {
    const label = auth.keyId ? keyLabel(auth.keyId) : undefined;
    return label ? `Key '${label}'` : "A key";
  }
  if (auth.method === "password") return auth.passwordId ? "A vault password" : "Password, asked when connecting";
  if (auth.method === "agent") return "SSH agent";
  return "As its folders say";
}

/** What a draft leaves to fill in later (the terminal asks for it when it connects). */
export function draftMissing(draft: SessionDraft): string[] {
  const missing: string[] = [];
  if (!draft.username) missing.push("user");
  if (draft.auth.method === "password" && !draft.auth.passwordId) missing.push("key or password");
  return missing;
}

/** The drafts that would be saved, and the VMs that get none. */
export function splitDrafts(drafts: readonly VmSessionDraft[]): {
  saving: VmSessionDraft[];
  refused: VmSessionDraft[];
} {
  return {
    saving: drafts.filter((d) => d.session !== null),
    refused: drafts.filter((d) => d.session === null),
  };
}

/** The core's notes and reasons are sentence fragments: capitalised, with a full stop, for the UI. */
export function sentence(text: string): string {
  const trimmed = text.trim();
  if (trimmed === "") return trimmed;
  const first = trimmed[0].toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(first) ? first : `${first}.`;
}

/** The toast after saving several: how many were saved, and which VMs got none. */
export function savedSummary(made: readonly VmSessionMade[]): { title: string; failed: VmSessionMade[] } {
  const saved = made.filter((m) => m.sessionId !== null).length;
  const failed = made.filter((m) => m.sessionId === null);
  const sessions = (n: number) => `${n} SSH session${n === 1 ? "" : "s"}`;
  if (saved === 0) return { title: "No SSH session was saved", failed };
  if (failed.length === 0) return { title: `Saved ${sessions(saved)}`, failed };
  return { title: `Saved ${sessions(saved)}; ${failed.length} VM${failed.length === 1 ? "" : "s"} got none`, failed };
}
