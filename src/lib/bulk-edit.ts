// QL-28: the Sessions page's bulk edit form as a BulkEdit for the core, as pure functions (tested in bulk-edit.test.ts).
// Each field is changed only when its box is ticked; tags are added and taken off. The core checks each session as an
// edit of it and asks for the vault password once when a login would send one somewhere new.

import type { Environment, SessionAuth } from "./api.ts";
import type { BulkEdit } from "./comfort-api.ts";

/** "folder", "asked", "agent", "password:<id>" or "key:<id>". */
export type LoginChoice = string;

export interface Field<T> {
  on: boolean;
  value: T;
}

export interface BulkForm {
  /** A folder's id, or null for the top level. */
  folder: Field<string | null>;
  port: Field<string>;
  /** Empty: as their folders say. */
  user: Field<string>;
  login: Field<LoginChoice>;
  /** "folder", "direct", or a session's id. */
  jump: Field<string>;
  environment: Field<Environment>;
  tagsAdd: string;
  tagsRemove: string;
}

export function emptyBulkForm(): BulkForm {
  return {
    folder: { on: false, value: null },
    port: { on: false, value: "22" },
    user: { on: false, value: "" },
    login: { on: false, value: "folder" },
    jump: { on: false, value: "folder" },
    environment: { on: false, value: "none" },
    tagsAdd: "",
    tagsRemove: "",
  };
}

/** Tags typed with commas or spaces between them, each once. */
export function parseTags(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const tag of text.split(/[,\s]+/)) {
    const t = tag.trim();
    if (t && !seen.has(t.toLowerCase())) {
      seen.add(t.toLowerCase());
      out.push(t);
    }
  }
  return out;
}

export function loginAuth(choice: LoginChoice): SessionAuth {
  if (choice === "agent") return { method: "agent" };
  if (choice === "asked") return { method: "password", passwordId: null };
  if (choice.startsWith("password:")) return { method: "password", passwordId: choice.slice("password:".length) };
  if (choice.startsWith("key:")) return { method: "key", keyId: choice.slice("key:".length), passphraseId: null };
  return { method: "folder" };
}

/** The edit, or why the form can't make one. */
export function bulkEditFrom(form: BulkForm): { edit: BulkEdit } | { error: string } {
  const edit: BulkEdit = {};
  if (form.folder.on) edit.folder = { folderId: form.folder.value };
  if (form.port.on) {
    const port = Number(form.port.value.trim());
    if (!Number.isInteger(port) || port < 1 || port > 65535) return { error: "The port must be 1 to 65535." };
    edit.port = port;
  }
  if (form.user.on) edit.username = { username: form.user.value.trim() || null };
  if (form.login.on) edit.auth = loginAuth(form.login.value);
  if (form.jump.on) {
    edit.jump =
      form.jump.value === "folder"
        ? { kind: "folder" }
        : form.jump.value === "direct"
          ? { kind: "direct" }
          : { kind: "session", id: form.jump.value };
  }
  if (form.environment.on) edit.environment = form.environment.value;
  const add = parseTags(form.tagsAdd);
  const remove = parseTags(form.tagsRemove);
  if (add.some((a) => remove.some((r) => r.toLowerCase() === a.toLowerCase())))
    return { error: "A tag can't be added and removed at once." };
  if (add.length > 0) edit.tagsAdd = add;
  if (remove.length > 0) edit.tagsRemove = remove;
  if (Object.keys(edit).length === 0) return { error: "Tick what to change." };
  return { edit };
}
