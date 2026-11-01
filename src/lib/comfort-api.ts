// 0.7.0 F5: notes (FD-06), stars and recents (QL-26), the trash (QL-27) and bulk session edit (QL-28): the types the
// core sends and the IPC wrappers. Notes, the trash and bulk edit are audited by the core and refused by the read-only
// lock; stars and recents are neither (like the notification centre).

import { invoke, type Environment, type SessionAuth } from "@/lib/api";

// ---- Notes --------------------------------------------------------------------------------------------------------

export type NoteKind = "session" | "vm" | "folder";

/** A session or folder by its id, a VM by its key (.vmx path or VirtualBox UUID). */
export interface NoteTarget {
  kind: NoteKind;
  key: string;
}

export interface Note {
  kind: NoteKind;
  key: string;
  /** What it is about: the session's, VM's or folder's name. */
  title: string;
  body: string;
  /** Included in the handover pack. */
  handover: boolean;
  createdAt: string;
  updatedAt: string;
  /** The text holds something that looks like a secret. */
  looksSecret: boolean;
}

export interface NoteInput {
  body: string;
  handover: boolean;
}

/** What a link in a note points at; the HTML carries `data-note-link="N"` for links[N]. */
export type NoteLink =
  | { kind: "web"; url: string }
  | { kind: "session"; name: string; id: string | null }
  | { kind: "vm"; name: string; key: string | null }
  | { kind: "vault"; name: string; found: boolean }
  | { kind: "command"; name: string; found: boolean }
  | { kind: "runbook"; name: string; found: boolean }
  | { kind: "refused"; target: string };

export interface RenderedNote {
  /** Made by the core: raw HTML in a note shows as text, images as text, links carry no address. */
  html: string;
  links: NoteLink[];
  /** Each `data-note-code="N"` block's text. */
  codeBlocks: string[];
  looksSecret: boolean;
}

// ---- Stars and recents ------------------------------------------------------------------------------------------

export type StarKind = "session" | "vm" | "command";
export type RecentKind = "session" | "vm" | "page";

export interface Star {
  kind: StarKind;
  /** A session's id, a VM's key, or a command's `favourite:<id>` / `library:<id>`. */
  key: string;
  createdAt: string;
}

export interface Recent {
  kind: RecentKind;
  key: string;
  openedAt: string;
}

// ---- Trash --------------------------------------------------------------------------------------------------------

export type TrashKind = "session" | "command" | "size" | "image" | "template" | "stack";

export interface TrashEntry {
  id: string;
  kind: TrashKind;
  itemId: string;
  name: string;
  /** Where it was ("Sessions › Customer A"). */
  place: string;
  /** What came along ("2 port forwards, its note"). */
  detail: string;
  deletedAt: string;
  expiresAt: string;
}

export interface RestoreReport {
  kind: TrashKind;
  itemId: string;
  name: string;
  /** What was left out or changed, in words. */
  notes: string[];
}

// ---- Bulk edit ----------------------------------------------------------------------------------------------------

export type JumpChoice = { kind: "folder" } | { kind: "direct" } | { kind: "session"; id: string };

/** A field left out stays as each session has it; tags are added and taken off. */
export interface BulkEdit {
  folder?: { folderId: string | null };
  port?: number;
  /** username null: as their folders say. */
  username?: { username: string | null };
  auth?: SessionAuth;
  jump?: JumpChoice;
  /** "none": no label of their own. */
  environment?: Environment;
  tagsAdd?: string[];
  tagsRemove?: string[];
}

export interface FieldChange {
  field: string;
  before: string;
  after: string;
}

export interface BulkEditRow {
  id: string;
  name: string;
  changes: FieldChange[];
}

export interface BulkEditPreview {
  rows: BulkEditRow[];
  changed: number;
}

export const comfortApi = {
  note: (target: NoteTarget) => invoke<Note | null>("note_get", { target }),
  saveNote: (target: NoteTarget, input: NoteInput) => invoke<Note | null>("note_save", { target, input }),
  setNoteHandover: (target: NoteTarget, handover: boolean) => invoke<Note>("note_set_handover", { target, handover }),
  notes: () => invoke<Note[]>("notes_list"),
  renderNote: (body: string) => invoke<RenderedNote>("note_render", { body }),
  /** Only after a confirm that showed the address; the core opens only http(s). */
  openNoteLink: (url: string) => invoke<void>("note_open_link", { url }),

  stars: () => invoke<Star[]>("stars_list"),
  setStar: (kind: StarKind, key: string, starred: boolean) => invoke<Star[]>("stars_set", { kind, key, starred }),
  recents: () => invoke<Recent[]>("recents_list"),
  opened: (kind: RecentKind, key: string) => invoke<Recent[]>("recents_opened", { kind, key }),

  trash: () => invoke<TrashEntry[]>("trash_list"),
  /** SS-04, AP-06: `reauth_required` when a restored session would send a vault password somewhere new. */
  restoreTrash: (id: string, vaultPassword?: string) =>
    invoke<RestoreReport>("trash_restore", { id, vaultPassword: vaultPassword ?? null }),
  /** A delete's Undo: the newest trash entry of that item. */
  undoDelete: (kind: TrashKind, itemId: string, vaultPassword?: string) =>
    invoke<RestoreReport>("trash_undo", { kind, itemId, vaultPassword: vaultPassword ?? null }),
  deleteTrash: (id: string) => invoke<void>("trash_delete", { id }),
  emptyTrash: () => invoke<number>("trash_empty"),

  bulkPreview: (ids: string[], edit: BulkEdit) => invoke<BulkEditPreview>("sessions_bulk_preview", { ids, edit }),
  /** SS-04, AP-06: `reauth_required` when the edit would send a vault password somewhere new. */
  bulkEdit: (ids: string[], edit: BulkEdit, vaultPassword?: string) =>
    invoke<BulkEditPreview>("sessions_bulk_edit", { ids, edit, vaultPassword: vaultPassword ?? null }),
};
