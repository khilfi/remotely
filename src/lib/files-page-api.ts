// SS-14, BX-10 (0.8.0 G3): the Files page's types as the core sends them, and the IPC wrappers. The local pane names
// this PC's files by the listing the core kept and their names in it, never by a path made up here; reads (find,
// preview, checksums, compare) skip the bus; a sync to the host, a push and a fetch come back as a SubmitOutcome for
// the approval dialog, built in the core.

import {
  invoke,
  type DownloadStart,
  type EntryKind,
  type ResolvedTargets,
  type StagedFiles,
  type SubmitOutcome,
  type TargetPicks,
  type UploadStart,
} from "@/lib/api";

/** What the local pane asks to show. */
export type LocalAsk =
  | { kind: "home" }
  | { kind: "downloads" }
  | { kind: "drives" }
  | { kind: "typed"; path: string }
  | { kind: "child"; listing: string; name: string }
  | { kind: "parent"; listing: string }
  | { kind: "again"; listing: string };

export interface LocalEntry {
  name: string;
  kind: EntryKind;
  /** A link or junction: listed, never opened or uploaded from here. */
  link: boolean;
  hidden: boolean;
  size: number;
  modified: number | null;
  /** In the drives view. */
  drive?: "fixed" | "removable" | "network" | "cd" | "ram";
}

export interface LocalListing {
  id: string;
  /** null: the drives view. */
  path: string | null;
  hasParent: boolean;
  entries: LocalEntry[];
  error: string | null;
  more: boolean;
}

export interface FindRequest {
  folder: string;
  pattern: string;
  ignoreCase: boolean;
  asRoot: boolean;
}

export interface FindHit {
  path: string;
  /** The path with control and invisible characters made visible. */
  shown: string;
  kind: EntryKind | null;
  link: boolean;
  size: number | null;
  modified: number | null;
}

export interface FindResult {
  hits: FindHit[];
  more: boolean;
  timedOut: boolean;
  unreadable: number;
  pathsOnly: boolean;
  asRoot: boolean;
}

export interface FilePreview {
  path: string;
  size: number;
  /** null: binary. */
  text: string | null;
  truncated: boolean;
  notUtf8: boolean;
  marked: number;
}

export interface FileChecksum {
  path: string;
  sha256: string;
  size: number;
  by: "host" | "read";
}

export interface Bookmark {
  id: string;
  sessionId: string;
  name: string;
  path: string;
  createdAt: string;
  updatedAt: string;
}

export interface SideInfo {
  folder: boolean;
  size: number;
  modified: number | null;
}

export type Side = "here" | "there";
export type RowState = "same" | "onlyHere" | "onlyThere" | "differs" | "conflict";

export interface DiffRow {
  path: string;
  here: SideInfo | null;
  there: SideInfo | null;
  state: RowState;
  newer: Side | null;
  larger: Side | null;
  sameContent: boolean | null;
}

export interface Comparison {
  id: string;
  local: string;
  host: string;
  terminalId: string;
  asRoot: boolean;
  contents: boolean;
  rows: DiffRow[];
  counts: { same: number; onlyHere: number; onlyThere: number; differs: number; conflicts: number };
  leftOut: number;
  /** More same-size files than the comparison hashes, or more time than it takes: the rest by size and time only. */
  contentsCapped: boolean;
  contentsCompared: number;
  /** Host files too large to read for a hash, or not hashed in time: by size and time only. */
  contentsUnread: number;
}

export type SyncDirection = "toHost" | "toPc";

export type SyncStart =
  | { status: "submitted"; outcome: SubmitOutcome }
  | { status: "downloads"; start: DownloadStart }
  | { status: "nothing" };

export interface BulkFilesStart {
  resolved: ResolvedTargets;
  outcome: SubmitOutcome;
}

export type PushFrom = { kind: "staged"; id: string } | { kind: "local"; listing: string; names: string[] };
export type FetchTo = { kind: "local"; listing: string } | { kind: "choose" };

export const filesPageApi = {
  localList: (ask: LocalAsk) => invoke<LocalListing>("files_local_list", { ask }),
  localChecksum: (listing: string, name: string) => invoke<string>("files_local_checksum", { listing, name }),
  /** Stages files of a local listing and asks for their upload (conflicts are answered with `filesUpload`). */
  localUpload: (id: string, listing: string, names: string[], folder: string, asRoot: boolean) =>
    invoke<{ staged: StagedFiles; start: UploadStart }>("files_local_upload", { id, listing, names, folder, asRoot }),
  /** Downloads host files into a local listing's folder; `choice` answers a conflict question. */
  downloadHere: (
    id: string,
    paths: string[],
    listing: string,
    existing: "ask" | "replace" | "replaceIfNewer" | "skip" | "keepBoth",
    asRoot: boolean,
    choice: string | null = null,
  ) => invoke<DownloadStart>("files_download_here", { id, paths, listing, existing, asRoot, choice }),
  find: (id: string, request: FindRequest) => invoke<FindResult>("files_find", { id, request }),
  preview: (id: string, path: string, asRoot: boolean) => invoke<FilePreview>("files_preview", { id, path, asRoot }),
  checksum: (id: string, path: string, asRoot: boolean) => invoke<FileChecksum>("files_checksum", { id, path, asRoot }),
  bookmarks: (sessionId: string) => invoke<Bookmark[]>("files_bookmarks", { sessionId }),
  addBookmark: (sessionId: string, name: string, path: string) =>
    invoke<Bookmark>("files_bookmark_add", { sessionId, name, path }),
  renameBookmark: (id: string, name: string) => invoke<Bookmark>("files_bookmark_rename", { id, name }),
  removeBookmark: (id: string) => invoke<boolean>("files_bookmark_remove", { id }),
  compare: (request: { terminalId: string; listing: string; hostFolder: string; contents: boolean; asRoot: boolean }) =>
    invoke<Comparison>("files_compare", { request }),
  sync: (request: { comparison: string; direction: SyncDirection; paths: string[]; delete: boolean }) =>
    invoke<SyncStart>("files_sync", { request }),
  push: (picks: TargetPicks, from: PushFrom, folder: string, replace: boolean, trustNewHostKeys: boolean) =>
    invoke<BulkFilesStart>("files_push", { picks, from, folder, replace, trustNewHostKeys }),
  /** null: the folder dialog was closed. */
  fetch: (picks: TargetPicks, path: string, to: FetchTo, trustNewHostKeys: boolean) =>
    invoke<BulkFilesStart | null>("files_fetch", { picks, path, to, trustNewHostKeys }),
  pickPush: () => invoke<StagedFiles | null>("files_pick_push"),
};
