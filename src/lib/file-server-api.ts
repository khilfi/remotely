// FD-09: typed wrappers over the File server tab's IPC commands in src-tauri/src/file_server.rs. Types mirror the serde
// shapes in crates/core/src/toolbox/file_server. Every answer and event goes past the presentation masker (FD-03)
// through api.ts's `invoke` and `listen`: the address a server listens on is `address`, a client's is `ip`.
//
// No path goes back to the core: a dialog's choice comes as a token (`PickedPath`), and the last choices are sent as
// `{ kind: "last" }`, which the core reads and checks again itself.

import { invoke, listen, type SubmitOutcome } from "@/lib/api";

/** The last choices in this workspace, as the core keeps them (shown only). */
export interface FileServerSpec {
  root: string;
  address: string;
  /** null: no TFTP. */
  tftpPort: number | null;
  /** null: no HTTP. */
  httpPort: number | null;
  minutes: number;
  uploads: UploadSpec | null;
}

export interface UploadSpec {
  folder: string;
  maxFileMb: number;
  maxTotalMb: number;
}

/** Where a path comes from: a dialog's pick (by its token), or this workspace's last choice. */
export type PathChoice = { kind: "picked"; token: string } | { kind: "last" };

/** What the tab sends to start a server. */
export interface FileServerRequest {
  root: PathChoice;
  address: string;
  tftpPort: number | null;
  httpPort: number | null;
  minutes: number;
  uploads: { folder: PathChoice; maxFileMb: number; maxTotalMb: number } | null;
}

/** A dialog's choice: the token to send back, and the path to show. */
export interface PickedPath {
  token: string;
  path: string;
}

export interface ServeAddress {
  address: string;
  /** The adapter's name, or "This PC only". */
  name: string;
  loopback: boolean;
}

export type RequestOutcome = "sent" | "received" | "refused" | "failed";

/** A row of the request log: one request, or repeats of it summed (`times`). */
export interface LogRow {
  firstAt: string;
  /** The last one's time. */
  at: string;
  protocol: "tftp" | "http";
  /** Empty for a row summed over clients. */
  ip: string;
  port: number;
  method: string;
  /** For a refusal row: the last path asked for. */
  path: string;
  bytes: number;
  outcome: RequestOutcome;
  detail: string;
  times: number;
}

export interface RequestCounts {
  requests: number;
  sent: number;
  received: number;
  refused: number;
  failed: number;
  bytesSent: number;
  bytesReceived: number;
  /** Refusals from clients past the 1,000 with a row, counted only. */
  refusalsUnlisted: number;
}

export interface UploadStatus {
  folder: string;
  maxFileMb: number;
  maxTotalMb: number;
  used: number;
  files: number;
}

export interface ServerStatus {
  jobId: string;
  running: boolean;
  served: string;
  folder: boolean;
  address: string;
  tftpPort: number | null;
  httpPort: number | null;
  urls: string[];
  uploads: UploadStatus | null;
  startedAt: string;
  endsAt: string;
  /** Why it stopped, once it has. */
  stopped: string | null;
  counts: RequestCounts;
  /** Transfers, repeats summed, the last changed first (at most 200 of `transferRows`; the job keeps all). */
  transfers: LogRow[];
  transferRows: number;
  /** Refused requests, folded per client, the last changed first (at most 200 of `refusalRows`). */
  refusals: LogRow[];
  refusalRows: number;
}

export interface FileServerOptions {
  addresses: ServeAddress[];
  /** The last choices in this workspace. */
  last: FileServerSpec | null;
  status: ServerStatus | null;
}

export type FileServerEvent =
  { kind: "started"; jobId: string } | { kind: "changed"; jobId: string } | { kind: "stopped"; jobId: string };

export type PickFor = "folder" | "file" | "uploads";

export const fileServerApi = {
  options: () => invoke<FileServerOptions>("file_server_options"),
  status: () => invoke<ServerStatus | null>("file_server_status"),
  /** Opens a file or folder dialog; the core keeps the choice. null: the dialog was closed. */
  pick: (purpose: PickFor) => invoke<PickedPath | null>("file_server_pick", { purpose }),
  start: (request: FileServerRequest) => invoke<SubmitOutcome>("file_server_start", { request }),
  stop: (jobId: string) => invoke<boolean>("file_server_stop", { jobId }),
  onEvent: (handler: (event: FileServerEvent) => void) =>
    listen<FileServerEvent>("fileserver://event", (e) => handler(e.payload)),
};
