// FD-09: typed wrappers over the File server tab's IPC commands in src-tauri/src/file_server.rs. Types mirror the serde
// shapes in crates/core/src/toolbox/file_server. Every answer and event goes past the presentation masker (FD-03)
// through api.ts's `invoke` and `listen`: the address a server listens on is `address`, a client's is `ip`.

import { invoke, listen, type SubmitOutcome } from "@/lib/api";

/** What the server serves, where and for how long (the core checks it against this PC before it starts). */
export interface FileServerSpec {
  /** The file or folder served, as a dialog chose it. */
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

export interface ServeAddress {
  address: string;
  /** The adapter's name, or "This PC only". */
  name: string;
  loopback: boolean;
}

export type RequestOutcome = "sent" | "received" | "refused" | "failed";

export interface RequestEntry {
  at: string;
  protocol: "tftp" | "http";
  ip: string;
  port: number;
  method: string;
  path: string;
  bytes: number;
  outcome: RequestOutcome;
  detail: string;
}

export interface RequestCounts {
  requests: number;
  sent: number;
  received: number;
  refused: number;
  failed: number;
  bytesSent: number;
  bytesReceived: number;
  dropped: number;
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
  /** The last requests, newest first. */
  requests: RequestEntry[];
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
  /** Opens a file or folder dialog. null: it was closed. */
  pick: (purpose: PickFor, current: string | null) => invoke<string | null>("file_server_pick", { purpose, current }),
  start: (spec: FileServerSpec) => invoke<SubmitOutcome>("file_server_start", { spec }),
  stop: (jobId: string) => invoke<boolean>("file_server_stop", { jobId }),
  onEvent: (handler: (event: FileServerEvent) => void) =>
    listen<FileServerEvent>("fileserver://event", (e) => handler(e.payload)),
};
