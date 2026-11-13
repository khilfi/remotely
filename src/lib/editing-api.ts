// SS-14, SS-08 (0.8.0 G4): typed wrappers over the editing IPC in src-tauri/src/editing.rs. Types mirror the serde shapes
// in crates/core/src/terminal/editor.rs and edit_local.rs. Like api.ts, every answer and event goes past the presentation
// masker (FD-03).

import { Channel } from "@tauri-apps/api/core";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { eventChannel, invoke, listen, type Settings, type SubmitOutcome, type TerminalEvent } from "@/lib/api";

/** SS-14: the editors a terminal's host has, and the session's choice. */
export interface HostEditors {
  /** Of nano, micro, vim, vi, nvim, emacs, mcedit, joe, ne: those the host has. */
  found: string[];
  /** The session's own choice; null: the first of nano, micro, vim, vi the host has. */
  chosen: string | null;
  /** What a double-click opens now; null: the host has none. */
  uses: string | null;
  /** The saved session the choice belongs to; null for a quick connection. */
  sessionId: string | null;
}

export type EditEnd =
  | "stopped"
  | "timeLimit"
  | "cancelled"
  | "vaultLocked"
  | "workspaceSwitched"
  | "appClosing"
  | "terminalClosed"
  | "rootEnded";

export type EditState =
  | { state: "watching" }
  | { state: "uploading" }
  | { state: "conflict"; message: string }
  | { state: "failed"; message: string }
  | { state: "ended"; reason: EditEnd; message: string };

/** SS-08: an editing session on this PC. */
export interface EditInfo {
  /** The session's job. */
  id: string;
  terminalId: string;
  /** The terminal's name. */
  name: string;
  path: string;
  asRoot: boolean;
  /** "VS Code", "Notepad++"... */
  editor: string;
  state: EditState;
  saves: number;
  note: string | null;
  startedAt: string;
  endsAt: string;
}

/** SS-08: the answer to a save held because the host's copy changed. */
export type EditAnswer = "overwrite" | "saveBeside" | "compare" | "keepEditing";

export const editingApi = {
  hostEditors: (terminalId: string) => invoke<HostEditors>("files_host_editors", { id: terminalId }),
  /** The session's own editor; null: the first the host has. Audited. */
  setHostEditor: (sessionId: string, editor: string | null) =>
    invoke<void>("files_set_host_editor", { sessionId, editor }),
  /** A command on the bus: queued (Low), or the approval dialog; the tab opens with `attach` once its job is queued. */
  openInEditor: (terminalId: string, path: string, asRoot: boolean, editor: string | null = null) =>
    invoke<SubmitOutcome>("files_open_in_editor", { id: terminalId, path, asRoot, editor }),
  /** The editor job's tab, once its job ran. */
  attach: (
    jobId: string,
    cols: number,
    rows: number,
    onOutput: (data: Uint8Array) => void,
    onEvent: (event: TerminalEvent) => void,
  ) => {
    const output = new Channel<ArrayBuffer>();
    output.onmessage = (data) => onOutput(new Uint8Array(data));
    return invoke<string>("terminal_editor_attach", {
      jobId,
      cols,
      rows,
      onOutput: output,
      onEvent: eventChannel(onEvent),
    });
  },
  /** A command on the bus, approved once for the editing session. */
  editOnPc: (terminalId: string, path: string, asRoot: boolean) =>
    invoke<SubmitOutcome>("files_edit_on_pc", { id: terminalId, path, asRoot }),
  edits: () => invoke<EditInfo[]>("files_edits"),
  stop: (id: string) => invoke<void>("files_edit_stop", { id }),
  /** null: try a failed upload again. */
  answer: (id: string, answer: EditAnswer | null) => invoke<void>("files_edit_answer", { id, answer }),
  onEdit: (handler: (edit: EditInfo) => void): Promise<UnlistenFn> =>
    listen<EditInfo>("files://edit", (e) => handler(e.payload)),
  /** Settings › Tools: the editor for files from hosts; null finds one. */
  setLocalEditorPath: (path: string | null) => invoke<Settings>("settings_set_local_editor_path", { path }),
};
