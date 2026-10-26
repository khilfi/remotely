// FD-02 and AP-08 IPC wrappers (src-tauri/src/workspaces.rs): the top bar's workspace switcher and its dialogs, the
// VMs page's Unassigned view, the change ID rule and FD-07's import into a new workspace. Kept apart from api.ts, as
// the other packages' wrappers are.
//
// Workspace names may be customer names: every answer that holds one teaches the FD-03 masker (`learnWorkspace`), so
// presentation mode masks them wherever they show.

import {
  invoke,
  type Hypervisor,
  type PowerState,
  type TransferCommit,
  type TransferReport,
  type VmRecord,
} from "@/lib/api";
import { masker } from "@/lib/presentation";
import type { WorkspaceColor } from "@/lib/workspaces";

/** FD-02: a workspace as the core shows it (crates/core/src/workspaces.rs). */
export interface Workspace {
  id: string;
  name: string;
  color: WorkspaceColor;
  archived: boolean;
  archivedAt: string | null;
  createdAt: string;
  /** The workspace shown now. */
  current: boolean;
}

export interface WorkspaceInput {
  name: string;
  color?: WorkspaceColor;
}

/** What switching to a workspace would close; `openJobs` above 0 refuses it. */
export interface SwitchPreview {
  to: Workspace;
  openJobs: number;
  terminals: number;
  multiexec: boolean;
  approvals: number;
}

/** A VM on this PC that no workspace has (crates/core/src/inventory.rs). */
export interface UnassignedVm {
  vmxPath: string;
  hypervisor: Hypervisor;
  configPath: string | null;
  displayName: string;
  guestOs: string | null;
  powerState: PowerState;
}

/** AP-08: the workspace's change ID rule. */
export interface ChangeIdRules {
  requiredForProd: boolean;
}

export interface NewWorkspaceImport {
  workspace: Workspace;
  report: TransferReport;
}

function learnt<T extends Workspace | Workspace[]>(answer: T): T {
  for (const w of Array.isArray(answer) ? answer : [answer]) masker.learnWorkspace(w.name);
  return answer;
}

export const workspacesApi = {
  list: () => invoke<Workspace[]>("workspaces_list").then(learnt),
  current: () => invoke<Workspace>("workspace_current").then(learnt),
  create: (input: WorkspaceInput) => invoke<Workspace>("workspace_create", { input }).then(learnt),
  rename: (id: string, name: string) => invoke<Workspace>("workspace_rename", { id, name }).then(learnt),
  setColor: (id: string, color: WorkspaceColor) => invoke<Workspace>("workspace_set_color", { id, color }).then(learnt),
  archive: (id: string) => invoke<Workspace>("workspace_archive", { id }).then(learnt),
  restore: (id: string) => invoke<Workspace>("workspace_restore", { id }).then(learnt),
  switchPreview: (id: string) =>
    invoke<SwitchPreview>("workspace_switch_preview", { id }).then((p) => {
      learnt(p.to);
      return p;
    }),
  /** The UI loads again after it, so nothing the old workspace showed stays in memory. */
  switchTo: (id: string) => invoke<Workspace>("workspace_switch", { id }).then(learnt),
  unassignedVms: () => invoke<UnassignedVm[]>("vm_unassigned"),
  claimVms: (vmxPaths: string[]) => invoke<VmRecord[]>("vm_claim", { vmxPaths }),
  releaseVms: (vmxPaths: string[]) => invoke<VmRecord[]>("vm_release", { vmxPaths }),
  changeIdRules: () => invoke<ChangeIdRules>("change_id_rules"),
  setChangeIdRules: (rules: ChangeIdRules) => invoke<ChangeIdRules>("change_id_rules_set", { rules }),
  importIntoNew: (workspace: WorkspaceInput, request: TransferCommit) =>
    invoke<NewWorkspaceImport>("transfer_commit_new_workspace", { workspace, request }).then((r) => {
      learnt(r.workspace);
      return r;
    }),
};
