// The Virtual machines page (QL-14: VMs and their snapshots on one page). The VM list (VM-01) with selection by
// click, shift-click, tag, saved filter or snapshots, and bulk power actions (VM-02, VM-03), protect and unprotect
// (AP-04), environment labels (SS-06) and bulk snapshot actions (VM-04) on the selection. Listing asks the core to read
// Workstation's library, the chosen folders and `vmrun list`, and VirtualBox's registered VMs (VM-18); every action is
// a command submitted to the command bus, never a vmrun or VBoxManage call. Tags and labels are the app's own data, so
// they skip the bus.
//
// A click on a VM's name opens its details beside the list (VmDetailsPanel): what the inventory knows, and its
// snapshot tree with take, revert and delete. Trees are read from the .vmsd (no vmrun call) only for the VM whose
// details are open, the selection when its Snapshots menu opens, and the shown VMs when the Select menu picks by
// snapshots, so the page stays fast with many VMs. They are read again after a job finishes, a setting changes or
// Refresh.
//
// VM-01, P2: the list is refreshed (every VM read again: vmrun, VBoxManage) only while the page shows. A finished VM job
// or a settings change while another page shows marks it stale, and it refreshes once when it shows again; the core
// also runs one refresh at a time and joins requests that come meanwhile.
//
// Each running VM shows its share of this host's CPU and RAM (MO-01), read from the metrics collector's latest
// 5-second round in memory, while the page shows and the window is visible: no extra polling. The sessions linked to
// each VM (QL-01, made automatically by IP address) show in their own column, where they can be kept, changed or
// removed. Columns sort by a click on their header.
//
// VM-18: each VM's hypervisor (VMware or VirtualBox) has its own column after Name and a filter in VmFilterBar (the
// `hypervisors` field of VmFilter, matched by the core like the others); VmDetailsPanel shows its own facts. A
// VirtualBox VM's key is its UUID, so the line under its name shows its .vbox file.

import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type MouseEvent, type ReactNode } from "react";
import {
  CameraIcon,
  ChevronDownIcon,
  Columns3Icon,
  CopyIcon,
  CpuIcon,
  EllipsisIcon,
  FilePlusIcon,
  FlagIcon,
  FolderPlusIcon,
  FolderSearchIcon,
  FileSpreadsheetIcon,
  InfoIcon,
  MonitorOffIcon,
  NetworkIcon,
  PauseIcon,
  PlayIcon,
  PlusIcon,
  PowerIcon,
  RecycleIcon,
  RocketIcon,
  RotateCcwIcon,
  ImportIcon,
  PackageIcon,
  ShieldIcon,
  ShieldOffIcon,
  SquareIcon,
  TagIcon,
  Trash2Icon,
  TriangleAlertIcon,
  Undo2Icon,
  UsersIcon,
  WrenchIcon,
  XIcon,
} from "lucide-react";
import { usePanelRef } from "react-resizable-panels";
import { toast } from "sonner";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { StarButton } from "@/components/StarButton";
import { isStarred, starredFirst } from "@/lib/stars";
import { noteOpened, useStars } from "@/lib/stars-store";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, HypervisorLabel, StateBadge } from "@/components/Badges";
import { EmptyState } from "@/components/EmptyState";
import { SelectionBar } from "@/components/SelectionBar";
import { Tip } from "@/components/Tip";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HostDetailsSheet } from "@/components/HostDetailsSheet";
import { HostNetworksSheet } from "@/components/HostNetworksSheet";
import { WasteFinderSheet } from "@/components/WasteFinderSheet";
import { MetricCell } from "@/components/MetricBits";
import { NameDialog } from "@/components/NameDialog";
import { SnapshotActionDialog, type SnapshotAction } from "@/components/SnapshotActionDialog";
import { SortableHead } from "@/components/SortableHead";
import { StackGroupRow } from "@/components/StackGroupRow";
import { VmDetailsPanel } from "@/components/VmDetailsPanel";
import type { ScheduleAsk } from "@/components/VmSchedulesTab";
import { ResourcesDialog } from "@/components/VmSettingsDialogs";
import { isEmptyFilter, VmFilterBar } from "@/components/VmFilterBar";
import { VmSessionLinks } from "@/components/VmLinkControls";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorCode,
  errorMessage,
  type AutoLinkReport,
  type Command,
  type DroppedFiles,
  type Environment,
  type InventoryWarning,
  type PowerOp,
  type PowerState,
  type SavedFilter,
  type SessionRecord,
  type SnapshotLimits,
  type SnapshotNode,
  type SubmitOutcome,
  type Tag,
  type VmFilter,
  type VmHostUsage,
  type VmRecord,
  type VmSnapshots,
} from "@/lib/api";
import { useVisibility } from "@/hooks/use-poll";
import { CloneDialog } from "@/components/CloneDialog";
import { PageHeader } from "@/components/PageHeader";
import { RefreshButton } from "@/components/RefreshButton";
import { plural } from "@/lib/format";
import { hypervisorName, vmLocation } from "@/lib/hypervisors";
import { refreshDue } from "@/lib/job-events";
import { compareNullsLast, formatPct, HOST_SHARE_HINT, useThresholds } from "@/lib/metrics";
import { shouldPoll } from "@/lib/polling";
import { groupByInstance } from "@/lib/stacks";
import { stacksApi, type StackInstance } from "@/lib/stacks-api";
import { cn } from "@/lib/utils";
import {
  bulkSnapshotReasons,
  noMatchText,
  PROTECTED_REASON,
  snapshotArg,
  vmsMatching,
  type SnapshotMatch,
  type VmView,
} from "@/lib/vm-snapshots";
import { resizeTargets } from "@/lib/vm-settings";
import {
  moreGroups,
  parseColumns,
  powerTargets,
  selectionPowerReason,
  serialiseColumns,
  stateDetail,
  visibleColumns,
  VM_COLUMNS,
  type MoreItemId,
  type VmColumnId,
} from "@/lib/vm-page";
import { UnassignedVmsSheet } from "@/components/UnassignedVmsSheet";
import { noVmsHere, releaseReason } from "@/lib/workspaces";
import { workspacesApi, type UnassignedVm } from "@/lib/workspaces-api";

/** VM-11, VM-16: the side sheets the page opens. */
export type VmPanel = "networks" | "waste";

/** QL-14: a VM to show from elsewhere (the palette, a shortcut, an old Snapshots link). `n` counts the requests. */
export interface VmPageRequest {
  /** The VMs to show; none: the snapshot view of the open or first selected VM. */
  vmxPaths: string[];
  view: VmView;
  n: number;
  /** VM-24: open the Settings tab's rename dialog too (the palette's Rename). */
  rename?: boolean;
  /** VM-11, VM-16: open the host networks or the waste finder instead of a VM. */
  panel?: VmPanel;
}

interface Props {
  /** True while the page is shown: the host shares (MO-01) follow the metrics rounds, and refreshes run, only then. */
  active: boolean;
  /** Shows the approval dialog for commands the policy engine says need one; `onJob` gets the job once queued. */
  onSubmitted: (outcome: SubmitOutcome, onJob?: (jobId: string) => void) => void;
  /** VM-21: opens the Deploy dialog. */
  onDeploy: () => void;
  /** CV-01: opens the Import dialog. */
  onImport?: () => void;
  /** VM-17, CV-02: opens the Export dialog on a VM. */
  onExport?: (vmxPath: string) => void;
  /** FD-05: the inventory to Excel. */
  onExportInventory?: () => void;
  onOpenSettings: () => void;
  /** FD-01: the command palette on one VM's actions. */
  onActions: (vmxPath: string) => void;
  request: VmPageRequest | null;
  /** Changes when the list should be read again: a VM job finished or a setting about where VMs are found changed. */
  refreshKey: number;
  /** VM-14, VM-27: the Schedules page, from a VM's Schedules tab. */
  onSchedules?: (ask: ScheduleAsk) => void;
}

interface Action {
  label: string;
  op: PowerOp;
  /** States the action makes sense in. VMs in other states are left out of the command. */
  appliesTo: PowerState[];
}

const ON: PowerState[] = ["running", "paused"];
const STARTABLE: PowerState[] = ["not_running", "suspended"];

/** UX-02: the power actions of the selection bar and its More menu, by the menu's item id. */
const POWER: Partial<Record<MoreItemId, Action & { icon: typeof PlayIcon }>> = {
  startGui: {
    label: "Start with a console window",
    op: { kind: "start", gui: true },
    appliesTo: STARTABLE,
    icon: PlayIcon,
  },
  suspend: { label: "Suspend", op: { kind: "suspend" }, appliesTo: ["running"], icon: PauseIcon },
  restart: { label: "Restart", op: { kind: "reset", mode: "soft" }, appliesTo: ON, icon: RotateCcwIcon },
  pause: { label: "Pause", op: { kind: "pause" }, appliesTo: ["running"], icon: PauseIcon },
  unpause: { label: "Unpause", op: { kind: "unpause" }, appliesTo: ["paused"], icon: PlayIcon },
  powerOff: { label: "Power off", op: { kind: "stop", mode: "hard" }, appliesTo: ON, icon: PowerIcon },
};

/** UX-02: the column picker's choice, kept in this window's local storage (a per-user convenience). */
const COLUMNS_KEY = "remotely.vms.columns";

function readColumns(): Set<VmColumnId> {
  try {
    return parseColumns(localStorage.getItem(COLUMNS_KEY));
  } catch {
    return parseColumns(null);
  }
}

function storeColumns(shown: Set<VmColumnId>) {
  try {
    localStorage.setItem(COLUMNS_KEY, serialiseColumns(shown));
  } catch {
    // Not remembered: the choice holds until the window closes.
  }
}

/** SS-06 labels, in the order the Label menu lists them. */
const LABELS: { value: Environment; label: string }[] = [
  { value: "none", label: "None" },
  { value: "lab", label: "Lab" },
  { value: "staging", label: "Staging" },
  { value: "prod", label: "Prod" },
];

type LoadError = { code?: string; message: string };
type SortKey = "name" | "hypervisor" | "vcpus" | "ram" | "state" | "hostCpu" | "hostMem" | "label";

/** Running first, then the states a VM passes through on its way down. */
const STATE_ORDER: PowerState[] = ["running", "paused", "suspended", "not_running", "unknown"];
const LABEL_ORDER: Environment[] = ["prod", "staging", "lab", "none"];

/** The details panel's width when it first opens, as a share of the page. */
const DETAILS_WIDTH = 40;
/** The divider between the list and the details; the library focuses it while the user drags it. */
const DIVIDER_ID = "vms-details-divider";

function sortValue(vm: VmRecord, key: SortKey, usage: VmHostUsage | undefined): number | string | null {
  switch (key) {
    case "name":
      return vm.displayName.toLowerCase();
    case "hypervisor":
      return hypervisorName(vm.hypervisor).toLowerCase();
    case "vcpus":
      return vm.numVcpus;
    case "ram":
      return vm.memsizeMb;
    case "state":
      return STATE_ORDER.indexOf(vm.powerState);
    case "hostCpu":
      return usage?.hostCpuPct ?? null;
    case "hostMem":
      return usage?.hostMemPct ?? null;
    case "label":
      return LABEL_ORDER.indexOf(vm.environment);
  }
}

/** QL-01: what a refresh linked by IP address, in one line. */
function linkNews(links: AutoLinkReport): string | null {
  const parts: string[] = [];
  if (links.linked.length > 0) {
    const names = links.linked.map((l) => `${l.sessionName} → ${l.vmName}`).join(", ");
    parts.push(`Linked ${plural(links.linked.length, "session")} to VMs by IP address: ${names}.`);
  }
  if (links.unlinked.length > 0) {
    const names = links.unlinked.map((l) => `${l.sessionName} (${l.vmName})`).join(", ");
    parts.push(`Unlinked ${plural(links.unlinked.length, "session")} whose VM has another address now: ${names}.`);
  }
  return parts.length > 0 ? parts.join(" ") : null;
}

type Dialog =
  | { kind: "addTag" }
  | { kind: "saveFilter" }
  /** Taking the Prod label off VMs lowers the tier of later actions on them, so it asks first. */
  | { kind: "lowerProd"; vmxPaths: string[]; environment: Environment; prodNames: string[] }
  /** VM-04: selects the shown VMs that have a snapshot with this name. */
  | { kind: "snapshotName" }
  /** VM-10: clones these VMs (the selection's that are off), or one picked in the dialog when there are none. */
  | { kind: "clone"; vms: VmRecord[] }
  /** VM-12: CPU and memory of the selected VMs that are off, one approval. */
  | { kind: "resize" }
  | null;

function formatRam(mb: number | null) {
  if (!mb) return "—";
  return mb % 1024 === 0 ? `${mb / 1024} GB` : `${(mb / 1024).toFixed(1)} GB`;
}

function labelName(env: Environment) {
  return LABELS.find((l) => l.value === env)?.label ?? env;
}

/** What the confirm says before Prod VMs lose the label (the "?" says what Prod does). */
function lowerProdText(prodNames: string[], environment: Environment) {
  const shown = prodNames.slice(0, 5).join(", ") + (prodNames.length > 5 ? ", …" : "");
  const who = prodNames.length === 1 ? prodNames[0] : `${prodNames.length} VMs (${shown})`;
  const change =
    environment === "none" ? "will no longer be Prod" : `will be ${labelName(environment)} instead of Prod`;
  const them = prodNames.length === 1 ? "it" : "them";
  return `${who} ${change}: actions on ${them} will need fewer approval steps.`;
}

/** .vmx paths are matched without regard to case, as Windows does. */
const keyOf = (vmxPath: string) => vmxPath.toLowerCase();

/** One column of the VM list. */
interface Column {
  id: "name" | VmColumnId;
  head: ReactNode;
  cell: (vm: VmRecord) => ReactNode;
  className?: string;
  /** The cell has its own controls: a click there doesn't select the row. */
  ownClicks?: boolean;
}

export function VmsPage({
  active,
  onSubmitted,
  onDeploy,
  onImport,
  onExport,
  onExportInventory,
  onOpenSettings,
  onActions,
  request,
  refreshKey,
  onSchedules,
}: Props) {
  // FD-03: power actions, snapshots, protection, tags and labels are off while the read-only lock applies (the core
  // refuses them too); the page's notice says so.
  const readOnly = useReadOnlyReason();
  const [listed, setListed] = useState<VmRecord[]>([]);
  // The filter `listed` was read for, so a deep link can wait for the list it asked for.
  const [listedFor, setListedFor] = useState<VmFilter | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [usage, setUsage] = useState<Map<string, VmHostUsage>>(new Map());
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [linksVersion, setLinksVersion] = useState(0);
  const [thresholds] = useThresholds();
  /** MO-13, MO-14: a linked session's host details, opened from a VM's System tab. */
  const [hostDetails, setHostDetails] = useState<{ id: string; name: string } | null>(null);
  const [total, setTotal] = useState({ vms: 0, running: 0 });
  const [warnings, setWarnings] = useState<InventoryWarning[]>([]);
  const [error, setError] = useState<LoadError | null>(null);
  const [filter, setFilter] = useState<VmFilter>({});
  const [tags, setTags] = useState<Tag[]>([]);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [refreshes, setRefreshes] = useState(0);
  // FD-02: VMs on this PC no workspace has (the last refresh's), and how many workspaces are active.
  const [unassigned, setUnassigned] = useState<UnassignedVm[]>([]);
  const [unassignedOpen, setUnassignedOpen] = useState(false);
  const [activeWorkspaces, setActiveWorkspaces] = useState(1);
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  // Bumped after a refresh or a change to tags, so the list is read again from the store.
  const [listVersion, setListVersion] = useState(0);
  const key = `${refreshes}:${refreshKey}`;
  const loading = loadedKey !== key;

  // QL-14: the VM whose details are open, and the tab they open on (kept when another VM opens).
  const [detail, setDetail] = useState<string | null>(null);
  const [view, setView] = useState<VmView>("details");
  // VM-11, VM-16: the host networks or the waste finder sheet.
  const [panel, setPanel] = useState<VmPanel | null>(null);
  // VM-04: snapshot trees read so far, by .vmx path. A refresh, a finished job or a setting change starts afresh.
  const [trees, setTrees] = useState<{ key: string; map: Map<string, VmSnapshots> }>({ key, map: new Map() });
  if (trees.key !== key) setTrees({ key, map: new Map() });
  const [treeError, setTreeError] = useState<{ key: string; vmxPath: string; message: string } | null>(null);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [limits, setLimits] = useState<SnapshotLimits | null>(null);
  const [snapshotDialog, setSnapshotDialog] = useState<SnapshotAction | null>(null);
  // VM-08: the stack instances on this PC, read with the list.
  const [instances, setInstances] = useState<StackInstance[]>([]);
  // UX-02: the columns the picker shows.
  const [shownColumnIds, setShownColumnIds] = useState<Set<VmColumnId>>(readColumns);
  function toggleColumn(id: VmColumnId) {
    setShownColumnIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      storeColumns(next);
      return next;
    });
  }

  useEffect(() => {
    if (!active) return;
    let stale = false;
    stacksApi.instances().then(
      (all) => !stale && setInstances(all),
      () => !stale && setInstances([]),
    );
    return () => {
      stale = true;
    };
  }, [active, key, listVersion]);

  useEffect(() => {
    api.snapshotLimits().then(setLimits, () => setLimits(null));
  }, []);

  // Finds every VM when the page first shows, on Refresh, after a VM job finishes and after a setting changes; a key
  // that moved while the page was hidden refreshes once when it shows (refreshDue). A refresh still out when the page
  // is hidden lands all the same; one for a key that moved on since is dropped.
  const latestKey = useRef(key);
  const refreshedFor = useRef<string | null>(null);
  useEffect(() => {
    latestKey.current = key;
    if (!refreshDue(active, key, refreshedFor.current)) return;
    refreshedFor.current = key;
    const stale = () => latestKey.current !== key;
    api.vmRefresh().then(
      (report) => {
        if (stale()) return;
        const news = linkNews(report.links);
        if (news) toast.info(news, { id: "vm-links" });
        setWarnings(report.warnings);
        setUnassigned(report.unassigned);
        workspacesApi.list().then(
          (all) => setActiveWorkspaces(all.filter((w) => !w.archived).length),
          () => {},
        );
        setTotal({
          vms: report.vms.length,
          running: report.vms.filter((v) => ON.includes(v.powerState)).length,
        });
        setError(null);
        setLoadedKey(key);
        setListVersion((v) => v + 1);
      },
      (err) => {
        if (stale()) return;
        setError({ code: errorCode(err), message: errorMessage(err) });
        setLoadedKey(key);
      },
    );
  }, [key, active]);

  // The shown list: what the last refresh saved, narrowed by the filter in the core (VM-02).
  useEffect(() => {
    let stale = false;
    Promise.all([api.vmList(filter), api.tags(), api.savedFilters()]).then(
      ([list, allTags, filters]) => {
        if (stale) return;
        setListed(list);
        setListedFor(filter);
        // Tags are shared with sessions (SS-01); this page offers the ones on VMs.
        setTags(allTags.filter((t) => t.vmCount > 0));
        setSavedFilters(filters);
        // Actions only reach VMs the user can see, and details only show for one of them.
        const shown = new Set(list.map((v) => v.vmxPath));
        setSelected((prev) => new Set([...prev].filter((p) => shown.has(p))));
        setDetail((open) => (open && shown.has(open) ? open : null));
      },
      (err) => {
        if (!stale) setError({ code: errorCode(err), message: errorMessage(err) });
      },
    );
    return () => {
      stale = true;
    };
  }, [filter, listVersion]);

  // QL-01: the sessions linked to each VM, read again when the page shows (they may have changed on
  // the Sessions page), after a refresh (it may link some) and after a change here.
  useEffect(() => {
    if (!active) return;
    let stale = false;
    api.sessions().then(
      (list) => {
        if (!stale) setSessions(list);
      },
      () => {
        if (!stale) setSessions([]);
      },
    );
    return () => {
      stale = true;
    };
  }, [active, listVersion, linksVersion]);
  const linksChanged = useCallback(() => setLinksVersion((v) => v + 1), []);

  // MO-01: each running VM's share of the host, after every metrics round while the page shows and the window is
  // visible (P8), and once when it shows again.
  const visibility = useVisibility();
  const readUsage = shouldPoll(active, visibility);
  useEffect(() => {
    if (!readUsage) return;
    let stale = false;
    const read = () =>
      api.metricsHostUsage().then(
        (list) => {
          if (!stale) setUsage(new Map(list.map((u) => [keyOf(u.vmxPath), u])));
        },
        () => {
          if (!stale) setUsage(new Map());
        },
      );
    void read();
    const unlisten = api.onMetricsRound(() => void read());
    return () => {
      stale = true;
      void unlisten.then((stop) => stop());
    };
  }, [readUsage]);

  const usageOf = useCallback((vm: VmRecord) => usage.get(keyOf(vm.vmxPath)), [usage]);
  // QL-26: starred VMs first, and the filter's "Starred only".
  const stars = useStars();
  const [starredOnly, setStarredOnly] = useState(false);
  // The shown order. Selection and shift-click ranges follow it.
  const sorted = useMemo(() => {
    const starred = (vm: VmRecord) => isStarred(stars, "vm", vm.vmxPath);
    const base = starredOnly ? listed.filter(starred) : listed;
    const ordered =
      sort.key === "name" && sort.dir === 1
        ? base
        : [...base].sort(
            (a, b) =>
              compareNullsLast(sortValue(a, sort.key, usageOf(a)), sortValue(b, sort.key, usageOf(b)), sort.dir) ||
              a.displayName.localeCompare(b.displayName),
          );
    return starredFirst(ordered, starred);
  }, [listed, sort, usageOf, stars, starredOnly]);
  // VM-08: a stack instance's VMs as a group under its header row, the other VMs after them.
  const groups = useMemo(() => groupByInstance(sorted, instances), [sorted, instances]);
  const vms = useMemo(() => groups.flatMap((g) => g.vms), [groups]);

  const detailVm = detail ? listed.find((v) => v.vmxPath === detail) : undefined;
  const detailTree = detailVm ? trees.map.get(keyOf(detailVm.vmxPath)) : undefined;
  const detailTreeError =
    detailVm && treeError?.key === key && treeError.vmxPath === detailVm.vmxPath ? treeError.message : null;

  /** Adds trees read for the list as it was at `forKey`; a later refresh drops them. */
  const keepTrees = useCallback((forKey: string, list: VmSnapshots[]) => {
    setTrees((prev) => {
      if (prev.key !== forKey) return prev;
      const map = new Map(prev.map);
      for (const t of list) map.set(keyOf(t.vmxPath), t);
      return { key: prev.key, map };
    });
  }, []);

  // VM-04: the open VM's tree, read when its details open (and again after a refresh or "Read again").
  const detailPath = detailVm?.vmxPath;
  const haveDetailTree = detailTree !== undefined || detailTreeError !== null;
  useEffect(() => {
    if (!detailPath || haveDetailTree) return;
    let stale = false;
    api.snapshots([detailPath]).then(
      (list) => {
        if (stale) return;
        keepTrees(key, list);
        if (!list.some((t) => t.vmxPath === detailPath))
          setTreeError({ key, vmxPath: detailPath, message: "This VM is no longer in the list. Refresh it." });
      },
      (err) => {
        if (!stale) setTreeError({ key, vmxPath: detailPath, message: errorMessage(err) });
      },
    );
    return () => {
      stale = true;
    };
  }, [detailPath, haveDetailTree, key, keepTrees]);

  function readTreeAgain(vmxPath: string) {
    setTreeError(null);
    setTrees((prev) => {
      const map = new Map(prev.map);
      map.delete(keyOf(vmxPath));
      return { key: prev.key, map };
    });
  }

  /** The trees of these VMs, reading the ones not read yet. */
  async function ensureTrees(paths: string[]): Promise<VmSnapshots[]> {
    const forKey = trees.key;
    const missing = paths.filter((p) => !trees.map.has(keyOf(p)));
    const read = missing.length > 0 ? await api.snapshots(missing) : [];
    keepTrees(forKey, read);
    const all = new Map(trees.map);
    for (const t of read) all.set(keyOf(t.vmxPath), t);
    return paths.flatMap((p) => all.get(keyOf(p)) ?? []);
  }

  // QL-14: a VM (or the snapshot view) asked for from the palette, a shortcut or an old Snapshots link. It waits for
  // the list, and shows every VM first when the filter hides the one asked for. Handled while rendering, once each.
  const [handledRequest, setHandledRequest] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // VM-24: bumped when the palette asks to rename the VM; its Settings tab opens the dialog until it is seen.
  const [renameAsk, setRenameAsk] = useState(0);
  const [renameSeen, setRenameSeen] = useState(0);
  const listReady = !loading && listedFor === filter;
  if (request && request.n !== handledRequest && request.panel) {
    setHandledRequest(request.n);
    setPanel(request.panel);
  } else if (request && request.n !== handledRequest && listReady) {
    const wanted = new Set(request.vmxPaths.map(keyOf));
    const found = listed.filter((v) => wanted.has(keyOf(v.vmxPath)));
    if (found.length < wanted.size && !isEmptyFilter(filter)) {
      // The list is read again for the empty filter; the request is handled then.
      setFilter({});
    } else {
      setHandledRequest(request.n);
      setView(request.view);
      if (request.rename) setRenameAsk((n) => n + 1);
      setNotice(null);
      const first =
        wanted.size > 0
          ? found[0]
          : (listed.find((v) => v.vmxPath === detail) ??
            vms.find((v) => selected.has(v.vmxPath)) ??
            (vms.length === 1 ? vms[0] : undefined));
      if (found.length > 1) setSelected(new Set(found.map((v) => v.vmxPath)));
      if (first) setDetail(first.vmxPath);
      else
        setNotice(
          wanted.size > 0
            ? "That VM is no longer in the list. Refresh to ask Workstation and VirtualBox again."
            : "Snapshots are on each VM's Snapshots tab: click a VM's name. For several VMs, tick them and use Snapshot.",
        );
    }
  }

  // The details panel opens at its last width and folds away when closed. Dragging it shut closes the details.
  const detailsPanel = usePanelRef();
  const detailsWidth = useRef(DETAILS_WIDTH);
  const hasRows = vms.length > 0;
  const detailOpen = detailVm !== undefined;
  useEffect(() => {
    const panel = detailsPanel.current;
    if (!panel) return;
    if (detailOpen && panel.isCollapsed()) panel.resize(`${detailsWidth.current}%`);
    if (!detailOpen && !panel.isCollapsed()) panel.collapse();
  }, [detailOpen, hasRows, detailsPanel]);

  function toggleDetails(vmxPath: string) {
    setNotice(null);
    setDetail((open) => (open === vmxPath ? null : vmxPath));
    // QL-26: a VM's details opened go to the top of Ctrl+K's Recent.
    noteOpened("vm", vmxPath);
  }

  function sortBy(key: SortKey) {
    setSort((s) =>
      s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: key === "name" || key === "state" ? 1 : -1 },
    );
    setAnchor(null);
  }

  // Click toggles one VM; shift-click selects the range from the last click (VM-02).
  function toggle(index: number, e: MouseEvent) {
    const path = vms[index].vmxPath;
    setSelected((prev) => {
      const next = new Set(prev);
      if (e.shiftKey && anchor !== null) {
        const [from, to] = anchor < index ? [anchor, index] : [index, anchor];
        for (let i = from; i <= to; i++) next.add(vms[i].vmxPath);
      } else if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
    setAnchor(index);
  }

  /** VM-02: shows the VMs a filter matches and selects all of them. */
  async function selectMatching(f: VmFilter) {
    try {
      const found = await api.vmList(f);
      setFilter(f);
      setSelected(new Set(found.map((v) => v.vmxPath)));
      setAnchor(null);
    } catch (err) {
      setError({ code: errorCode(err), message: errorMessage(err) });
    }
  }

  /** VM-04: selects the shown VMs whose snapshots match. Throws when none does, for the name dialog to show. */
  async function selectBySnapshots(match: SnapshotMatch) {
    const found = vmsMatching(await ensureTrees(vms.map((v) => v.vmxPath)), match);
    if (found.length === 0) throw new Error(noMatchText(match, vms.length, limits?.oldAfterDays ?? 30));
    setSelected(new Set(found));
    setAnchor(null);
  }

  function pickBySnapshots(match: SnapshotMatch) {
    selectBySnapshots(match).catch((err: unknown) => toast.info(errorMessage(err)));
  }

  const selectedVms = vms.filter((v) => selected.has(v.vmxPath));
  const allSelected = vms.length > 0 && selected.size === vms.length;
  const selectedTags = [...new Set(selectedVms.flatMap((v) => v.tags))].sort((a, b) => a.localeCompare(b));
  const refs = (targets: { vmxPath: string }[]) => targets.map((v) => ({ kind: "vm" as const, vmxPath: v.vmxPath }));

  /** Selected VMs the action applies to. Unknown state (vmrun missing) is sent as is. */
  function targetsFor(appliesTo: PowerState[]) {
    return selectedVms.filter((v) => v.powerState === "unknown" || appliesTo.includes(v.powerState));
  }

  /** Submits to the bus; resolves true when the bus took it (queued, or waiting for approval). */
  async function submit(command: Command) {
    setSubmitting(true);
    try {
      onSubmitted(await api.submit(command));
      return true;
    } catch (err) {
      toast.error(errorMessage(err));
      return false;
    } finally {
      setSubmitting(false);
    }
  }

  /** VM-24: a VM's own window; a stopped VirtualBox VM starts with it (a power command, shown like any other). */
  async function openConsole(vmxPath: string) {
    try {
      const done = await api.vmOpenConsole(vmxPath);
      if (done.kind === "starting") onSubmitted(done.outcome);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  /** VM-24: an existing VM from a file dialog the shell opens. */
  async function addExisting() {
    try {
      const outcome = await api.vmPickExisting();
      if (outcome) onSubmitted(outcome);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  // VM-23: an ISO dropped on a VM's row or its details attaches to its CD/DVD drive. The shell stages the drop, so
  // its path never comes through here; this page only says which VM it fell on.
  const dropRef = useRef<(dropped: DroppedFiles) => void>(() => undefined);
  useEffect(() => {
    const unlisten = api.onFilesDropped((dropped) => dropRef.current(dropped));
    return () => void unlisten.then((stop) => stop());
  }, []);
  useEffect(() => {
    dropRef.current = (dropped) => {
      if (!active) return;
      if (dropped.error) {
        toast.error(dropped.error);
        return;
      }
      if (!dropped.staged) return;
      const at = document.elementFromPoint(dropped.x, dropped.y)?.closest<HTMLElement>("[data-vm-drop]");
      const vmxPath = at?.dataset.vmDrop;
      if (!vmxPath) {
        void api.filesUnstage(dropped.staged.id).catch(() => undefined);
        toast.info("Drop an ISO image on a VM to attach it to its CD/DVD drive.");
        return;
      }
      if (readOnly) {
        void api.filesUnstage(dropped.staged.id).catch(() => undefined);
        toast.error(readOnly);
        return;
      }
      api.vmAttachDroppedIso(dropped.staged.id, vmxPath).then(onSubmitted, (err: unknown) => {
        void api.filesUnstage(dropped.staged!.id).catch(() => undefined);
        toast.error(errorMessage(err));
      });
    };
  });

  /** VM-04: reverting to or deleting one snapshot of the open VM. Both are High: the approval dialog follows. */
  function onSnapshot(tree: VmSnapshots, node: SnapshotNode, kind: "revert" | "delete") {
    void submit({ type: "vmSnapshot", targets: refs([tree]), op: { kind, name: snapshotArg(tree, node) } });
  }

  async function untag(tag: string) {
    try {
      await api.untagVms(
        selectedVms.map((v) => v.vmxPath),
        tag,
      );
      setListVersion((v) => v + 1);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function applyLabel(vmxPaths: string[], environment: Environment) {
    await api.setVmEnvironment(vmxPaths, environment);
    setListVersion((v) => v + 1);
  }

  /** SS-06: labels the selected VMs. Taking Prod off any of them asks first. */
  function chooseLabel(environment: Environment) {
    const vmxPaths = selectedVms.map((v) => v.vmxPath);
    const prodNames = selectedVms
      .filter((v) => v.environment === "prod" && environment !== "prod")
      .map((v) => v.displayName);
    if (prodNames.length > 0) {
      setDialog({ kind: "lowerProd", vmxPaths, environment, prodNames });
      return;
    }
    applyLabel(vmxPaths, environment).catch((err: unknown) => toast.error(errorMessage(err)));
  }

  async function deleteSaved(saved: SavedFilter) {
    try {
      await api.deleteFilter(saved.id);
      setListVersion((v) => v + 1);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  // VM-04: the selection's trees, read when its More menu opens or Snapshot is clicked; null until every one is read.
  const selectionTrees = selectedVms.every((v) => trees.map.has(keyOf(v.vmxPath)))
    ? selectedVms.flatMap((v) => trees.map.get(keyOf(v.vmxPath)) ?? [])
    : null;
  const snapshotReasons = selectionError
    ? { take: selectionError, revert: selectionError, delete: selectionError }
    : bulkSnapshotReasons({ readOnly, selected: selectedVms, trees: selectionTrees, busy: submitting });
  const withSnapshots = (selectionTrees ?? []).filter((t) => t.snapshots.length > 0);

  function readSelection() {
    setSelectionError(null);
    ensureTrees(selectedVms.map((v) => v.vmxPath)).catch((err: unknown) =>
      setSelectionError(`Could not read the snapshots: ${errorMessage(err)}`),
    );
  }

  function openBulk(kind: SnapshotAction["kind"]) {
    if (!selectionTrees) return;
    setSnapshotDialog({ kind, vms: kind === "take" ? selectionTrees : withSnapshots });
  }

  /** Snapshot in the selection bar: the take dialog, once the selection's trees are read (it checks the name). */
  async function takeSelected() {
    setSelectionError(null);
    try {
      setSnapshotDialog({ kind: "take", vms: await ensureTrees(selectedVms.map((v) => v.vmxPath)) });
    } catch (err) {
      toast.error(`Could not read the snapshots: ${errorMessage(err)}`);
    }
  }

  const start = targetsFor(STARTABLE);
  const shutDown = targetsFor(["running"]);
  const startOff = readOnly ?? selectionPowerReason(selectedVms, "start");
  const shutDownOff = readOnly ?? selectionPowerReason(selectedVms, "shutDown");
  const takeOff =
    readOnly ??
    (selectedVms.length > 0 && selectedVms.every((v) => v.protected)
      ? selectedVms.length === 1
        ? PROTECTED_REASON
        : "All selected VMs are protected"
      : submitting
        ? "Sending the last action…"
        : null);
  // FD-02: taking VMs out of this workspace, into Unassigned.
  const releaseOff = readOnly ?? releaseReason(selectedVms, activeWorkspaces);
  const noVms = noVmsHere(activeWorkspaces, unassigned.length);
  async function release() {
    try {
      const keys = selectedVms.map((v) => v.vmxPath);
      await workspacesApi.releaseVms(keys);
      toast.success(keys.length === 1 ? "The VM is in Unassigned now" : `${keys.length} VMs are in Unassigned now`);
      setSelected(new Set());
      setRefreshes((n) => n + 1);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }
  const toProtect = selectedVms.filter((v) => !v.protected);
  const toUnprotect = selectedVms.filter((v) => v.protected);
  // VM-12, VM-15, VM-24: what the selection's settings and lifecycle actions go to.
  const resize = resizeTargets(selectedVms);
  const toolsTargets = selectedVms.filter((v) => v.powerState === "running" && !v.protected);
  const deletable = selectedVms.filter((v) => !v.protected && v.powerState !== "running" && v.powerState !== "paused");
  const cloneable = selectedVms.filter((v) => v.powerState === "not_running");
  const selectedLabels = new Set(selectedVms.map((v) => v.environment));
  // Ticked in the Environment menu when every selected VM has it.
  const sharedLabel = selectedLabels.size === 1 ? [...selectedLabels][0] : "";
  const missingWorkstation = warnings.some((w) => w.code === "vmrun_not_found");
  const virtualboxTrouble = warnings.some((w) => w.code.startsWith("vboxmanage"));
  const filtered = !isEmptyFilter(filter) || starredOnly;
  const oldAfterDays = limits?.oldAfterDays ?? 30;
  // UX-02: More shows only what applies to the selection.
  const more = moreGroups(selectedVms, {
    snapshots: selectionTrees === null ? null : snapshotReasons.revert === null ? withSnapshots.length : 0,
    canRelease: releaseOff === null,
    canExport: onExport !== undefined && selectedVms.length === 1,
  });

  /** One item of the More menu. The count says how many of the selected VMs it goes to, when not all of them. */
  function moreItem(id: MoreItemId, count: number): ReactNode {
    const n = count > 0 && count < selectedVms.length ? <DropdownMenuShortcut>{count}</DropdownMenuShortcut> : null;
    const action = POWER[id];
    if (action) {
      const Icon = action.icon;
      return (
        <DropdownMenuItem
          key={id}
          variant={id === "powerOff" ? "destructive" : undefined}
          onSelect={() =>
            void submit({
              type: "vmPower",
              targets: refs(powerTargets(selectedVms, action.appliesTo)),
              op: action.op,
            })
          }
        >
          <Icon />
          {action.label}
          {n}
        </DropdownMenuItem>
      );
    }
    switch (id) {
      case "revert":
        return (
          <DropdownMenuItem key={id} onSelect={() => openBulk("revert")}>
            <Undo2Icon />
            Revert to a snapshot…
            {n}
          </DropdownMenuItem>
        );
      case "deleteSnapshot":
        return (
          <DropdownMenuItem key={id} onSelect={() => openBulk("delete")}>
            <Trash2Icon />
            Delete a snapshot…
            {n}
          </DropdownMenuItem>
        );
      case "resize":
        return (
          <DropdownMenuItem key={id} onSelect={() => setDialog({ kind: "resize" })}>
            <CpuIcon />
            Resize CPU and memory…
            {n}
          </DropdownMenuItem>
        );
      case "tools":
        return (
          <DropdownMenuItem
            key={id}
            onSelect={() =>
              void submit({ type: "vmDevice", targets: refs(toolsTargets), op: { kind: "installTools" } })
            }
          >
            <WrenchIcon />
            Install or upgrade guest tools
            {n}
          </DropdownMenuItem>
        );
      case "clone":
        return (
          <DropdownMenuItem key={id} onSelect={() => setDialog({ kind: "clone", vms: cloneable })}>
            <CopyIcon />
            Clone…
            {n}
          </DropdownMenuItem>
        );
      case "export":
        return (
          <DropdownMenuItem key={id} onSelect={() => selectedVms[0] && onExport?.(selectedVms[0].vmxPath)}>
            <PackageIcon />
            Export…
          </DropdownMenuItem>
        );
      case "delete":
        return (
          <DropdownMenuItem
            key={id}
            variant="destructive"
            onSelect={() => void submit({ type: "vmLifecycle", targets: refs(deletable), op: { kind: "delete" } })}
          >
            <Trash2Icon />
            Delete with their files…
            {n}
          </DropdownMenuItem>
        );
      case "addTag":
        return (
          <DropdownMenuItem key={id} onSelect={() => setDialog({ kind: "addTag" })}>
            <TagIcon />
            Add a tag…
          </DropdownMenuItem>
        );
      case "removeTag":
        return (
          <DropdownMenuSub key={id}>
            <DropdownMenuSubTrigger>
              <TagIcon />
              Remove a tag
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent>
              {selectedTags.map((t) => (
                <DropdownMenuItem key={t} onSelect={() => void untag(t)}>
                  {t}
                </DropdownMenuItem>
              ))}
            </DropdownMenuSubContent>
          </DropdownMenuSub>
        );
      case "environment":
        return (
          <DropdownMenuSub key={id}>
            <DropdownMenuSubTrigger>
              <FlagIcon />
              Environment
            </DropdownMenuSubTrigger>
            <DropdownMenuSubContent className="w-44">
              <DropdownMenuRadioGroup value={sharedLabel} onValueChange={(v) => chooseLabel(v as Environment)}>
                {LABELS.map((l) => (
                  <DropdownMenuRadioItem key={l.value} value={l.value}>
                    {l.label}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuSubContent>
          </DropdownMenuSub>
        );
      case "protect":
        return (
          <DropdownMenuItem
            key={id}
            onSelect={() => void submit({ type: "vmProtect", targets: refs(toProtect), protected: true })}
          >
            <ShieldIcon />
            Mark as Protected
            {n}
          </DropdownMenuItem>
        );
      case "unprotect":
        return (
          <DropdownMenuItem
            key={id}
            onSelect={() => void submit({ type: "vmProtect", targets: refs(toUnprotect), protected: false })}
          >
            <ShieldOffIcon />
            Remove Protected
            {n}
          </DropdownMenuItem>
        );
      case "release":
        return (
          <DropdownMenuItem key={id} onSelect={() => void release()}>
            <UsersIcon />
            Take out of this workspace
          </DropdownMenuItem>
        );
      default:
        return null;
    }
  }

  const sortHead = (key: SortKey, label: string, className?: string, hint?: string) => (
    <SortableHead
      label={label}
      hint={hint}
      className={className}
      active={sort.key === key}
      dir={sort.dir}
      onSort={() => sortBy(key)}
    />
  );

  // The list's columns, in order: Name, then the ones the picker shows (UX-02).
  const allColumns: Column[] = [
    {
      id: "name",
      head: sortHead("name", "Name", "min-w-40"),
      cell: (vm) => (
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          <StarButton kind="vm" itemKey={vm.vmxPath} name={vm.displayName} className="-ml-1" />
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                className="rounded-sm text-left font-medium underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                aria-expanded={detail === vm.vmxPath}
                aria-controls={detail === vm.vmxPath ? "vm-details" : undefined}
                onClick={(e) => {
                  e.stopPropagation();
                  toggleDetails(vm.vmxPath);
                }}
              >
                {vm.displayName}
              </button>
            </TooltipTrigger>
            <TooltipContent className="max-w-md font-mono text-xs break-all">{vmLocation(vm)}</TooltipContent>
          </Tooltip>
          {vm.protected && (
            <Tooltip>
              <TooltipTrigger asChild>
                <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
              </TooltipTrigger>
              <TooltipContent>{PROTECTED_REASON}</TooltipContent>
            </Tooltip>
          )}
          {vm.tags.slice(0, 2).map((t) => (
            <Badge key={t} variant="secondary" className="font-normal">
              {t}
            </Badge>
          ))}
          {vm.tags.length > 2 && (
            <Badge variant="secondary" className="font-normal" title={vm.tags.join(", ")}>
              +{vm.tags.length - 2}
            </Badge>
          )}
        </div>
      ),
    },
    {
      id: "hypervisor",
      head: sortHead("hypervisor", "Hypervisor"),
      cell: (vm) => <HypervisorLabel hypervisor={vm.hypervisor} />,
    },
    {
      id: "guestOs",
      head: <TableHead>Guest OS</TableHead>,
      cell: (vm) => {
        const os = vm.guestOsName ?? vm.guestOs;
        return os ? (
          <span className="block max-w-44 truncate" title={os}>
            {os}
          </span>
        ) : (
          <span className="text-muted-foreground">—</span>
        );
      },
    },
    {
      id: "vcpus",
      head: sortHead("vcpus", "vCPU", "text-right"),
      className: "text-right tabular-nums",
      cell: (vm) => vm.numVcpus ?? "—",
    },
    {
      id: "ram",
      head: sortHead("ram", "RAM", "text-right"),
      className: "text-right tabular-nums",
      cell: (vm) => formatRam(vm.memsizeMb),
    },
    {
      id: "ip",
      head: <TableHead>IP address</TableHead>,
      className: "font-mono text-xs",
      cell: (vm) =>
        vm.ipAddress ? (
          <span data-mask="ip">{vm.ipAddress}</span>
        ) : (
          <span className="font-sans text-muted-foreground">—</span>
        ),
    },
    {
      id: "state",
      head: sortHead("state", "State"),
      cell: (vm) => {
        const state = stateDetail(vm);
        return (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-1">
                <StateBadge state={vm.powerState} />
                {state.toolsWarning && (
                  <TriangleAlertIcon className="size-3.5 text-tier-medium" role="img" aria-label={state.text} />
                )}
              </span>
            </TooltipTrigger>
            <TooltipContent>{state.text}</TooltipContent>
          </Tooltip>
        );
      },
    },
    {
      id: "hostCpu",
      head: sortHead("hostCpu", "Host CPU", undefined, HOST_SHARE_HINT.cpu),
      cell: (vm) => {
        const pct = usageOf(vm)?.hostCpuPct ?? null;
        return (
          <MetricCell
            value={pct}
            text={formatPct(pct)}
            pct={pct}
            limits={thresholds.cpu}
            label={`${vm.displayName}'s share of this host's CPU`}
          />
        );
      },
    },
    {
      id: "hostMem",
      head: sortHead("hostMem", "Host RAM", undefined, HOST_SHARE_HINT.memory),
      cell: (vm) => {
        const pct = usageOf(vm)?.hostMemPct ?? null;
        return (
          <MetricCell
            value={pct}
            text={formatPct(pct)}
            pct={pct}
            limits={thresholds.memory}
            label={`${vm.displayName}'s share of this host's RAM`}
          />
        );
      },
    },
    {
      id: "sessions",
      head: <TableHead>Sessions</TableHead>,
      ownClicks: true,
      cell: (vm) => <VmSessionLinks vm={vm} sessions={sessions} onChanged={linksChanged} />,
    },
    { id: "environment", head: sortHead("label", "Environment"), cell: (vm) => <EnvBadge env={vm.environment} /> },
  ];
  const columns: Column[] = [
    allColumns[0],
    ...visibleColumns(shownColumnIds, detailOpen).flatMap((id) => allColumns.filter((c) => c.id === id)),
  ];
  const shownColumns = columns;

  /** UX-02: the primary, New VM ▾: every way to make or add a VM. */
  const newVm = (
    <DropdownMenu>
      <WhyDisabled reason={readOnly}>
        <DropdownMenuTrigger asChild>
          <Button disabled={readOnly !== null}>
            <PlusIcon data-icon="inline-start" />
            New VM
            <ChevronDownIcon data-icon="inline-end" />
          </Button>
        </DropdownMenuTrigger>
      </WhyDisabled>
      <DropdownMenuContent align="end" className="w-60">
        {/* VM-21: from a launch template or Custom. */}
        <DropdownMenuItem onSelect={onDeploy}>
          <RocketIcon />
          Deploy…
        </DropdownMenuItem>
        {/* VM-10: a full clone of a VM that is off. */}
        <DropdownMenuItem onSelect={() => setDialog({ kind: "clone", vms: cloneable })}>
          <CopyIcon />
          Clone…
        </DropdownMenuItem>
        {/* CV-01: a foreign VM or disk (OVA, VHD/VHDX, qcow2, raw, libvirt, Proxmox) as a new VM. */}
        {onImport && (
          <DropdownMenuItem onSelect={() => onImport()}>
            <ImportIcon />
            Import…
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void addExisting()}>
          <FilePlusIcon />
          Add an existing VM…
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );

  /** UX-01: Tools ▾, the page's views (VM-11, VM-16, FD-02); their actions go through the bus. */
  const tools = (
    <>
      <DropdownMenuItem onSelect={() => setPanel("networks")}>
        <NetworkIcon />
        Networks
      </DropdownMenuItem>
      <DropdownMenuItem onSelect={() => setPanel("waste")}>
        <RecycleIcon />
        Waste finder
      </DropdownMenuItem>
      <DropdownMenuItem onSelect={() => setUnassignedOpen(true)}>
        <UsersIcon />
        Unassigned VMs
        {unassigned.length > 0 && <DropdownMenuShortcut>{unassigned.length}</DropdownMenuShortcut>}
      </DropdownMenuItem>
      {onExportInventory && (
        <>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={onExportInventory}>
            <FileSpreadsheetIcon />
            Export the inventory to Excel…
          </DropdownMenuItem>
        </>
      )}
      <DropdownMenuSeparator />
      <DropdownMenuItem onSelect={onOpenSettings}>
        <FolderSearchIcon />
        Where VMs are found…
      </DropdownMenuItem>
    </>
  );

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <PageHeader page="vms" primary={newVm} tools={tools} toolsLabel="Tools">
        {selectedVms.length > 0 ? (
          <SelectionBar count={selectedVms.length} onClear={() => setSelected(new Set())}>
            <WhyDisabled reason={startOff}>
              <Button
                variant="ghost"
                size="sm"
                disabled={startOff !== null || submitting}
                onClick={() =>
                  void submit({ type: "vmPower", targets: refs(start), op: { kind: "start", gui: false } })
                }
              >
                <PlayIcon data-icon="inline-start" />
                Start
              </Button>
            </WhyDisabled>
            <WhyDisabled reason={shutDownOff}>
              <Button
                variant="ghost"
                size="sm"
                disabled={shutDownOff !== null || submitting}
                onClick={() =>
                  void submit({ type: "vmPower", targets: refs(shutDown), op: { kind: "stop", mode: "soft" } })
                }
              >
                <SquareIcon data-icon="inline-start" />
                Shut down
              </Button>
            </WhyDisabled>
            {/* VM-04: a snapshot of each selected VM; revert and delete are under More. */}
            <WhyDisabled reason={takeOff}>
              <Button variant="ghost" size="sm" disabled={takeOff !== null} onClick={() => void takeSelected()}>
                <CameraIcon data-icon="inline-start" />
                Snapshot
              </Button>
            </WhyDisabled>
            <DropdownMenu onOpenChange={(open) => open && readSelection()}>
              <WhyDisabled reason={readOnly}>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm" disabled={readOnly !== null || submitting}>
                    <EllipsisIcon data-icon="inline-start" />
                    More
                  </Button>
                </DropdownMenuTrigger>
              </WhyDisabled>
              <DropdownMenuContent align="start" className="w-64">
                {more.map((group, g) => (
                  <Fragment key={group.label}>
                    {g > 0 && <DropdownMenuSeparator />}
                    <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                      {group.label}
                    </DropdownMenuLabel>
                    {group.items.map((item) => moreItem(item.id, item.count))}
                    {group.label === "Power" && selectionTrees === null && (
                      <>
                        <DropdownMenuSeparator />
                        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                          {selectionError ?? "Reading their snapshots…"}
                        </DropdownMenuLabel>
                      </>
                    )}
                  </Fragment>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </SelectionBar>
        ) : (
          <>
            <VmFilterBar
              filter={filter}
              onChange={setFilter}
              tags={tags}
              savedFilters={savedFilters}
              onApplySaved={(saved) => void selectMatching(saved.filter)}
              onSaveCurrent={() => setDialog({ kind: "saveFilter" })}
              onDeleteSaved={(saved) => void deleteSaved(saved)}
              starredOnly={starredOnly}
              onStarredOnly={setStarredOnly}
            />
            <span className="ml-auto text-sm whitespace-nowrap text-muted-foreground">
              {filtered ? `${vms.length} of ${plural(total.vms, "VM")}` : plural(total.vms, "VM")} · {total.running}{" "}
              running
            </span>
            <RefreshButton busy={loading} onClick={() => setRefreshes((n) => n + 1)} />
          </>
        )}
      </PageHeader>

      {notice && (
        <Alert>
          <InfoIcon />
          <AlertDescription>{notice}</AlertDescription>
          <AlertAction>
            <Button size="icon-sm" variant="ghost" aria-label="Dismiss" onClick={() => setNotice(null)}>
              <XIcon />
            </Button>
          </AlertAction>
        </Alert>
      )}

      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      )}

      {warnings.length > 0 && (
        <Alert>
          <TriangleAlertIcon />
          <AlertTitle>
            {missingWorkstation
              ? "VMware Workstation was not found"
              : virtualboxTrouble
                ? "VirtualBox could not be asked about every VM"
                : "Some VMs may be missing from the list"}
          </AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-5">
              {warnings.map((w) => (
                <li key={w.message}>{w.message}</li>
              ))}
            </ul>
          </AlertDescription>
          <AlertAction>
            <Button size="sm" variant="outline" onClick={onOpenSettings}>
              {missingWorkstation ? "Set the vmrun.exe path" : "Settings"}
            </Button>
          </AlertAction>
        </Alert>
      )}

      {!error && !loading && total.vms === 0 && (
        <EmptyState
          icon={MonitorOffIcon}
          title={noVms?.title ?? "No VMs found"}
          description={
            noVms?.description ?? "Remotely lists Workstation's library, the folders you add, and VirtualBox's VMs."
          }
          help="page.vms"
          action={
            unassigned.length > 0 ? (
              <Button onClick={() => setUnassignedOpen(true)}>
                <UsersIcon data-icon="inline-start" />
                Show unassigned VMs
              </Button>
            ) : (
              <Button onClick={onOpenSettings}>
                <FolderPlusIcon data-icon="inline-start" />
                Add a VM folder
              </Button>
            )
          }
        />
      )}

      {total.vms > 0 && vms.length === 0 && filtered && (
        <EmptyState
          title="No VMs match the filter"
          action={
            <Button variant="outline" onClick={() => setFilter({})}>
              <XIcon data-icon="inline-start" />
              Clear the filter
            </Button>
          }
        />
      )}

      {hasRows && (
        <Tip id="vms.selection">
          Tick VMs to act on several at once, Shift+click for a range; click a VM&apos;s name for its details.
        </Tip>
      )}

      {hasRows && (
        <ResizablePanelGroup orientation="horizontal" id="vms-split" className="min-h-0 flex-1">
          <ResizablePanel id="vms-list" minSize="30%">
            <div className="h-full overflow-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-14">
                      <span className="flex items-center">
                        <Checkbox
                          aria-label="Select all shown VMs"
                          checked={allSelected ? true : selected.size > 0 ? "indeterminate" : false}
                          onCheckedChange={() =>
                            setSelected(allSelected ? new Set() : new Set(vms.map((v) => v.vmxPath)))
                          }
                        />
                        <SelectMenu
                          vms={vms.length}
                          tags={tags}
                          oldAfterDays={oldAfterDays}
                          onSelectTag={(tag) => void selectMatching({ tags: [tag] })}
                          onSnapshots={pickBySnapshots}
                          onNamed={() => setDialog({ kind: "snapshotName" })}
                        />
                      </span>
                    </TableHead>
                    {shownColumns.map((c) => (
                      <Fragment key={c.id}>{c.head}</Fragment>
                    ))}
                    <TableHead className="w-10 text-right">
                      <ColumnPicker shown={shownColumnIds} onToggle={toggleColumn} />
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {groups.map((group, g) => {
                    // Row indexes run through the groups, so shift-click ranges follow the shown order.
                    const offset = groups.slice(0, g).reduce((n, x) => n + x.vms.length, 0);
                    return (
                      <Fragment key={group.instance?.id ?? "rest"}>
                        {group.instance && (
                          <StackGroupRow
                            instance={group.instance}
                            colSpan={shownColumns.length + 2}
                            readOnly={readOnly}
                            onSubmitted={onSubmitted}
                          />
                        )}
                        {!group.instance && groups.length > 1 && (
                          <TableRow className="hover:bg-transparent">
                            <TableCell colSpan={shownColumns.length + 2} className="py-1 text-xs text-muted-foreground">
                              Not in a stack
                            </TableCell>
                          </TableRow>
                        )}
                        {group.vms.map((vm, j) => {
                          const i = offset + j;
                          return (
                            <TableRow
                              key={vm.vmxPath}
                              data-vm-drop={vm.vmxPath}
                              data-state={selected.has(vm.vmxPath) ? "selected" : undefined}
                              onClick={(e) => toggle(i, e)}
                              className={cn(
                                "group select-none",
                                detail === vm.vmxPath && "shadow-[inset_3px_0_0_var(--color-primary)]",
                              )}
                            >
                              <TableCell>
                                {/* The click (or Space) bubbles to the row, which does the selecting. */}
                                <Checkbox aria-label={`Select ${vm.displayName}`} checked={selected.has(vm.vmxPath)} />
                              </TableCell>
                              {shownColumns.map((c) => (
                                <TableCell
                                  key={c.id}
                                  className={c.className}
                                  onClick={c.ownClicks ? (e) => e.stopPropagation() : undefined}
                                >
                                  {c.cell(vm)}
                                </TableCell>
                              ))}
                              <TableCell />
                            </TableRow>
                          );
                        })}
                      </Fragment>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </ResizablePanel>
          <ResizableHandle
            id={DIVIDER_ID}
            withHandle
            disabled={!detailOpen}
            className={cn("mx-1", !detailOpen && "hidden")}
          />
          <ResizablePanel
            id="vms-details"
            panelRef={detailsPanel}
            collapsible
            collapsedSize="0%"
            defaultSize="0%"
            minSize="22rem"
            maxSize="65%"
            onResize={(size, _id, before) => {
              if (size.asPercentage > 0) detailsWidth.current = size.asPercentage;
              // Dragged (or moved with the keyboard) shut: the details close. Sizes are reported by a ResizeObserver,
              // so a fold from the close button can be reported after the panel opened again; the divider has focus
              // only while the user resizes.
              else if (before && before.asPercentage > 0 && document.activeElement?.id === DIVIDER_ID) setDetail(null);
            }}
          >
            {detailVm && (
              <VmDetailsPanel
                vm={detailVm}
                view={view}
                onViewChange={setView}
                onClose={() => setDetail(null)}
                refreshKey={key}
                readOnly={readOnly}
                busy={submitting}
                onActions={() => onActions(detailVm.vmxPath)}
                onHostDetails={setHostDetails}
                usage={usageOf(detailVm)}
                thresholds={thresholds}
                sessions={sessions}
                onLinksChanged={linksChanged}
                tree={detailTree}
                treeError={detailTreeError}
                onReadTree={() => readTreeAgain(detailVm.vmxPath)}
                limits={limits}
                onTake={() => detailTree && setSnapshotDialog({ kind: "take", vms: [detailTree] })}
                onRevert={(node) => detailTree && onSnapshot(detailTree, node, "revert")}
                onDelete={(node) => detailTree && onSnapshot(detailTree, node, "delete")}
                onSubmit={submit}
                onSubmitted={onSubmitted}
                onOpenConsole={() => void openConsole(detailVm.vmxPath)}
                askRename={renameAsk}
                renameSeen={renameSeen}
                onRenameSeen={setRenameSeen}
                onSchedules={onSchedules}
              />
            )}
          </ResizablePanel>
        </ResizablePanelGroup>
      )}

      <HostDetailsSheet session={hostDetails} thresholds={thresholds} onClose={() => setHostDetails(null)} />
      <UnassignedVmsSheet
        open={unassignedOpen}
        vms={unassigned}
        readOnly={readOnly}
        onOpenChange={setUnassignedOpen}
        onAdded={() => setRefreshes((n) => n + 1)}
      />
      <HostNetworksSheet
        open={panel === "networks"}
        onClose={() => setPanel(null)}
        readOnly={readOnly}
        onSubmitted={onSubmitted}
      />
      <WasteFinderSheet
        open={panel === "waste"}
        onClose={() => setPanel(null)}
        readOnly={readOnly}
        onSubmitted={onSubmitted}
        onOpenVm={(vmxPath, wanted) => {
          setPanel(null);
          setView(wanted);
          setDetail(vmxPath);
        }}
      />

      {snapshotDialog && limits && (
        <SnapshotActionDialog
          action={snapshotDialog}
          limits={limits}
          onSubmit={submit}
          onClose={() => setSnapshotDialog(null)}
        />
      )}
      {dialog?.kind === "addTag" && (
        <NameDialog
          title={`Tag ${plural(selectedVms.length, "VM")}`}
          description="Remotely's own labels for finding and picking VMs; the VMs don't change."
          label="Tag"
          submitLabel="Add tag"
          suggestions={tags.map((t) => t.name)}
          onSubmit={async (name) => {
            await api.tagVms(
              selectedVms.map((v) => v.vmxPath),
              name,
            );
            setListVersion((v) => v + 1);
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "saveFilter" && (
        <NameDialog
          title="Save this filter"
          description="It shows in the Filter menu; a name in use replaces that filter."
          label="Name"
          submitLabel="Save"
          suggestions={savedFilters.map((f) => f.name)}
          onSubmit={async (name) => {
            await api.saveFilter(name, filter);
            setListVersion((v) => v + 1);
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "snapshotName" && (
        <NameDialog
          title="Select VMs by snapshot name"
          description="Selects the VMs shown that have a snapshot whose name contains this text."
          label="Snapshot name, or part of it"
          submitLabel="Select"
          maxLength={limits?.maxNameLength ?? 80}
          onSubmit={(name) => selectBySnapshots({ kind: "named", text: name })}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "resize" && (
        <ResourcesDialog
          vms={resize.targets}
          hardware={null}
          left={resize.left}
          onSubmit={submit}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "clone" && (
        <CloneDialog
          vms={dialog.vms}
          choices={listed.filter((v) => v.powerState === "not_running")}
          onSubmitted={onSubmitted}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "lowerProd" && (
        <ConfirmDialog
          title="Change the environment from Prod?"
          description={lowerProdText(dialog.prodNames, dialog.environment)}
          confirmLabel={`Set to ${dialog.environment === "none" ? "None" : labelName(dialog.environment)}`}
          onConfirm={() => applyLabel(dialog.vmxPaths, dialog.environment)}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

/** UX-02: beside the select-all box, ways to select by tag or by snapshots (VM-02, VM-04). */
function SelectMenu({
  vms,
  tags,
  oldAfterDays,
  onSelectTag,
  onSnapshots,
  onNamed,
}: {
  vms: number;
  tags: { id: string; name: string; vmCount: number }[];
  oldAfterDays: number;
  onSelectTag: (tag: string) => void;
  onSnapshots: (match: SnapshotMatch) => void;
  onNamed: () => void;
}) {
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-xs" aria-label="Select by…" disabled={vms === 0}>
              <ChevronDownIcon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Select by tag or snapshots</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuSub>
          <DropdownMenuSubTrigger disabled={tags.length === 0}>
            <TagIcon />
            With a tag
          </DropdownMenuSubTrigger>
          <DropdownMenuSubContent>
            {tags.map((t) => (
              <DropdownMenuItem key={t.id} onSelect={() => onSelectTag(t.name)}>
                {t.name}
                <DropdownMenuShortcut>{t.vmCount}</DropdownMenuShortcut>
              </DropdownMenuItem>
            ))}
          </DropdownMenuSubContent>
        </DropdownMenuSub>
        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Of the VMs shown</DropdownMenuLabel>
        <DropdownMenuItem onSelect={() => onSnapshots({ kind: "old" })}>
          <CameraIcon />
          With snapshots older than {oldAfterDays} days
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onSnapshots({ kind: "safety" })}>
          <CameraIcon />
          With safety snapshots
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onNamed}>
          <CameraIcon />
          With a snapshot named…
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** UX-02: which columns the list shows; Name always does. */
function ColumnPicker({ shown, onToggle }: { shown: Set<VmColumnId>; onToggle: (id: VmColumnId) => void }) {
  return (
    <DropdownMenu>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-xs" aria-label="Columns">
              <Columns3Icon />
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>Columns</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="end" className="w-48">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Columns</DropdownMenuLabel>
        {VM_COLUMNS.map((c) => (
          <DropdownMenuCheckboxItem
            key={c.id}
            checked={shown.has(c.id)}
            onCheckedChange={() => onToggle(c.id)}
            onSelect={(e) => e.preventDefault()}
          >
            {c.label}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
