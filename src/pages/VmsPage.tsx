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
  CopyIcon,
  EllipsisIcon,
  FlagIcon,
  FolderPlusIcon,
  InfoIcon,
  ListChecksIcon,
  MonitorOffIcon,
  PlayIcon,
  RefreshCwIcon,
  RocketIcon,
  ShieldIcon,
  ShieldOffIcon,
  TagIcon,
  Trash2Icon,
  TriangleAlertIcon,
  Undo2Icon,
  XIcon,
} from "lucide-react";
import { usePanelRef } from "react-resizable-panels";
import { toast } from "sonner";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
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
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, HypervisorLabel, StateBadge, ToolsLabel } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HostDetailsSheet } from "@/components/HostDetailsSheet";
import { MetricCell } from "@/components/MetricBits";
import { NameDialog } from "@/components/NameDialog";
import { SnapshotActionDialog, type SnapshotAction } from "@/components/SnapshotActionDialog";
import { SortableHead } from "@/components/SortableHead";
import { VmDetailsPanel } from "@/components/VmDetailsPanel";
import { isEmptyFilter, VmFilterBar } from "@/components/VmFilterBar";
import { VmSessionLinks } from "@/components/VmLinkControls";
import { useReadOnlyReason } from "@/components/Presentation";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorCode,
  errorMessage,
  type AutoLinkReport,
  type Command,
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
import { hypervisorName, vmLocation } from "@/lib/hypervisors";
import { refreshDue } from "@/lib/job-events";
import { compareNullsLast, formatPct, HOST_SHARE_HINT, useThresholds } from "@/lib/metrics";
import { shouldPoll } from "@/lib/polling";
import { cn } from "@/lib/utils";
import {
  bulkSnapshotReasons,
  noMatchText,
  PROTECTED_REASON,
  snapshotArg,
  summarize,
  vmsMatching,
  type SnapshotMatch,
  type VmView,
} from "@/lib/vm-snapshots";

/** QL-14: a VM to show from elsewhere (the palette, a shortcut, an old Snapshots link). `n` counts the requests. */
export interface VmPageRequest {
  /** The VMs to show; none: the snapshot view of the open or first selected VM. */
  vmxPaths: string[];
  view: VmView;
  n: number;
}

interface Props {
  /** True while the page is shown: the host shares (MO-01) follow the metrics rounds, and refreshes run, only then. */
  active: boolean;
  /** Shows the approval dialog for commands the policy engine says need one; `onJob` gets the job once queued. */
  onSubmitted: (outcome: SubmitOutcome, onJob?: (jobId: string) => void) => void;
  /** VM-21: opens the Deploy dialog. */
  onDeploy: () => void;
  onOpenSettings: () => void;
  /** FD-01: the command palette on one VM's actions. */
  onActions: (vmxPath: string) => void;
  request: VmPageRequest | null;
  /** Changes when the list should be read again: a VM job finished or a setting about where VMs are found changed. */
  refreshKey: number;
}

interface Action {
  label: string;
  op: PowerOp;
  /** States the action makes sense in. VMs in other states are left out of the command. */
  appliesTo: PowerState[];
}

const ON: PowerState[] = ["running", "paused"];
const STARTABLE: PowerState[] = ["not_running", "suspended"];

const SHUT_DOWN: Action = { label: "Shut down", op: { kind: "stop", mode: "soft" }, appliesTo: ["running"] };
const SUSPEND: Action = { label: "Suspend", op: { kind: "suspend" }, appliesTo: ["running"] };
const POWER_OFF: Action = { label: "Power off", op: { kind: "stop", mode: "hard" }, appliesTo: ON };
const MORE: Action[] = [
  { label: "Pause", op: { kind: "pause" }, appliesTo: ["running"] },
  { label: "Unpause", op: { kind: "unpause" }, appliesTo: ["paused"] },
  { label: "Restart", op: { kind: "reset", mode: "soft" }, appliesTo: ON },
];

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
  /** VM-10: clones the selected VMs. */
  | { kind: "clone" }
  | null;

function formatRam(mb: number | null) {
  if (!mb) return "—";
  return mb % 1024 === 0 ? `${mb / 1024} GB` : `${(mb / 1024).toFixed(1)} GB`;
}

function plural(n: number, word: string) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function labelName(env: Environment) {
  return LABELS.find((l) => l.value === env)?.label ?? env;
}

/** What the confirm says before Prod VMs lose the label. */
function lowerProdText(prodNames: string[], environment: Environment) {
  const shown = prodNames.slice(0, 5).join(", ") + (prodNames.length > 5 ? ", …" : "");
  const who = prodNames.length === 1 ? prodNames[0] : `${prodNames.length} VMs (${shown})`;
  const change =
    environment === "none" ? "will lose the Prod label" : `will be labelled ${labelName(environment)} instead of Prod`;
  const them = prodNames.length === 1 ? "it" : "them";
  return `${who} ${change}. Actions on ${them} will no longer move up one approval tier, so they need fewer approval steps. The change is logged.`;
}

/** .vmx paths are matched without regard to case, as Windows does. */
const keyOf = (vmxPath: string) => vmxPath.toLowerCase();

/** One column of the VM list. */
interface Column {
  id: string;
  /** Left out while a VM's details are open beside the list; the details panel shows it. */
  wide?: boolean;
  head: ReactNode;
  cell: (vm: VmRecord) => ReactNode;
  className?: string;
  /** The cell has its own controls: a click there doesn't select the row. */
  ownClicks?: boolean;
}

export function VmsPage({ active, onSubmitted, onDeploy, onOpenSettings, onActions, request, refreshKey }: Props) {
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
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  // Bumped after a refresh or a change to tags, so the list is read again from the store.
  const [listVersion, setListVersion] = useState(0);
  const key = `${refreshes}:${refreshKey}`;
  const loading = loadedKey !== key;

  // QL-14: the VM whose details are open, and the tab they open on (kept when another VM opens).
  const [detail, setDetail] = useState<string | null>(null);
  const [view, setView] = useState<VmView>("details");
  // VM-04: snapshot trees read so far, by .vmx path. A refresh, a finished job or a setting change starts afresh.
  const [trees, setTrees] = useState<{ key: string; map: Map<string, VmSnapshots> }>({ key, map: new Map() });
  if (trees.key !== key) setTrees({ key, map: new Map() });
  const [treeError, setTreeError] = useState<{ key: string; vmxPath: string; message: string } | null>(null);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [limits, setLimits] = useState<SnapshotLimits | null>(null);
  const [snapshotDialog, setSnapshotDialog] = useState<SnapshotAction | null>(null);

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
  // The shown order. Selection and shift-click ranges follow it.
  const vms = useMemo(() => {
    if (sort.key === "name" && sort.dir === 1) return listed;
    return [...listed].sort(
      (a, b) =>
        compareNullsLast(sortValue(a, sort.key, usageOf(a)), sortValue(b, sort.key, usageOf(b)), sort.dir) ||
        a.displayName.localeCompare(b.displayName),
    );
  }, [listed, sort, usageOf]);

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
  const listReady = !loading && listedFor === filter;
  if (request && request.n !== handledRequest && listReady) {
    const wanted = new Set(request.vmxPaths.map(keyOf));
    const found = listed.filter((v) => wanted.has(keyOf(v.vmxPath)));
    if (found.length < wanted.size && !isEmptyFilter(filter)) {
      // The list is read again for the empty filter; the request is handled then.
      setFilter({});
    } else {
      setHandledRequest(request.n);
      setView(request.view);
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
            : "Snapshots are in each VM's details: click a VM's name. To work on several VMs, select them and use the Snapshots button.",
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

  function power(action: Action) {
    const targets = targetsFor(action.appliesTo);
    return {
      count: targets.length,
      run: () => void submit({ type: "vmPower", targets: refs(targets), op: action.op }),
    };
  }

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

  // VM-04: the selection's trees, read when its Snapshots menu opens; null until every one is read.
  const selectionTrees = selectedVms.every((v) => trees.map.has(keyOf(v.vmxPath)))
    ? selectedVms.flatMap((v) => trees.map.get(keyOf(v.vmxPath)) ?? [])
    : null;
  const selectionSummary = selectionTrees ? summarize(selectionTrees) : null;
  const snapshotReasons = selectionError
    ? { take: selectionError, revert: selectionError, delete: selectionError }
    : bulkSnapshotReasons({ readOnly, selected: selectedVms, trees: selectionTrees, busy: submitting });
  const snapshotMenuReason = readOnly ?? (selected.size === 0 ? "Select VMs first" : null);
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

  const start = targetsFor(STARTABLE);
  const shutDown = power(SHUT_DOWN);
  const suspend = power(SUSPEND);
  const powerOff = power(POWER_OFF);
  const toProtect = selectedVms.filter((v) => !v.protected);
  const toUnprotect = selectedVms.filter((v) => v.protected);
  const selectedLabels = new Set(selectedVms.map((v) => v.environment));
  // Ticked in the Label menu when every selected VM has it.
  const sharedLabel = selectedLabels.size === 1 ? [...selectedLabels][0] : "";
  const missingWorkstation = warnings.some((w) => w.code === "vmrun_not_found");
  const virtualboxTrouble = warnings.some((w) => w.code.startsWith("vboxmanage"));
  const filtered = !isEmptyFilter(filter);
  const oldAfterDays = limits?.oldAfterDays ?? 30;

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

  // The list's columns, in order.
  const columns: Column[] = [
    {
      id: "name",
      head: sortHead("name", "Name", "min-w-48"),
      cell: (vm) => (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              className="rounded-sm text-left font-medium underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              title="Show its details and snapshots"
              aria-expanded={detail === vm.vmxPath}
              aria-controls={detail === vm.vmxPath ? "vm-details" : undefined}
              onClick={(e) => {
                e.stopPropagation();
                toggleDetails(vm.vmxPath);
              }}
            >
              {vm.displayName}
            </button>
            {vm.protected && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
                </TooltipTrigger>
                <TooltipContent>{PROTECTED_REASON}</TooltipContent>
              </Tooltip>
            )}
            {vm.tags.map((t) => (
              <Badge key={t} variant="secondary" className="font-normal">
                {t}
              </Badge>
            ))}
          </div>
          <div className="font-mono text-xs break-all whitespace-normal text-muted-foreground">{vmLocation(vm)}</div>
        </>
      ),
    },
    {
      id: "hypervisor",
      head: sortHead("hypervisor", "Hypervisor"),
      cell: (vm) => <HypervisorLabel hypervisor={vm.hypervisor} />,
    },
    {
      id: "guestOs",
      wide: true,
      head: <TableHead>Guest OS</TableHead>,
      cell: (vm) => vm.guestOsName ?? vm.guestOs ?? <span className="text-muted-foreground">—</span>,
    },
    {
      id: "vcpus",
      wide: true,
      head: sortHead("vcpus", "vCPU", "text-right"),
      className: "text-right tabular-nums",
      cell: (vm) => vm.numVcpus ?? "—",
    },
    {
      id: "ram",
      wide: true,
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
    { id: "tools", wide: true, head: <TableHead>Tools</TableHead>, cell: (vm) => <ToolsLabel state={vm.toolsState} /> },
    { id: "state", head: sortHead("state", "State"), cell: (vm) => <StateBadge state={vm.powerState} /> },
    {
      id: "hostCpu",
      head: sortHead("hostCpu", "% of host CPU", "w-24 whitespace-normal", HOST_SHARE_HINT.cpu),
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
      head: sortHead("hostMem", "% of host RAM", "w-24 whitespace-normal", HOST_SHARE_HINT.memory),
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
    { id: "label", head: sortHead("label", "Label"), cell: (vm) => <EnvBadge env={vm.environment} /> },
  ];
  const shownColumns = detailOpen ? columns.filter((c) => !c.wide) : columns;

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" onClick={() => setRefreshes((n) => n + 1)} disabled={loading}>
          <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : undefined} />
          Refresh
        </Button>
        {/* VM-21: new VMs from a launch template or Custom (the Deploy dialog). */}
        <WhyDisabled reason={readOnly}>
          <Button variant="outline" disabled={readOnly !== null} onClick={onDeploy}>
            <RocketIcon data-icon="inline-start" />
            Deploy
          </Button>
        </WhyDisabled>
        <VmFilterBar
          filter={filter}
          onChange={setFilter}
          tags={tags}
          savedFilters={savedFilters}
          onApplySaved={(saved) => void selectMatching(saved.filter)}
          onSaveCurrent={() => setDialog({ kind: "saveFilter" })}
          onDeleteSaved={(saved) => void deleteSaved(saved)}
        />
        <span className="ml-auto text-sm text-muted-foreground">
          {filtered ? `${vms.length} of ${plural(total.vms, "VM")}` : plural(total.vms, "VM")} · {total.running} running
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline">
              <ListChecksIcon data-icon="inline-start" />
              Select
              <ChevronDownIcon data-icon="inline-end" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64">
            <DropdownMenuItem
              disabled={vms.length === 0}
              onSelect={() => setSelected(new Set(vms.map((v) => v.vmxPath)))}
            >
              All shown
              <DropdownMenuShortcut>{vms.length}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem disabled={selected.size === 0} onSelect={() => setSelected(new Set())}>
              None
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuSub>
              <DropdownMenuSubTrigger disabled={tags.length === 0}>By tag</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                {tags.map((t) => (
                  <DropdownMenuItem key={t.id} onSelect={() => void selectMatching({ tags: [t.name] })}>
                    {t.name}
                    <DropdownMenuShortcut>{t.vmCount}</DropdownMenuShortcut>
                  </DropdownMenuItem>
                ))}
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger disabled={savedFilters.length === 0}>By saved filter</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                {savedFilters.map((f) => (
                  <DropdownMenuItem key={f.id} onSelect={() => void selectMatching(f.filter)}>
                    {f.name}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger disabled={vms.length === 0}>By snapshots</DropdownMenuSubTrigger>
              <DropdownMenuSubContent className="w-64">
                <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                  Reads the snapshots of the VMs shown
                </DropdownMenuLabel>
                <DropdownMenuItem onSelect={() => pickBySnapshots({ kind: "old" })}>
                  With snapshots older than {oldAfterDays} days
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => pickBySnapshots({ kind: "safety" })}>
                  With safety snapshots
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setDialog({ kind: "snapshotName" })}>
                  With a snapshot named…
                </DropdownMenuItem>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
          </DropdownMenuContent>
        </DropdownMenu>
        <span className="mr-2 text-sm text-muted-foreground">{selected.size} selected</span>

        <WhyDisabled reason={readOnly}>
          <ButtonGroup>
            <Button
              variant="outline"
              disabled={start.length === 0 || submitting || readOnly !== null}
              onClick={() => void submit({ type: "vmPower", targets: refs(start), op: { kind: "start", gui: false } })}
            >
              <PlayIcon data-icon="inline-start" />
              Start
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="More ways to start"
                  disabled={start.length === 0 || submitting || readOnly !== null}
                >
                  <ChevronDownIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-64">
                <DropdownMenuItem
                  onSelect={() =>
                    void submit({ type: "vmPower", targets: refs(start), op: { kind: "start", gui: false } })
                  }
                >
                  Start in the background
                  <DropdownMenuShortcut>{start.length}</DropdownMenuShortcut>
                </DropdownMenuItem>
                <DropdownMenuItem
                  onSelect={() =>
                    void submit({ type: "vmPower", targets: refs(start), op: { kind: "start", gui: true } })
                  }
                >
                  Start with a console window
                  <DropdownMenuShortcut>{start.length}</DropdownMenuShortcut>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </ButtonGroup>
        </WhyDisabled>
        <WhyDisabled reason={readOnly}>
          <Button
            variant="outline"
            disabled={shutDown.count === 0 || submitting || readOnly !== null}
            onClick={shutDown.run}
          >
            {SHUT_DOWN.label}
          </Button>
        </WhyDisabled>
        <WhyDisabled reason={readOnly}>
          <Button
            variant="outline"
            disabled={suspend.count === 0 || submitting || readOnly !== null}
            onClick={suspend.run}
          >
            {SUSPEND.label}
          </Button>
        </WhyDisabled>
        <WhyDisabled reason={readOnly}>
          <Button
            variant="destructive"
            disabled={powerOff.count === 0 || submitting || readOnly !== null}
            onClick={powerOff.run}
          >
            {POWER_OFF.label}
          </Button>
        </WhyDisabled>

        {/* VM-04: snapshots of the selection. The trees are read when the menu opens. */}
        <DropdownMenu onOpenChange={(open) => open && readSelection()}>
          <WhyDisabled reason={snapshotMenuReason}>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" disabled={snapshotMenuReason !== null}>
                <CameraIcon data-icon="inline-start" />
                Snapshots
                <ChevronDownIcon data-icon="inline-end" />
              </Button>
            </DropdownMenuTrigger>
          </WhyDisabled>
          <DropdownMenuContent align="start" className="w-72">
            <DropdownMenuLabel>
              Snapshots of {plural(selectedVms.length, "selected VM")}
              <span className="block text-xs font-normal text-muted-foreground">
                {selectionError ??
                  (selectionSummary
                    ? `${plural(selectionSummary.snapshots, "snapshot")}` +
                      (selectionSummary.old > 0 ? ` · ${selectionSummary.old} older than ${oldAfterDays} days` : "") +
                      (selectionSummary.safety > 0 ? ` · ${selectionSummary.safety} safety` : "")
                    : "Reading their snapshots…")}
              </span>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled={snapshotReasons.take !== null} onSelect={() => openBulk("take")}>
              <CameraIcon />
              <span>
                Take a snapshot…
                <ReasonLine reason={snapshotReasons.take} />
              </span>
              <DropdownMenuShortcut>{selectedVms.length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem disabled={snapshotReasons.revert !== null} onSelect={() => openBulk("revert")}>
              <Undo2Icon />
              <span>
                Revert to a snapshot…
                <ReasonLine reason={snapshotReasons.revert} />
              </span>
              <DropdownMenuShortcut>{withSnapshots.length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem disabled={snapshotReasons.delete !== null} onSelect={() => openBulk("delete")}>
              <Trash2Icon />
              <span>
                Delete a snapshot…
                <ReasonLine reason={snapshotReasons.delete} />
              </span>
              <DropdownMenuShortcut>{withSnapshots.length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" disabled={selected.size === 0 || submitting || readOnly !== null}>
              <EllipsisIcon data-icon="inline-start" />
              More
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-56">
            {MORE.map((a) => {
              const { count, run } = power(a);
              return (
                <DropdownMenuItem key={a.label} disabled={count === 0} onSelect={run}>
                  {a.label}
                  <DropdownMenuShortcut>{count || ""}</DropdownMenuShortcut>
                </DropdownMenuItem>
              );
            })}
            <DropdownMenuSeparator />
            {/* VM-10: a full clone of each selected VM, as one job. */}
            <DropdownMenuItem onSelect={() => setDialog({ kind: "clone" })}>
              <CopyIcon />
              Clone…
              <DropdownMenuShortcut>{selectedVms.length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Tags</DropdownMenuLabel>
            <DropdownMenuItem onSelect={() => setDialog({ kind: "addTag" })}>
              <TagIcon />
              Add a tag…
            </DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger disabled={selectedTags.length === 0}>Remove a tag</DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                {selectedTags.map((t) => (
                  <DropdownMenuItem key={t} onSelect={() => void untag(t)}>
                    {t}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSeparator />
            <DropdownMenuSub>
              <DropdownMenuSubTrigger>
                <FlagIcon />
                Label
              </DropdownMenuSubTrigger>
              <DropdownMenuSubContent className="w-44">
                <DropdownMenuRadioGroup value={sharedLabel} onValueChange={(v) => chooseLabel(v as Environment)}>
                  {LABELS.map((l) => {
                    const changes = selectedVms.filter((v) => v.environment !== l.value).length;
                    return (
                      <DropdownMenuRadioItem key={l.value} value={l.value}>
                        {l.label}
                        <DropdownMenuShortcut>{changes || ""}</DropdownMenuShortcut>
                      </DropdownMenuRadioItem>
                    );
                  })}
                </DropdownMenuRadioGroup>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSeparator />
            <DropdownMenuLabel>Do not touch (AP-04)</DropdownMenuLabel>
            <DropdownMenuItem
              disabled={toProtect.length === 0}
              onSelect={() => void submit({ type: "vmProtect", targets: refs(toProtect), protected: true })}
            >
              <ShieldIcon />
              Protect
              <DropdownMenuShortcut>{toProtect.length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={toUnprotect.length === 0}
              onSelect={() => void submit({ type: "vmProtect", targets: refs(toUnprotect), protected: false })}
            >
              <ShieldOffIcon />
              Unprotect
              <DropdownMenuShortcut>{toUnprotect.length || ""}</DropdownMenuShortcut>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

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
        <Empty className="border">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <MonitorOffIcon />
            </EmptyMedia>
            <EmptyTitle>No VMs found</EmptyTitle>
            <EmptyDescription>
              Remotely lists the VMs in VMware Workstation&apos;s library and in folders you choose, and the VMs
              registered in Oracle VirtualBox. Open a VM in Workstation once, add the folder that holds your VMs, or
              register the VM in VirtualBox.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button variant="outline" onClick={onOpenSettings}>
              <FolderPlusIcon data-icon="inline-start" />
              Add a VM folder
            </Button>
          </EmptyContent>
        </Empty>
      )}

      {total.vms > 0 && vms.length === 0 && filtered && (
        <p className="text-sm text-muted-foreground">No VMs match the filter.</p>
      )}

      {hasRows && (
        <ResizablePanelGroup orientation="horizontal" id="vms-split" className="min-h-0 flex-1">
          <ResizablePanel id="vms-list" minSize="30%">
            <div className="h-full overflow-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        aria-label="Select all shown VMs"
                        checked={allSelected ? true : selected.size > 0 ? "indeterminate" : false}
                        onCheckedChange={() =>
                          setSelected(allSelected ? new Set() : new Set(vms.map((v) => v.vmxPath)))
                        }
                      />
                    </TableHead>
                    {shownColumns.map((c) => (
                      <Fragment key={c.id}>{c.head}</Fragment>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vms.map((vm, i) => (
                    <TableRow
                      key={vm.vmxPath}
                      data-state={selected.has(vm.vmxPath) ? "selected" : undefined}
                      onClick={(e) => toggle(i, e)}
                      className={cn(
                        "select-none",
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
                    </TableRow>
                  ))}
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
              />
            )}
          </ResizablePanel>
        </ResizablePanelGroup>
      )}

      {hasRows && (
        <p className="text-xs text-muted-foreground">
          Click a row to select it, Shift+click to select a range. Click a VM&apos;s name for its details and snapshots;
          the Snapshots button works on the selection.
        </p>
      )}

      <HostDetailsSheet session={hostDetails} thresholds={thresholds} onClose={() => setHostDetails(null)} />

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
          description="Tags are Remotely's own labels for picking VMs. They do not change the VMs."
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
          title="Save the current filter"
          description="Pick it later from Saved filters to show and select the VMs it matches. Saving under an existing name replaces that filter."
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
          description={`Of the ${plural(vms.length, "VM")} shown, selects the ones with a snapshot whose name contains this text, in any letter case. Their snapshot lists are read first.`}
          label="Snapshot name, or part of it"
          submitLabel="Select"
          maxLength={limits?.maxNameLength ?? 80}
          onSubmit={(name) => selectBySnapshots({ kind: "named", text: name })}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "clone" && (
        <CloneDialog vms={selectedVms} onSubmitted={onSubmitted} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "lowerProd" && (
        <ConfirmDialog
          title="Remove the Prod label?"
          description={lowerProdText(dialog.prodNames, dialog.environment)}
          confirmLabel={dialog.environment === "none" ? "Remove label" : `Label ${labelName(dialog.environment)}`}
          onConfirm={() => applyLabel(dialog.vmxPaths, dialog.environment)}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}
