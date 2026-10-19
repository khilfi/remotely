// VM list (VM-01) with selection by click, shift-click, tag or saved filter and bulk power actions
// (VM-02, VM-03), plus protect and unprotect (AP-04) and environment labels (SS-06). The selection
// opens in the snapshot manager (VM-04). Listing asks the core to read Workstation's library, the
// chosen folders and `vmrun list`; every action is a command submitted to the command bus, never a
// vmrun call. Tags and labels are the app's own data, so they skip the bus.
//
// Each running VM shows its share of this host's CPU and RAM (MO-01), read from the metrics
// collector's latest 5-second round in memory: no extra polling. The sessions linked to each VM
// (QL-01, made automatically by IP address) show in their own column, where they can be kept,
// changed or removed. Columns sort by a click on their header.

import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";
import {
  CameraIcon,
  ChevronDownIcon,
  EllipsisIcon,
  FlagIcon,
  FolderPlusIcon,
  ListChecksIcon,
  MonitorOffIcon,
  PlayIcon,
  RefreshCwIcon,
  ShieldIcon,
  ShieldOffIcon,
  TagIcon,
  TriangleAlertIcon,
} from "lucide-react";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, StateBadge, ToolsLabel } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { MetricCell } from "@/components/MetricBits";
import { NameDialog } from "@/components/NameDialog";
import { SortableHead } from "@/components/SortableHead";
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
  type Environment,
  type InventoryWarning,
  type PowerOp,
  type PowerState,
  type SavedFilter,
  type SessionRecord,
  type SubmitOutcome,
  type Tag,
  type VmFilter,
  type VmHostUsage,
  type VmRecord,
} from "@/lib/api";
import { compareNullsLast, formatPct, HOST_SHARE_HINT, useThresholds } from "@/lib/metrics";

interface Props {
  /** True while the page is shown: the host shares (MO-01) follow the metrics rounds only then. */
  active: boolean;
  /** Shows the approval dialog for commands the policy engine says need one. */
  onSubmitted: (outcome: SubmitOutcome) => void;
  onOpenSettings: () => void;
  /** VM-04: opens the snapshot manager with these VMs selected. */
  onOpenSnapshots: (vmxPaths: string[]) => void;
  /** Changes when the list should be read again: a job finished or a setting changed. */
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
type SortKey = "name" | "vcpus" | "ram" | "state" | "hostCpu" | "hostMem" | "label";

/** Running first, then the states a VM passes through on its way down. */
const STATE_ORDER: PowerState[] = ["running", "paused", "suspended", "not_running", "unknown"];
const LABEL_ORDER: Environment[] = ["prod", "staging", "lab", "none"];

function sortValue(vm: VmRecord, key: SortKey, usage: VmHostUsage | undefined): number | string | null {
  switch (key) {
    case "name":
      return vm.displayName.toLowerCase();
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

export function VmsPage({ active, onSubmitted, onOpenSettings, onOpenSnapshots, refreshKey }: Props) {
  // FD-03: power actions, protection, tags and labels are off while the read-only lock applies (the core refuses them
  // too); the page's notice says so.
  const readOnly = useReadOnlyReason();
  const [listed, setListed] = useState<VmRecord[]>([]);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "name", dir: 1 });
  const [usage, setUsage] = useState<Map<string, VmHostUsage>>(new Map());
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [linksVersion, setLinksVersion] = useState(0);
  const [thresholds] = useThresholds();
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

  // Finds every VM on open, on Refresh, after a job finishes and after a setting changes.
  useEffect(() => {
    let stale = false;
    api.vmRefresh().then(
      (report) => {
        if (stale) return;
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
        if (stale) return;
        setError({ code: errorCode(err), message: errorMessage(err) });
        setLoadedKey(key);
      },
    );
    return () => {
      stale = true;
    };
  }, [key]);

  // The shown list: what the last refresh saved, narrowed by the filter in the core (VM-02).
  useEffect(() => {
    let stale = false;
    Promise.all([api.vmList(filter), api.tags(), api.savedFilters()]).then(
      ([list, allTags, filters]) => {
        if (stale) return;
        setListed(list);
        // Tags are shared with sessions (SS-01); this page offers the ones on VMs.
        setTags(allTags.filter((t) => t.vmCount > 0));
        setSavedFilters(filters);
        // Actions only reach VMs the user can see.
        setSelected((prev) => new Set(list.map((v) => v.vmxPath).filter((p) => prev.has(p))));
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

  // MO-01: each running VM's share of the host, after every metrics round while the page shows.
  useEffect(() => {
    if (!active) return;
    let stale = false;
    const read = () =>
      api.metricsHostUsage().then(
        (list) => {
          if (!stale) setUsage(new Map(list.map((u) => [u.vmxPath.toLowerCase(), u])));
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
  }, [active]);

  const usageOf = useCallback((vm: VmRecord) => usage.get(vm.vmxPath.toLowerCase()), [usage]);
  // The shown order. Selection and shift-click ranges follow it.
  const vms = useMemo(() => {
    if (sort.key === "name" && sort.dir === 1) return listed;
    return [...listed].sort(
      (a, b) =>
        compareNullsLast(sortValue(a, sort.key, usageOf(a)), sortValue(b, sort.key, usageOf(b)), sort.dir) ||
        a.displayName.localeCompare(b.displayName),
    );
  }, [listed, sort, usageOf]);

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

  const selectedVms = vms.filter((v) => selected.has(v.vmxPath));
  const allSelected = vms.length > 0 && selected.size === vms.length;
  const selectedTags = [...new Set(selectedVms.flatMap((v) => v.tags))].sort((a, b) => a.localeCompare(b));
  const refs = (targets: VmRecord[]) => targets.map((v) => ({ kind: "vm" as const, vmxPath: v.vmxPath }));

  /** Selected VMs the action applies to. Unknown state (vmrun missing) is sent as is. */
  function targetsFor(appliesTo: PowerState[]) {
    return selectedVms.filter((v) => v.powerState === "unknown" || appliesTo.includes(v.powerState));
  }

  async function submit(command: Command) {
    setSubmitting(true);
    try {
      onSubmitted(await api.submit(command));
    } catch (err) {
      toast.error(errorMessage(err));
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
  const filtered = !isEmptyFilter(filter);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" onClick={() => setRefreshes((n) => n + 1)} disabled={loading}>
          <RefreshCwIcon data-icon="inline-start" className={loading ? "animate-spin" : undefined} />
          Refresh
        </Button>
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
          <DropdownMenuContent align="start" className="w-56">
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

        <Button
          variant="outline"
          disabled={selected.size === 0}
          onClick={() => onOpenSnapshots(selectedVms.map((v) => v.vmxPath))}
        >
          <CameraIcon data-icon="inline-start" />
          Snapshots
        </Button>

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
            {missingWorkstation ? "VMware Workstation was not found" : "Some VMs may be missing from the list"}
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
              Remotely lists the VMs in VMware Workstation&apos;s library and in folders you choose. Open a VM in
              Workstation once, or add the folder that holds your VMs.
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

      {vms.length > 0 && (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10">
                  <Checkbox
                    aria-label="Select all shown VMs"
                    checked={allSelected ? true : selected.size > 0 ? "indeterminate" : false}
                    onCheckedChange={() => setSelected(allSelected ? new Set() : new Set(vms.map((v) => v.vmxPath)))}
                  />
                </TableHead>
                <SortableHead
                  label="Name"
                  className="min-w-48"
                  active={sort.key === "name"}
                  dir={sort.dir}
                  onSort={() => sortBy("name")}
                />
                <TableHead>Guest OS</TableHead>
                <SortableHead
                  label="vCPU"
                  className="text-right"
                  active={sort.key === "vcpus"}
                  dir={sort.dir}
                  onSort={() => sortBy("vcpus")}
                />
                <SortableHead
                  label="RAM"
                  className="text-right"
                  active={sort.key === "ram"}
                  dir={sort.dir}
                  onSort={() => sortBy("ram")}
                />
                <TableHead>IP address</TableHead>
                <TableHead>Tools</TableHead>
                <SortableHead
                  label="State"
                  active={sort.key === "state"}
                  dir={sort.dir}
                  onSort={() => sortBy("state")}
                />
                <SortableHead
                  label="% of host CPU"
                  hint={HOST_SHARE_HINT.cpu}
                  className="w-24 whitespace-normal"
                  active={sort.key === "hostCpu"}
                  dir={sort.dir}
                  onSort={() => sortBy("hostCpu")}
                />
                <SortableHead
                  label="% of host RAM"
                  hint={HOST_SHARE_HINT.memory}
                  className="w-24 whitespace-normal"
                  active={sort.key === "hostMem"}
                  dir={sort.dir}
                  onSort={() => sortBy("hostMem")}
                />
                <TableHead>Sessions</TableHead>
                <SortableHead
                  label="Label"
                  active={sort.key === "label"}
                  dir={sort.dir}
                  onSort={() => sortBy("label")}
                />
              </TableRow>
            </TableHeader>
            <TableBody>
              {vms.map((vm, i) => {
                const share = usageOf(vm);
                const hostCpu = share?.hostCpuPct ?? null;
                const hostMem = share?.hostMemPct ?? null;
                return (
                  <TableRow
                    key={vm.vmxPath}
                    data-state={selected.has(vm.vmxPath) ? "selected" : undefined}
                    onClick={(e) => toggle(i, e)}
                    className="select-none"
                  >
                    <TableCell>
                      {/* The click (or Space) bubbles to the row, which does the selecting. */}
                      <Checkbox aria-label={`Select ${vm.displayName}`} checked={selected.has(vm.vmxPath)} />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-1.5 font-medium">
                        {vm.displayName}
                        {vm.protected && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
                            </TooltipTrigger>
                            <TooltipContent>Protected: actions skip this VM until it is unprotected</TooltipContent>
                          </Tooltip>
                        )}
                        {vm.tags.map((t) => (
                          <Badge key={t} variant="secondary" className="font-normal">
                            {t}
                          </Badge>
                        ))}
                      </div>
                      <div className="font-mono text-xs break-all whitespace-normal text-muted-foreground">
                        {vm.vmxPath}
                      </div>
                    </TableCell>
                    <TableCell>
                      {vm.guestOsName ?? vm.guestOs ?? <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{vm.numVcpus ?? "—"}</TableCell>
                    <TableCell className="text-right tabular-nums">{formatRam(vm.memsizeMb)}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {vm.ipAddress ? (
                        <span data-mask="ip">{vm.ipAddress}</span>
                      ) : (
                        <span className="font-sans text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <ToolsLabel state={vm.toolsState} />
                    </TableCell>
                    <TableCell>
                      <StateBadge state={vm.powerState} />
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={hostCpu}
                        text={formatPct(hostCpu)}
                        pct={hostCpu}
                        limits={thresholds.cpu}
                        label={`${vm.displayName}'s share of this host's CPU`}
                      />
                    </TableCell>
                    <TableCell>
                      <MetricCell
                        value={hostMem}
                        text={formatPct(hostMem)}
                        pct={hostMem}
                        limits={thresholds.memory}
                        label={`${vm.displayName}'s share of this host's RAM`}
                      />
                    </TableCell>
                    {/* The cell has its own controls: a click there doesn't select the row. */}
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <VmSessionLinks vm={vm} sessions={sessions} onChanged={linksChanged} />
                    </TableCell>
                    <TableCell>
                      <EnvBadge env={vm.environment} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
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
