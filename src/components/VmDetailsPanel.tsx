// QL-14: one VM's panel beside the list on the Virtual machines page, with two tabs. Details: what the inventory knows
// (VM-01), its share of this host (MO-01), its label (SS-06), protection (AP-04), tags and linked sessions (QL-01).
// Snapshots: its tree from the .vmsd (VM-04), read when the panel opens, with take, revert and delete on it. Every
// action is a command for the bus; the tiers shown come from the policy engine's preview, and the approval dialog
// (AP-02 impact preview, VM-05 safety snapshot) follows the submit as from anywhere else.
//
// VM-18: the hypervisor comes first in `detailRows`, then its own facts (a VirtualBox VM's UUID), and the guest tools
// row is named for it ("VMware Tools" or "Guest Additions").
// MO-13: the System tab (VmSystemTab) shows the VM's virtual hardware and its guest's own facts.

import { useEffect, useState, type ReactNode } from "react";
import {
  CameraIcon,
  HistoryIcon,
  InfoIcon,
  MonitorIcon,
  RefreshCwIcon,
  ShieldIcon,
  TriangleAlertIcon,
  XIcon,
  ZapIcon,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, StateBadge, ToolsLabel } from "@/components/Badges";
import { MetricCell } from "@/components/MetricBits";
import { SnapshotTree } from "@/components/SnapshotTree";
import { VmSessionLinks } from "@/components/VmLinkControls";
import { VmSystemTab } from "@/components/VmSystemTab";
import { WhyDisabled } from "@/components/WhyDisabled";
import { VmSettingsTab } from "@/components/VmSettingsTab";
import { VmSchedulesTab, type ScheduleAsk } from "@/components/VmSchedulesTab";
import {
  api,
  type Command,
  type SubmitOutcome,
  type SessionRecord,
  type SnapshotLimits,
  type SnapshotNode,
  type SnapshotOp,
  type VmHostUsage,
  type VmRecord,
  type VmSnapshots,
} from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";
import { HYPERVISORS, toolsName, vmLocation } from "@/lib/hypervisors";
import { formatPct, HOST_SHARE_HINT, type Thresholds } from "@/lib/metrics";
import { approvalHint, PROTECTED_REASON, takeReason, type VmView } from "@/lib/vm-snapshots";

interface Props {
  vm: VmRecord;
  view: VmView;
  onViewChange: (view: VmView) => void;
  onClose: () => void;
  /** Changes when a job finished or a setting changed: the tiers are asked again. */
  refreshKey: string;
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  busy: boolean;
  /** FD-01: the command palette on this VM (power and protection, with their tiers). */
  onActions: () => void;
  /** MO-13: opens a linked session's host details. */
  onHostDetails: (session: { id: string; name: string }) => void;

  usage: VmHostUsage | undefined;
  thresholds: Thresholds;
  sessions: SessionRecord[];
  onLinksChanged: () => void;

  /** The VM's tree, once read; undefined while it is read or when reading failed. */
  tree: VmSnapshots | undefined;
  treeError: string | null;
  onReadTree: () => void;
  limits: SnapshotLimits | null;
  onTake: () => void;
  onRevert: (node: SnapshotNode) => void;
  onDelete: (node: SnapshotNode) => void;

  /** VM-23: submits a settings command to the bus; resolves true when the bus took it. */
  onSubmit: (command: Command) => Promise<boolean>;
  /** VM-23: the outcome of a command the shell built (ISO, shared folder). */
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** VM-24: the hypervisor's own window. */
  onOpenConsole: () => void;
  /** VM-24: the palette's asks to rename the VM, and the last one its dialog showed for. */
  askRename: number;
  renameSeen: number;
  onRenameSeen: (n: number) => void;
  /** VM-14, VM-27: the Schedules page, for a new schedule on this VM or one schedule's runs. */
  onSchedules?: (ask: ScheduleAsk) => void;
}

type Hints = { take: string | null; revert: string | null; delete: string | null };

function formatRam(mb: number | null) {
  if (!mb) return "—";
  return mb % 1024 === 0 ? `${mb / 1024} GB` : `${(mb / 1024).toFixed(1)} GB`;
}

const dash = <span className="text-muted-foreground">—</span>;

export function VmDetailsPanel(props: Props) {
  const { vm, view, onViewChange, onClose, refreshKey, onActions, tree } = props;
  const hints = useHints(vm, tree, refreshKey);

  return (
    <aside
      id="vm-details"
      data-vm-drop={vm.vmxPath}
      aria-label={`${vm.displayName}: details and snapshots`}
      className="flex h-full min-h-0 flex-col rounded-lg border"
    >
      <div className="flex items-start gap-2 border-b p-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <h2 className="font-semibold break-words">{vm.displayName}</h2>
            {vm.protected && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />
                </TooltipTrigger>
                <TooltipContent>{PROTECTED_REASON}</TooltipContent>
              </Tooltip>
            )}
            {vm.environment !== "none" && <EnvBadge env={vm.environment} />}
            <StateBadge state={vm.powerState} />
          </div>
          <div className="font-mono text-xs break-all text-muted-foreground">{vmLocation(vm)}</div>
        </div>
        <Button size="icon-sm" variant="ghost" aria-label="Close the details" onClick={onClose}>
          <XIcon />
        </Button>
      </div>

      <Tabs
        value={view}
        onValueChange={(v) => onViewChange(v as VmView)}
        className="min-h-0 flex-1 gap-0"
        aria-label={`${vm.displayName}'s details`}
      >
        <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
          <TabsList>
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="settings">Settings</TabsTrigger>
            <TabsTrigger value="system">System</TabsTrigger>
            <TabsTrigger value="snapshots">
              Snapshots
              {tree && (
                <Badge variant="secondary" className="h-4 min-w-4 px-1 tabular-nums">
                  {tree.snapshots.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="schedules">Schedules</TabsTrigger>
          </TabsList>
          <WhyDisabled reason={props.readOnly} className="ml-auto">
            <Button
              variant="outline"
              size="sm"
              className={props.readOnly ? undefined : "ml-auto"}
              disabled={props.readOnly !== null}
              title={
                vm.hypervisor === "virtualbox"
                  ? "VirtualBox's own window; a VM that is off starts with it"
                  : "Workstation's own window, in a tab, without powering the VM on"
              }
              onClick={props.onOpenConsole}
            >
              <MonitorIcon data-icon="inline-start" />
              Console
            </Button>
          </WhyDisabled>
          <Button variant="outline" size="sm" onClick={onActions}>
            <ZapIcon data-icon="inline-start" />
            Actions…
          </Button>
        </div>
        <TabsContent value="details" className="min-h-0 overflow-auto p-3">
          <DetailsTab {...props} />
        </TabsContent>
        <TabsContent value="settings" className="min-h-0 overflow-auto p-3">
          {view === "settings" && (
            <VmSettingsTab
              vm={vm}
              readOnly={props.readOnly}
              busy={props.busy}
              snapshots={!tree ? null : tree.error ? "failed" : tree.snapshots.length}
              refreshKey={refreshKey}
              onSubmit={props.onSubmit}
              onSubmitted={props.onSubmitted}
              askRename={props.askRename}
              renameSeen={props.renameSeen}
              onRenameSeen={props.onRenameSeen}
            />
          )}
        </TabsContent>
        <TabsContent value="system" className="min-h-0 overflow-auto p-3">
          {view === "system" && (
            <VmSystemTab vm={vm} thresholds={props.thresholds} onHostDetails={props.onHostDetails} />
          )}
        </TabsContent>
        <TabsContent value="snapshots" className="min-h-0 overflow-auto p-3">
          <SnapshotsTab {...props} hints={hints} />
        </TabsContent>
        <TabsContent value="schedules" className="min-h-0 overflow-auto p-3">
          {view === "schedules" && (
            <VmSchedulesTab
              vm={vm}
              refreshKey={refreshKey}
              readOnly={props.readOnly}
              onSchedules={(ask) => props.onSchedules?.(ask)}
            />
          )}
        </TabsContent>
      </Tabs>
    </aside>
  );
}

/** One row of the Details tab. */
interface DetailRow {
  label: string;
  value: ReactNode;
  hint?: string;
}

/** The Details tab's rows, in order: the hypervisor and its own facts first (VM-18). */
function detailRows({ vm, usage, thresholds, sessions, onLinksChanged }: Props): DetailRow[] {
  const hostCpu = usage?.hostCpuPct ?? null;
  const hostMem = usage?.hostMemPct ?? null;
  const hypervisor: DetailRow[] = [
    { label: "Hypervisor", value: HYPERVISORS.find((h) => h.value === vm.hypervisor)?.label ?? vm.hypervisor },
  ];
  if (vm.hypervisor === "virtualbox") {
    hypervisor.push({
      label: "UUID",
      hint: "VirtualBox's id for the VM; it stays the same when the VM is renamed or moved",
      value: <span className="font-mono text-xs break-all">{vm.vmxPath}</span>,
    });
  }
  const rows: DetailRow[] = [
    ...hypervisor,
    { label: "Guest OS", value: vm.guestOsName ?? vm.guestOs ?? dash },
    { label: "vCPUs", value: vm.numVcpus ?? dash },
    { label: "RAM", value: formatRam(vm.memsizeMb) },
    {
      label: "IP address",
      value: vm.ipAddress ? (
        <span className="font-mono text-xs" data-mask="ip">
          {vm.ipAddress}
        </span>
      ) : (
        dash
      ),
    },
    { label: toolsName(vm.hypervisor), value: <ToolsLabel state={vm.toolsState} /> },
    {
      label: "% of host CPU",
      hint: HOST_SHARE_HINT.cpu,
      value: (
        <MetricCell
          value={hostCpu}
          text={formatPct(hostCpu)}
          pct={hostCpu}
          limits={thresholds.cpu}
          label={`${vm.displayName}'s share of this host's CPU`}
        />
      ),
    },
    {
      label: "% of host RAM",
      hint: HOST_SHARE_HINT.memory,
      value: (
        <MetricCell
          value={hostMem}
          text={formatPct(hostMem)}
          pct={hostMem}
          limits={thresholds.memory}
          label={`${vm.displayName}'s share of this host's RAM`}
        />
      ),
    },
    { label: "Label", value: <EnvBadge env={vm.environment} /> },
    {
      label: "Protected",
      value: vm.protected ? (
        <span className="flex items-center gap-1.5">
          <ShieldIcon className="size-3.5 text-tier-high" aria-hidden />
          Yes: actions skip this VM
        </span>
      ) : (
        "No"
      ),
    },
    {
      label: "Tags",
      value:
        vm.tags.length === 0 ? (
          dash
        ) : (
          <span className="flex flex-wrap gap-1">
            {vm.tags.map((t) => (
              <Badge key={t} variant="secondary" className="font-normal">
                {t}
              </Badge>
            ))}
          </span>
        ),
    },
    { label: "Sessions", value: <VmSessionLinks vm={vm} sessions={sessions} onChanged={onLinksChanged} /> },
    { label: "Last seen", value: formatWhen(vm.lastSeenAt) },
  ];
  return rows;
}

function DetailsTab(props: Props) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] items-center gap-x-4 gap-y-2.5">
      {detailRows(props).map((row) => (
        <div key={row.label} className="contents">
          <dt className="text-muted-foreground" title={row.hint}>
            {row.label}
          </dt>
          <dd className="min-w-0">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function SnapshotsTab({
  vm,
  tree,
  treeError,
  onReadTree,
  limits,
  readOnly,
  busy,
  onTake,
  onRevert,
  onDelete,
  hints,
}: Props & { hints: Hints }) {
  const loading = !tree && !treeError;
  const takeOff = takeReason({ readOnly, protected: vm.protected, loading, busy });
  const oldAfterDays = limits?.oldAfterDays ?? 30;
  const error = treeError ?? tree?.error ?? null;
  const takeButton = (
    <Button variant="outline" size="sm" disabled={takeOff !== null} onClick={onTake}>
      <CameraIcon data-icon="inline-start" />
      Take snapshot…
    </Button>
  );

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        {takeOff ? (
          <WhyDisabled reason={takeOff}>{takeButton}</WhyDisabled>
        ) : (
          <Tooltip>
            <TooltipTrigger asChild>{takeButton}</TooltipTrigger>
            <TooltipContent className="max-w-72">{hints.take ?? "Take a snapshot of this VM"}</TooltipContent>
          </Tooltip>
        )}
        <Button
          size="icon-sm"
          variant="ghost"
          aria-label="Read the snapshots again"
          title="Read the snapshots again"
          disabled={loading}
          onClick={onReadTree}
        >
          <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
        </Button>
        {tree && tree.snapshots.length > 0 && (
          <span className="ml-auto text-xs text-muted-foreground">
            {plural(tree.snapshots.length, "snapshot")}
            {tree.oldCount > 0 && (
              <span className="text-tier-medium">
                {" "}
                · {tree.oldCount} older than {oldAfterDays} days
              </span>
            )}
            {tree.safetyCount > 0 && <> · {tree.safetyCount} safety</>}
          </span>
        )}
      </div>

      {vm.protected && (
        <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <ShieldIcon className="mt-0.5 size-3.5 shrink-0 text-tier-high" aria-hidden />
          Protected (do not touch): snapshot actions skip this VM until it is unprotected.
        </p>
      )}

      {error && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>Could not read the snapshots</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {loading && (
        <div className="flex flex-col gap-2" aria-label="Reading the snapshots">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="ml-5 h-9 w-[90%]" />
          <Skeleton className="ml-10 h-9 w-[80%]" />
        </div>
      )}

      {tree && !tree.error && tree.snapshots.length === 0 && (
        <Empty className="border py-8">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <HistoryIcon />
            </EmptyMedia>
            <EmptyTitle>No snapshots</EmptyTitle>
            <EmptyDescription>
              Take one before a risky change. Remotely also takes a safety snapshot before high-risk actions when the
              approval dialog has it ticked.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <WhyDisabled reason={takeOff}>{takeButton}</WhyDisabled>
          </EmptyContent>
        </Empty>
      )}

      {tree && tree.snapshots.length > 0 && (
        <SnapshotTree
          tree={tree}
          oldAfterDays={oldAfterDays}
          readOnly={readOnly}
          busy={busy}
          hints={{ revert: hints.revert, delete: hints.delete }}
          onRevert={onRevert}
          onDelete={onDelete}
        />
      )}

      {tree && tree.snapshots.length > 0 && (
        <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <InfoIcon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          <span>
            Reverting loses what changed since the snapshot{hints.revert ? ` (${hints.revert})` : ""}. Deleting keeps
            the snapshot&apos;s children and the VM&apos;s current state, and takes no safety snapshot
            {hints.delete ? ` (${hints.delete})` : ""}.
          </span>
        </p>
      )}
    </div>
  );
}

/**
 * The tier and approval steps each snapshot action would get on this VM (its label raises them for Prod), from the
 * policy engine's preview. Nothing is submitted. Asked again when the VM, its label or the rules change.
 */
function useHints(vm: VmRecord, tree: VmSnapshots | undefined, refreshKey: string): Hints {
  const [hints, setHints] = useState<Hints & { for: string }>({ for: "", take: null, revert: null, delete: null });
  // Any name does: the tier depends on the action and the VM, not on which snapshot.
  const name = tree?.snapshots[0]?.name ?? "";
  const asked = `${vm.vmxPath}|${vm.environment}|${vm.protected}|${refreshKey}`;
  const vmxPath = vm.vmxPath;
  useEffect(() => {
    let stale = false;
    const targets = [{ kind: "vm" as const, vmxPath }];
    const ask = (op: SnapshotOp) =>
      api.commandPreview({ type: "vmSnapshot", targets, op }).then(approvalHint, () => null);
    Promise.all([
      ask({ kind: "take", name: "preview" }),
      ask({ kind: "revert", name }),
      ask({ kind: "delete", name }),
    ]).then(([take, revert, del]) => {
      if (!stale) setHints({ for: asked, take, revert, delete: del });
    });
    return () => {
      stale = true;
    };
  }, [asked, vmxPath, name]);
  return hints.for === asked ? hints : { take: null, revert: null, delete: null };
}
