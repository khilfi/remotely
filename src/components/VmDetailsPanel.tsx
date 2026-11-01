// QL-14: one VM's panel beside the list on the Virtual machines page. UX-03 (0.6.0): five tabs, each action in one
// place. Overview: what the inventory knows (VM-01), its share of this host (MO-01), its environment (SS-06),
// protection (AP-04), tags and linked sessions (QL-01), with the system facts from its files and its guest (MO-13).
// Snapshots: its tree from the .vmsd (VM-04), read when the panel opens, with take, revert and delete. Settings: the
// virtual hardware and its edits (VM-23), the guest tools and resize included. Log: its own logs (VM-25). Activity:
// the schedules that act on it (VM-14, VM-27) and what Remotely did to it (VM-25's timeline). Power and protection for
// this one VM are in the actions palette (FD-01, with their tiers); the page's selection bar acts on several. Every
// action is a command for the bus; the approval dialog (AP-02 impact preview, VM-05 safety snapshot) follows the submit
// as from anywhere else.
//
// VM-18: the hypervisor comes first in the Overview's rows, then its own facts (a VirtualBox VM's UUID), and the
// guest tools row is named for it ("VMware Tools" or "Guest Additions").

import { useEffect, useState, type ReactNode } from "react";
import { CameraIcon, HistoryIcon, MonitorIcon, ShieldIcon, TriangleAlertIcon, XIcon, ZapIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge, StateBadge, ToolsLabel } from "@/components/Badges";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { MetricCell } from "@/components/MetricBits";
import { SnapshotTree } from "@/components/SnapshotTree";
import { Term } from "@/components/Term";
import { VmSessionLinks } from "@/components/VmLinkControls";
import { VmSystemTab } from "@/components/VmSystemTab";
import { WhyDisabled } from "@/components/WhyDisabled";
import { VmSettingsTab } from "@/components/VmSettingsTab";
import { VmLogTab } from "@/components/VmLogTab";
import { VmTimelineTab } from "@/components/VmTimelineTab";
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
import { RefreshButton } from "@/components/RefreshButton";
import { formatWhen, plural } from "@/lib/format";
import { HYPERVISORS, toolsName, vmLocation } from "@/lib/hypervisors";
import { formatPct, HOST_SHARE_HINT, type Thresholds } from "@/lib/metrics";
import { viewOfTab, VM_TABS, vmTabOf, type VmTab } from "@/lib/vm-page";
import { approvalHint, PROTECTED_REASON, takeReason, type VmView } from "@/lib/vm-snapshots";
import { ToolboxIconMenu } from "@/components/toolbox/ToolboxMenu";

interface Props {
  vm: VmRecord;
  /** The view asked for; each opens the tab that holds it (lib/vm-page.ts vmTabOf). */
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

/** An icon button with its name in a tooltip (UX-13). */
function IconAction({
  label,
  icon,
  onClick,
  disabledReason,
}: {
  label: string;
  icon: ReactNode;
  onClick: () => void;
  disabledReason?: string | null;
}) {
  if (disabledReason) {
    return (
      <WhyDisabled reason={disabledReason}>
        <Button variant="ghost" size="icon-sm" aria-label={label} disabled>
          {icon}
        </Button>
      </WhyDisabled>
    );
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={label} onClick={onClick}>
          {icon}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

export function VmDetailsPanel(props: Props) {
  const { vm, view, onViewChange, onClose, refreshKey, onActions, tree } = props;
  const hints = useHints(vm, tree, refreshKey);
  const tab = vmTabOf(view);

  return (
    <aside
      id="vm-details"
      data-vm-drop={vm.vmxPath}
      aria-label={`${vm.displayName}: details and snapshots`}
      className="flex h-full min-h-0 flex-col rounded-lg border"
    >
      <div className="flex items-center gap-1 border-b py-2 pr-2 pl-3">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
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
        <IconAction
          label={vm.hypervisor === "virtualbox" ? "Open its VirtualBox window" : "Open it in Workstation"}
          icon={<MonitorIcon />}
          disabledReason={props.readOnly}
          onClick={props.onOpenConsole}
        />
        <IconAction label="Actions: power and protection" icon={<ZapIcon />} onClick={onActions} />
        <ToolboxIconMenu target={{ kind: "vm", vmKey: vm.vmxPath, label: vm.displayName }} />
        <IconAction label="Close the details" icon={<XIcon />} onClick={onClose} />
      </div>

      <Tabs
        value={tab}
        onValueChange={(v) => onViewChange(viewOfTab(v as VmTab))}
        className="min-h-0 flex-1 gap-0"
        aria-label={`${vm.displayName}'s details`}
      >
        <div className="border-b px-3 py-2">
          <TabsList className="h-auto! max-w-full flex-wrap justify-start *:flex-none">
            {VM_TABS.map((t) => (
              <TabsTrigger key={t.id} value={t.id}>
                {t.label}
                {t.id === "snapshots" && tree && tree.snapshots.length > 0 && (
                  <Badge variant="secondary" className="h-4 min-w-4 px-1 tabular-nums">
                    {tree.snapshots.length}
                  </Badge>
                )}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        <TabsContent value="overview" className="min-h-0 overflow-auto p-3">
          {tab === "overview" && (
            <div className="flex flex-col gap-4">
              <OverviewRows {...props} />
              <Separator />
              <VmSystemTab vm={vm} thresholds={props.thresholds} onHostDetails={props.onHostDetails} />
            </div>
          )}
        </TabsContent>
        <TabsContent value="snapshots" className="min-h-0 overflow-auto p-3">
          <SnapshotsTab {...props} hints={hints} />
        </TabsContent>
        <TabsContent value="settings" className="min-h-0 overflow-auto p-3">
          {tab === "settings" && (
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
        {/* VM-25: mounted only while shown, so a followed log stops being read when the tab is left. */}
        <TabsContent value="log" className="flex min-h-0 flex-col p-3">
          {tab === "log" && <VmLogTab key={vm.vmxPath} vm={vm} />}
        </TabsContent>
        <TabsContent value="activity" className="min-h-0 overflow-auto p-3">
          {tab === "activity" && (
            <div className="flex flex-col gap-4">
              <VmSchedulesTab
                vm={vm}
                refreshKey={refreshKey}
                readOnly={props.readOnly}
                onSchedules={(ask) => props.onSchedules?.(ask)}
              />
              <Separator />
              <VmTimelineTab key={vm.vmxPath} vm={vm} refreshKey={refreshKey} />
            </div>
          )}
        </TabsContent>
      </Tabs>
    </aside>
  );
}

/** One row of the Overview. */
interface DetailRow {
  label: ReactNode;
  key: string;
  value: ReactNode;
  hint?: string;
}

/** The Overview's rows, in order: the hypervisor and its own facts first (VM-18). */
function detailRows({ vm, usage, thresholds, sessions, onLinksChanged }: Props): DetailRow[] {
  const hostCpu = usage?.hostCpuPct ?? null;
  const hostMem = usage?.hostMemPct ?? null;
  const rows: DetailRow[] = [
    {
      key: "hypervisor",
      label: "Hypervisor",
      value: HYPERVISORS.find((h) => h.value === vm.hypervisor)?.label ?? vm.hypervisor,
    },
    {
      key: "file",
      label: vm.hypervisor === "virtualbox" ? "Settings file" : "File",
      value: <span className="font-mono text-xs break-all">{vmLocation(vm)}</span>,
    },
  ];
  if (vm.hypervisor === "virtualbox") {
    rows.push({
      key: "uuid",
      label: "UUID",
      hint: "VirtualBox's id for the VM; it stays the same when the VM is renamed or moved",
      value: <span className="font-mono text-xs break-all">{vm.vmxPath}</span>,
    });
  }
  rows.push(
    { key: "os", label: "Guest OS", value: vm.guestOsName ?? vm.guestOs ?? dash },
    { key: "cpu", label: "vCPUs", value: vm.numVcpus ?? dash },
    { key: "ram", label: "RAM", value: formatRam(vm.memsizeMb) },
    {
      key: "ip",
      label: "IP address",
      value: vm.ipAddress ? (
        <span className="font-mono text-xs" data-mask="ip">
          {vm.ipAddress}
        </span>
      ) : (
        dash
      ),
    },
    { key: "tools", label: toolsName(vm.hypervisor), value: <ToolsLabel state={vm.toolsState} /> },
    {
      key: "hostCpu",
      label: "Host CPU",
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
      key: "hostMem",
      label: "Host RAM",
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
    // UX-12: a VM's environment is its own (nothing passes one on to a VM), and Prod moves its actions up a tier.
    {
      key: "environment",
      label: <Term id="environment" />,
      value:
        vm.environment === "prod" ? (
          <span className="flex flex-wrap items-center gap-1.5">
            <EnvBadge env="prod" />
            <span className="text-xs text-muted-foreground">actions ask one tier higher</span>
            <HelpTip topic="prodTier" />
          </span>
        ) : vm.environment === "none" ? (
          <span className="text-muted-foreground">None</span>
        ) : (
          <EnvBadge env={vm.environment} />
        ),
    },
    {
      key: "protected",
      label: <Term id="protected" />,
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
      key: "tags",
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
    {
      key: "sessions",
      label: "Sessions",
      value: <VmSessionLinks vm={vm} sessions={sessions} onChanged={onLinksChanged} />,
    },
    { key: "seen", label: "Last seen", value: formatWhen(vm.lastSeenAt) },
  );
  return rows;
}

function OverviewRows(props: Props) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] items-center gap-x-4 gap-y-2.5 text-sm">
      {detailRows(props).map((row) => (
        <div key={row.key} className="contents">
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
  const takeButton = (variant: "outline" | "default") => (
    <Button variant={variant} size="sm" disabled={takeOff !== null} onClick={onTake}>
      <CameraIcon data-icon="inline-start" />
      Take a snapshot…
    </Button>
  );

  return (
    <div className="flex flex-col gap-3">
      {!loading && (
        <div className="flex flex-wrap items-center gap-2">
          {tree && tree.snapshots.length > 0 && (
            <>
              {takeOff ? (
                <WhyDisabled reason={takeOff}>{takeButton("outline")}</WhyDisabled>
              ) : (
                <Tooltip>
                  <TooltipTrigger asChild>{takeButton("outline")}</TooltipTrigger>
                  <TooltipContent className="max-w-72">{hints.take ?? "Take a snapshot of this VM"}</TooltipContent>
                </Tooltip>
              )}
              <span className="text-xs text-muted-foreground">
                {plural(tree.snapshots.length, "snapshot")}
                {tree.oldCount > 0 && (
                  <span className="text-tier-medium">
                    {" "}
                    · {tree.oldCount} older than {oldAfterDays} days
                  </span>
                )}
                {tree.safetyCount > 0 && (
                  <>
                    {" "}
                    · {tree.safetyCount} <Term id="safetySnapshot">safety</Term>
                  </>
                )}
              </span>
            </>
          )}
          <span className="ml-auto flex items-center">
            {tree && tree.snapshots.length > 0 && <HelpTip topic="snapshotActions" align="end" />}
            <RefreshButton busy={loading} onClick={onReadTree} />
          </span>
        </div>
      )}

      {vm.protected && (
        <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
          <ShieldIcon className="mt-0.5 size-3.5 shrink-0 text-tier-high" aria-hidden />
          Protected: snapshot actions skip this VM.
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
        <EmptyState
          className="py-8"
          icon={HistoryIcon}
          title="No snapshots"
          description="Take one before a risky change."
          help="safetySnapshot"
          action={<WhyDisabled reason={takeOff}>{takeButton("default")}</WhyDisabled>}
        />
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
