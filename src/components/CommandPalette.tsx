// FD-01 command palette (Ctrl+K): jump to a page, a VM or a session, and start common actions. Every
// action that changes something is a command submitted to the command bus, so it gets the same tier,
// approval dialog and audit entry as from any page; the palette only shows the tier first
// (`command_preview`). Pick a VM or session to see its own actions; Backspace in an empty search goes
// back.

import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeftIcon,
  CalendarClockIcon,
  CameraIcon,
  EyeIcon,
  EyeOffIcon,
  GaugeIcon,
  InfoIcon,
  MonitorIcon,
  PauseIcon,
  PencilIcon,
  PlayIcon,
  PowerIcon,
  RotateCcwIcon,
  ServerIcon,
  ShieldIcon,
  ShieldOffIcon,
  SlidersHorizontalIcon,
  SquareIcon,
  SquareTerminalIcon,
  Trash2Icon,
  WrenchIcon,
  type LucideIcon,
} from "lucide-react";
import { toast } from "sonner";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { Command as CommandRoot } from "@/components/ui/command";
import { StateBadge, TierBadge } from "@/components/Badges";
import { toolsName } from "@/lib/hypervisors";
import type { VmView } from "@/lib/vm-snapshots";
import {
  api,
  errorMessage,
  type Command,
  type PowerOp,
  type PowerState,
  type SessionRecord,
  type Tier,
  type VmRecord,
} from "@/lib/api";

export interface PalettePage {
  id: string;
  label: string;
  icon: LucideIcon;
  shortcut?: string;
}

/** An app-level action: navigation and the app's own data (no command bus involved). */
export interface PaletteAction {
  id: string;
  label: string;
  icon: LucideIcon;
  keywords?: string;
  run: () => void | Promise<void>;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Opens straight on this VM's actions. The app remounts the palette for each opening. */
  vmFocus: string | null;
  pages: PalettePage[];
  onNavigate: (page: string) => void;
  actions: PaletteAction[];
  /** Submits to the command bus; the app shows the approval dialog when the tier needs one. */
  onSubmit: (command: Command) => Promise<void>;
  onConnect: (sessionId: string) => void;
  onShowMetrics: (key: string) => void;
  /** QL-14: the VM's details on the Virtual machines page, on a tab (VM-24: with its rename dialog). */
  onOpenVm: (vmxPath: string, view: VmView, rename?: boolean) => void;
  /** VM-24: the hypervisor's own window on the VM. */
  onOpenConsole: (vmxPath: string) => void;
}

type View = { kind: "root" } | { kind: "vm"; vmxPath: string } | { kind: "session"; id: string };

interface VmAction {
  id: string;
  label: string;
  icon: LucideIcon;
  command: Command;
}

const ON: PowerState[] = ["running", "paused"];

function power(vms: VmRecord[], op: PowerOp): Command {
  return { type: "vmPower", targets: vms.map((v) => ({ kind: "vm", vmxPath: v.vmxPath })), op };
}

/** The power actions that make sense in a VM's state, as commands for the bus. */
function vmActions(vm: VmRecord): VmAction[] {
  const one = [vm];
  const actions: VmAction[] = [];
  const add = (id: string, label: string, icon: LucideIcon, op: PowerOp) =>
    actions.push({ id, label, icon, command: power(one, op) });
  if (vm.powerState === "running") {
    add("stop", "Shut down", SquareIcon, { kind: "stop", mode: "soft" });
    add("reset", "Restart", RotateCcwIcon, { kind: "reset", mode: "soft" });
    add("suspend", "Suspend", PauseIcon, { kind: "suspend" });
    add("pause", "Pause", PauseIcon, { kind: "pause" });
  }
  if (vm.powerState === "paused") add("unpause", "Unpause", PlayIcon, { kind: "unpause" });
  if (ON.includes(vm.powerState)) add("off", "Power off (hard)", PowerIcon, { kind: "stop", mode: "hard" });
  if (vm.powerState === "not_running" || vm.powerState === "suspended" || vm.powerState === "unknown") {
    add("start", "Start", PlayIcon, { kind: "start", gui: false });
    add("start-gui", "Start with its console window", PlayIcon, { kind: "start", gui: true });
  }
  actions.push({
    id: "protect",
    label: vm.protected ? "Unprotect (allow actions again)" : "Protect (do not touch)",
    icon: vm.protected ? ShieldOffIcon : ShieldIcon,
    command: { type: "vmProtect", targets: [{ kind: "vm", vmxPath: vm.vmxPath }], protected: !vm.protected },
  });
  // VM-15, VM-24.
  const target = [{ kind: "vm" as const, vmxPath: vm.vmxPath }];
  if (vm.powerState === "running") {
    actions.push({
      id: "tools",
      label: `Install or upgrade ${toolsName(vm.hypervisor)}`,
      icon: WrenchIcon,
      command: { type: "vmDevice", targets: target, op: { kind: "installTools" } },
    });
  }
  if (!ON.includes(vm.powerState)) {
    actions.push({
      id: "delete",
      label: "Delete the VM and its files…",
      icon: Trash2Icon,
      command: { type: "vmLifecycle", targets: target, op: { kind: "delete" } },
    });
  }
  return actions;
}

export function CommandPalette({
  open,
  onOpenChange,
  vmFocus,
  pages,
  onNavigate,
  actions,
  onSubmit,
  onConnect,
  onShowMetrics,
  onOpenVm,
  onOpenConsole,
}: Props) {
  // The app mounts the palette afresh for each opening, so it starts here.
  const [view, setView] = useState<View>(vmFocus ? { kind: "vm", vmxPath: vmFocus } : { kind: "root" });
  const [search, setSearch] = useState("");
  const [vms, setVms] = useState<VmRecord[]>([]);
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [watched, setWatched] = useState<Set<string>>(new Set());
  const [tiers, setTiers] = useState<Record<string, Tier>>({});

  // Fresh lists each time it opens.
  useEffect(() => {
    if (!open) return;
    api.vmList().then(setVms, () => setVms([]));
    api.sessions().then(setSessions, () => setSessions([]));
    api.metricsOverview().then(
      (o) => setWatched(new Set(o.rows.flatMap((r) => (r.watchedSession ? [r.watchedSession] : [])))),
      () => setWatched(new Set()),
    );
  }, [open]);

  const running = useMemo(() => vms.filter((v) => v.powerState === "running" && !v.protected), [vms]);
  const vm = view.kind === "vm" ? vms.find((v) => v.vmxPath === view.vmxPath) : undefined;
  const session = view.kind === "session" ? sessions.find((s) => s.id === view.id) : undefined;

  const bulk = useMemo<VmAction[]>(
    () =>
      running.length === 0
        ? []
        : [
            {
              id: "stop-all",
              label: `Shut down all running VMs (${running.length})`,
              icon: SquareIcon,
              command: power(running, { kind: "stop", mode: "soft" }),
            },
            {
              id: "suspend-all",
              label: `Suspend all running VMs (${running.length})`,
              icon: PauseIcon,
              command: power(running, { kind: "suspend" }),
            },
          ],
    [running],
  );
  const shownActions = useMemo(() => (vm ? vmActions(vm) : view.kind === "root" ? bulk : []), [vm, view.kind, bulk]);

  // FD-01: the tier each action would get, from the policy engine, before anything is submitted.
  useEffect(() => {
    if (!open || shownActions.length === 0) return;
    let stale = false;
    for (const action of shownActions) {
      api.commandPreview(action.command).then(
        (preview) => {
          if (!stale) setTiers((t) => ({ ...t, [`${view.kind}:${action.id}`]: preview.tier }));
        },
        () => {},
      );
    }
    return () => {
      stale = true;
    };
  }, [open, shownActions, view.kind]);

  function close() {
    onOpenChange(false);
  }

  function goTo(next: View) {
    setView(next);
    setSearch("");
  }

  async function run(command: Command) {
    close();
    await onSubmit(command);
  }

  async function watch(id: string, on: boolean) {
    close();
    try {
      await api.metricsWatch(id, on);
      toast.success(on ? "Watching the guest on the dashboard" : "Stopped guest metrics");
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  function actionItem(action: VmAction) {
    const tier = tiers[`${view.kind}:${action.id}`];
    return (
      <CommandItem key={action.id} value={action.label} onSelect={() => void run(action.command)}>
        <action.icon />
        <span>{action.label}</span>
        <CommandShortcut className="tracking-normal">{tier && <TierBadge tier={tier} />}</CommandShortcut>
      </CommandItem>
    );
  }

  const placeholder =
    view.kind === "vm"
      ? `Actions for ${vm?.displayName ?? "the VM"}…`
      : view.kind === "session"
        ? `Actions for ${session?.name ?? "the session"}…`
        : "Search pages, VMs, sessions and actions…";

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Command palette"
      description="Jump to a page, a VM or a session, or start an action"
      className="sm:max-w-xl"
    >
      <CommandRoot
        onKeyDown={(e) => {
          if (e.key === "Backspace" && search === "" && view.kind !== "root") {
            e.preventDefault();
            goTo({ kind: "root" });
          }
        }}
      >
        <CommandInput placeholder={placeholder} value={search} onValueChange={setSearch} />
        <CommandList className="max-h-[min(60vh,28rem)]">
          <CommandEmpty>Nothing matches.</CommandEmpty>

          {view.kind === "vm" && vm && (
            <>
              <CommandGroup
                heading={
                  <span className="flex items-center gap-2">
                    {vm.displayName} <StateBadge state={vm.powerState} />
                  </span>
                }
              >
                {vm.protected && (
                  <p className="px-2 py-1.5 text-xs text-muted-foreground">
                    Protected: actions skip it until it is unprotected.
                  </p>
                )}
                {shownActions.map(actionItem)}
              </CommandGroup>
              <CommandSeparator />
              <CommandGroup heading="Go to">
                {ON.includes(vm.powerState) && (
                  <CommandItem
                    value="show on the dashboard metrics"
                    onSelect={() => {
                      close();
                      onShowMetrics(vm.vmxPath);
                    }}
                  >
                    <GaugeIcon /> Show its metrics
                  </CommandItem>
                )}
                <CommandItem
                  value="details info guest os ip sessions"
                  onSelect={() => {
                    close();
                    onOpenVm(vm.vmxPath, "details");
                  }}
                >
                  <InfoIcon /> Show its details
                </CommandItem>
                <CommandItem
                  value="snapshots take revert delete"
                  onSelect={() => {
                    close();
                    onOpenVm(vm.vmxPath, "snapshots");
                  }}
                >
                  <CameraIcon /> Snapshots…
                </CommandItem>
                <CommandItem
                  value="settings hardware cpu memory disks network firmware resize"
                  onSelect={() => {
                    close();
                    onOpenVm(vm.vmxPath, "settings");
                  }}
                >
                  <SlidersHorizontalIcon /> Settings…
                </CommandItem>
                <CommandItem
                  value="schedules snapshot power timetable nightly suspend idle"
                  onSelect={() => {
                    close();
                    onOpenVm(vm.vmxPath, "schedules");
                  }}
                >
                  <CalendarClockIcon /> Schedules…
                </CommandItem>
                <CommandItem
                  value="rename name"
                  onSelect={() => {
                    close();
                    onOpenVm(vm.vmxPath, "settings", true);
                  }}
                >
                  <PencilIcon /> Rename…
                </CommandItem>
                <CommandItem
                  value="open console window screen"
                  onSelect={() => {
                    close();
                    onOpenConsole(vm.vmxPath);
                  }}
                >
                  <MonitorIcon /> Open its console
                </CommandItem>
                {sessions
                  .filter((s) => s.vmId === vm.id)
                  .map((s) => (
                    <CommandItem
                      key={s.id}
                      value={`terminal ${s.name}`}
                      onSelect={() => {
                        close();
                        onConnect(s.id);
                      }}
                    >
                      <SquareTerminalIcon /> Open a terminal ({s.name})
                    </CommandItem>
                  ))}
              </CommandGroup>
            </>
          )}

          {view.kind === "session" && session && (
            <CommandGroup
              heading={`${session.name} · ${session.username ? `${session.username}@` : ""}${session.host}`}
            >
              <CommandItem
                value="connect terminal"
                onSelect={() => {
                  close();
                  onConnect(session.id);
                }}
              >
                <SquareTerminalIcon /> Open a terminal
              </CommandItem>
              {watched.has(session.id) ? (
                <>
                  <CommandItem
                    value="show metrics dashboard"
                    onSelect={() => {
                      close();
                      onShowMetrics(session.id);
                    }}
                  >
                    <GaugeIcon /> Show its metrics
                  </CommandItem>
                  <CommandItem value="stop guest metrics" onSelect={() => void watch(session.id, false)}>
                    <EyeOffIcon /> Stop guest metrics
                  </CommandItem>
                </>
              ) : (
                <CommandItem value="watch guest metrics dashboard" onSelect={() => void watch(session.id, true)}>
                  <EyeIcon /> Watch its guest metrics (Linux, over SSH)
                </CommandItem>
              )}
            </CommandGroup>
          )}

          {view.kind !== "root" && (
            <CommandGroup heading="Back">
              <CommandItem value="back to everything" onSelect={() => goTo({ kind: "root" })}>
                <ArrowLeftIcon />
                <span>Back</span>
                <CommandShortcut>Backspace</CommandShortcut>
              </CommandItem>
            </CommandGroup>
          )}

          {view.kind === "root" && (
            <>
              <CommandGroup heading="Pages">
                {pages.map((p) => (
                  <CommandItem
                    key={p.id}
                    value={`go to ${p.label}`}
                    onSelect={() => {
                      close();
                      onNavigate(p.id);
                    }}
                  >
                    <p.icon />
                    <span>{p.label}</span>
                    {p.shortcut && <CommandShortcut>{p.shortcut}</CommandShortcut>}
                  </CommandItem>
                ))}
              </CommandGroup>
              <CommandGroup heading="Actions">
                {bulk.map(actionItem)}
                {actions.map((a) => (
                  <CommandItem
                    key={a.id}
                    value={`${a.label} ${a.keywords ?? ""}`}
                    onSelect={() => {
                      close();
                      void a.run();
                    }}
                  >
                    <a.icon />
                    <span>{a.label}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
              {vms.length > 0 && (
                <CommandGroup heading="Virtual machines">
                  {vms.map((v) => (
                    <CommandItem
                      key={v.vmxPath}
                      value={`vm ${v.displayName} ${v.ipAddress ?? ""} ${v.tags.join(" ")} ${v.vmxPath} ${v.hypervisor}`}
                      onSelect={() => goTo({ kind: "vm", vmxPath: v.vmxPath })}
                    >
                      <MonitorIcon />
                      <span className="truncate">{v.displayName}</span>
                      <CommandShortcut className="tracking-normal">
                        <StateBadge state={v.powerState} />
                      </CommandShortcut>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
              {sessions.length > 0 && (
                <CommandGroup heading="Sessions">
                  {sessions.map((s) => (
                    <CommandItem
                      key={s.id}
                      value={`session ${s.name} ${s.host} ${s.username ?? ""} ${s.tags.join(" ")}`}
                      onSelect={() => goTo({ kind: "session", id: s.id })}
                    >
                      <ServerIcon />
                      <span className="truncate">{s.name}</span>
                      <CommandShortcut className="truncate tracking-normal" data-mask="host">
                        {s.host}
                      </CommandShortcut>
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
            </>
          )}
        </CommandList>
        <div className="flex items-center gap-3 border-t px-3 py-2 text-xs text-muted-foreground">
          <span>Enter to choose</span>
          <span>Esc to close</span>
          <span className="ml-auto">Actions go through the approval rules; the tier shows first.</span>
        </div>
      </CommandRoot>
    </CommandDialog>
  );
}
