// App shell (shadcn/ui): sidebar navigation with the vault status (SS-04), top bar with the command
// palette and the Dark mode switch (FD-01, QL-11: "Follow Windows" is in Settings), pages, the approval dialog and job
// toasts. Pages stay mounted
// while hidden so terminal connections survive a page switch. Bulk execution lives in the Terminal page (post-MVP P6):
// MultiExec (SS-10) and Compare output (BX-03) replace the MVP's Bulk run page.
//
// FD-01 keyboard: Ctrl+K opens the command palette (Ctrl+Shift+K inside a terminal, where Ctrl+K belongs
// to the shell), Ctrl+1 to Ctrl+9 open the pages by their own shortcut and Ctrl+, opens Settings.
//
// QL-14: snapshots are part of the Virtual machines page. The sidebar's third slot is left for Containers (Q6); until
// then Ctrl+3, Snapshots' old shortcut, opens the snapshot view there (lib/navigation.ts).
//
// FD-03: the top bar's Present button (Presenting menu while on) and the palette start and stop presentation mode,
// its read-only lock and "Hide terminal output" (Presentation.tsx).

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  CameraIcon,
  DownloadIcon,
  GaugeIcon,
  ContainerIcon,
  GitCompareArrowsIcon,
  HistoryIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  ListTreeIcon,
  LockIcon,
  LockOpenIcon,
  MonitorIcon,
  MoonIcon,
  PresentationIcon,
  RadioTowerIcon,
  RefreshCwIcon,
  SearchIcon,
  ServerIcon,
  SettingsIcon,
  ShieldCheckIcon,
  SunIcon,
  TerminalIcon,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Kbd } from "@/components/ui/kbd";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Toaster } from "@/components/ui/sonner";
import { Switch } from "@/components/ui/switch";
import { TooltipProvider } from "@/components/ui/tooltip";
import logo from "@/assets/remotely-logo.png";
import { ApprovalDialog } from "@/components/ApprovalDialog";
import { CommandPalette, type PaletteAction } from "@/components/CommandPalette";
import {
  PresentationButton,
  PresentationLayer,
  READ_ONLY_PAGES,
  ReadOnlyNotice,
  requestReadOnlyLock,
  requestStopPresenting,
  setHideTerminals,
  startPresenting,
  usePresentation,
  useReadOnlyReason,
} from "@/components/Presentation";
import { UpdateBanner, UpdateNotice } from "@/components/UpdateBanner";
import {
  api,
  errorCode,
  errorMessage,
  UPDATE_TOKEN_ERRORS,
  type AppInfo,
  type ApprovalRequest,
  type Command,
  type SubmitOutcome,
  type UpdateCheck,
  type VaultInfo,
} from "@/lib/api";
import { useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { ActivityPage } from "@/pages/ActivityPage";
import { ContainersPage, type ContainerShellRequest } from "@/pages/ContainersPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { KnownHostsPage } from "@/pages/KnownHostsPage";
import { SessionsPage } from "@/pages/SessionsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { TerminalPage } from "@/pages/TerminalPage";
import { VaultPage } from "@/pages/VaultPage";
import { VmsPage, type VmPageRequest } from "@/pages/VmsPage";
import { navTarget, shortcutTarget, type NavTarget } from "@/lib/navigation";
import type { VmView } from "@/lib/vm-snapshots";

type PageId =
  "vms" | "dashboard" | "containers" | "sessions" | "terminal" | "knownHosts" | "vault" | "activity" | "settings";

const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

/** In sidebar order, each with its own shortcut. Ctrl+3 is Containers (Q6); the old Snapshots alias stops. */
const PAGES: { id: PageId; label: string; title: string; icon: LucideIcon; shortcut: string }[] = [
  { id: "vms", label: "Virtual machines", title: "Virtual machines", icon: ServerIcon, shortcut: "Ctrl+1" },
  { id: "dashboard", label: "Dashboard", title: "Dashboard", icon: LayoutDashboardIcon, shortcut: "Ctrl+2" },
  { id: "containers", label: "Containers", title: "Containers", icon: ContainerIcon, shortcut: "Ctrl+3" },
  { id: "sessions", label: "Sessions", title: "Sessions", icon: ListTreeIcon, shortcut: "Ctrl+4" },
  { id: "terminal", label: "Terminal", title: "Terminal", icon: TerminalIcon, shortcut: "Ctrl+5" },
  { id: "knownHosts", label: "Known hosts", title: "Known hosts", icon: ShieldCheckIcon, shortcut: "Ctrl+6" },
  { id: "vault", label: "Vault", title: "Vault", icon: KeyRoundIcon, shortcut: "Ctrl+7" },
  { id: "activity", label: "Activity", title: "Jobs and audit log", icon: HistoryIcon, shortcut: "Ctrl+8" },
  { id: "settings", label: "Settings", title: "Settings", icon: SettingsIcon, shortcut: "Ctrl+," },
];

/** Focus is in a terminal pane, where Ctrl+letter and Ctrl+digit keys belong to the remote shell. */
function inTerminal(target: EventTarget | null) {
  return target instanceof Element && target.closest(".xterm") !== null;
}

export default function App() {
  const [page, setPage] = useState<PageId>("vms");
  const [info, setInfo] = useState<AppInfo | null>(null);
  // The open approval, and who wants the job id once it is approved (Compare output follows its run).
  const [approval, setApproval] = useState<{ request: ApprovalRequest; onJob?: (jobId: string) => void } | null>(null);
  const [jobsVersion, setJobsVersion] = useState(0);
  // Bumped when a job finishes, so the VM list shows the new power states.
  const [jobsFinished, setJobsFinished] = useState(0);
  const [settingsVersion, setSettingsVersion] = useState(0);
  // FD-14: the last update check, a problem with the GitHub update token it ran into, and the banner
  // put off with "Later" (an update's version, or "noToken" / the problem's code).
  const [updateCheck, setUpdateCheck] = useState<UpdateCheck | null>(null);
  const [updateProblem, setUpdateProblem] = useState<{ code: string; message: string } | null>(null);
  const [laterFor, setLaterFor] = useState<string | null>(null);
  const [updateRun, setUpdateRun] = useState(0);
  const lastUpdateStatus = useRef<UpdateCheck["status"] | null>(null);
  const offered = updateCheck?.status === "available" ? updateCheck.update : null;
  // QL-14: a VM (or the snapshot view) to show on the Virtual machines page.
  const [vmRequest, setVmRequest] = useState<VmPageRequest | null>(null);
  // SS-03: a session to open in a new terminal tab; CT-01: a shell in one of its containers.
  const [terminalOpen, setTerminalOpen] = useState<{
    sessionId: string;
    n: number;
    container?: ContainerShellRequest;
  } | null>(null);
  // QL-02: the New terminal form, opened from the palette.
  const [terminalNew, setTerminalNew] = useState(0);
  // BX-03, SS-10: Compare output and MultiExec, opened from the palette.
  const [terminalCompare, setTerminalCompare] = useState(0);
  const [terminalMultiExec, setTerminalMultiExec] = useState(0);
  // SS-10: MultiExec lines are jobs too; their terminals show what happened, so they get no toasts.
  const quietJobs = useRef(new Set<string>());
  // SS-04: the vault's status for the sidebar, the pages and the approval dialog (AP-06).
  const [vault, setVault] = useState<VaultInfo | null>(null);
  // FD-01: the command palette, opened on everything or on one VM's actions.
  // `n` counts openings: each one starts the palette afresh.
  const [palette, setPalette] = useState<{ open: boolean; vm: string | null; n: number }>({
    open: false,
    vm: null,
    n: 0,
  });
  const paletteOpen = useRef(false);
  // MO-03: a row the palette asked the dashboard to open.
  const [dashboardFocus, setDashboardFocus] = useState<{ key: string; n: number } | null>(null);
  // Bumped when the palette refreshed the VM list.
  const [inventoryVersion, setInventoryVersion] = useState(0);
  const { resolved, followWindows, setDark, setFollowWindows } = useTheme();
  // FD-03: presenting, the read-only lock (QL-08: the update banner's Install says why it is off).
  const presentation = usePresentation();
  const readOnlyReason = useReadOnlyReason();

  const openPalette = useCallback((vm: string | null) => setPalette((p) => ({ open: true, vm, n: p.n + 1 })), []);

  /** QL-14: the Virtual machines page with these VMs' details, or (none) the snapshot view of the open one. */
  const openVms = useCallback((vmxPaths: string[], view: VmView) => {
    setVmRequest((prev) => ({ vmxPaths, view, n: (prev?.n ?? 0) + 1 }));
    setPage("vms");
  }, []);

  /** A page, or a page from before 0.4.0 that is now part of another (Snapshots). */
  const go = useCallback(
    (target: NavTarget) => {
      if (!target) return;
      if ("moved" in target) openVms([], "snapshots");
      else setPage(target.page as PageId);
    },
    [openVms],
  );

  useEffect(() => {
    paletteOpen.current = palette.open;
  }, [palette.open]);

  // FD-01: keyboard shortcuts, caught before a focused terminal sees them.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!e.ctrlKey || e.altKey || e.metaKey) return;
      const terminal = inTerminal(e.target);
      if (e.key.toLowerCase() === "k" && (e.shiftKey || !terminal)) {
        // Not over another dialog (an approval in progress keeps the keyboard).
        const otherDialog =
          !paletteOpen.current &&
          document.querySelector('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]');
        if (otherDialog) return;
        e.preventDefault();
        e.stopPropagation();
        setPalette((p) => (p.open ? { ...p, open: false } : { open: true, vm: null, n: p.n + 1 }));
        return;
      }
      if (terminal || e.shiftKey || paletteOpen.current) return;
      const target = /^[1-9,]$/.test(e.key) ? shortcutTarget(e.key, PAGES) : null;
      if (target) {
        e.preventDefault();
        go(target);
      }
    }
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [go]);

  const loadVault = useCallback(() => {
    api.vaultInfo().then(
      (info) => {
        setVault(info);
        // FD-14: a check that found the vault locked runs again once the update token can be read.
        if (info.status === "unlocked" && lastUpdateStatus.current === "vaultLocked") setUpdateRun((n) => n + 1);
      },
      () => setVault(null),
    );
  }, []);

  useEffect(() => {
    loadVault();
    // The vault locks itself after the idle time; the core says so.
    const unlisten = api.onVaultStatus(() => loadVault());
    return () => void unlisten.then((stop) => stop());
  }, [loadVault]);

  const loadInfo = useCallback(() => {
    api.appInfo().then(setInfo, () => setInfo(null));
  }, []);

  useEffect(loadInfo, [loadInfo, settingsVersion]);

  const applyUpdateCheck = useCallback((result: UpdateCheck) => {
    lastUpdateStatus.current = result.status;
    setUpdateProblem(null);
    // A locked vault says nothing new: keep showing an update found earlier.
    setUpdateCheck((prev) => (result.status === "vaultLocked" && prev?.status === "available" ? prev : result));
  }, []);

  const applyUpdateError = useCallback((err: unknown) => {
    const code = errorCode(err);
    if (code && UPDATE_TOKEN_ERRORS.includes(code)) {
      lastUpdateStatus.current = null;
      setUpdateProblem({ code, message: errorMessage(err) });
    } else {
      // Offline or GitHub having a moment: not worth interrupting anyone for. "Check now" in Settings
      // shows the error.
      console.warn("update check failed", err);
    }
  }, []);

  // FD-14: check for a newer release at start and every 24 hours, again when settings change, and
  // once the vault is unlocked if it was locked. The core makes no network call when update checks
  // are off, there is no GitHub update token or the vault is locked.
  useEffect(() => {
    let stopped = false;
    const check = () =>
      api.checkForUpdate().then(
        (result) => {
          if (!stopped) applyUpdateCheck(result);
        },
        (err) => {
          if (!stopped) applyUpdateError(err);
        },
      );
    void check();
    const timer = window.setInterval(() => void check(), UPDATE_CHECK_INTERVAL_MS);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [settingsVersion, updateRun, applyUpdateCheck, applyUpdateError]);

  async function installUpdate(version: string) {
    try {
      submitted(await api.submit({ type: "appUpdate", version }));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  // Job progress from the core -> toasts (one per job, updated in place) and an Activity refresh.
  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      setJobsVersion((v) => v + 1);
      const id = event.jobId;
      if (event.event === "queued" && event.quiet) quietJobs.current.add(id);
      if (quietJobs.current.has(id)) {
        if (event.event === "finished") quietJobs.current.delete(id);
        // A countdown still shows: it can be cancelled from the toast.
        if (event.event !== "countdown") return;
      }
      switch (event.event) {
        case "queued":
          toast.info(event.summary, { id, description: "Queued" });
          break;
        case "countdown":
          toast.warning(`Starts in ${event.seconds} seconds`, {
            id,
            description: "Nothing has been done yet. Cancel here or in Activity.",
            duration: event.seconds * 1000 + 2000,
            action: { label: "Cancel", onClick: () => void api.cancelJob(id) },
          });
          break;
        case "started":
          // Updates keep the earlier description unless it is cleared.
          toast.loading("Running…", { id, description: null });
          break;
        case "stillRunning": {
          // VM-03: offer the hard power-off, which goes through the bus and its own Critical approval.
          const names = event.targets.map((t) => t.name).join(", ");
          const targets = event.targets.map((t) => t.target);
          toast.warning(`Still running after the shutdown: ${names}`, {
            id: `${id}-still-running`,
            description: "The guest did not shut down in time. Forcing it off needs its own approval.",
            duration: Infinity,
            closeButton: true,
            action: {
              label: "Force off…",
              onClick: () =>
                void api
                  .submit({ type: "vmPower", targets, op: { kind: "stop", mode: "hard" } })
                  .then(submitted, (err) => toast.error(errorMessage(err))),
            },
          });
          break;
        }
        case "finished":
          setJobsFinished((v) => v + 1);
          if (event.status === "succeeded") toast.success("Job succeeded", { id, description: null, duration: 5000 });
          else toast.error(`Job ${event.status.replace("_", " ")}`, { id, description: null, duration: 8000 });
          break;
      }
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  function submitted(outcome: SubmitOutcome, onJob?: (jobId: string) => void) {
    if (outcome.status === "needsApproval") {
      setApproval({ request: outcome.request, onJob });
      return;
    }
    onJob?.(outcome.jobId);
    if (outcome.skipped.length > 0) {
      // AP-04: a Low action has no dialog, so say which protected targets it left alone.
      const names = outcome.skipped.map((t) => t.name).join(", ");
      toast.info(`Skipped ${outcome.skipped.length} protected: ${names}`, { duration: 8000 });
    }
  }

  async function submitCommand(command: Command) {
    try {
      submitted(await api.submit(command));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  function openTerminal(sessionId: string) {
    setTerminalOpen((prev) => ({ sessionId, n: (prev?.n ?? 0) + 1 }));
    setPage("terminal");
  }

  /** CT-01 "Open a shell": a terminal tab inside a container on a session's host. */
  function openContainerShell(container: ContainerShellRequest) {
    setTerminalOpen((prev) => ({ sessionId: container.sessionId, n: (prev?.n ?? 0) + 1, container }));
    setPage("terminal");
  }

  // FD-01: the app's own actions in the palette. Changes to VMs and hosts are commands it submits.
  const paletteActions: PaletteAction[] = [
    {
      id: "refresh",
      label: "Refresh the VM list",
      icon: RefreshCwIcon,
      keywords: "reload discover inventory",
      // The VM list refreshes itself when its key changes, and shows what it could not read.
      run: () => {
        setInventoryVersion((v) => v + 1);
        setPage("vms");
      },
    },
    {
      id: "snapshots",
      label: "Snapshots: take, revert or delete…",
      icon: CameraIcon,
      keywords: "snapshot safety restore vm virtual machines",
      run: () => openVms([], "snapshots"),
    },
    {
      id: "watch",
      label: "Watch hosts on the dashboard",
      icon: GaugeIcon,
      keywords: "metrics monitoring guest",
      run: () => setPage("dashboard"),
    },
    {
      id: "new-terminal",
      label: "New terminal (quick connect)…",
      icon: TerminalIcon,
      keywords: "ssh connect host open quick",
      run: () => {
        setTerminalNew((n) => n + 1);
        setPage("terminal");
      },
    },
    {
      id: "compare",
      label: "Compare output on several hosts…",
      icon: GitCompareArrowsIcon,
      keywords: "bulk run command script many hosts group diff",
      run: () => {
        setTerminalCompare((n) => n + 1);
        setPage("terminal");
      },
    },
    {
      id: "multiexec",
      label: "MultiExec: type into several terminals",
      icon: RadioTowerIcon,
      keywords: "broadcast bulk many tabs at once",
      run: () => {
        setTerminalMultiExec((n) => n + 1);
        setPage("terminal");
      },
    },
    vault?.status === "unlocked"
      ? {
          id: "lock",
          label: "Lock the vault",
          icon: LockIcon,
          run: async () => {
            try {
              setVault(await api.vaultLock());
            } catch (err) {
              toast.error(errorMessage(err));
            }
          },
        }
      : { id: "unlock", label: "Unlock the vault", icon: LockOpenIcon, run: () => setPage("vault") },
    {
      id: "theme-dark",
      label: resolved === "dark" ? "Turn dark mode off" : "Turn dark mode on",
      icon: resolved === "dark" ? SunIcon : MoonIcon,
      keywords: "theme appearance dark light colour",
      run: () => setDark(resolved !== "dark"),
    },
    {
      id: "theme-system",
      label: followWindows ? "Stop following the Windows theme" : "Follow the Windows theme",
      icon: MonitorIcon,
      keywords: "theme appearance dark light colour system",
      run: () => setFollowWindows(!followWindows),
    },
    presentation.presenting
      ? {
          id: "stop-presenting",
          label: "Stop presenting…",
          icon: PresentationIcon,
          keywords: "presentation mode screen share mask unmask",
          run: () => requestStopPresenting(),
        }
      : {
          id: "present",
          label: "Present: mask host names, IP addresses and user names",
          icon: PresentationIcon,
          keywords: "presentation mode screen share call hide mask demo",
          run: () => void startPresenting(),
        },
    {
      id: "read-only-lock",
      label: presentation.readOnly ? "Turn the read-only lock off…" : "Turn the read-only lock on (while presenting)",
      icon: presentation.readOnly ? LockOpenIcon : LockIcon,
      keywords: "presentation mode block changes safe demo",
      run: () => requestReadOnlyLock(!presentation.readOnly),
    },
    {
      id: "hide-terminals",
      label: presentation.hideTerminals
        ? "Show terminal output while presenting"
        : "Hide terminal output while presenting",
      icon: TerminalIcon,
      keywords: "presentation mode blur screen share",
      run: () => setHideTerminals(!presentation.hideTerminals),
    },
    {
      id: "update",
      label: "Check for updates",
      icon: DownloadIcon,
      keywords: "version release",
      run: async () => {
        setLaterFor(null);
        try {
          const result = await api.checkForUpdate();
          applyUpdateCheck(result);
          if (result.status === "upToDate") toast.info("Remotely is up to date");
          if (result.status === "off") toast.info("Update checks are off in Settings");
          if (result.status === "vaultLocked")
            toast.info("Unlock the vault first: the GitHub update token is kept there");
        } catch (err) {
          applyUpdateError(err);
          toast.error(errorMessage(err));
        }
      },
    },
    {
      id: "audit",
      label: "Export the audit log…",
      icon: HistoryIcon,
      keywords: "csv download",
      run: async () => {
        try {
          const report = await api.exportAudit();
          if (report) toast.success(`Exported the audit log (${report.entries} entries)`);
        } catch (err) {
          toast.error(errorMessage(err));
        }
      },
    },
  ];

  const current = PAGES.find((p) => p.id === page) ?? PAGES[0];

  return (
    <TooltipProvider>
      <SidebarProvider>
        <Sidebar collapsible="icon">
          <SidebarHeader>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton size="lg" className="pointer-events-none">
                  <img src={logo} alt="" className="size-8 shrink-0" draggable={false} />
                  <div className="grid text-left text-sm leading-tight">
                    <span className="truncate font-semibold">Remotely</span>
                    <span className="truncate text-xs text-muted-foreground">Version {info?.version ?? "…"}</span>
                  </div>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarHeader>

          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupContent>
                <SidebarMenu>
                  {PAGES.map((p) => (
                    <SidebarMenuItem key={p.id}>
                      <SidebarMenuButton
                        isActive={page === p.id}
                        tooltip={`${p.label} (${p.shortcut})`}
                        aria-keyshortcuts={p.shortcut.replace("Ctrl", "Control")}
                        onClick={() => setPage(p.id)}
                      >
                        <p.icon />
                        <span>{p.label}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>

          <SidebarFooter>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton tooltip={vaultLabel(vault)} onClick={() => setPage("vault")}>
                  {vault?.status === "unlocked" ? <LockOpenIcon className="text-success" /> : <LockIcon />}
                  <span>{vaultLabel(vault)}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip={info?.vmrunPath ?? "vmrun.exe was not found"}
                  onClick={() => setPage("settings")}
                >
                  <span
                    className={cn("size-2 shrink-0 rounded-full", info?.vmrunPath ? "bg-success" : "bg-destructive")}
                    aria-hidden
                  />
                  <span>{info?.vmrunPath ? "Workstation found" : "Workstation not found"}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarFooter>
          <SidebarRail />
        </Sidebar>

        <SidebarInset className="h-svh overflow-hidden">
          <header className="flex h-12 shrink-0 items-center gap-2 border-b px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
            <h1 className="text-sm font-semibold">{current.title}</h1>
            <Button
              variant="outline"
              size="sm"
              className="ml-auto w-64 justify-start text-muted-foreground"
              aria-keyshortcuts="Control+K"
              onClick={() => openPalette(null)}
            >
              <SearchIcon />
              Search or run an action…
              <Kbd className="ml-auto">Ctrl K</Kbd>
            </Button>
            <PresentationButton />
            <label
              className="flex items-center gap-2 text-sm whitespace-nowrap text-muted-foreground"
              title={
                followWindows
                  ? "Follows Windows now. Switching picks a theme and stops following Windows (Settings, General)."
                  : undefined
              }
            >
              Dark mode
              <Switch checked={resolved === "dark"} onCheckedChange={setDark} />
            </label>
          </header>
          <div className="min-h-0 flex-1 overflow-auto p-6">
            {READ_ONLY_PAGES[page] && <ReadOnlyNotice {...READ_ONLY_PAGES[page]} />}
            {offered && laterFor !== offered.version && (
              <UpdateBanner
                update={offered}
                disabledReason={readOnlyReason}
                onInstall={() => void installUpdate(offered.version)}
                onLater={() => setLaterFor(offered.version)}
              />
            )}
            {!offered && updateProblem && laterFor !== updateProblem.code && (
              <UpdateNotice
                destructive
                title="Remotely can't check for updates"
                description={sentence(updateProblem.message)}
                onOpenSettings={() => setPage("settings")}
                onLater={() => setLaterFor(updateProblem.code)}
              />
            )}
            {!offered && !updateProblem && updateCheck?.status === "noToken" && laterFor !== "noToken" && (
              <UpdateNotice
                title="Updates need a GitHub update token"
                description="Remotely's releases are in a private GitHub repository. Add a read-only token in Settings, under Updates, to get new versions, or turn update checks off there."
                onOpenSettings={() => setPage("settings")}
                onLater={() => setLaterFor("noToken")}
              />
            )}
            <section hidden={page !== "vms"} className="h-full">
              <VmsPage
                active={page === "vms"}
                onSubmitted={submitted}
                onOpenSettings={() => setPage("settings")}
                onActions={openPalette}
                request={vmRequest}
                refreshKey={jobsFinished + settingsVersion + inventoryVersion}
              />
            </section>
            <section hidden={page !== "dashboard"}>
              <DashboardPage
                active={page === "dashboard"}
                theme={resolved}
                focus={dashboardFocus}
                onConnect={openTerminal}
                onActions={(vmxPath) => openPalette(vmxPath)}
                onOpenVms={() => setPage("vms")}
                onOpenSessions={() => setPage("sessions")}
              />
            </section>
            <section hidden={page !== "containers"} className="h-full">
              <ContainersPage
                active={page === "containers"}
                onSubmitted={submitted}
                onOpenShell={openContainerShell}
                onOpenSettings={() => setPage("settings")}
                refreshKey={jobsFinished + settingsVersion}
              />
            </section>
            <section hidden={page !== "sessions"}>
              <SessionsPage
                vault={vault}
                onVaultChanged={setVault}
                onOpenVault={() => setPage("vault")}
                onConnect={openTerminal}
                active={page === "sessions"}
              />
            </section>
            <section hidden={page !== "terminal"} className="h-full">
              <TerminalPage
                active={page === "terminal"}
                theme={resolved}
                openRequest={terminalOpen}
                newRequest={terminalNew}
                compareRequest={terminalCompare}
                multiExecRequest={terminalMultiExec}
                vault={vault}
                onSubmitted={submitted}
                onOpenVault={() => setPage("vault")}
              />
            </section>
            <section hidden={page !== "knownHosts"}>
              <KnownHostsPage active={page === "knownHosts"} />
            </section>
            <section hidden={page !== "vault"}>
              <VaultPage
                vault={vault}
                onVaultChanged={setVault}
                active={page === "vault"}
                onSubmitted={submitted}
                onOpenSessions={() => setPage("sessions")}
              />
            </section>
            <section hidden={page !== "activity"}>
              <ActivityPage version={jobsVersion} active={page === "activity"} />
            </section>
            <section hidden={page !== "settings"}>
              <SettingsPage
                onChanged={() => setSettingsVersion((v) => v + 1)}
                vault={vault}
                onVaultChanged={setVault}
                onOpenVault={() => setPage("vault")}
              />
            </section>
          </div>
        </SidebarInset>
      </SidebarProvider>

      {approval && (
        <ApprovalDialog
          request={approval.request}
          vault={vault}
          onOpenVault={() => {
            setApproval(null);
            setPage("vault");
          }}
          onApproved={approval.onJob}
          onClose={(jobId) => {
            setApproval(null);
            if (jobId) setJobsVersion((v) => v + 1);
          }}
        />
      )}
      <CommandPalette
        key={palette.n}
        open={palette.open}
        onOpenChange={(open) => setPalette((p) => ({ ...p, open }))}
        vmFocus={palette.vm}
        pages={PAGES}
        onNavigate={(id) => go(navTarget(id, PAGES))}
        actions={paletteActions}
        onSubmit={submitCommand}
        onConnect={openTerminal}
        onShowMetrics={(key) => {
          setDashboardFocus((prev) => ({ key, n: (prev?.n ?? 0) + 1 }));
          setPage("dashboard");
        }}
        onOpenVm={(vmxPath, view) => openVms([vmxPath], view)}
      />
      <Toaster theme={resolved} position="bottom-right" />
      <PresentationLayer />
    </TooltipProvider>
  );
}

/** Core messages start in lower case and end without a full stop, so they read well after a prefix. */
function sentence(text: string) {
  const capital = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

function vaultLabel(vault: VaultInfo | null) {
  switch (vault?.status) {
    case "unlocked":
      return "Vault unlocked";
    case "locked":
      return "Vault locked";
    case "notSetUp":
      return "Vault not set up";
    default:
      return "Vault";
  }
}
