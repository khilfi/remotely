// App shell (shadcn/ui): sidebar navigation with the vault status (SS-04), top bar with the command
// palette and the Dark mode switch (FD-01, QL-11: "Follow Windows" is in Settings), pages, the approval dialog and job
// toasts. Pages stay mounted
// while hidden so terminal connections survive a page switch. Bulk execution lives in the Terminal page (post-MVP P6):
// MultiExec (SS-10) and Compare output (BX-03) replace the MVP's Bulk run page.
//
// FD-01 keyboard: Ctrl+K opens the command palette (Ctrl+Shift+K inside a terminal, where Ctrl+K belongs
// to the shell), Ctrl+1 to Ctrl+9 open the pages by their own shortcut and Ctrl+, opens Settings. VM-19 to VM-21: the
// Templates page (sizes, images, launch templates) sits under Virtual machines with Ctrl+9.
//
// QL-14: snapshots are part of the Virtual machines page. The sidebar's third slot is left for Containers (Q6); until
// then Ctrl+3, Snapshots' old shortcut, opens the snapshot view there (lib/navigation.ts).
//
// FD-03: the top bar's Present button (Presenting menu while on) and the palette start and stop presentation mode,
// its read-only lock and "Hide terminal output" (Presentation.tsx).
//
// R10 (0.5.0): every link in the app (QL-20 search results, QL-21 map nodes, QL-22 status bar items, QL-25
// notifications) is an AppLink (lib/links.ts) that `openLink` below opens; the Map page has Ctrl+0; the status bar runs
// along the bottom with the notification centre's bell; Ctrl+/ shows every shortcut (QL-24); the first-run wizard
// offers itself when there is no vault and no session (QL-23).
//
// P6: App renders again only when a job is queued or ends, not on each of its progress events (src/lib/job-events.ts),
// and the pages are memoised with stable callbacks, so a render here doesn't re-render the pages whose props stayed
// the same. VM-01: a finished job refreshes the VM list only when it may have changed VMs (its scope), and a settings
// save only when it changed where VMs are found; the Containers page likewise for container jobs and docker.exe.

import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";
import {
  CameraIcon,
  FilePlusIcon,
  DownloadIcon,
  GaugeIcon,
  ContainerIcon,
  DiscIcon,
  GitCompareArrowsIcon,
  HistoryIcon,
  BellIcon,
  BoxesIcon,
  CompassIcon,
  KeyboardIcon,
  KeyRoundIcon,
  LayersIcon,
  NetworkIcon,
  Rows3Icon,
  RocketIcon,
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
  TextSearchIcon,
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
import { DeployDialog } from "@/components/DeployDialog";
import { CommandPalette, type PaletteAction } from "@/components/CommandPalette";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { ReauthDialog } from "@/components/ReauthDialog";
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
import { AlertNotifier } from "@/components/AlertNotifier";
import { FirstRunWizard } from "@/components/FirstRunWizard";
import { NotificationCentre } from "@/components/NotificationCentre";
import { NotificationSources } from "@/components/NotificationSources";
import { ShortcutSheet } from "@/components/ShortcutSheet";
import { StatusBar } from "@/components/StatusBar";
import { useDensity } from "@/lib/density";
import { firstRunDismissed, onFirstRunRequest, requestFirstRun, shouldOfferFirstRun } from "@/lib/first-run";
import type { AppLink } from "@/lib/links";
import { fromSkipped, fromUpdate } from "@/lib/notifications";
import { notify } from "@/lib/notifications-store";
import { opensShortcutSheet } from "@/lib/shortcuts";
import { reportVault } from "@/lib/status-bar";
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
import { shouldPingActivity } from "@/lib/reauth";
import { useTheme } from "@/lib/theme";
import { checkMessage, isNotice, recheckDelayMs, UPDATE_CHECK_INTERVAL_MS } from "@/lib/updates";
import { cn } from "@/lib/utils";
import { ActivityPage } from "@/pages/ActivityPage";
import { ContainersPage, type ContainerRequest, type ContainerShellRequest } from "@/pages/ContainersPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { KnownHostsPage } from "@/pages/KnownHostsPage";
import { MapPage } from "@/pages/MapPage";
import { SessionsPage } from "@/pages/SessionsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { TemplatesPage, type TemplatesTab } from "@/pages/TemplatesPage";
import { TerminalPage } from "@/pages/TerminalPage";
import { VaultPage } from "@/pages/VaultPage";
import { VmsPage, type VmPageRequest } from "@/pages/VmsPage";
import { navTarget, shortcutTarget, type NavTarget } from "@/lib/navigation";
import {
  changesAppInfo,
  changesContainerHosts,
  changesJobList,
  changesUpdates,
  changesVmList,
  refreshesContainers,
  refreshesVms,
  type SettingsChange,
} from "@/lib/job-events";
import type { VmView } from "@/lib/vm-snapshots";

type PageId =
  | "vms"
  | "templates"
  | "map"
  | "dashboard"
  | "containers"
  | "sessions"
  | "terminal"
  | "knownHosts"
  | "vault"
  | "activity"
  | "settings";

/** In sidebar order, each with its own shortcut. Ctrl+3 is Containers (Q6); the old Snapshots alias stops. */
const PAGES: { id: PageId; label: string; title: string; icon: LucideIcon; shortcut: string }[] = [
  { id: "vms", label: "Virtual machines", title: "Virtual machines", icon: ServerIcon, shortcut: "Ctrl+1" },
  { id: "templates", label: "Templates", title: "VM templates", icon: LayersIcon, shortcut: "Ctrl+9" },
  { id: "map", label: "Map", title: "Topology map", icon: NetworkIcon, shortcut: "Ctrl+0" },
  { id: "dashboard", label: "Dashboard", title: "Dashboard", icon: LayoutDashboardIcon, shortcut: "Ctrl+2" },
  { id: "containers", label: "Containers", title: "Containers", icon: ContainerIcon, shortcut: "Ctrl+3" },
  { id: "sessions", label: "Sessions", title: "Sessions", icon: ListTreeIcon, shortcut: "Ctrl+4" },
  { id: "terminal", label: "Terminal", title: "Terminal", icon: TerminalIcon, shortcut: "Ctrl+5" },
  { id: "knownHosts", label: "Known hosts", title: "Known hosts", icon: ShieldCheckIcon, shortcut: "Ctrl+6" },
  { id: "vault", label: "Vault", title: "Vault", icon: KeyRoundIcon, shortcut: "Ctrl+7" },
  { id: "activity", label: "Activity", title: "Jobs and audit log", icon: HistoryIcon, shortcut: "Ctrl+8" },
  { id: "settings", label: "Settings", title: "Settings", icon: SettingsIcon, shortcut: "Ctrl+," },
];

// P6: memoised pages. Each one renders again only when its own props change; App passes them stable callbacks.
const Vms = memo(VmsPage);
const Templates = memo(TemplatesPage);
const TopologyMap = memo(MapPage);
const Dashboard = memo(DashboardPage);
const Containers = memo(ContainersPage);
const Sessions = memo(SessionsPage);
const Terminal = memo(TerminalPage);
const KnownHosts = memo(KnownHostsPage);
const Vault = memo(VaultPage);
const Activity = memo(ActivityPage);
const SettingsView = memo(SettingsPage);

/** Focus is in a terminal pane, where Ctrl+letter and Ctrl+digit keys belong to the remote shell. */
function inTerminal(target: EventTarget | null) {
  return target instanceof Element && target.closest(".xterm") !== null;
}

export default function App() {
  const [page, setPage] = useState<PageId>("vms");
  const [info, setInfo] = useState<AppInfo | null>(null);
  // The open approval, and who wants the job id once it is approved (Compare output follows its run).
  const [approval, setApproval] = useState<{ request: ApprovalRequest; onJob?: (jobId: string) => void } | null>(null);
  // Bumped when a job is queued or ends (P6: not on its progress, which Activity reads itself while it shows).
  const [jobsVersion, setJobsVersion] = useState(0);
  // VM-01: bumped when a job that may have changed VMs finished, so the VM list shows the new power states; CT-01 the
  // same for container actions and the Containers page.
  const [vmJobs, setVmJobs] = useState(0);
  const [containerJobs, setContainerJobs] = useState(0);
  // Bumped by settings saves, each for what depends on it: the sidebar's app info, update checks, where VMs are found
  // and this PC's docker.exe.
  const [infoVersion, setInfoVersion] = useState(0);
  const [updatesVersion, setUpdatesVersion] = useState(0);
  const [vmSettings, setVmSettings] = useState(0);
  const [containerSettings, setContainerSettings] = useState(0);
  // FD-14: the last update check, a problem with the GitHub update token it ran into, and the banner
  // put off with "Later" (an update's version, or "tokenNeeded" / the problem's code).
  const [updateCheck, setUpdateCheck] = useState<UpdateCheck | null>(null);
  const [updateProblem, setUpdateProblem] = useState<{ code: string; message: string } | null>(null);
  const [laterFor, setLaterFor] = useState<string | null>(null);
  const [updateRun, setUpdateRun] = useState(0);
  const lastUpdateStatus = useRef<UpdateCheck["status"] | null>(null);
  const updateRetry = useRef<number | undefined>(undefined);
  const offered = updateCheck?.status === "available" ? updateCheck.update : null;
  // QL-14: a VM (or the snapshot view) to show on the Virtual machines page.
  const [vmRequest, setVmRequest] = useState<VmPageRequest | null>(null);
  // VM-19 to VM-21: a tab of the Templates page, or a new item there, asked for from the palette.
  const [templatesRequest, setTemplatesRequest] = useState<{
    tab: TemplatesTab;
    create?: boolean;
    id?: string;
    n: number;
  } | null>(null);
  // R10: what a link (a search result, a map node, a notification, the status bar) asked a page to show.
  const [sessionsFocus, setSessionsFocus] = useState<{ sessionId: string; n: number } | null>(null);
  const [terminalFocus, setTerminalFocus] = useState<{ terminalId: string; tunnels?: boolean; n: number } | null>(null);
  const [snippetRequest, setSnippetRequest] = useState<{ command: string; n: number } | null>(null);
  const [jobFocus, setJobFocus] = useState<{ jobId: string; n: number } | null>(null);
  const [settingsFocus, setSettingsFocus] = useState<{ section: string; n: number } | null>(null);
  const [containerRequest, setContainerRequest] = useState<ContainerRequest | null>(null);
  // QL-25, QL-24, QL-23: the notification centre, the shortcut sheet and the first-run wizard.
  const [centreOpen, setCentreOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [firstRunOpen, setFirstRunOpen] = useState(false);
  const [density, setDensity] = useDensity();
  // VM-21: the Deploy dialog, on a template (its row's Deploy) or on none (the VMs page, the palette).
  const [deploying, setDeploying] = useState<{ templateId: string | null } | null>(null);
  const openDeploy = useCallback((templateId?: string) => setDeploying({ templateId: templateId ?? null }), []);
  const openDeployBlank = useCallback(() => setDeploying({ templateId: null }), []);
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
  // QL-18: Search all terminals, opened from the palette.
  const [terminalSearch, setTerminalSearch] = useState(0);
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
  const openVms = useCallback((vmxPaths: string[], view: VmView, rename?: boolean) => {
    setVmRequest((prev) => ({ vmxPaths, view, rename, n: (prev?.n ?? 0) + 1 }));
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
      // QL-24: the shortcut sheet (Ctrl+Shift+/ inside a terminal, where Ctrl+/ belongs to the shell).
      if (opensShortcutSheet(e, terminal) && !paletteOpen.current) {
        e.preventDefault();
        e.stopPropagation();
        setShortcutsOpen((open) => !open);
        return;
      }
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
      const target = /^[0-9,]$/.test(e.key) ? shortcutTarget(e.key, PAGES) : null;
      if (target) {
        e.preventDefault();
        go(target);
      }
    }
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [go]);

  // SS-04: the vault's idle lock counts from the user's own input, never from background reads, so typing and
  // clicking anywhere in the window (terminals included) tell the core, at most every 20 seconds.
  useEffect(() => {
    let last: number | null = null;
    function onInput() {
      const now = Date.now();
      if (!shouldPingActivity(last, now)) return;
      last = now;
      // QL-22: the answer moves the status bar's lock countdown on.
      void api.vaultActivity().then(
        (info) => reportVault(info),
        () => {},
      );
    }
    const events = ["keydown", "pointerdown", "wheel"] as const;
    for (const name of events) window.addEventListener(name, onInput, { capture: true, passive: true });
    return () => {
      for (const name of events) window.removeEventListener(name, onInput, { capture: true });
    };
  }, []);

  const loadVault = useCallback(() => {
    api.vaultInfo().then(
      (info) => {
        setVault(info);
        // FD-14: a check that needed the update token from the locked vault, or ran into GitHub's limit for
        // checks without one, runs again once the token can be read.
        const last = lastUpdateStatus.current;
        if (info.status === "unlocked" && (last === "vaultLocked" || last === "rateLimited"))
          setUpdateRun((n) => n + 1);
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

  useEffect(loadInfo, [loadInfo, infoVersion]);

  const applyUpdateCheck = useCallback((result: UpdateCheck) => {
    lastUpdateStatus.current = result.status;
    setUpdateProblem(null);
    // A locked vault or a used-up GitHub limit says nothing new: keep showing an update found earlier.
    const nothingNew = result.status === "vaultLocked" || result.status === "rateLimited";
    setUpdateCheck((prev) => (nothingNew && prev?.status === "available" ? prev : result));
    // QL-25: kept once per version.
    if (result.status === "available") notify(fromUpdate(result.update));
    // GitHub's limit was used up: one more check just after the time it named (the core makes no call before).
    window.clearTimeout(updateRetry.current);
    const delay = recheckDelayMs(result, Date.now());
    updateRetry.current = delay === null ? undefined : window.setTimeout(() => setUpdateRun((n) => n + 1), delay);
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

  // FD-14: check for a newer release at start and every 24 hours, again when the update settings change, and
  // once the vault is unlocked if the check needed it. The releases are public, so the core checks
  // without a token unless the vault can give it one. It makes no network call when update checks
  // are off, or while GitHub's API limit is used up; then one more check runs just after the limit resets.
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
  }, [updatesVersion, updateRun, applyUpdateCheck, applyUpdateError]);

  // Stable (P6): the memoised pages get it as a prop.
  const submitted = useCallback((outcome: SubmitOutcome, onJob?: (jobId: string) => void) => {
    if (outcome.status === "needsApproval") {
      setApproval({ request: outcome.request, onJob });
      return;
    }
    onJob?.(outcome.jobId);
    if (outcome.skipped.length > 0) {
      // AP-04: a Low action has no dialog, so say which protected targets it left alone.
      const names = outcome.skipped.map((t) => t.name).join(", ");
      toast.info(`Skipped ${outcome.skipped.length} protected: ${names}`, { duration: 8000 });
      notify(fromSkipped(outcome.skipped.map((t) => t.name)));
    }
  }, []);

  useEffect(() => {
    const retry = updateRetry;
    return () => window.clearTimeout(retry.current);
  }, []);

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
      // P6: progress (a countdown, a start, each target) changes no state here: the toasts below show it.
      if (changesJobList(event)) setJobsVersion((v) => v + 1);
      if (refreshesVms(event)) setVmJobs((v) => v + 1);
      if (refreshesContainers(event)) setContainerJobs((v) => v + 1);
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
        case "canaryWaiting":
          // H9: the rest wait for a look at the canary's result (Compare output, or the key push dialog), so the
          // toast has no go-ahead of its own.
          toast.warning(`${event.name} finished without errors`, {
            id,
            description: `The other ${event.rest === 1 ? "host waits" : `${event.rest} hosts wait`} for you to look at its result and say go on.`,
            duration: 15000,
          });
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
          if (event.status === "succeeded") toast.success("Job succeeded", { id, description: null, duration: 5000 });
          else toast.error(`Job ${event.status.replace("_", " ")}`, { id, description: null, duration: 8000 });
          break;
      }
    });
    return () => void unlisten.then((stop) => stop());
  }, [submitted]);

  async function submitCommand(command: Command) {
    try {
      submitted(await api.submit(command));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const openTerminal = useCallback((sessionId: string) => {
    setTerminalOpen((prev) => ({ sessionId, n: (prev?.n ?? 0) + 1 }));
    setPage("terminal");
  }, []);

  /** CT-01 "Open a shell": a terminal tab inside a container on a session's host. */
  const openContainerShell = useCallback((container: ContainerShellRequest) => {
    setTerminalOpen((prev) => ({ sessionId: container.sessionId, n: (prev?.n ?? 0) + 1, container }));
    setPage("terminal");
  }, []);

  // The update banner's state, for links to it, without making openLink change with every check (P6).
  const offeredRef = useRef(offered);
  useEffect(() => {
    offeredRef.current = offered;
  }, [offered]);

  /** R10: opens what a link is about. A later package adds its kind to lib/links.ts and a case here. */
  const openLink = useCallback(
    (link: AppLink) => {
      switch (link.kind) {
        case "page":
          go(navTarget(link.page, PAGES));
          break;
        case "vm":
          openVms([link.vmxPath], link.view ?? "details");
          break;
        case "session":
          setSessionsFocus((prev) => ({ sessionId: link.sessionId, n: (prev?.n ?? 0) + 1 }));
          setPage("sessions");
          break;
        case "terminal":
          setTerminalFocus((prev) => ({ terminalId: link.terminalId, tunnels: link.tunnels, n: (prev?.n ?? 0) + 1 }));
          setPage("terminal");
          break;
        case "job":
          setJobFocus((prev) => ({ jobId: link.jobId, n: (prev?.n ?? 0) + 1 }));
          setPage("activity");
          break;
        case "container":
          setContainerRequest((prev) => ({
            host: link.host,
            engine: link.engine,
            containerId: link.containerId,
            n: (prev?.n ?? 0) + 1,
          }));
          setPage("containers");
          break;
        case "catalog":
          setTemplatesRequest((prev) => ({ tab: link.tab, id: link.id, n: (prev?.n ?? 0) + 1 }));
          setPage("templates");
          break;
        case "setting":
          setSettingsFocus((prev) => ({ section: link.section, n: (prev?.n ?? 0) + 1 }));
          setPage("settings");
          break;
        case "snippet":
          setSnippetRequest((prev) => ({ command: link.command, n: (prev?.n ?? 0) + 1 }));
          setPage("terminal");
          break;
        case "alerts":
          setPage("dashboard");
          break;
        case "update":
          // The banner shows on every page; "Later" put it off, so it comes back. Nothing offered: Settings.
          if (offeredRef.current) setLaterFor(null);
          else {
            setSettingsFocus((prev) => ({ section: "updates", n: (prev?.n ?? 0) + 1 }));
            setPage("settings");
          }
          break;
        case "vault":
          setPage("vault");
          break;
        case "map":
          setPage("map");
          break;
      }
    },
    [go, openVms],
  );

  // QL-23: the wizard offers itself when there is no vault and no session yet (once the vault is known), and opens
  // again from Settings or the palette.
  const offeredFirstRun = useRef(false);
  useEffect(() => {
    if (offeredFirstRun.current || !vault) return;
    offeredFirstRun.current = true;
    if (vault.status !== "notSetUp" || firstRunDismissed()) return;
    api.sessions().then(
      (list) => {
        if (shouldOfferFirstRun({ vaultStatus: vault.status, sessionCount: list.length }, false)) setFirstRunOpen(true);
      },
      () => undefined,
    );
  }, [vault]);
  useEffect(() => onFirstRunRequest(() => setFirstRunOpen(true)), []);

  /** Pages the others link to, as stable callbacks (P6). */
  const show = useMemo(
    () => ({
      vms: () => setPage("vms"),
      sessions: () => setPage("sessions"),
      vault: () => setPage("vault"),
      settings: () => setPage("settings"),
    }),
    [],
  );

  /** What a settings save changed: only what depends on it is read again. */
  const settingsChanged = useCallback((change: SettingsChange) => {
    if (changesAppInfo(change)) setInfoVersion((v) => v + 1);
    if (changesUpdates(change)) setUpdatesVersion((v) => v + 1);
    if (changesVmList(change)) setVmSettings((v) => v + 1);
    if (changesContainerHosts(change)) setContainerSettings((v) => v + 1);
  }, []);

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
      // VM-24: a .vmx or .vbox from a file dialog the shell opens.
      id: "add-vm",
      label: "Add an existing VM…",
      icon: FilePlusIcon,
      keywords: "register vmx vbox open import virtual machine",
      run: async () => {
        try {
          const outcome = await api.vmPickExisting();
          if (outcome) submitted(outcome);
        } catch (err) {
          toast.error(errorMessage(err));
        }
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
      id: "deploy",
      label: "Deploy VMs from a launch template…",
      icon: RocketIcon,
      keywords: "vm template create clone cloud-init iso ova new virtual machine",
      run: () => openDeployBlank(),
    },
    {
      id: "new-template",
      label: "New launch template…",
      icon: LayersIcon,
      keywords: "vm template size image deploy create cloud",
      run: () => {
        setTemplatesRequest((prev) => ({ tab: "templates", create: true, n: (prev?.n ?? 0) + 1 }));
        setPage("templates");
      },
    },
    {
      id: "add-image",
      label: "Add a VM image (cloud image, ISO, OVA or golden VM)…",
      icon: DiscIcon,
      keywords: "vmdk qcow2 iso ova ovf snapshot template cloud-init",
      run: () => {
        setTemplatesRequest((prev) => ({ tab: "images", create: true, n: (prev?.n ?? 0) + 1 }));
        setPage("templates");
      },
    },
    {
      id: "sizes",
      label: "VM sizes (gp.medium and the others)",
      icon: LayersIcon,
      keywords: "instance type cpu ram disk vcpu template",
      run: () => {
        setTemplatesRequest((prev) => ({ tab: "sizes", n: (prev?.n ?? 0) + 1 }));
        setPage("templates");
      },
    },
    {
      // VM-08.
      id: "stacks",
      label: "Stacks: deploy, start, stop or tear down several VMs as one",
      icon: BoxesIcon,
      keywords: "stack lab blueprint boot order instance teardown templates group",
      run: () => {
        setTemplatesRequest((prev) => ({ tab: "stacks", n: (prev?.n ?? 0) + 1 }));
        setPage("templates");
      },
    },
    {
      id: "new-stack",
      label: "New stack of launch templates…",
      icon: BoxesIcon,
      keywords: "stack lab blueprint boot order readiness create",
      run: () => {
        setTemplatesRequest((prev) => ({ tab: "stacks", create: true, n: (prev?.n ?? 0) + 1 }));
        setPage("templates");
      },
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
    {
      id: "search-terminals",
      label: "Search all terminals (Ctrl+Shift+G)",
      icon: TextSearchIcon,
      keywords: "find scrollback output grep every tab",
      run: () => {
        setTerminalSearch((n) => n + 1);
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
      id: "notifications",
      label: "Notifications",
      icon: BellIcon,
      keywords: "notification centre history alerts jobs finished unread",
      run: () => setCentreOpen(true),
    },
    {
      id: "shortcuts",
      label: "Keyboard shortcuts (Ctrl+/)",
      icon: KeyboardIcon,
      keywords: "keys hotkeys help sheet list",
      run: () => setShortcutsOpen(true),
    },
    {
      id: "first-run",
      label: "Open the setup guide",
      icon: CompassIcon,
      keywords: "first run wizard welcome getting started vault import sessions",
      run: () => requestFirstRun(),
    },
    {
      id: "density",
      label: density === "compact" ? "Comfortable spacing" : "Compact spacing",
      icon: Rows3Icon,
      keywords: "density compact comfortable dense rows appearance",
      run: () => setDensity(density === "compact" ? "comfortable" : "compact"),
    },
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
          if (isNotice(result)) toast.info(checkMessage(result));
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
              {/* VM-18: optional, so not finding it is grey rather than red. */}
              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip={info?.vboxmanagePath ?? "VBoxManage.exe was not found: no VirtualBox VMs are listed"}
                  onClick={() => setPage("settings")}
                >
                  <span
                    className={cn(
                      "size-2 shrink-0 rounded-full",
                      info?.vboxmanagePath ? "bg-success" : "bg-muted-foreground/40",
                    )}
                    aria-hidden
                  />
                  <span>{info?.vboxmanagePath ? "VirtualBox found" : "VirtualBox not found"}</span>
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
              className="ml-auto min-w-64 justify-start text-muted-foreground"
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
            {!offered && !updateProblem && updateCheck?.status === "tokenNeeded" && laterFor !== "tokenNeeded" && (
              <UpdateNotice
                title="Updates need a GitHub update token"
                description={`GitHub doesn't show the releases of ${updateCheck.repository} without a token, so the repository may be private again. Add a read-only token in Settings, under Updates, to get new versions, or turn update checks off there.`}
                onOpenSettings={() => setPage("settings")}
                onLater={() => setLaterFor("tokenNeeded")}
              />
            )}
            <section hidden={page !== "vms"} className="h-full">
              <ErrorBoundary name="Virtual machines">
                <Vms
                  active={page === "vms"}
                  onSubmitted={submitted}
                  onDeploy={openDeployBlank}
                  onOpenSettings={show.settings}
                  onActions={openPalette}
                  request={vmRequest}
                  refreshKey={vmJobs + vmSettings + inventoryVersion}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "templates"}>
              <ErrorBoundary name="Templates">
                <Templates
                  active={page === "templates"}
                  request={templatesRequest}
                  onDeploy={openDeploy}
                  onSubmitted={submitted}
                  refreshKey={vmJobs + inventoryVersion}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "map"} className="h-full">
              <ErrorBoundary name="Map">
                <TopologyMap active={page === "map"} onOpenLink={openLink} />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "dashboard"}>
              <ErrorBoundary name="Dashboard">
                <Dashboard
                  active={page === "dashboard"}
                  theme={resolved}
                  focus={dashboardFocus}
                  onConnect={openTerminal}
                  onActions={openPalette}
                  onOpenVms={show.vms}
                  onOpenSessions={show.sessions}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "containers"} className="h-full">
              <ErrorBoundary name="Containers">
                <Containers
                  active={page === "containers"}
                  request={containerRequest}
                  onSubmitted={submitted}
                  onOpenShell={openContainerShell}
                  onOpenSettings={show.settings}
                  refreshKey={containerJobs + containerSettings}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "sessions"}>
              <ErrorBoundary name="Sessions">
                <Sessions
                  vault={vault}
                  onVaultChanged={setVault}
                  onOpenVault={show.vault}
                  onConnect={openTerminal}
                  active={page === "sessions"}
                  focus={sessionsFocus}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "terminal"} className="h-full">
              <ErrorBoundary name="Terminal">
                <Terminal
                  active={page === "terminal"}
                  theme={resolved}
                  openRequest={terminalOpen}
                  newRequest={terminalNew}
                  compareRequest={terminalCompare}
                  multiExecRequest={terminalMultiExec}
                  searchRequest={terminalSearch}
                  focusRequest={terminalFocus}
                  snippetRequest={snippetRequest}
                  vault={vault}
                  onSubmitted={submitted}
                  onOpenVault={show.vault}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "knownHosts"}>
              <ErrorBoundary name="Known hosts">
                <KnownHosts active={page === "knownHosts"} />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "vault"}>
              <ErrorBoundary name="Vault">
                <Vault
                  vault={vault}
                  onVaultChanged={setVault}
                  active={page === "vault"}
                  onSubmitted={submitted}
                  onOpenSessions={show.sessions}
                />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "activity"}>
              <ErrorBoundary name="Activity">
                <Activity version={jobsVersion} active={page === "activity"} focusJob={jobFocus} />
              </ErrorBoundary>
            </section>
            <section hidden={page !== "settings"}>
              <ErrorBoundary name="Settings">
                <SettingsView
                  onChanged={settingsChanged}
                  vault={vault}
                  onVaultChanged={setVault}
                  onOpenVault={show.vault}
                  focus={settingsFocus}
                />
              </ErrorBoundary>
            </section>
          </div>
          <StatusBar
            vault={vault}
            updateCheck={updateCheck}
            updateProblem={updateProblem?.message ?? null}
            onOpenLink={openLink}
            onOpenNotifications={() => setCentreOpen(true)}
          />
        </SidebarInset>
      </SidebarProvider>

      {deploying && (
        <DeployDialog templateId={deploying.templateId} onSubmitted={submitted} onClose={() => setDeploying(null)} />
      )}
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
        onOpenVm={(vmxPath, view, rename) => openVms([vmxPath], view, rename)}
        onOpenLink={openLink}
        onOpenConsole={(vmxPath) =>
          void api.vmOpenConsole(vmxPath).then(
            (done) => done.kind === "starting" && submitted(done.outcome),
            (err: unknown) => toast.error(errorMessage(err)),
          )
        }
      />
      <ReauthDialog />
      {/* MO-07: alerts notify through Windows whatever page shows. */}
      <AlertNotifier />
      {/* QL-25: jobs and alerts are kept in the notification centre whatever page shows. */}
      <NotificationSources />
      <NotificationCentre open={centreOpen} onOpenChange={setCentreOpen} onOpenLink={openLink} />
      <ShortcutSheet open={shortcutsOpen} onOpenChange={setShortcutsOpen} pages={PAGES} />
      <FirstRunWizard
        open={firstRunOpen}
        onOpenChange={setFirstRunOpen}
        vault={vault}
        onVaultChanged={setVault}
        onOpenVault={show.vault}
        onSettingsChanged={settingsChanged}
        onGoTo={(id) => go(navTarget(id, PAGES))}
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
