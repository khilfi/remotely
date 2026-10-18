// App shell (shadcn/ui): sidebar navigation with the vault status (SS-04), top bar with the theme switch
// (FD-01), pages, the approval dialog and job toasts. Pages stay mounted while hidden so terminal
// connections survive a page switch.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  CameraIcon,
  HistoryIcon,
  KeyRoundIcon,
  LayoutDashboardIcon,
  ListTreeIcon,
  LockIcon,
  LockOpenIcon,
  MonitorIcon,
  MoonIcon,
  ServerIcon,
  SettingsIcon,
  ShieldCheckIcon,
  SquareTerminalIcon,
  SunIcon,
  TerminalIcon,
  type LucideIcon,
} from "lucide-react";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Toaster } from "@/components/ui/sonner";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { TooltipProvider } from "@/components/ui/tooltip";
import logo from "@/assets/remotely-logo.png";
import { ApprovalDialog } from "@/components/ApprovalDialog";
import { UpdateBanner } from "@/components/UpdateBanner";
import {
  api,
  errorMessage,
  type AppInfo,
  type ApprovalRequest,
  type SubmitOutcome,
  type UpdateInfo,
  type VaultInfo,
} from "@/lib/api";
import { useTheme, type ThemePreference } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { ActivityPage } from "@/pages/ActivityPage";
import { BulkRunPage } from "@/pages/BulkRunPage";
import { KnownHostsPage } from "@/pages/KnownHostsPage";
import { SessionsPage } from "@/pages/SessionsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { SnapshotsPage } from "@/pages/SnapshotsPage";
import { TerminalPage } from "@/pages/TerminalPage";
import { VaultPage } from "@/pages/VaultPage";
import { VmsPage } from "@/pages/VmsPage";

type PageId = "vms" | "snapshots" | "sessions" | "terminal" | "bulk" | "knownHosts" | "vault" | "activity" | "settings";

const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

const PAGES: { id: PageId; label: string; title: string; icon: LucideIcon }[] = [
  { id: "vms", label: "Virtual machines", title: "Virtual machines", icon: ServerIcon },
  { id: "snapshots", label: "Snapshots", title: "Snapshots", icon: CameraIcon },
  { id: "sessions", label: "Sessions", title: "Sessions", icon: ListTreeIcon },
  { id: "terminal", label: "Terminal", title: "Terminal", icon: TerminalIcon },
  { id: "bulk", label: "Bulk run", title: "Bulk run", icon: SquareTerminalIcon },
  { id: "knownHosts", label: "Known hosts", title: "Known hosts", icon: ShieldCheckIcon },
  { id: "vault", label: "Vault", title: "Vault", icon: KeyRoundIcon },
  { id: "activity", label: "Activity", title: "Jobs and audit log", icon: HistoryIcon },
  { id: "settings", label: "Settings", title: "Settings", icon: SettingsIcon },
];

/** MVP pages that are not built yet, shown so the roadmap is visible in the app. */
const LATER: { label: string; req: string; icon: LucideIcon }[] = [
  { label: "Dashboard", req: "MO-03", icon: LayoutDashboardIcon },
];

const THEMES: { value: ThemePreference; label: string; icon: LucideIcon }[] = [
  { value: "system", label: "Follow Windows", icon: MonitorIcon },
  { value: "light", label: "Light", icon: SunIcon },
  { value: "dark", label: "Dark", icon: MoonIcon },
];

export default function App() {
  const [page, setPage] = useState<PageId>("vms");
  const [info, setInfo] = useState<AppInfo | null>(null);
  // The open approval, and who wants the job id once it is approved (the Bulk run page follows its run).
  const [approval, setApproval] = useState<{ request: ApprovalRequest; onJob?: (jobId: string) => void } | null>(null);
  const [jobsVersion, setJobsVersion] = useState(0);
  // Bumped when a job finishes, so the VM list shows the new power states.
  const [jobsFinished, setJobsFinished] = useState(0);
  const [settingsVersion, setSettingsVersion] = useState(0);
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [laterFor, setLaterFor] = useState<string | null>(null);
  // VMs picked on the VMs page to open in the snapshot manager (VM-04).
  const [snapshotPick, setSnapshotPick] = useState<{ paths: string[]; n: number } | null>(null);
  // SS-03: a session to open in a new terminal tab.
  const [terminalOpen, setTerminalOpen] = useState<{ sessionId: string; n: number } | null>(null);
  // SS-04: the vault's status for the sidebar, the pages and the approval dialog (AP-06).
  const [vault, setVault] = useState<VaultInfo | null>(null);
  const { preference, setPreference, resolved } = useTheme();

  const loadVault = useCallback(() => {
    api.vaultInfo().then(setVault, () => setVault(null));
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

  // FD-14: check for a newer release at start and every 24 hours, and again when settings change.
  // The core skips the network call when update checks are turned off.
  useEffect(() => {
    let stopped = false;
    const check = () =>
      api.checkForUpdate().then(
        (found) => {
          if (!stopped) setUpdate(found);
        },
        // No release yet, offline or blocked: not worth interrupting anyone for.
        (err) => console.warn("update check failed", err),
      );
    void check();
    const timer = window.setInterval(() => void check(), UPDATE_CHECK_INTERVAL_MS);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [settingsVersion]);

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
                      <SidebarMenuButton isActive={page === p.id} tooltip={p.label} onClick={() => setPage(p.id)}>
                        <p.icon />
                        <span>{p.label}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
            <SidebarGroup>
              <SidebarGroupLabel>Coming in the MVP</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {LATER.map((p) => (
                    <SidebarMenuItem key={p.req}>
                      <SidebarMenuButton disabled tooltip={`${p.label} (${p.req})`}>
                        <p.icon />
                        <span>{p.label}</span>
                      </SidebarMenuButton>
                      <SidebarMenuBadge className="font-mono text-[10px]">{p.req}</SidebarMenuBadge>
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
            <ToggleGroup
              type="single"
              variant="outline"
              size="sm"
              className="ml-auto"
              aria-label="Theme"
              value={preference}
              onValueChange={(value) => value && setPreference(value as ThemePreference)}
            >
              {THEMES.map((t) => (
                <ToggleGroupItem key={t.value} value={t.value} aria-label={t.label} title={t.label}>
                  <t.icon />
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
          </header>
          <div className="min-h-0 flex-1 overflow-auto p-6">
            {update && laterFor !== update.version && (
              <UpdateBanner
                update={update}
                onInstall={() => void installUpdate(update.version)}
                onLater={() => setLaterFor(update.version)}
              />
            )}
            <section hidden={page !== "vms"}>
              <VmsPage
                onSubmitted={submitted}
                onOpenSettings={() => setPage("settings")}
                onOpenSnapshots={(paths) => {
                  setSnapshotPick((prev) => ({ paths, n: (prev?.n ?? 0) + 1 }));
                  setPage("snapshots");
                }}
                refreshKey={jobsFinished + settingsVersion}
              />
            </section>
            <section hidden={page !== "snapshots"}>
              <SnapshotsPage
                active={page === "snapshots"}
                onSubmitted={submitted}
                refreshKey={jobsFinished + settingsVersion}
                preselect={snapshotPick}
              />
            </section>
            <section hidden={page !== "sessions"}>
              <SessionsPage
                vault={vault}
                onVaultChanged={setVault}
                onOpenVault={() => setPage("vault")}
                onConnect={(sessionId) => {
                  setTerminalOpen((prev) => ({ sessionId, n: (prev?.n ?? 0) + 1 }));
                  setPage("terminal");
                }}
                active={page === "sessions"}
              />
            </section>
            <section hidden={page !== "terminal"} className="h-full">
              <TerminalPage
                active={page === "terminal"}
                theme={resolved}
                openRequest={terminalOpen}
                onOpenVault={() => setPage("vault")}
              />
            </section>
            <section hidden={page !== "bulk"}>
              <BulkRunPage
                active={page === "bulk"}
                vault={vault}
                onSubmit={submitted}
                onOpenVault={() => setPage("vault")}
                onOpenSessions={() => setPage("sessions")}
              />
            </section>
            <section hidden={page !== "knownHosts"}>
              <KnownHostsPage active={page === "knownHosts"} />
            </section>
            <section hidden={page !== "vault"}>
              <VaultPage vault={vault} onVaultChanged={setVault} active={page === "vault"} />
            </section>
            <section hidden={page !== "activity"}>
              <ActivityPage version={jobsVersion} active={page === "activity"} />
            </section>
            <section hidden={page !== "settings"}>
              <SettingsPage onChanged={() => setSettingsVersion((v) => v + 1)} />
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
      <Toaster theme={resolved} position="bottom-right" />
    </TooltipProvider>
  );
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
