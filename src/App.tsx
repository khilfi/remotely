// App shell (shadcn/ui): sidebar navigation, top bar with the theme switch (FD-01), pages, the
// approval dialog and job toasts. Pages stay mounted while hidden so the terminal session survives
// a page switch.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  HistoryIcon,
  LayoutDashboardIcon,
  ListTreeIcon,
  MonitorIcon,
  MoonIcon,
  ServerIcon,
  SettingsIcon,
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
import { api, errorMessage, type AppInfo, type ApprovalRequest, type SubmitOutcome, type UpdateInfo } from "@/lib/api";
import { useTheme, type ThemePreference } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { ActivityPage } from "@/pages/ActivityPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { TerminalPage } from "@/pages/TerminalPage";
import { VmsPage } from "@/pages/VmsPage";

type PageId = "vms" | "terminal" | "activity" | "settings";

const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;

const PAGES: { id: PageId; label: string; title: string; icon: LucideIcon }[] = [
  { id: "vms", label: "Virtual machines", title: "Virtual machines", icon: ServerIcon },
  { id: "terminal", label: "Terminal", title: "Terminal", icon: TerminalIcon },
  { id: "activity", label: "Activity", title: "Jobs and audit log", icon: HistoryIcon },
  { id: "settings", label: "Settings", title: "Settings", icon: SettingsIcon },
];

/** MVP pages that are not built yet, shown so the roadmap is visible in the app. */
const LATER: { label: string; req: string; icon: LucideIcon }[] = [
  { label: "Sessions", req: "SS-01", icon: ListTreeIcon },
  { label: "Bulk run", req: "BX-02", icon: SquareTerminalIcon },
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
  const [approval, setApproval] = useState<ApprovalRequest | null>(null);
  const [jobsVersion, setJobsVersion] = useState(0);
  // Bumped when a job finishes, so the VM list shows the new power states.
  const [jobsFinished, setJobsFinished] = useState(0);
  const [settingsVersion, setSettingsVersion] = useState(0);
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [laterFor, setLaterFor] = useState<string | null>(null);
  const { preference, setPreference, resolved } = useTheme();

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
            duration: event.seconds * 1000 + 2000,
            action: { label: "Cancel", onClick: () => void api.cancelJob(id) },
          });
          break;
        case "started":
          toast.loading("Running…", { id });
          break;
        case "finished":
          setJobsFinished((v) => v + 1);
          if (event.status === "succeeded") toast.success("Job succeeded", { id, duration: 5000 });
          else toast.error(`Job ${event.status.replace("_", " ")}`, { id, duration: 8000 });
          break;
      }
    });
    return () => void unlisten.then((stop) => stop());
  }, []);

  function submitted(outcome: SubmitOutcome) {
    if (outcome.status === "needsApproval") setApproval(outcome.request);
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
                refreshKey={jobsFinished + settingsVersion}
              />
            </section>
            <section hidden={page !== "terminal"} className="h-full">
              <TerminalPage active={page === "terminal"} theme={resolved} />
            </section>
            <section hidden={page !== "activity"}>
              <ActivityPage version={jobsVersion} />
            </section>
            <section hidden={page !== "settings"}>
              <SettingsPage onChanged={() => setSettingsVersion((v) => v + 1)} />
            </section>
          </div>
        </SidebarInset>
      </SidebarProvider>

      {approval && (
        <ApprovalDialog
          request={approval}
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
