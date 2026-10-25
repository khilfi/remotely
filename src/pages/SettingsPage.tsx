// Settings: the vmrun.exe and (VM-18) VBoxManage.exe paths (configurable, never hard-coded), the folders scanned for
// VMs (VM-01),
// power-on limit (VM-06), shutdown wait (VM-03), hosts Compare output reaches at once (BX-02), how long job outputs
// and command text are kept with Purge now (BX-02), and update checks with the optional GitHub update token (FD-14)
// under General, keep-alive,
// auto-reconnect and copy-on-select under Terminal (SS-03), and the editable approval rules (AP-01) under
// Approval rules. QL-11: "Follow Windows" for the theme is under General; the Dark mode switch is in the top bar. QL-15:
// About has the version and opens the logs folder (logs and crash reports). MO-02: how often the dashboard polls each
// watched host is under General too. P6: each save tells App what it changed, so only what depends on it is read again.
// R10: each card has an id from lib/settings-index.ts, so the palette's search (QL-20) opens its tab and shows it;
// Appearance has QL-24's density, and Setup guide opens QL-23's first-run wizard again.

import { useEffect, useState, type ReactNode } from "react";
import { CompassIcon, FileTextIcon, FolderIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DashboardHistoryCard } from "@/components/DashboardHistoryCard";
import { DataRetentionCard } from "@/components/DataRetentionCard";
import { PolicyRulesEditor } from "@/components/PolicyRulesEditor";
import { WindowsLoginNotice } from "@/components/WindowsLoginNotice";
import { PresentationCard } from "@/components/Presentation";
import { TerminalRulesCard } from "@/components/TerminalRulesCard";
import { TerminalSettingsCard } from "@/components/TerminalSettingsCard";
import { UpdateTokenField } from "@/components/UpdateTokenField";
import { api, errorMessage, type AppInfo, type LogsInfo, type Settings, type VaultInfo } from "@/lib/api";
import type { SettingsChange } from "@/lib/job-events";
import { useTheme } from "@/lib/theme";
import { checkMessage, isNotice } from "@/lib/updates";
import { DENSITIES, useDensity, type Density } from "@/lib/density";
import { requestFirstRun } from "@/lib/first-run";
import { settingsCardId, settingsSection, type SettingsTab } from "@/lib/settings-index";
import { reveal } from "@/lib/reveal";
import { cn } from "@/lib/utils";

/** MO-02: the dashboard's polling intervals for watched hosts, in seconds (the core takes these only). */
const GUEST_POLL_SECS = [5, 15, 30, 60];

interface Props {
  /** Called after a setting changes, with what changed, so the sidebar status, update banner and lists refresh. */
  onChanged: (change: SettingsChange) => void;
  /** FD-14: the update token is kept in the vault. */
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  /** R10: a card to show (a search result, a link): its tab opened, the card scrolled to and lit. */
  focus?: { section: string; n: number } | null;
}

type Message = { ok: boolean; text: string } | null;

function StatusLine({ message }: { message: Message }) {
  if (!message) return null;
  return (
    <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
      {message.text}
    </p>
  );
}

/** A card's place on the page, for links to it (QL-20). */
function Section({ id, lit, children }: { id: string; lit: string | null; children: ReactNode }) {
  return (
    <div
      id={settingsCardId(id)}
      className={cn("scroll-mt-4 rounded-xl transition-shadow", lit === id && "ring-2 ring-ring ring-offset-2")}
    >
      {children}
    </div>
  );
}

export function SettingsPage({ onChanged, vault, onVaultChanged, onOpenVault, focus = null }: Props) {
  const [tab, setTab] = useState<SettingsTab>("general");
  const [lit, setLit] = useState<string | null>(null);
  const [focusHandled, setFocusHandled] = useState(focus?.n ?? 0);
  if (focus && focus.n !== focusHandled) {
    setFocusHandled(focus.n);
    const section = settingsSection(focus.section);
    if (section) {
      setTab(section.tab);
      setLit(section.id);
    }
  }
  useEffect(() => {
    if (!lit) return;
    const frame = window.requestAnimationFrame(() => reveal(document.getElementById(settingsCardId(lit)), "top"));
    const timer = window.setTimeout(() => setLit(null), 2500);
    return () => {
      window.cancelAnimationFrame(frame);
      window.clearTimeout(timer);
    };
  }, [lit, focus?.n]);

  const [settings, setSettings] = useState<Settings | null>(null);
  const [path, setPath] = useState("");
  const [vmrunMessage, setVmrunMessage] = useState<Message>(null);
  const [ovftoolPath, setOvftoolPath] = useState("");
  const [ovftoolMessage, setOvftoolMessage] = useState<Message>(null);
  const [vboxPath, setVboxPath] = useState("");
  const [vboxMessage, setVboxMessage] = useState<Message>(null);
  const [dockerPath, setDockerPath] = useState("");
  const [dockerMessage, setDockerMessage] = useState<Message>(null);
  const [updateMessage, setUpdateMessage] = useState<Message>(null);
  const [newFolder, setNewFolder] = useState("");
  const [folderMessage, setFolderMessage] = useState<Message>(null);
  const [powerOnLimit, setPowerOnLimit] = useState("");
  const [shutdownWait, setShutdownWait] = useState("");
  const [powerMessage, setPowerMessage] = useState<Message>(null);
  const [bulkLimit, setBulkLimit] = useState("");
  const [bulkMessage, setBulkMessage] = useState<Message>(null);
  const [guestPollMessage, setGuestPollMessage] = useState<Message>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    api.settings().then(
      (s) => {
        setSettings(s);
        setPath(s.vmrunPathSaved ?? "");
        setOvftoolPath(s.ovftoolPathSaved ?? "");
        setVboxPath(s.vboxmanagePathSaved ?? "");
        setDockerPath(s.dockerPathSaved ?? "");
        setPowerOnLimit(String(s.powerOnLimit));
        setShutdownWait(String(s.shutdownWaitSecs));
        setBulkLimit(String(s.bulkParallelLimit));
      },
      (err) => setVmrunMessage({ ok: false, text: errorMessage(err) }),
    );
  }, []);

  async function saveVmrun(next: string | null) {
    try {
      const s = await api.setVmrunPath(next);
      setSettings(s);
      setPath(s.vmrunPathSaved ?? "");
      setVmrunMessage({
        ok: s.vmrunPathInUse !== null,
        text: s.vmrunPathInUse ? `Using ${s.vmrunPathInUse}` : "vmrun.exe was not found",
      });
      onChanged("vmrun");
    } catch (err) {
      setVmrunMessage({ ok: false, text: errorMessage(err) });
    }
  }

  /** VM-21: ovftool.exe, which imports OVA and OVF appliances into Workstation. */
  async function saveOvftool(next: string | null) {
    try {
      const s = await api.setOvftoolPath(next);
      setSettings(s);
      setOvftoolPath(s.ovftoolPathSaved ?? "");
      setOvftoolMessage({
        ok: s.ovftoolPathInUse !== null,
        text: s.ovftoolPathInUse ? `Using ${s.ovftoolPathInUse}` : "ovftool.exe was not found",
      });
    } catch (err) {
      setOvftoolMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function saveVboxmanage(next: string | null) {
    try {
      const s = await api.setVboxmanagePath(next);
      setSettings(s);
      setVboxPath(s.vboxmanagePathSaved ?? "");
      setVboxMessage({
        ok: true,
        text: s.vboxmanagePathInUse
          ? `Using ${s.vboxmanagePathInUse}`
          : "VBoxManage.exe was not found: no VirtualBox VMs are listed",
      });
      onChanged("vboxmanage");
    } catch (err) {
      setVboxMessage({ ok: false, text: errorMessage(err) });
    }
  }

  /** CT-02: Docker Desktop's docker.exe. */
  async function saveDocker(next: string | null) {
    try {
      const s = await api.setDockerPath(next);
      setSettings(s);
      setDockerPath(s.dockerPathSaved ?? "");
      setDockerMessage({
        ok: s.dockerPathInUse !== null,
        text: s.dockerPathInUse ? `Using ${s.dockerPathInUse}` : "docker.exe was not found",
      });
      onChanged("docker");
    } catch (err) {
      setDockerMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function saveFolders(folders: string[]) {
    try {
      const s = await api.setScanFolders(folders);
      setSettings(s);
      setNewFolder("");
      setFolderMessage(null);
      onChanged("scanFolders");
    } catch (err) {
      setFolderMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function savePowerActions() {
    try {
      await api.setPowerOnLimit(Number(powerOnLimit));
      const s = await api.setShutdownWait(Number(shutdownWait));
      setSettings(s);
      setPowerOnLimit(String(s.powerOnLimit));
      setShutdownWait(String(s.shutdownWaitSecs));
      setPowerMessage({ ok: true, text: "Saved. Applies from the next action on." });
    } catch (err) {
      setPowerMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function saveBulkLimit() {
    try {
      const s = await api.setBulkParallel(Number(bulkLimit));
      setSettings(s);
      setBulkLimit(String(s.bulkParallelLimit));
      setBulkMessage({ ok: true, text: "Saved. Applies from the next run on." });
    } catch (err) {
      setBulkMessage({ ok: false, text: errorMessage(err) });
    }
  }

  /** MO-02: seconds between two polls of each watched host. */
  async function saveGuestPoll(secs: number) {
    try {
      setSettings(await api.setGuestPoll(secs));
      setGuestPollMessage({ ok: true, text: "Saved. Applies from the next poll on." });
    } catch (err) {
      setGuestPollMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function setUpdateChecks(enabled: boolean) {
    try {
      setSettings(await api.setUpdateChecks(enabled));
      setUpdateMessage(null);
      onChanged("updates");
    } catch (err) {
      setUpdateMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function checkNow() {
    setChecking(true);
    try {
      const result = await api.checkForUpdate();
      setUpdateMessage({
        ok: result.status === "available" || result.status === "upToDate",
        text: checkMessage(result),
      });
      // The banner shows the update, or asks for a token; after a used-up limit, the app checks again later.
      if (result.status === "available" || isNotice(result)) onChanged("updates");
    } catch (err) {
      setUpdateMessage({ ok: false, text: `Could not check for updates: ${errorMessage(err)}` });
    } finally {
      setChecking(false);
    }
  }

  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as SettingsTab)} className="max-w-3xl gap-4">
      <TabsList>
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="terminal">Terminal</TabsTrigger>
        <TabsTrigger value="rules">Approval rules</TabsTrigger>
        <TabsTrigger value="about">About</TabsTrigger>
      </TabsList>
      <TabsContent value="about">
        <Section id="about" lit={lit}>
          <AboutCard />
        </Section>
      </TabsContent>
      <TabsContent value="terminal" className="flex flex-col gap-6">
        <Section id="terminal" lit={lit}>
          <TerminalSettingsCard />
        </Section>
        <Section id="terminal-rules" lit={lit}>
          <TerminalRulesCard />
        </Section>
      </TabsContent>
      <TabsContent value="rules">
        <Section id="rules" lit={lit}>
          <PolicyRulesEditor />
        </Section>
      </TabsContent>
      <TabsContent value="general" className="flex flex-col gap-6">
        <Section id="appearance" lit={lit}>
          <AppearanceCard />
        </Section>
        <Section id="presentation" lit={lit}>
          <PresentationCard />
        </Section>
        <Section id="first-run" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Setup guide</CardTitle>
              <CardDescription>
                The steps Remotely offers on a new PC: find Workstation and VirtualBox, create the vault, pick VM
                folders and import sessions. Each one saves what it does as this page and the Vault and Sessions pages
                would.
              </CardDescription>
            </CardHeader>
            <CardFooter>
              <Button variant="outline" onClick={() => requestFirstRun()}>
                <CompassIcon /> Open the setup guide
              </Button>
            </CardFooter>
          </Card>
        </Section>
        <Section id="vmware" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>VMware Workstation</CardTitle>
              <CardDescription>
                Every VM action runs through vmrun.exe. Leave the path empty to find it automatically: the registry
                first, then the default install folders.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Label htmlFor="vmrun-path">vmrun.exe path</Label>
              <Input
                id="vmrun-path"
                className="font-mono"
                placeholder="Found automatically"
                spellCheck={false}
                value={path}
                onChange={(e) => setPath(e.currentTarget.value)}
              />
              <p className="text-sm text-muted-foreground">
                In use: <span className="font-mono">{settings?.vmrunPathInUse ?? "not found"}</span>
              </p>
              <StatusLine message={vmrunMessage} />
            </CardContent>
            <CardFooter className="gap-2">
              <Button onClick={() => void saveVmrun(path)}>Save</Button>
              <Button variant="outline" onClick={() => void saveVmrun(null)}>
                Find automatically
              </Button>
            </CardFooter>
            <CardContent className="grid gap-2 border-t pt-4">
              <Label htmlFor="ovftool-path">ovftool.exe path (OVA and OVF imports)</Label>
              <Input
                id="ovftool-path"
                className="font-mono"
                placeholder="Found automatically, in the OVFTool folder next to vmrun.exe"
                spellCheck={false}
                value={ovftoolPath}
                onChange={(e) => setOvftoolPath(e.currentTarget.value)}
              />
              <p className="text-sm text-muted-foreground">
                In use: <span className="font-mono">{settings?.ovftoolPathInUse ?? "not found"}</span>
              </p>
              <StatusLine message={ovftoolMessage} />
            </CardContent>
            <CardFooter className="gap-2">
              <Button onClick={() => void saveOvftool(ovftoolPath)}>Save</Button>
              <Button variant="outline" onClick={() => void saveOvftool(null)}>
                Find automatically
              </Button>
            </CardFooter>
          </Card>
        </Section>

        <Section id="virtualbox" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Oracle VirtualBox</CardTitle>
              <CardDescription>
                Remotely lists the VMs registered in VirtualBox (7.0 or later) and runs every action on them through
                VBoxManage.exe. Leave the path empty to find it automatically: the REMOTELY_VBOXMANAGE variable, the
                registry, then the default install folder. Without VirtualBox, the list just has no VirtualBox VMs.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Label htmlFor="vboxmanage-path">VBoxManage.exe path</Label>
              <Input
                id="vboxmanage-path"
                className="font-mono"
                placeholder="Found automatically"
                spellCheck={false}
                value={vboxPath}
                onChange={(e) => setVboxPath(e.currentTarget.value)}
              />
              <p className="text-sm text-muted-foreground">
                In use:{" "}
                <span className="font-mono">
                  {settings?.vboxmanagePathInUse ?? "not found (VirtualBox not installed)"}
                </span>
              </p>
              <StatusLine message={vboxMessage} />
            </CardContent>
            <CardFooter className="gap-2">
              <Button onClick={() => void saveVboxmanage(vboxPath)}>Save</Button>
              <Button variant="outline" onClick={() => void saveVboxmanage(null)}>
                Find automatically
              </Button>
            </CardFooter>
          </Card>
        </Section>

        <Section id="docker" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Docker Desktop on this PC</CardTitle>
              <CardDescription>
                The Containers page lists this PC&apos;s containers through Docker Desktop&apos;s docker.exe, when it is
                installed. Leave the path empty to find it: REMOTELY_DOCKER first, then Docker Desktop&apos;s folder.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Label htmlFor="docker-path">docker.exe path</Label>
              <Input
                id="docker-path"
                className="font-mono"
                placeholder="Found automatically"
                spellCheck={false}
                value={dockerPath}
                onChange={(e) => setDockerPath(e.currentTarget.value)}
              />
              <p className="text-sm text-muted-foreground">
                In use: <span className="font-mono">{settings?.dockerPathInUse ?? "not found"}</span>
              </p>
              <StatusLine message={dockerMessage} />
            </CardContent>
            <CardFooter className="gap-2">
              <Button onClick={() => void saveDocker(dockerPath)}>Save</Button>
              <Button variant="outline" onClick={() => void saveDocker(null)}>
                Find automatically
              </Button>
            </CardFooter>
          </Card>
        </Section>

        <Section id="vm-folders" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>VM folders</CardTitle>
              <CardDescription>
                Remotely lists every VM in VMware Workstation&apos;s library. Add folders that hold other VMs; they are
                searched for .vmx files up to five folder levels down.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              {settings && settings.scanFolders.length > 0 && (
                <ul className="grid gap-1">
                  {settings.scanFolders.map((folder) => (
                    <li key={folder} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                      <FolderIcon className="size-4 shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1 truncate font-mono text-sm" title={folder}>
                        {folder}
                      </span>
                      <Button
                        size="icon-sm"
                        variant="ghost"
                        aria-label={`Stop scanning ${folder}`}
                        onClick={() => void saveFolders(settings.scanFolders.filter((f) => f !== folder))}
                      >
                        <XIcon />
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
              <form
                className="flex gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (settings && newFolder.trim()) void saveFolders([...settings.scanFolders, newFolder.trim()]);
                }}
              >
                <Label htmlFor="scan-folder" className="sr-only">
                  Folder to scan
                </Label>
                <Input
                  id="scan-folder"
                  className="font-mono"
                  placeholder="D:\VMs"
                  spellCheck={false}
                  value={newFolder}
                  onChange={(e) => setNewFolder(e.currentTarget.value)}
                />
                <Button type="submit" variant="outline" disabled={!settings || !newFolder.trim()}>
                  Add folder
                </Button>
              </form>
              <StatusLine message={folderMessage} />
            </CardContent>
          </Card>
        </Section>

        <Section id="power" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Power actions</CardTitle>
              <CardDescription>
                Starting many VMs at once can saturate the host&apos;s disk and CPU, so bulk starts power on a few at a
                time. Shut down asks each guest to stop and waits; a VM still running after the wait is reported and
                left running, and forcing it off needs its own approval.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4">
              <div className="grid gap-2">
                <Label htmlFor="power-on-limit">VMs powered on at once</Label>
                <Input
                  id="power-on-limit"
                  type="number"
                  min={1}
                  max={32}
                  className="w-28"
                  value={powerOnLimit}
                  onChange={(e) => setPowerOnLimit(e.currentTarget.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="shutdown-wait">Shutdown wait (seconds)</Label>
                <Input
                  id="shutdown-wait"
                  type="number"
                  min={1}
                  max={3600}
                  className="w-28"
                  value={shutdownWait}
                  onChange={(e) => setShutdownWait(e.currentTarget.value)}
                />
              </div>
              <StatusLine message={powerMessage} />
            </CardContent>
            <CardFooter>
              <Button onClick={() => void savePowerActions()} disabled={!settings}>
                Save
              </Button>
            </CardFooter>
          </Card>
        </Section>

        <Section id="compare" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Compare output</CardTitle>
              <CardDescription>
                Compare output (and a key push) runs a command on this many hosts at a time; the rest wait their turn.
                More at once finishes sooner but opens more SSH connections from this PC.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4">
              <div className="grid gap-2">
                <Label htmlFor="bulk-parallel">Hosts at once</Label>
                <Input
                  id="bulk-parallel"
                  type="number"
                  min={1}
                  max={50}
                  className="w-28"
                  value={bulkLimit}
                  onChange={(e) => setBulkLimit(e.currentTarget.value)}
                />
              </div>
              <StatusLine message={bulkMessage} />
            </CardContent>
            <CardFooter>
              <Button
                onClick={() => void saveBulkLimit()}
                disabled={!settings || bulkLimit === String(settings.bulkParallelLimit)}
              >
                Save
              </Button>
            </CardFooter>
          </Card>
        </Section>

        {vault && vault.status !== "notSetUp" && (
          <Section id="vault" lit={lit}>
            <Card>
              <CardHeader>
                <CardTitle>Vault</CardTitle>
                <CardDescription>
                  How the vault unlocks. It locks itself after {vault.idleLockMinutes} minutes without you typing or
                  clicking in Remotely.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <WindowsLoginNotice vault={vault} onVaultChanged={onVaultChanged} showWhenOff />
              </CardContent>
            </Card>
          </Section>
        )}

        <Section id="retention" lit={lit}>
          <DataRetentionCard />
        </Section>
        <Section id="history" lit={lit}>
          <DashboardHistoryCard />
        </Section>

        <Section id="dashboard" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Dashboard</CardTitle>
              <CardDescription>
                Watching a host on the dashboard keeps one SSH connection to it, and each poll runs a short read of
                /proc there: a few processes, which security tools that log every program a host runs will see. Polling
                less often is gentler on the hosts and their logs; the charts then move in bigger steps.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Label htmlFor="guest-poll">Poll each watched host every</Label>
              <Select
                value={settings ? String(settings.guestPollSecs) : ""}
                disabled={!settings}
                onValueChange={(v) => void saveGuestPoll(Number(v))}
              >
                <SelectTrigger id="guest-poll" className="w-40">
                  <SelectValue placeholder="5 seconds" />
                </SelectTrigger>
                <SelectContent>
                  {GUEST_POLL_SECS.map((secs) => (
                    <SelectItem key={secs} value={String(secs)}>
                      {secs} seconds{secs === 5 ? " (default)" : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <StatusLine message={guestPollMessage} />
            </CardContent>
          </Card>
        </Section>

        <Section id="updates" lit={lit}>
          <Card>
            <CardHeader>
              <CardTitle>Updates</CardTitle>
              <CardDescription>
                Remotely checks GitHub Releases at start and every 24 hours, without a token while the repository is
                public. Every update is signature-checked, and installing always asks first. Turn checks off at
                air-gapped sites.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-3">
              <div className="flex items-center gap-3">
                <Switch
                  id="update-checks"
                  checked={settings?.updateChecks ?? true}
                  disabled={!settings}
                  onCheckedChange={(checked) => void setUpdateChecks(checked)}
                />
                <Label htmlFor="update-checks">Check for updates</Label>
              </div>
              <StatusLine message={updateMessage} />
              <UpdateTokenField
                settings={settings}
                vault={vault}
                onSettings={setSettings}
                onChanged={() => onChanged("updates")}
                onVaultChanged={onVaultChanged}
                onOpenVault={onOpenVault}
              />
            </CardContent>
            <CardFooter>
              <Button variant="outline" onClick={() => void checkNow()} disabled={checking || !settings?.updateChecks}>
                {checking ? "Checking…" : "Check now"}
              </Button>
            </CardFooter>
          </Card>
        </Section>
      </TabsContent>
    </Tabs>
  );
}

/** QL-11: whether Windows decides the theme. The top bar's Dark mode switch picks one and turns this off. */
function AppearanceCard() {
  const { resolved, followWindows, setFollowWindows } = useTheme();
  const [density, setDensity] = useDensity();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Appearance</CardTitle>
        <CardDescription>
          Light or dark, as Windows is set, or as you pick with the Dark mode switch in the top bar. Using the switch
          stops following Windows.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-1.5">
        <div className="flex items-center gap-3">
          <Switch id="follow-windows" checked={followWindows} onCheckedChange={setFollowWindows} />
          <Label htmlFor="follow-windows">Follow Windows</Label>
        </div>
        <p className="text-sm text-muted-foreground">
          {followWindows
            ? `Windows is set to ${resolved} now.`
            : `Dark mode is ${resolved === "dark" ? "on" : "off"}. Turning this on lets Windows decide again.`}
        </p>
        {/* QL-24: the spacing of every page, kept on this PC like the theme. */}
        <div className="mt-3 grid gap-1.5">
          <Label htmlFor="density">Density</Label>
          <Select value={density} onValueChange={(v) => setDensity(v as Density)}>
            <SelectTrigger id="density" className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DENSITIES.map((d) => (
                <SelectItem key={d.value} value={d.value}>
                  {d.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-sm text-muted-foreground">{DENSITIES.find((d) => d.value === density)?.hint}</p>
        </div>
      </CardContent>
    </Card>
  );
}

/** QL-15: the version, and where the logs and crash reports are, with a button that opens the folder. */
function AboutCard() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [logs, setLogs] = useState<LogsInfo | null>(null);
  const [message, setMessage] = useState<Message>(null);
  useEffect(() => {
    api.appInfo().then(setInfo, () => setInfo(null));
    api.logsInfo().then(setLogs, () => setLogs(null));
  }, []);

  async function openLogs() {
    try {
      await api.openLogs();
      setMessage(null);
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Remotely {info?.version ?? ""}</CardTitle>
        <CardDescription>
          Remotely keeps a log of what it did and what went wrong, one file a day for the last {logs?.keepDays ?? 7}{" "}
          days, and a crash report if it ever stops unexpectedly. Neither holds passwords, keys or tokens. Send them
          along when you report a problem.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-1.5">
        <Label>Logs folder</Label>
        <p className="font-mono text-sm break-all">
          {logs?.folder ?? "Not known: the app's data folder was not found."}
        </p>
        <StatusLine message={message} />
      </CardContent>
      <CardFooter>
        <Button variant="outline" onClick={() => void openLogs()} disabled={!logs?.folder}>
          <FileTextIcon />
          Open the logs folder
        </Button>
      </CardFooter>
    </Card>
  );
}
