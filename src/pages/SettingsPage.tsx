// Settings: the vmrun.exe and (VM-18) VBoxManage.exe paths (configurable, never hard-coded), the folders scanned for
// VMs (VM-01),
// power-on limit (VM-06), shutdown wait (VM-03), hosts Compare output reaches at once (BX-02), and update
// checks with the GitHub update token (FD-14) under General, keep-alive,
// auto-reconnect and copy-on-select under Terminal (SS-03), and the editable approval rules (AP-01) under
// Approval rules. QL-11: "Follow Windows" for the theme is under General; the Dark mode switch is in the top bar. QL-15:
// About has the version and opens the logs folder (logs and crash reports). MO-02: how often the dashboard polls each
// watched host is under General too. P6: each save tells App what it changed, so only what depends on it is read again.

import { useEffect, useState } from "react";
import { FileTextIcon, FolderIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PolicyRulesEditor } from "@/components/PolicyRulesEditor";
import { PresentationCard } from "@/components/Presentation";
import { TerminalSettingsCard } from "@/components/TerminalSettingsCard";
import { UpdateTokenField } from "@/components/UpdateTokenField";
import {
  api,
  errorMessage,
  type AppInfo,
  type LogsInfo,
  type Settings,
  type UpdateCheck,
  type VaultInfo,
} from "@/lib/api";
import type { SettingsChange } from "@/lib/job-events";
import { useTheme } from "@/lib/theme";

/** MO-02: the dashboard's polling intervals for watched hosts, in seconds (the core takes these only). */
const GUEST_POLL_SECS = [5, 15, 30, 60];

interface Props {
  /** Called after a setting changes, with what changed, so the sidebar status, update banner and lists refresh. */
  onChanged: (change: SettingsChange) => void;
  /** FD-14: the update token is kept in the vault. */
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
}

/** FD-14: what "Check now" found, for the status line. */
function checkResult(result: UpdateCheck) {
  switch (result.status) {
    case "available":
      return `Version ${result.update.version} is available.`;
    case "upToDate":
      return "You have the latest version.";
    case "noToken":
      return "Add a GitHub update token below first: the releases are in a private repository.";
    case "vaultLocked":
      return "Unlock the vault first: the GitHub update token is kept there.";
    case "off":
      return "Update checks are off.";
  }
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

export function SettingsPage({ onChanged, vault, onVaultChanged, onOpenVault }: Props) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [path, setPath] = useState("");
  const [vmrunMessage, setVmrunMessage] = useState<Message>(null);
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
        text: checkResult(result),
      });
      if (result.status === "available") onChanged("updates");
    } catch (err) {
      setUpdateMessage({ ok: false, text: `Could not check for updates: ${errorMessage(err)}` });
    } finally {
      setChecking(false);
    }
  }

  return (
    <Tabs defaultValue="general" className="max-w-3xl gap-4">
      <TabsList>
        <TabsTrigger value="general">General</TabsTrigger>
        <TabsTrigger value="terminal">Terminal</TabsTrigger>
        <TabsTrigger value="rules">Approval rules</TabsTrigger>
        <TabsTrigger value="about">About</TabsTrigger>
      </TabsList>
      <TabsContent value="about">
        <AboutCard />
      </TabsContent>
      <TabsContent value="terminal">
        <TerminalSettingsCard />
      </TabsContent>
      <TabsContent value="rules">
        <PolicyRulesEditor />
      </TabsContent>
      <TabsContent value="general" className="flex flex-col gap-6">
        <AppearanceCard />
        <PresentationCard />
        <Card>
          <CardHeader>
            <CardTitle>VMware Workstation</CardTitle>
            <CardDescription>
              Every VM action runs through vmrun.exe. Leave the path empty to find it automatically: the registry first,
              then the default install folders.
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
        </Card>

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

        <Card>
          <CardHeader>
            <CardTitle>Power actions</CardTitle>
            <CardDescription>
              Starting many VMs at once can saturate the host&apos;s disk and CPU, so bulk starts power on a few at a
              time. Shut down asks each guest to stop and waits; a VM still running after the wait is reported and left
              running, and forcing it off needs its own approval.
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

        <Card>
          <CardHeader>
            <CardTitle>Dashboard</CardTitle>
            <CardDescription>
              Watching a host on the dashboard keeps one SSH connection to it, and each poll runs a short read of /proc
              there: a few processes, which security tools that log every program a host runs will see. Polling less
              often is gentler on the hosts and their logs; the charts then move in bigger steps.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2">
            <Label htmlFor="guest-poll">Poll each watched host every</Label>
            <Select
              value={settings ? String(settings.guestPollSecs) : undefined}
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

        <Card>
          <CardHeader>
            <CardTitle>Updates</CardTitle>
            <CardDescription>
              Remotely checks GitHub Releases at start and every 24 hours. Every update is signature-checked, and
              installing always asks first. Turn checks off at air-gapped sites.
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
      </TabsContent>
    </Tabs>
  );
}

/** QL-11: whether Windows decides the theme. The top bar's Dark mode switch picks one and turns this off. */
function AppearanceCard() {
  const { resolved, followWindows, setFollowWindows } = useTheme();
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
