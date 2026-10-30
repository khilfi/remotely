// Settings: the tool paths (vmrun.exe and VM-18 VBoxManage.exe, ovftool, qemu-img and docker; configurable, never
// hard-coded), the folders scanned for VMs (VM-01), power-on limit (VM-06), shutdown wait (VM-03), hosts Compare hosts
// reaches at once (BX-02), how long job outputs and command text are kept with Purge now (BX-02), update checks with
// the optional GitHub update token (FD-14), keep-alive, auto-reconnect and copy-on-select (SS-03), the approval rules
// (AP-01) and this workspace's change ID rule (AP-08). QL-11: "Follow Windows" for the theme; the Dark mode switch is in
// the top bar. QL-15: About has the version and opens the logs folder. MO-02: how often the dashboard polls each
// watched host. P6: each save tells App what it changed, so only what depends on it is read again.
//
// UX-10: a side list of groups (lib/settings-index.ts) shows one group at a time; the search box in the header finds a
// setting by name across groups, as the palette does (QL-20, R10: a link to a section opens its group and lights its
// card or row). One save model: every change saves at once, with a quiet "Saved" and Undo in the card's header
// (SaveStatus); only the approval rules' Advanced editor keeps a Save button (PolicyRulesEditor says why). Each card
// shows at most one line of help; the rest is behind "?".

import { useEffect, useState, type ReactNode } from "react";
import { CompassIcon, FileTextIcon, FolderOpenIcon, KeyRoundIcon, SearchIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { ApprovalRulesCard } from "@/components/ApprovalRulesCard";
import { DashboardHistoryCard } from "@/components/DashboardHistoryCard";
import { DataRetentionCard } from "@/components/DataRetentionCard";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { PageHeader } from "@/components/PageHeader";
import { PresentationCard, useReadOnlyReason } from "@/components/Presentation";
import { NumberSetting, SaveStatus, useSaveStatus } from "@/components/SaveStatus";
import { ShowTipsAgainButton } from "@/components/Tip";
import { TerminalRulesCard } from "@/components/TerminalRulesCard";
import { TerminalSettingsCard } from "@/components/TerminalSettingsCard";
import { ToolPathsCard } from "@/components/ToolPathsCard";
import { UpdateTokenField } from "@/components/UpdateTokenField";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type AppInfo, type LogsInfo, type Settings, type VaultInfo } from "@/lib/api";
import { DENSITIES, useDensity, type Density } from "@/lib/density";
import { requestFirstRun } from "@/lib/first-run";
import type { SettingsChange } from "@/lib/job-events";
import { navigationApi } from "@/lib/navigation-api";
import { reveal } from "@/lib/reveal";
import {
  groupSections,
  groupTitle,
  searchCards,
  sectionCard,
  SETTINGS_GROUPS,
  settingsCardId,
  settingsSection,
  type SettingsGroup,
} from "@/lib/settings-index";
import { useTheme } from "@/lib/theme";
import { checkMessage, isNotice } from "@/lib/updates";
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
  /** R10: a section to show (a search result, a link): its group opened, its card or row scrolled to and lit. */
  focus?: { section: string; n: number } | null;
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

/** The cards of a group, each once, in order. */
function groupCards(group: SettingsGroup): string[] {
  const cards: string[] = [];
  for (const s of groupSections(group)) {
    const card = sectionCard(s);
    if (!cards.includes(card)) cards.push(card);
  }
  return cards;
}

export function SettingsPage({ onChanged, vault, onVaultChanged, onOpenVault, focus = null }: Props) {
  const [group, setGroup] = useState<SettingsGroup>("general");
  const [query, setQuery] = useState("");
  const [lit, setLit] = useState<string | null>(null);
  const [focusHandled, setFocusHandled] = useState(focus?.n ?? 0);
  if (focus && focus.n !== focusHandled) {
    setFocusHandled(focus.n);
    const section = settingsSection(focus.section);
    if (section) {
      setGroup(section.group);
      setQuery("");
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
  const [loadError, setLoadError] = useState<string | null>(null);
  useEffect(() => {
    api.settings().then(setSettings, (err) => setLoadError(errorMessage(err)));
  }, []);

  const found = query.trim() ? searchCards(query) : null;
  const foundSections = new Set(found?.flatMap((c) => c.sections) ?? []);

  const card = (id: string): ReactNode => {
    switch (id) {
      case "appearance":
        return <AppearanceCard />;
      case "first-run":
        return <SetupGuideCard />;
      case "tools":
        return <ToolPathsCard settings={settings} onSettings={setSettings} onChanged={onChanged} lit={lit} />;
      case "vm-folders":
        return <VmFoldersCard settings={settings} onSettings={setSettings} onChanged={onChanged} />;
      case "power":
        return <PowerCard settings={settings} onSettings={setSettings} />;
      case "terminal":
        return <TerminalSettingsCard />;
      case "compare":
        return <CompareCard settings={settings} onSettings={setSettings} />;
      case "terminal-rules":
        return <TerminalRulesCard />;
      case "rules":
        return <ApprovalRulesCard lit={lit} openAdvanced={foundSections.has("rules")} />;
      case "presentation":
        return <PresentationCard />;
      case "vault":
        return <VaultSettingsCard vault={vault} onOpenVault={onOpenVault} />;
      case "retention":
        return <DataRetentionCard />;
      case "dashboard":
        return <DashboardPollingCard settings={settings} onSettings={setSettings} />;
      case "history":
        return <DashboardHistoryCard />;
      case "updates":
        return (
          <UpdatesCard
            settings={settings}
            onSettings={setSettings}
            onChanged={onChanged}
            vault={vault}
            onVaultChanged={onVaultChanged}
            onOpenVault={onOpenVault}
          />
        );
      case "about":
        return <AboutCard />;
      default:
        return null;
    }
  };

  const matches = (g: SettingsGroup) => found?.filter((c) => c.group === g).length ?? 0;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader page="settings">
        <div className="relative w-full max-w-xs">
          <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            className="pl-8"
            placeholder="Search settings"
            aria-label="Search settings"
            value={query}
            onChange={(e) => setQuery(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setQuery("");
            }}
          />
        </div>
      </PageHeader>

      <div className="grid max-w-5xl gap-6 md:grid-cols-[12rem_minmax(0,1fr)]">
        <nav aria-label="Settings groups" className="self-start md:sticky md:top-0">
          <ul className="flex flex-wrap gap-1 md:flex-col">
            {SETTINGS_GROUPS.map((g) => {
              const current = !found && group === g.id;
              const n = matches(g.id);
              return (
                <li key={g.id}>
                  <button
                    type="button"
                    aria-current={current ? "page" : undefined}
                    className={cn(
                      "flex w-full items-center rounded-md px-3 py-1.5 text-left text-sm hover:bg-accent focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none",
                      current && "bg-accent font-medium",
                      found && n === 0 && "text-muted-foreground",
                    )}
                    onClick={() => {
                      setQuery("");
                      setGroup(g.id);
                    }}
                  >
                    {g.title}
                    {found && n > 0 && <span className="ml-auto text-xs text-muted-foreground tabular-nums">{n}</span>}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="flex max-w-3xl min-w-0 flex-col gap-6">
          {loadError && <p className="text-sm text-destructive">{loadError}</p>}
          {found === null ? (
            groupCards(group).map((id) => (
              <Section key={id} id={id} lit={lit}>
                {card(id)}
              </Section>
            ))
          ) : found.length === 0 ? (
            <EmptyState
              icon={SearchIcon}
              title="No setting matches"
              description="Try another word, or pick a group on the left."
              action={
                <Button variant="outline" onClick={() => setQuery("")}>
                  Clear the search
                </Button>
              }
            />
          ) : (
            found.map((c, i) => (
              <div key={c.card} className="flex flex-col gap-2">
                {(i === 0 || found[i - 1].group !== c.group) && (
                  <h2 className="text-sm font-medium text-muted-foreground">{groupTitle(c.group)}</h2>
                )}
                <Section id={c.card} lit={lit}>
                  {card(c.card)}
                </Section>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

/** QL-11: whether Windows decides the theme; QL-24: the spacing of every page. Both kept on this PC. */
function AppearanceCard() {
  const { resolved, followWindows, setFollowWindows } = useTheme();
  const [density, setDensity] = useDensity();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Appearance</CardTitle>
        <CardDescription>Kept on this PC.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <Switch id="follow-windows" checked={followWindows} onCheckedChange={setFollowWindows} />
          <Label htmlFor="follow-windows">Follow Windows for dark mode</Label>
          <span className="text-sm text-muted-foreground">
            {followWindows ? `Windows is ${resolved} now` : `The top bar's switch sets it: ${resolved} now`}
          </span>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="density">Density</Label>
          <Select value={density} onValueChange={(v) => setDensity(v as Density)}>
            <SelectTrigger id="density" className="w-48" title={DENSITIES.find((d) => d.value === density)?.hint}>
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
        </div>
      </CardContent>
    </Card>
  );
}

/** QL-23: the first-run wizard again; UX-09: the tips dismissed. */
function SetupGuideCard() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Setup guide and tips</CardTitle>
        <CardDescription>The steps offered on a new PC, and the one-time tips you dismissed.</CardDescription>
      </CardHeader>
      <CardFooter className="flex-wrap gap-2">
        <Button variant="outline" onClick={() => requestFirstRun()}>
          <CompassIcon data-icon="inline-start" />
          Open the setup guide
        </Button>
        <ShowTipsAgainButton />
      </CardFooter>
    </Card>
  );
}

interface SettingsCardProps {
  settings: Settings | null;
  onSettings: (settings: Settings) => void;
}

/** VM-01: folders searched for .vmx files besides Workstation's library. Adding and removing save at once. */
function VmFoldersCard({
  settings,
  onSettings,
  onChanged,
}: SettingsCardProps & { onChanged: (c: SettingsChange) => void }) {
  const status = useSaveStatus();
  const readOnly = useReadOnlyReason();
  const [newFolder, setNewFolder] = useState("");
  const folders = settings?.scanFolders ?? [];

  async function apply(next: string[]) {
    onSettings(await api.setScanFolders(next));
    onChanged("scanFolders");
  }

  async function add(folder: string) {
    if (!folder || folders.includes(folder)) return;
    const before = folders;
    if (
      await status.run(
        () => apply([...folders, folder]),
        () => apply(before),
      )
    )
      setNewFolder("");
  }

  async function browse() {
    try {
      const picked = await navigationApi.vmFolderPick();
      if (picked) await add(picked);
    } catch (err) {
      void status.run(() => Promise.reject(err));
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>VM folders</CardTitle>
        <CardDescription>
          Folders with Workstation VMs its library doesn&apos;t list, searched five levels down.
        </CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        {folders.length > 0 && (
          <ul className="grid gap-1">
            {folders.map((folder) => (
              <li key={folder} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                <span className="min-w-0 flex-1 truncate font-mono text-sm" title={folder}>
                  {folder}
                </span>
                <WhyDisabled reason={readOnly}>
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    aria-label={`Stop scanning ${folder}`}
                    disabled={readOnly !== null}
                    onClick={() => {
                      const before = folders;
                      void status.run(
                        () => apply(folders.filter((f) => f !== folder)),
                        () => apply(before),
                      );
                    }}
                  >
                    <XIcon />
                  </Button>
                </WhyDisabled>
              </li>
            ))}
          </ul>
        )}
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void add(newFolder.trim());
          }}
        >
          <Label htmlFor="scan-folder" className="sr-only">
            Folder to scan
          </Label>
          <Input
            id="scan-folder"
            className="min-w-48 flex-1 font-mono"
            placeholder="D:\VMs"
            spellCheck={false}
            value={newFolder}
            onChange={(e) => setNewFolder(e.currentTarget.value)}
          />
          <Button type="submit" variant="outline" disabled={!settings || !newFolder.trim() || readOnly !== null}>
            Add a folder
          </Button>
          <Button type="button" variant="ghost" disabled={!settings || readOnly !== null} onClick={() => void browse()}>
            <FolderOpenIcon data-icon="inline-start" />
            Browse…
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

/** VM-06, VM-03: how many VMs start at once, and how long a shutdown may take. */
function PowerCard({ settings, onSettings }: SettingsCardProps) {
  const status = useSaveStatus();
  const set = (save: (n: number) => Promise<Settings>, next: number, before: number) =>
    void status.run(
      async () => onSettings(await save(next)),
      async () => onSettings(await save(before)),
    );
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Power actions
          <HelpTip topic="powerActions" />
        </CardTitle>
        <CardDescription>Applies from the next action on.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2">
        <NumberSetting
          id="power-on-limit"
          label="VMs powered on at once"
          min={1}
          max={32}
          value={settings?.powerOnLimit}
          onCommit={(n) => settings && set(api.setPowerOnLimit, n, settings.powerOnLimit)}
        />
        <NumberSetting
          id="shutdown-wait"
          label="Shutdown wait"
          suffix="seconds"
          min={1}
          max={3600}
          value={settings?.shutdownWaitSecs}
          onCommit={(n) => settings && set(api.setShutdownWait, n, settings.shutdownWaitSecs)}
        />
      </CardContent>
    </Card>
  );
}

/** BX-02: how many hosts Compare hosts (and a key push) reaches at a time. */
function CompareCard({ settings, onSettings }: SettingsCardProps) {
  const status = useSaveStatus();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Compare hosts</CardTitle>
        <CardDescription>More at once finishes sooner, but opens more SSH connections from this PC.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent>
        <NumberSetting
          id="bulk-parallel"
          label="Hosts at once"
          min={1}
          max={50}
          value={settings?.bulkParallelLimit}
          onCommit={(n) => {
            if (!settings) return;
            const before = settings.bulkParallelLimit;
            void status.run(
              async () => onSettings(await api.setBulkParallel(n)),
              async () => onSettings(await api.setBulkParallel(before)),
            );
          }}
        />
      </CardContent>
    </Card>
  );
}

/** SS-04: how the vault locks and unlocks is set on the Vault page; this says how it is now. */
function VaultSettingsCard({ vault, onOpenVault }: { vault: VaultInfo | null; onOpenVault: () => void }) {
  const set = vault && vault.status !== "notSetUp";
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Vault
          <HelpTip topic="vaultIdleLock" />
        </CardTitle>
        <CardDescription>
          {set
            ? `Locks after ${vault.idleLockMinutes} minutes without activity. Your Windows login ${vault.windowsLogin ? "unlocks it too" : "doesn't unlock it"}.`
            : "Not set up yet."}
        </CardDescription>
        <CardAction>
          <Button variant="outline" onClick={onOpenVault}>
            <KeyRoundIcon data-icon="inline-start" />
            {set ? "Open the Vault" : "Set up the vault"}
          </Button>
        </CardAction>
      </CardHeader>
    </Card>
  );
}

/** MO-02: seconds between two polls of each watched host. */
function DashboardPollingCard({ settings, onSettings }: SettingsCardProps) {
  const status = useSaveStatus();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Dashboard polling
          <HelpTip topic="dashboardPolling" />
        </CardTitle>
        <CardDescription>How often watched hosts are read. Less often is gentler on them.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-2">
        <Label htmlFor="guest-poll">Poll each watched host every</Label>
        <Select
          value={settings ? String(settings.guestPollSecs) : ""}
          disabled={!settings}
          onValueChange={(v) => {
            if (!settings) return;
            const before = settings.guestPollSecs;
            void status.run(
              async () => onSettings(await api.setGuestPoll(Number(v))),
              async () => onSettings(await api.setGuestPoll(before)),
            );
          }}
        >
          <SelectTrigger id="guest-poll" className="w-48">
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
      </CardContent>
    </Card>
  );
}

/** FD-14: update checks and the optional GitHub update token. */
function UpdatesCard({
  settings,
  onSettings,
  onChanged,
  vault,
  onVaultChanged,
  onOpenVault,
}: SettingsCardProps & {
  onChanged: (change: SettingsChange) => void;
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
}) {
  const status = useSaveStatus();
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  async function checkNow() {
    setChecking(true);
    try {
      const check = await api.checkForUpdate();
      setResult({ ok: check.status === "available" || check.status === "upToDate", text: checkMessage(check) });
      // The banner shows the update, or asks for a token; after a used-up limit, the app checks again later.
      if (check.status === "available" || isNotice(check)) onChanged("updates");
    } catch (err) {
      setResult({ ok: false, text: `Could not check for updates: ${errorMessage(err)}` });
    } finally {
      setChecking(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Updates
          <HelpTip topic="updateChecks" />
        </CardTitle>
        <CardDescription>Checked at start and every 24 hours; installing always asks first.</CardDescription>
        <CardAction>
          <SaveStatus status={status} />
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <Switch
            id="update-checks"
            checked={settings?.updateChecks ?? true}
            disabled={!settings}
            onCheckedChange={(checked) =>
              void status.run(async () => {
                onSettings(await api.setUpdateChecks(checked));
                onChanged("updates");
              })
            }
          />
          <Label htmlFor="update-checks">Check for updates</Label>
          <WhyDisabled reason={settings && !settings.updateChecks ? "Update checks are off" : null}>
            <Button
              variant="outline"
              size="sm"
              className="ml-auto"
              onClick={() => void checkNow()}
              disabled={checking || !settings?.updateChecks}
            >
              {checking ? "Checking…" : "Check now"}
            </Button>
          </WhyDisabled>
        </div>
        {result && (
          <p className={result.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
            {result.text}
          </p>
        )}
        <UpdateTokenField
          settings={settings}
          vault={vault}
          onSettings={onSettings}
          onChanged={() => onChanged("updates")}
          onVaultChanged={onVaultChanged}
          onOpenVault={onOpenVault}
        />
      </CardContent>
    </Card>
  );
}

/** QL-15: the version, and where the logs and crash reports are, with a button that opens the folder. */
function AboutCard() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [logs, setLogs] = useState<LogsInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api.appInfo().then(setInfo, () => setInfo(null));
    api.logsInfo().then(setLogs, () => setLogs(null));
  }, []);

  async function openLogs() {
    try {
      await api.openLogs();
      setError(null);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Remotely {info?.version ?? ""}</CardTitle>
        <CardDescription>
          Logs ({logs?.keepDays ?? 7} days) and crash reports never hold passwords, keys or tokens: send them when you
          report a problem.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-1.5">
        <Label>Logs folder</Label>
        <p className="font-mono text-sm break-all">
          {logs?.folder ?? "Not known: the app's data folder was not found."}
        </p>
        {error && (
          <p className="text-sm text-destructive" role="status">
            {error}
          </p>
        )}
      </CardContent>
      <CardFooter>
        <Button variant="outline" onClick={() => void openLogs()} disabled={!logs?.folder}>
          <FileTextIcon data-icon="inline-start" />
          Open the logs folder
        </Button>
      </CardFooter>
    </Card>
  );
}
