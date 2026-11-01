// FD-04: the support bundle dialog. Picks hosts like Compare hosts (saved sessions; a VM only through a chosen or
// confirmed link), presets and custom commands and files, and the run's options (sudo from the vault, a time limit
// per host, one host first, a stop after failures). Collect opens the shell's save dialog for the zip, then the app's
// approval dialog asks what the tier needs (the presets only read: Low, Medium on Prod). Each host's progress shows
// live; once the job ends, Show folder opens Explorer at the zip.

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ChevronRightIcon, FolderOpenIcon, KeyRoundIcon, PackageIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import { BulkResultsView } from "@/components/BulkResultsView";
import { BulkTargetPicker } from "@/components/BulkTargetPicker";
import { HelpTip } from "@/components/HelpTip";
import { usePresentation } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type BundleLimits,
  type BundlePreset,
  type BundlePresetId,
  type BundleRequest,
  type CommandPreview,
  type JobStatus,
  type ResolvedTargets,
  type SecretMeta,
  type SubmitOutcome,
  type TargetPicks,
  type VaultInfo,
} from "@/lib/api";
import { plural } from "@/lib/format";
import { readOnlyLocked } from "@/lib/presentation-state";
import { compareOptionsSummary, parseStopAfter } from "@/lib/rollout";
import {
  collectReason,
  itemCount,
  lines,
  pathProblem,
  presetItemsText,
  shownPresets,
  stepsText,
  windowsPathProblem,
} from "@/lib/support-bundle";
import { cn } from "@/lib/utils";

interface Props {
  /** Hosts picked already (the Sessions page's selection); the picker adds or drops more. */
  sessionIds: string[];
  vault: VaultInfo | null;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmit: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenSessions: () => void;
  onOpenVault: () => void;
  onClose: () => void;
}

/** sudo gets each session's own login password. */
const LOGIN = "login";
const DEFAULT_TIMEOUT = "600";
// BX-13: the Windows ones too; each kind of host gets its own.
const DEFAULT_PRESETS: BundlePresetId[] = ["system", "logs", "windowsSystem", "windowsLogs"];
/** The job ended with a zip saved (some hosts may have failed). */
const SAVED: JobStatus[] = ["succeeded", "partially_failed"];

export function SupportBundleDialog({ sessionIds, vault, onSubmit, onOpenSessions, onOpenVault, onClose }: Props) {
  // FD-03: Collect says why it is off while the read-only lock applies.
  const presentation = usePresentation();
  const [presets, setPresets] = useState<BundlePreset[]>([]);
  const [limits, setLimits] = useState<BundleLimits | null>(null);
  const [chosen, setChosen] = useState<BundlePresetId[]>(DEFAULT_PRESETS);
  const [commandsText, setCommandsText] = useState("");
  const [filesText, setFilesText] = useState("");
  const [windowsCommandsText, setWindowsCommandsText] = useState("");
  const [windowsFilesText, setWindowsFilesText] = useState("");
  // BX-13: WinRM sessions are hosts too.
  const [picks, setPicks] = useState<TargetPicks>({ sessionIds, winrm: true });
  const [resolved, setResolved] = useState<ResolvedTargets | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [sudo, setSudo] = useState(false);
  const [sudoPassword, setSudoPassword] = useState(LOGIN);
  const [trustNew, setTrustNew] = useState(false);
  const [timeout, setTimeoutText] = useState(DEFAULT_TIMEOUT);
  const [canary, setCanary] = useState(false);
  const [stopAfter, setStopAfter] = useState("");
  const [optionsOpen, setOptionsOpen] = useState(false);
  const [preview, setPreview] = useState<{ key: string; preview: CommandPreview } | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [ended, setEnded] = useState<JobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const hosts = resolved?.hosts ?? [];
  const reach = hosts.filter((h) => !h.protected).length;
  const commands = lines(commandsText);
  const files = lines(filesText);
  const windowsCommands = lines(windowsCommandsText);
  const windowsFiles = lines(windowsFilesText);
  const windowsHosts = hosts.filter((h) => h.scriptKind === "powerShell").length;
  const linuxHosts = hosts.length - windowsHosts;
  const timeoutSecs = timeout.trim() === "" ? null : Number(timeout);
  const timeoutOk =
    timeoutSecs === null || (Number.isInteger(timeoutSecs) && timeoutSecs >= 1 && timeoutSecs <= 86_400);
  const stopAfterParsed = parseStopAfter(stopAfter);
  const request: BundleRequest = {
    sessionIds: hosts.map((h) => h.sessionId),
    presets: chosen,
    commands,
    files,
    windowsCommands,
    windowsFiles,
    sudo,
    sudoPasswordId: sudo && sudoPassword !== LOGIN ? sudoPassword : null,
    trustNewHostKeys: trustNew,
    timeoutSecs: timeoutOk ? timeoutSecs : null,
    rollout: { canary, stopAfterFailures: stopAfterParsed.value },
  };
  const requestKey = JSON.stringify(request);
  const items = itemCount(presets, chosen, commands, files, "linux");
  const windowsItems = itemCount(presets, chosen, windowsCommands, windowsFiles, "windows");
  const notReady = collectReason({
    readOnly: readOnlyLocked(presentation),
    hosts,
    items,
    windowsItems,
    maxItems: limits?.maxItems ?? 100,
    pathProblem: pathProblem(files) ?? windowsPathProblem(windowsFiles),
    timeoutOk,
    stopAfterOk: stopAfterParsed.ok,
    submitting: busy,
  });
  const shownPreview = reach > 0 && items + windowsItems > 0 && preview?.key === requestKey ? preview.preview : null;
  const optionsSummary = compareOptionsSummary({
    sudo,
    trustNewKeys: trustNew,
    timeoutSecs: timeoutOk ? timeoutSecs : Number(DEFAULT_TIMEOUT),
    defaultTimeoutSecs: Number(DEFAULT_TIMEOUT),
    canary,
    stopAfter: stopAfterParsed.value,
  });
  const vaultLocked = vault?.status !== "unlocked";

  useEffect(() => {
    let stale = false;
    Promise.all([api.bundlePresets(), api.bundleLimits(), api.secrets()]).then(
      ([p, l, s]) => {
        if (stale) return;
        setPresets(p);
        setLimits(l);
        setSecrets(s.filter((x) => x.kind === "password"));
      },
      (err) => !stale && setError(errorMessage(err)),
    );
    return () => {
      stale = true;
    };
  }, []);

  // BX-01: the hosts the picks reach.
  useEffect(() => {
    let stale = false;
    api.bulkTargets(picks).then(
      (r) => !stale && setResolved(r),
      (err) => !stale && setError(errorMessage(err)),
    );
    return () => {
      stale = true;
    };
  }, [picks]);

  // The tier it would get, before anything runs.
  useEffect(() => {
    const parsed = JSON.parse(requestKey) as BundleRequest;
    if (parsed.sessionIds.length === 0) return;
    let stale = false;
    const timer = window.setTimeout(() => {
      api.bundlePreview(parsed).then(
        (p) => !stale && setPreview({ key: requestKey, preview: p }),
        () => {},
      );
    }, 250);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [requestKey]);

  // Show folder once the job has ended.
  useEffect(() => {
    if (!jobId) return;
    const unlisten = api.onJobEvent((event) => {
      if (event.jobId === jobId && event.event === "finished") setEnded(event.status);
    });
    return () => void unlisten.then((stop) => stop());
  }, [jobId]);

  async function collect() {
    setBusy(true);
    setError(null);
    try {
      const outcome = await api.bundleSubmit(request);
      if (outcome) onSubmit(outcome, setJobId);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function showFolder() {
    if (!jobId) return;
    try {
      await api.bundleShowFolder(jobId);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  function toggle(id: BundlePresetId, on: boolean) {
    setChosen((list) => (on ? [...list.filter((x) => x !== id), id] : list.filter((x) => x !== id)));
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <PackageIcon className="size-4" aria-hidden />
            Collect a support bundle
            <HelpTip topic="supportBundle" />
          </DialogTitle>
          <DialogDescription>
            {jobId && !ended
              ? "The zip is saved once every host is done. Cancel saves nothing."
              : "The same commands' output and files from each host, in one zip with a manifest."}
          </DialogDescription>
        </DialogHeader>

        {jobId ? (
          <div className="max-h-[60vh] overflow-y-auto pr-1">
            <BulkResultsView
              jobId={jobId}
              bundle
              onRetry={(outcome) => onSubmit(outcome, setJobId)}
              extraActions={
                ended && SAVED.includes(ended) ? (
                  <Button variant="outline" size="sm" onClick={() => void showFolder()}>
                    <FolderOpenIcon data-icon="inline-start" />
                    Show folder
                  </Button>
                ) : null
              }
            />
          </div>
        ) : (
          <div className="grid max-h-[60vh] gap-4 overflow-y-auto pr-1">
            <BulkTargetPicker
              active
              picks={picks}
              onPicksChange={(next) => setPicks({ ...next, winrm: true })}
              resolved={resolved}
              onOpenSessions={onOpenSessions}
              winrm
            />

            <fieldset className="grid gap-2">
              <legend className="mb-1 text-sm font-medium">What to collect</legend>
              {shownPresets(presets, linuxHosts, windowsHosts).map((p) => (
                <div key={p.id} className="flex items-start gap-3">
                  <Checkbox
                    id={`bundle-preset-${p.id}`}
                    className="mt-0.5"
                    checked={chosen.includes(p.id)}
                    onCheckedChange={(v) => toggle(p.id, v === true)}
                  />
                  <div className="grid min-w-0 gap-0.5">
                    <Label htmlFor={`bundle-preset-${p.id}`} className="font-normal">
                      {p.label}
                      {linuxHosts > 0 && windowsHosts > 0 && (
                        <span className="text-muted-foreground">
                          {p.hostKind === "windows" ? " (Windows hosts)" : " (Linux hosts)"}
                        </span>
                      )}
                    </Label>
                    <p className="text-xs break-words text-muted-foreground" title={presetItemsText(p)}>
                      {p.description}
                    </p>
                  </div>
                </div>
              ))}
            </fieldset>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor="bundle-commands">More commands, one per line</Label>
                <Textarea
                  id="bundle-commands"
                  rows={3}
                  spellCheck={false}
                  className="font-mono text-xs"
                  placeholder="journalctl -u nginx -n 200"
                  value={commandsText}
                  onChange={(e) => setCommandsText(e.currentTarget.value)}
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="bundle-files">Files, one full path per line</Label>
                <Textarea
                  id="bundle-files"
                  rows={3}
                  spellCheck={false}
                  className="font-mono text-xs"
                  placeholder="/etc/nginx/nginx.conf"
                  value={filesText}
                  onChange={(e) => setFilesText(e.currentTarget.value)}
                  aria-invalid={pathProblem(files) ? true : undefined}
                />
              </div>
            </div>

            {windowsHosts > 0 && (
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="grid gap-1.5">
                  <Label htmlFor="bundle-windows-commands">More PowerShell commands for Windows hosts</Label>
                  <Textarea
                    id="bundle-windows-commands"
                    rows={3}
                    spellCheck={false}
                    className="font-mono text-xs"
                    placeholder="Get-EventLog -LogName Application -Newest 100"
                    value={windowsCommandsText}
                    onChange={(e) => setWindowsCommandsText(e.currentTarget.value)}
                  />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="bundle-windows-files">Windows files, one full path per line</Label>
                  <Textarea
                    id="bundle-windows-files"
                    rows={3}
                    spellCheck={false}
                    className="font-mono text-xs"
                    placeholder="C:\ProgramData\App\app.log"
                    value={windowsFilesText}
                    onChange={(e) => setWindowsFilesText(e.currentTarget.value)}
                    aria-invalid={windowsPathProblem(windowsFiles) ? true : undefined}
                  />
                </div>
              </div>
            )}

            <Collapsible open={optionsOpen} onOpenChange={setOptionsOpen} className="min-w-0 rounded-md border">
              <CollapsibleTrigger asChild>
                <button
                  type="button"
                  className="flex w-full min-w-0 items-center gap-2 rounded-md px-3 py-2 text-left text-sm hover:bg-muted/60"
                >
                  <ChevronRightIcon
                    className={cn("size-4 shrink-0 transition-transform", optionsOpen && "rotate-90")}
                    aria-hidden
                  />
                  <span className="font-medium">Options</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{optionsSummary}</span>
                </button>
              </CollapsibleTrigger>
              <CollapsibleContent className="grid gap-3 border-t p-3">
                <div className="flex items-center gap-3">
                  <Switch id="bundle-sudo" checked={sudo} onCheckedChange={setSudo} />
                  <Label htmlFor="bundle-sudo" className="font-normal">
                    {windowsHosts > 0 ? "Run the Linux hosts' commands with sudo" : "Run the commands with sudo"}
                  </Label>
                </div>
                {sudo && (
                  <div className="grid min-w-0 gap-1.5 pl-12">
                    <Label htmlFor="bundle-sudo-password" className="font-normal text-muted-foreground">
                      Password for sudo, from the vault
                    </Label>
                    <Select value={sudoPassword} onValueChange={setSudoPassword}>
                      <SelectTrigger id="bundle-sudo-password" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={LOGIN}>Each session&apos;s login password</SelectItem>
                        {secrets.length > 0 && <SelectSeparator />}
                        {secrets.map((s) => (
                          <SelectItem key={s.id} value={s.id}>
                            {s.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <p className="text-xs break-words text-muted-foreground">
                      Files are still read as the session&apos;s user.
                    </p>
                  </div>
                )}
                <div className="flex items-start gap-3">
                  <Checkbox
                    id="bundle-trust"
                    className="mt-0.5"
                    checked={trustNew}
                    onCheckedChange={(v) => setTrustNew(v === true)}
                  />
                  <div className="grid min-w-0 gap-0.5">
                    <Label htmlFor="bundle-trust" className="font-normal">
                      Trust new host keys
                    </Label>
                    <p className="text-xs break-words text-muted-foreground">
                      Else a host with a key not trusted yet fails. A changed key always blocks.
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Label htmlFor="bundle-timeout" className="font-normal">
                    Time limit per host
                  </Label>
                  <Input
                    id="bundle-timeout"
                    className="w-24"
                    inputMode="numeric"
                    value={timeout}
                    onChange={(e) => setTimeoutText(e.currentTarget.value)}
                    aria-invalid={!timeoutOk || undefined}
                  />
                  <span className="text-sm text-muted-foreground">seconds (empty: none)</span>
                </div>
                <div className="flex items-start gap-3">
                  <Checkbox
                    id="bundle-canary"
                    className="mt-0.5"
                    checked={canary}
                    onCheckedChange={(v) => setCanary(v === true)}
                  />
                  <div className="grid min-w-0 gap-0.5">
                    <Label htmlFor="bundle-canary" className="font-normal">
                      Collect from one host first
                    </Label>
                    <p className="text-xs break-words text-muted-foreground">
                      You see its result before the others run.
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <Label htmlFor="bundle-stop-after" className="font-normal">
                    Stop after
                  </Label>
                  <Input
                    id="bundle-stop-after"
                    className="w-20"
                    inputMode="numeric"
                    placeholder="never"
                    value={stopAfter}
                    onChange={(e) => setStopAfter(e.currentTarget.value)}
                    aria-invalid={!stopAfterParsed.ok || undefined}
                  />
                  <span className="text-sm text-muted-foreground">failures (empty: never)</span>
                </div>
              </CollapsibleContent>
            </Collapsible>

            {vaultLocked && (
              <Alert>
                <KeyRoundIcon />
                <AlertTitle>
                  {vault?.status === "notSetUp" ? "The vault is not set up" : "The vault is locked"}
                </AlertTitle>
                <AlertDescription>
                  Hosts that log in with a saved password or key, and sudo, need the vault unlocked.
                </AlertDescription>
                <AlertAction>
                  <Button size="sm" variant="outline" onClick={onOpenVault}>
                    Vault
                  </Button>
                </AlertAction>
              </Alert>
            )}

            {shownPreview && (
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <TierBadge tier={shownPreview.tier} />
                <span className="text-muted-foreground">{stepsText(shownPreview.steps)}</span>
                {shownPreview.dangerous.length > 0 && (
                  <span className="text-destructive">
                    Matches {shownPreview.dangerous.map((d) => d.rule).join(", ")}
                  </span>
                )}
              </div>
            )}
          </div>
        )}

        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
            {jobId ? "Close" : "Cancel"}
          </Button>
          {!jobId && (
            <WhyDisabled reason={notReady}>
              <Button type="button" onClick={() => void collect()} disabled={notReady !== null}>
                {reach > 0 ? `Collect from ${plural(reach, "host")}…` : "Collect…"}
              </Button>
            </WhyDisabled>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
