// QL-23 first-run wizard: find Workstation and VirtualBox (the paths as Settings resolves them), create the vault (the
// Vault page's own form: NewPasswordField with its strength meter and Generate, the Windows login off by default with
// its trade-off), pick folders of VMs to scan, and import sessions (the Sessions page's import dialog, SS-02). It
// offers itself at start when there is no vault and no session (lib/first-run.ts); every step can be left, and
// Settings, General opens it again. Each step calls the same commands as those pages, so the core checks and audits
// what it saves exactly as it does there.

import { useCallback, useEffect, useState } from "react";
import {
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  CircleDashedIcon,
  CircleIcon,
  FolderIcon,
  FolderOpenIcon,
  UploadIcon,
  XIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ImportDialog } from "@/components/ImportDialog";
import { api, errorMessage, type SessionFolder, type Settings, type VaultInfo } from "@/lib/api";
import {
  FIRST_RUN_STEPS,
  dismissFirstRun,
  nextStep,
  previousStep,
  stepMark,
  type FirstRunFacts,
  type FirstRunStep,
} from "@/lib/first-run";
import type { SettingsChange } from "@/lib/job-events";
import { navigationApi } from "@/lib/navigation-api";
import { cn } from "@/lib/utils";
import { SetupCard } from "@/pages/VaultPage";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  /** A setting changed: the VM list and the sidebar read again (as from Settings). */
  onSettingsChanged: (change: SettingsChange) => void;
  /** Where to go once it is done. */
  onGoTo: (page: string) => void;
}

type Message = { ok: boolean; text: string } | null;

export function FirstRunWizard({
  open,
  onOpenChange,
  vault,
  onVaultChanged,
  onOpenVault,
  onSettingsChanged,
  onGoTo,
}: Props) {
  const [step, setStep] = useState<FirstRunStep>("hypervisors");
  const [settings, setSettings] = useState<Settings | null>(null);
  const [sessionCount, setSessionCount] = useState<number | null>(null);

  const read = useCallback(() => {
    api.settings().then(setSettings, () => setSettings(null));
    api.sessions().then(
      (list) => setSessionCount(list.length),
      () => setSessionCount(null),
    );
  }, []);

  useEffect(() => {
    if (open) read();
  }, [open, read]);

  const facts: FirstRunFacts = {
    vaultStatus: vault?.status ?? null,
    sessionCount,
    vmrunFound: Boolean(settings?.vmrunPathInUse),
    vboxmanageFound: Boolean(settings?.vboxmanagePathInUse),
    scanFolders: settings?.scanFolders.length ?? 0,
  };

  function close(how: "done" | "skipped") {
    dismissFirstRun(how);
    onOpenChange(false);
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close("skipped"))}>
      <DialogContent className="max-h-[90vh] overflow-hidden sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Set up Remotely</DialogTitle>
          <DialogDescription>
            Four steps, each one optional and each one in Settings, the Vault page or the Sessions page later. Settings,
            General opens this again.
          </DialogDescription>
        </DialogHeader>
        <div className="grid min-h-0 min-w-0 gap-6 overflow-auto md:grid-cols-[13rem_minmax(0,1fr)]">
          <ol className="flex flex-col gap-1" aria-label="Steps">
            {FIRST_RUN_STEPS.map((s, i) => {
              const mark = stepMark(s.id, facts);
              return (
                <li key={s.id}>
                  <button
                    type="button"
                    className={cn(
                      "flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-accent",
                      step === s.id && "bg-accent font-medium",
                    )}
                    aria-current={step === s.id ? "step" : undefined}
                    onClick={() => setStep(s.id)}
                  >
                    <span className="mt-0.5">
                      {mark === "done" ? (
                        <CheckIcon className="size-4 text-success" aria-label="Done" />
                      ) : mark === "todo" ? (
                        <CircleIcon className="size-4 text-muted-foreground" aria-label="To do" />
                      ) : (
                        <CircleDashedIcon className="size-4 text-muted-foreground" aria-label="Optional" />
                      )}
                    </span>
                    <span>
                      {i + 1}. {s.title}
                    </span>
                  </button>
                </li>
              );
            })}
          </ol>
          <div className="min-w-0">
            {step === "hypervisors" && (
              <HypervisorsStep settings={settings} onSettings={setSettings} onChanged={onSettingsChanged} />
            )}
            {step === "vault" &&
              (vault && vault.status === "notSetUp" ? (
                <SetupCard vault={vault} onDone={onVaultChanged} />
              ) : (
                <p className="text-sm text-muted-foreground">
                  The vault is set up{vault?.status === "locked" ? " (locked now)" : ""}. Change its password or the
                  Windows login on the Vault page.
                </p>
              ))}
            {step === "folders" && (
              <FoldersStep settings={settings} onSettings={setSettings} onChanged={onSettingsChanged} />
            )}
            {step === "sessions" && (
              <SessionsStep
                count={sessionCount}
                vault={vault}
                onVaultChanged={onVaultChanged}
                onOpenVault={onOpenVault}
                onImported={read}
              />
            )}
            {step === "done" && (
              <DoneStep
                facts={facts}
                onGoTo={(page) => {
                  close("done");
                  onGoTo(page);
                }}
              />
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 border-t pt-4">
          <Button variant="ghost" onClick={() => close("skipped")}>
            Skip for now
          </Button>
          <div className="ml-auto flex gap-2">
            <Button variant="outline" disabled={step === "hypervisors"} onClick={() => setStep(previousStep(step))}>
              <ArrowLeftIcon /> Back
            </Button>
            {step === "done" ? (
              <Button onClick={() => close("done")}>Finish</Button>
            ) : (
              <Button onClick={() => setStep(nextStep(step))}>
                Next <ArrowRightIcon />
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function StatusLine({ message }: { message: Message }) {
  if (!message) return null;
  return (
    <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
      {message.text}
    </p>
  );
}

/** A tool's path: in use as Settings resolves it, and a path to use instead. */
function PathField({
  id,
  label,
  inUse,
  missing,
  saved,
  onSave,
}: {
  id: string;
  label: string;
  inUse: string | null;
  missing: string;
  saved: string | null;
  onSave: (path: string | null) => Promise<string | null>;
}) {
  const [path, setPath] = useState(saved ?? "");
  const [message, setMessage] = useState<Message>(null);
  // The saved path changed (saved here, or read again): the field shows it.
  const [shownSaved, setShownSaved] = useState(saved);
  if (saved !== shownSaved) {
    setShownSaved(saved);
    setPath(saved ?? "");
  }
  async function save(next: string | null) {
    try {
      const used = await onSave(next);
      setMessage({ ok: used !== null, text: used ? `Using ${used}` : missing });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }
  return (
    <div className="grid grid-cols-1 gap-2">
      <Label htmlFor={id}>{label}</Label>
      <p className="text-sm">
        {inUse ? (
          <>
            Found: <span className="font-mono break-all">{inUse}</span>
          </>
        ) : (
          <span className="text-muted-foreground">{missing}</span>
        )}
      </p>
      <div className="flex gap-2">
        <Input
          id={id}
          className="font-mono"
          placeholder="Found automatically"
          spellCheck={false}
          value={path}
          onChange={(e) => setPath(e.currentTarget.value)}
        />
        <Button variant="outline" disabled={!path.trim()} onClick={() => void save(path.trim())}>
          Use this path
        </Button>
        {saved && (
          <Button variant="ghost" onClick={() => void save(null)}>
            Find automatically
          </Button>
        )}
      </div>
      <StatusLine message={message} />
    </div>
  );
}

function HypervisorsStep({
  settings,
  onSettings,
  onChanged,
}: {
  settings: Settings | null;
  onSettings: (s: Settings) => void;
  onChanged: (change: SettingsChange) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-6">
      <p className="text-sm text-muted-foreground">
        Remotely runs every VM action through VMware Workstation&apos;s vmrun.exe and VirtualBox&apos;s VBoxManage.exe.
        It looks for them the way Settings does: a path saved there, then the registry and the default install folders.
        Either one is enough; without VirtualBox the list just has no VirtualBox VMs.
      </p>
      <PathField
        id="first-run-vmrun"
        label="VMware Workstation (vmrun.exe)"
        inUse={settings?.vmrunPathInUse ?? null}
        missing="Not found. Install Workstation Pro 17 or later, or give the path."
        saved={settings?.vmrunPathSaved ?? null}
        onSave={async (path) => {
          const s = await api.setVmrunPath(path);
          onSettings(s);
          onChanged("vmrun");
          return s.vmrunPathInUse;
        }}
      />
      <PathField
        id="first-run-vboxmanage"
        label="Oracle VirtualBox (VBoxManage.exe)"
        inUse={settings?.vboxmanagePathInUse ?? null}
        missing="Not found (VirtualBox 7.0 or later isn't installed, or give the path)."
        saved={settings?.vboxmanagePathSaved ?? null}
        onSave={async (path) => {
          const s = await api.setVboxmanagePath(path);
          onSettings(s);
          onChanged("vboxmanage");
          return s.vboxmanagePathInUse;
        }}
      />
    </div>
  );
}

function FoldersStep({
  settings,
  onSettings,
  onChanged,
}: {
  settings: Settings | null;
  onSettings: (s: Settings) => void;
  onChanged: (change: SettingsChange) => void;
}) {
  const [newFolder, setNewFolder] = useState("");
  const [message, setMessage] = useState<Message>(null);
  const folders = settings?.scanFolders ?? [];

  async function save(next: string[]) {
    try {
      const s = await api.setScanFolders(next);
      onSettings(s);
      setNewFolder("");
      setMessage(null);
      onChanged("scanFolders");
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function browse() {
    try {
      const picked = await navigationApi.vmFolderPick();
      if (picked && !folders.includes(picked)) await save([...folders, picked]);
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    }
  }

  return (
    <div className="grid grid-cols-1 gap-4">
      <p className="text-sm text-muted-foreground">
        Every VM in Workstation&apos;s library and every VM registered in VirtualBox is listed already. Add folders that
        hold other Workstation VMs: they are searched for .vmx files up to five folder levels down.
      </p>
      {folders.length > 0 && (
        <ul className="grid grid-cols-1 gap-1">
          {folders.map((folder) => (
            <li key={folder} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
              <FolderIcon className="size-4 shrink-0 text-muted-foreground" />
              <span className="min-w-0 flex-1 truncate font-mono text-sm" title={folder}>
                {folder}
              </span>
              <Button
                size="icon-sm"
                variant="ghost"
                aria-label={`Stop scanning ${folder}`}
                onClick={() => void save(folders.filter((f) => f !== folder))}
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
          if (settings && newFolder.trim()) void save([...folders, newFolder.trim()]);
        }}
      >
        <Label htmlFor="first-run-folder" className="sr-only">
          Folder to scan
        </Label>
        <Input
          id="first-run-folder"
          className="font-mono"
          placeholder="D:\VMs"
          spellCheck={false}
          value={newFolder}
          onChange={(e) => setNewFolder(e.currentTarget.value)}
        />
        <Button type="submit" variant="outline" disabled={!settings || !newFolder.trim()}>
          Add
        </Button>
        <Button type="button" variant="outline" disabled={!settings} onClick={() => void browse()}>
          <FolderOpenIcon /> Browse…
        </Button>
      </form>
      <StatusLine message={message} />
    </div>
  );
}

function SessionsStep({
  count,
  vault,
  onVaultChanged,
  onOpenVault,
  onImported,
}: {
  count: number | null;
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
  onImported: () => void;
}) {
  const [folders, setFolders] = useState<SessionFolder[] | null>(null);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setError(null);
    try {
      setFolders(await api.sessionFolders());
      setImporting(true);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <div className="grid grid-cols-1 gap-4">
      <p className="text-sm text-muted-foreground">
        Bring your saved sessions from PuTTY (this PC&apos;s or an exported .reg file), MobaXterm, an OpenSSH config or
        a CSV file. You see what would be imported before anything is saved; passwords are never read from them.
      </p>
      <p className="text-sm">
        {count === null
          ? ""
          : count === 0
            ? "No session yet."
            : `${count === 1 ? "1 session" : `${count} sessions`} saved.`}
      </p>
      <div>
        <Button onClick={() => void start()}>
          <UploadIcon /> Import sessions…
        </Button>
      </div>
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
      {importing && folders && (
        <ImportDialog
          folders={folders}
          folderId={null}
          vault={vault}
          onVaultChanged={onVaultChanged}
          onOpenVault={onOpenVault}
          onImported={onImported}
          onClose={() => setImporting(false)}
        />
      )}
    </div>
  );
}

function DoneStep({ facts, onGoTo }: { facts: FirstRunFacts; onGoTo: (page: string) => void }) {
  return (
    <div className="grid grid-cols-1 gap-4">
      <p className="text-sm">
        {facts.vaultStatus === "notSetUp"
          ? "The vault isn't set up yet: sessions that log in with a password or a key ask for it first."
          : "Remotely is ready."}
      </p>
      <ul className="grid gap-2 text-sm">
        <li>
          <Button variant="link" className="h-auto p-0" onClick={() => onGoTo("vms")}>
            Virtual machines
          </Button>{" "}
          lists every VM found, with power, snapshots and settings.
        </li>
        <li>
          <Button variant="link" className="h-auto p-0" onClick={() => onGoTo("sessions")}>
            Sessions
          </Button>{" "}
          holds your SSH sessions; open one in a terminal from there.
        </li>
        <li>
          <Button variant="link" className="h-auto p-0" onClick={() => onGoTo("map")}>
            Map
          </Button>{" "}
          shows how the VMs, networks and sessions connect.
        </li>
        <li className="text-muted-foreground">Ctrl+K searches everything; Ctrl+/ lists every shortcut.</li>
      </ul>
    </div>
  );
}
