// FD-03 presentation mode in the app chrome: the Present button in the top bar (always visible), which becomes a
// "Presenting" menu with the read-only lock, "Hide terminal output" and "Stop presenting" (UX-22, 0.9.0: their one
// home); a coloured frame round the window while presenting; the one confirm before presenting or the lock stops; and
// Settings' one line, whose "Show it" lights the button. The palette has the same commands (App.tsx).
//
// Starting masks the screen at once and then tells the core (which saves and audits it); stopping, or turning the lock
// off, asks first and changes the screen only once the core has saved it, so a failure leaves the screen masked.

import { useEffect, useRef, useState, useSyncExternalStore, type RefObject } from "react";
import { toast } from "sonner";
import { EyeOffIcon, LockKeyholeIcon, PresentationIcon } from "lucide-react";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { HelpTip } from "@/components/HelpTip";
import { api, errorMessage } from "@/lib/api";
import { READ_ONLY_REASON } from "@/lib/disabled-reasons";
import { cn } from "@/lib/utils";
import { workspacesApi } from "@/lib/workspaces-api";
import {
  presentationView,
  readOnlyLocked,
  setPresentationView,
  subscribePresentation,
  type PresentationView,
} from "@/lib/presentation-state";

export function usePresentation(): PresentationView {
  return useSyncExternalStore(subscribePresentation, presentationView);
}

/** QL-08: the reason a changing action is disabled now, or null. The core refuses it anyway. */
export function useReadOnlyReason(): string | null {
  return readOnlyLocked(usePresentation()) ? READ_ONLY_REASON : null;
}

/**
 * Asks the core for what the masker should know before it masks a page: sessions, VMs, known hosts and recent quick
 * connections (their hosts, IPs and users). The answers are learnt on the way in (api.ts). Never waits long.
 */
export async function primeMasker(waitMs = 1500): Promise<void> {
  // FD-02: the workspace list teaches the masker every workspace name, archived ones included.
  const reads = Promise.allSettled([
    api.sessions(),
    api.vmList(),
    api.knownHosts(),
    api.quickConnectHistory(),
    workspacesApi.list(),
  ]);
  await Promise.race([reads, new Promise((resolve) => window.setTimeout(resolve, waitMs))]);
}

/** Masks the screen now, then saves it (audited). */
export async function startPresenting() {
  setPresentationView({ presenting: true });
  void primeMasker();
  try {
    const saved = await api.setPresentation({ enabled: true, readOnly: presentationView().readOnly });
    setPresentationView({ presenting: saved.enabled, readOnly: saved.readOnly });
  } catch (err) {
    toast.error(`Presenting on this screen, but Remotely could not save it: ${errorMessage(err)}`);
  }
}

/** After the confirm: saves it, then shows real values again. Throws (the dialog shows why) and stays masked. */
async function stopPresenting() {
  const saved = await api.setPresentation({ enabled: false, readOnly: presentationView().readOnly });
  setPresentationView({ presenting: saved.enabled, readOnly: saved.readOnly });
}

/** On applies at once; off (while presenting) only after the confirm, and only once saved. */
export async function setReadOnlyLock(on: boolean) {
  if (on) setPresentationView({ readOnly: true });
  try {
    const saved = await api.setPresentation({ enabled: presentationView().presenting, readOnly: on });
    setPresentationView({ presenting: saved.enabled, readOnly: saved.readOnly });
  } catch (err) {
    if (!on) throw err;
    toast.error(`The read-only lock could not be saved: ${errorMessage(err)}`);
  }
}

export function setHideTerminals(on: boolean) {
  setPresentationView({ hideTerminals: on });
}

// ---- the one confirm, asked from the top bar, the palette or Settings ----

type Ask = "stop" | "unlock" | null;
let ask: Ask = null;
const askListeners = new Set<() => void>();

export function askPresentationConfirm(next: Ask) {
  ask = next;
  askListeners.forEach((l) => l());
}

function useAsk(): Ask {
  return useSyncExternalStore(
    (listener) => {
      askListeners.add(listener);
      return () => askListeners.delete(listener);
    },
    () => ask,
  );
}

/** Stopping, or turning the lock off while it applies, needs this one confirm; turning either on never does. */
export function requestStopPresenting() {
  askPresentationConfirm("stop");
}

export function requestReadOnlyLock(on: boolean) {
  if (on || !readOnlyLocked()) void setReadOnlyLock(on).catch((err) => toast.error(errorMessage(err)));
  else askPresentationConfirm("unlock");
}

/** The frame round the window while presenting, and the confirm dialog. Rendered once, in App. */
export function PresentationLayer() {
  const view = usePresentation();
  const current = useAsk();
  return (
    <>
      {view.presenting && (
        <div
          aria-hidden
          className="pointer-events-none fixed inset-0 z-[100] border-[3px] border-presenting"
          data-presentation-frame
        />
      )}
      {current === "stop" && (
        <ConfirmDialog
          title="Stop presenting?"
          description={
            <>
              Host names, IP addresses and user names show again, on screen and in the terminals
              {view.readOnly ? ", and the read-only lock stops applying" : ""}. Check that your screen is no longer
              shared first.
            </>
          }
          confirmLabel="Stop presenting"
          onConfirm={stopPresenting}
          onClose={() => askPresentationConfirm(null)}
        />
      )}
      {current === "unlock" && (
        <ConfirmDialog
          title="Turn the read-only lock off?"
          description="While you present, VMs, hosts and Remotely's own data can be changed again: power actions, commands, uploads, tunnels, imports and edits go through as usual."
          confirmLabel="Turn the lock off"
          onConfirm={() => setReadOnlyLock(false)}
          onClose={() => askPresentationConfirm(null)}
        />
      )}
    </>
  );
}

/** The top bar's control: Present, or the Presenting menu. */
export function PresentationButton() {
  const view = usePresentation();
  // UX-22: Settings' "Show it" lights this button and focuses it.
  const [ref, lit] = usePointedAt();
  const ring = lit ? "ring-2 ring-ring ring-offset-2" : undefined;
  if (!view.presenting) {
    return (
      <Button
        ref={ref}
        variant="outline"
        size="sm"
        className={ring}
        title="Present: mask host names, IP addresses and user names for a screen share"
        onClick={() => void startPresenting()}
      >
        <PresentationIcon />
        Present
      </Button>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          ref={ref}
          size="sm"
          className={cn("bg-presenting text-white hover:bg-presenting/90", ring)}
          aria-label="Presenting: options"
        >
          <PresentationIcon />
          Presenting
          {view.readOnly && <LockKeyholeIcon aria-label="read-only" />}
          {view.hideTerminals && <EyeOffIcon aria-label="terminal output hidden" />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel className="font-normal text-muted-foreground">
          Host names, IP addresses and user names are masked on screen.
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuCheckboxItem
          checked={view.readOnly}
          onCheckedChange={(on) => requestReadOnlyLock(on)}
          onSelect={(e) => e.preventDefault()}
        >
          <div className="grid">
            <span>Read-only lock</span>
            <span className="text-xs text-muted-foreground">Blocks every change</span>
          </div>
        </DropdownMenuCheckboxItem>
        <DropdownMenuCheckboxItem
          checked={view.hideTerminals}
          onCheckedChange={(on) => setHideTerminals(on)}
          onSelect={(e) => e.preventDefault()}
        >
          <div className="grid">
            <span>Hide terminal output</span>
            <span className="text-xs text-muted-foreground">Blurs the terminals</span>
          </div>
        </DropdownMenuCheckboxItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => requestStopPresenting()}>Stop presenting…</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ---- UX-22 (0.9.0): Settings' one line points at the top bar, presentation mode's home ----

let pointed = 0;
const pointListeners = new Set<() => void>();

/** Lights the top bar's Present (or Presenting) button and gives it the focus. */
export function pointAtPresentButton() {
  pointed += 1;
  pointListeners.forEach((l) => l());
}

function usePointed(): number {
  return useSyncExternalStore(
    (listener) => {
      pointListeners.add(listener);
      return () => pointListeners.delete(listener);
    },
    () => pointed,
  );
}

/** While Settings points at it: the button's ref to focus, and whether it is lit. */
function usePointedAt(): [RefObject<HTMLButtonElement | null>, boolean] {
  const asked = usePointed();
  const ref = useRef<HTMLButtonElement>(null);
  const [handled, setHandled] = useState(asked);
  const [lit, setLit] = useState(false);
  if (asked !== handled) {
    setHandled(asked);
    setLit(true);
  }
  useEffect(() => {
    if (!lit) return;
    ref.current?.focus();
    const timer = window.setTimeout(() => setLit(false), 2500);
    return () => window.clearTimeout(timer);
  }, [lit, asked]);
  return [ref, lit];
}

/** Settings › Privacy and data: one line on presentation mode, and a link to the top bar's button, its one home. */
export function PresentationLine() {
  const view = usePresentation();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Presentation mode
          <HelpTip topic="presentationMode" />
        </CardTitle>
        {/* The Presenting menu is a modal dropdown, which a help popover inside it would close: its "?"s live here. */}
        <CardDescription className="flex flex-wrap items-center gap-x-1">
          {view.presenting ? "On now." : "For screen shares."} The top bar&apos;s Present masks host names, IP addresses
          and user names; its menu has the read-only lock
          <HelpTip topic="readOnlyLock" />
          and hides terminal output
          <HelpTip topic="hideTerminals" />
          <Button variant="link" className="h-auto p-0" onClick={pointAtPresentButton}>
            Show it
          </Button>
        </CardDescription>
      </CardHeader>
    </Card>
  );
}

/**
 * A page's note while the read-only lock applies: what is blocked there, and what still works. The page's buttons for
 * those say why they are off too (QL-08), and the core refuses them whatever the UI does.
 */
export function ReadOnlyNotice({ blocked, still }: { blocked: string; still?: string }) {
  const reason = useReadOnlyReason();
  if (!reason) return null;
  return (
    <Alert className="mb-6">
      <LockKeyholeIcon />
      <AlertTitle>Read-only while presenting</AlertTitle>
      <AlertDescription>
        {blocked} are blocked until the read-only lock is turned off (Presenting menu).{still ? ` ${still}` : ""}
      </AlertDescription>
    </Alert>
  );
}

/** What the read-only lock blocks on each page, for its notice (the Terminal page says it in its toolbar). */
export const READ_ONLY_PAGES: Record<string, { blocked: string; still?: string }> = {
  vms: {
    blocked:
      "Power actions, snapshots (taking, reverting and deleting), Protected, tags, environments and saved filters",
    still: "Refreshing, reading the list and each VM's details and snapshots still work.",
  },
  templates: {
    blocked: "Adding, editing, duplicating and deleting sizes, images and launch templates",
    still: "Reading them and opening the cloud image pages still work.",
  },
  schedules: {
    blocked:
      "New schedules, edits, approvals, pausing, resuming and deleting, and every scheduled run (it is reported as skipped, not caught up)",
    still: "Reading schedules and their runs still works.",
  },
  dashboard: { blocked: "Changes to VMs and hosts", still: "Watching hosts and reading metrics still work." },
  containers: {
    blocked: "Starting, stopping and removing containers, pulling and pruning, and marking container hosts",
    still: "Reading containers, logs, stats, images, volumes and networks, and opening a shell still work.",
  },
  files: {
    blocked: "Uploads, changes to a host's files, syncs to a host, many-hosts pushes and fetches, and bookmark edits",
    still: "Browsing, find, previews, checksums, comparing and downloads still work.",
  },
  sessions: {
    blocked: "New sessions, edits, folders, imports, links to VMs and port forwards",
    still: "Connecting and exporting still work.",
  },
  vault: {
    blocked: "Adding, replacing, renaming and deleting secrets, the vault password, SSH keys and trusted host keys",
    still: "Locking and unlocking the vault, and trusting a new host's key when you connect, still work.",
  },
  // UX-18 (0.9.0 H3): what Activity offers, bulk jobs' grouped results included.
  activity: {
    blocked: "Retries of a job's failed hosts and the go-ahead for the rest of a run after its first host",
    still:
      "Reading jobs, their grouped results and diffs, cancelling a job, and exporting results, reports and the audit log still work.",
  },
  settings: {
    blocked: "Changes to settings and the approval rules",
    still: "Presentation mode itself can still be changed here.",
  },
};
