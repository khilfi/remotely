// FD-03 presentation mode in the app chrome: the Present button in the top bar (always visible), which becomes a
// "Presenting" menu with the read-only lock, "Hide terminal output" and "Stop presenting"; a coloured frame round the
// window while presenting; the one confirm before presenting or the lock stops; and the Settings card. The palette
// has the same commands (App.tsx).
//
// Starting masks the screen at once and then tells the core (which saves and audits it); stopping, or turning the lock
// off, asks first and changes the screen only once the core has saved it, so a failure leaves the screen masked.

import { useSyncExternalStore } from "react";
import { toast } from "sonner";
import { EyeOffIcon, LockKeyholeIcon, PresentationIcon } from "lucide-react";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api, errorMessage } from "@/lib/api";
import { READ_ONLY_REASON } from "@/lib/disabled-reasons";
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
  const reads = Promise.allSettled([api.sessions(), api.vmList(), api.knownHosts(), api.quickConnectHistory()]);
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
  if (!view.presenting) {
    return (
      <Button
        variant="outline"
        size="sm"
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
        <Button size="sm" className="bg-presenting text-white hover:bg-presenting/90" aria-label="Presenting: options">
          <PresentationIcon />
          Presenting
          {view.readOnly && <LockKeyholeIcon aria-label="read-only" />}
          {view.hideTerminals && <EyeOffIcon aria-label="terminal output hidden" />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80">
        <DropdownMenuLabel className="font-normal text-muted-foreground">
          Host names, IP addresses, user names and your Windows user name in paths are masked on screen. Copies, saved
          output, session logs and exports keep the real text; printing (its preview is on screen) is masked.
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuCheckboxItem
          checked={view.readOnly}
          onCheckedChange={(on) => requestReadOnlyLock(on)}
          onSelect={(e) => e.preventDefault()}
        >
          <div className="grid">
            <span>Read-only lock</span>
            <span className="text-xs text-muted-foreground">
              Blocks every change. Typing into one terminal still works: it is your own shell.
            </span>
          </div>
        </DropdownMenuCheckboxItem>
        <DropdownMenuCheckboxItem
          checked={view.hideTerminals}
          onCheckedChange={(on) => setHideTerminals(on)}
          onSelect={(e) => e.preventDefault()}
        >
          <div className="grid">
            <span>Hide terminal output</span>
            <span className="text-xs text-muted-foreground">
              Blurs the terminals, for what masking can't catch (full-screen programs such as top or vim).
            </span>
          </div>
        </DropdownMenuCheckboxItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => requestStopPresenting()}>Stop presenting…</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Settings → General. */
export function PresentationCard() {
  const view = usePresentation();
  return (
    <Card>
      <CardHeader>
        <CardTitle>Presentation mode</CardTitle>
        <CardDescription>
          For screen shares: masks host names, IP addresses, user names and your Windows user name in paths everywhere
          on screen, with stand-ins such as host-3 or ip-5 that stay the same until Remotely closes. Remotely starts
          presenting if it was presenting when it closed. Starting and stopping are in the audit log.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex items-start justify-between gap-4">
          <Label htmlFor="presenting" className="grid gap-1">
            <span>Present</span>
            <span className="text-xs font-normal text-muted-foreground">
              Copies and saved terminal output, session logs and exports keep the real text; printing is masked, since
              its preview is on screen. Windows file dialogs show real paths.
            </span>
          </Label>
          <Switch
            id="presenting"
            checked={view.presenting}
            onCheckedChange={(on) => (on ? void startPresenting() : requestStopPresenting())}
          />
        </div>
        <div className="flex items-start justify-between gap-4">
          <Label htmlFor="read-only-lock" className="grid gap-1">
            <span>Read-only lock while presenting</span>
            <span className="text-xs font-normal text-muted-foreground">
              Blocks power actions, snapshots, commands, MultiExec, uploads, tunnels, key pushes, imports, edits of
              sessions and settings, and updates. Reading, downloads and typing into one terminal still work.
            </span>
          </Label>
          <Switch id="read-only-lock" checked={view.readOnly} onCheckedChange={(on) => requestReadOnlyLock(on)} />
        </div>
        <div className="flex items-start justify-between gap-4">
          <Label htmlFor="hide-terminals" className="grid gap-1">
            <span>Hide terminal output while presenting</span>
            <span className="text-xs font-normal text-muted-foreground">
              Terminal output is masked as it arrives, but a full-screen program that redraws part of a name can show
              that part. This blurs the terminals instead.
            </span>
          </Label>
          <Switch id="hide-terminals" checked={view.hideTerminals} onCheckedChange={(on) => setHideTerminals(on)} />
        </div>
      </CardContent>
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
    blocked: "Power actions, snapshots, protection, tags, labels and saved filters",
    still: "Refreshing and reading the list still work.",
  },
  dashboard: { blocked: "Changes to VMs and hosts", still: "Watching hosts and reading metrics still work." },
  snapshots: { blocked: "Taking, reverting and deleting snapshots" },
  sessions: {
    blocked: "New sessions, edits, folders, imports, links to VMs and port forwards",
    still: "Connecting and exporting still work.",
  },
  knownHosts: { blocked: "Removing trusted keys", still: "A new host's key can still be trusted when you connect." },
  vault: {
    blocked: "Adding, replacing, renaming and deleting secrets, the vault password and SSH keys",
    still: "Locking and unlocking the vault still work.",
  },
  activity: { blocked: "Retrying and starting jobs", still: "Reading and exporting the audit log still work." },
  settings: {
    blocked: "Changes to settings and the approval rules",
    still: "Presentation mode itself can still be changed here.",
  },
};
