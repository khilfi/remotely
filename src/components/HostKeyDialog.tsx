// SS-05: host key decisions. A first connection shows the server's SHA-256 fingerprint and asks before
// trusting it. A changed key has already blocked the connection: the dialog says so plainly, and
// replacing the saved key takes a deliberate extra step (audited in the core). SS-07: through jump hosts,
// each hop asks on its own, and the dialog names the jump host it is about.

import { useState } from "react";
import { ShieldAlertIcon, ShieldQuestionIcon } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type HostKey } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import type { HostKeyQuestion } from "@/lib/terminal-session";

interface Props {
  question: HostKeyQuestion;
  /** The session being connected, for the title. */
  sessionName: string;
  onTrust: () => Promise<void>;
  onReject: () => Promise<void>;
  onReplace: () => Promise<void>;
  /** Closes a changed-key notice without replacing anything. */
  onDismiss: () => void;
}

function address(key: HostKey) {
  const host = key.host.includes(":") && !key.host.startsWith("[") ? `[${key.host}]` : key.host;
  return `${host}:${key.port}`;
}

function Fingerprint({ label, keyType, fingerprint }: { label: string; keyType: string; fingerprint: string }) {
  return (
    <div className="grid gap-1">
      <span className="text-xs font-medium text-muted-foreground">
        {label} · {keyType}
      </span>
      <code className="rounded-md border bg-muted px-2 py-1.5 font-mono text-xs break-all select-all">
        {fingerprint}
      </code>
    </div>
  );
}

export function HostKeyDialog({ question, sessionName, onTrust, onReject, onReplace, onDismiss }: Props) {
  // FD-03: replacing a trusted key is blocked by the read-only lock (trusting a new host's key is not).
  const readOnly = useReadOnlyReason();
  const [busy, setBusy] = useState(false);
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  // SS-07: which hop of the chain this is about.
  const hop = question.jump ? `the jump host '${question.jump}', on the way to ${sessionName}` : sessionName;
  if (question.kind === "unknown") {
    const { key, otherKeyTypes } = question;
    return (
      <AlertDialog open onOpenChange={(open) => !open && !busy && void run(onReject)}>
        <AlertDialogContent className="data-[size=default]:sm:max-w-md">
          <AlertDialogHeader>
            <AlertDialogMedia>
              <ShieldQuestionIcon />
            </AlertDialogMedia>
            <AlertDialogTitle>
              {question.jump ? `Trust the jump host ${address(key)}?` : `Trust ${address(key)}?`}
            </AlertDialogTitle>
            <AlertDialogDescription>
              Remotely has not connected to this host before ({hop}). Check that the fingerprint below matches the
              host's own, for example with its owner or on its console, before you trust it.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <Fingerprint label="Fingerprint (SHA-256)" keyType={key.keyType} fingerprint={key.fingerprint} />
          {otherKeyTypes.length > 0 && (
            <Alert variant="destructive">
              <ShieldAlertIcon />
              <AlertTitle>This host had keys of another type</AlertTitle>
              <AlertDescription>
                Remotely trusts a {otherKeyTypes.join(", ")} key for this host. Servers seldom change key types; ask its
                owner whether the keys were replaced before you trust this one.
              </AlertDescription>
            </Alert>
          )}
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>Don't connect</AlertDialogCancel>
            <AlertDialogAction
              disabled={busy}
              onClick={(e) => {
                e.preventDefault();
                void run(onTrust);
              }}
            >
              Trust and connect
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    );
  }

  const { key, previous } = question;
  return (
    <AlertDialog open onOpenChange={(open) => !open && !busy && onDismiss()}>
      <AlertDialogContent className="data-[size=default]:sm:max-w-lg">
        <AlertDialogHeader>
          <AlertDialogMedia className="bg-destructive/10 text-destructive">
            <ShieldAlertIcon />
          </AlertDialogMedia>
          <AlertDialogTitle>
            The host key of {question.jump ? `the jump host ${address(key)}` : address(key)} has changed
          </AlertDialogTitle>
          <AlertDialogDescription>
            The key this host ({hop}) presented is not the one you trusted, so Remotely did not connect and sent nothing
            to it (no password, no key){question.jump ? ", nor went any further" : ""}. Someone may be intercepting the
            connection, or the host was reinstalled or had its keys replaced.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <div className="grid gap-3">
          <Fingerprint
            label={`Trusted since ${formatWhen(previous.firstSeenAt)}`}
            keyType={previous.keyType}
            fingerprint={previous.fingerprint}
          />
          <Fingerprint label="Presented now" keyType={key.keyType} fingerprint={key.fingerprint} />
        </div>
        <div className="flex items-start gap-2 rounded-md border p-3">
          <Checkbox
            id="host-key-confirm"
            checked={checked}
            onCheckedChange={(v) => setChecked(v === true)}
            disabled={busy}
          />
          <Label htmlFor="host-key-confirm" className="text-sm leading-snug font-normal">
            The host's owner confirmed that the new fingerprint is right. Replace the saved key and connect.
          </Label>
        </div>
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Close, don't connect</AlertDialogCancel>
          <WhyDisabled
            reason={
              readOnly ??
              (!checked
                ? "Tick the box first: the host's owner confirmed the new fingerprint"
                : busy
                  ? "Connecting…"
                  : null)
            }
          >
            <AlertDialogAction
              variant="destructive"
              disabled={busy || !checked || readOnly !== null}
              onClick={(e) => {
                e.preventDefault();
                void run(onReplace);
              }}
            >
              Replace key and connect
            </AlertDialogAction>
          </WhyDisabled>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
