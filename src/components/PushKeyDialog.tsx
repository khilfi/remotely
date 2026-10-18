// SS-09: push a public key to many hosts. Picks hosts like a bulk run (BX-01), then submits a pushSshKey
// command: the policy engine gives it its tier (Medium by default; Prod raises it), the app's approval
// dialog asks what that tier needs, and each host appends the key to ~/.ssh/authorized_keys unless it is
// there already. The results show live, grouped like a bulk run's.

import { useEffect, useState } from "react";
import { UploadIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Textarea } from "@/components/ui/textarea";
import { TierBadge } from "@/components/Badges";
import { BulkResultsView } from "@/components/BulkResultsView";
import { BulkTargetPicker } from "@/components/BulkTargetPicker";
import {
  api,
  errorMessage,
  type Command,
  type CommandPreview,
  type PublicKeyInfo,
  type ResolvedTargets,
  type SshKey,
  type SubmitOutcome,
  type TargetPicks,
} from "@/lib/api";
import { plural } from "@/lib/format";

interface Props {
  /** The vault key to push; null: a public key pasted here (a colleague's, say). */
  sshKey: SshKey | null;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmit: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenSessions: () => void;
  onClose: () => void;
}

const DEFAULT_TIMEOUT = "120";

export function PushKeyDialog({ sshKey, onSubmit, onOpenSessions, onClose }: Props) {
  const [pasted, setPasted] = useState("");
  const [parsed, setParsed] = useState<{ text: string; key: PublicKeyInfo | null; error: string | null } | null>(null);
  const [picks, setPicks] = useState<TargetPicks>({});
  const [resolved, setResolved] = useState<ResolvedTargets | null>(null);
  const [trustNew, setTrustNew] = useState(false);
  const [timeout, setTimeoutText] = useState(DEFAULT_TIMEOUT);
  const [preview, setPreview] = useState<{ key: string; preview: CommandPreview } | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const publicKey = sshKey?.public ?? (parsed?.text === pasted.trim() ? parsed.key : null);
  const hosts = resolved?.hosts ?? [];
  const reach = hosts.filter((h) => !h.protected).length;
  const timeoutSecs = timeout.trim() === "" ? null : Number(timeout);
  const timeoutOk =
    timeoutSecs === null || (Number.isInteger(timeoutSecs) && timeoutSecs >= 1 && timeoutSecs <= 86_400);
  const command: Command | null = publicKey
    ? {
        type: "pushSshKey",
        targets: hosts.map((h) => ({ kind: "session", sessionId: h.sessionId })),
        publicKey: publicKey.line,
        trustNewHostKeys: trustNew,
        timeoutSecs: timeoutOk ? timeoutSecs : null,
      }
    : null;
  const commandKey = JSON.stringify(command);
  const shownPreview = command && reach > 0 && preview?.key === commandKey ? preview.preview : null;

  // A pasted key is checked by the core as it is typed.
  useEffect(() => {
    if (sshKey) return;
    const text = pasted.trim();
    if (!text) return;
    let stale = false;
    const timer = window.setTimeout(() => {
      api.parsePublicKey(text).then(
        (key) => !stale && setParsed({ text, key, error: null }),
        (err) => !stale && setParsed({ text, key: null, error: errorMessage(err) }),
      );
    }, 250);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [pasted, sshKey]);

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
    if (commandKey === "null") return;
    let stale = false;
    const parsedCommand = JSON.parse(commandKey) as Command;
    const timer = window.setTimeout(() => {
      api.commandPreview(parsedCommand).then(
        (p) => !stale && setPreview({ key: commandKey, preview: p }),
        () => {},
      );
    }, 200);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [commandKey]);

  async function push() {
    if (!command) return;
    setBusy(true);
    setError(null);
    try {
      onSubmit(await api.submit(command), setJobId);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <UploadIcon className="size-4" aria-hidden />
            {sshKey ? `Push '${sshKey.label}' to hosts` : "Push a public key to hosts"}
          </DialogTitle>
          <DialogDescription>
            Adds the public key to ~/.ssh/authorized_keys of the user each session logs in as, unless it is there
            already, and makes ~/.ssh 700 and the file 600. Each host is reached with the session&apos;s own login.
          </DialogDescription>
        </DialogHeader>

        {jobId ? (
          <div className="max-h-[60vh] overflow-y-auto pr-1">
            <BulkResultsView jobId={jobId} onRetry={(outcome) => onSubmit(outcome, setJobId)} />
          </div>
        ) : (
          <div className="grid max-h-[60vh] gap-4 overflow-y-auto pr-1">
            {!sshKey && (
              <div className="grid gap-2">
                <Label htmlFor="push-public-key">Public key</Label>
                <Textarea
                  id="push-public-key"
                  rows={3}
                  spellCheck={false}
                  className="font-mono text-xs"
                  placeholder="ssh-ed25519 AAAA… alice@example.com"
                  value={pasted}
                  onChange={(e) => setPasted(e.currentTarget.value)}
                />
                {pasted.trim() && parsed?.text === pasted.trim() && parsed.error && (
                  <p className="text-sm text-destructive">{parsed.error}</p>
                )}
              </div>
            )}
            {publicKey && (
              <p className="text-sm">
                <span className="text-muted-foreground">Key: </span>
                <span className="font-mono text-xs">{publicKey.fingerprint}</span>
                {publicKey.comment && <span className="text-muted-foreground"> ({publicKey.comment})</span>}
              </p>
            )}
            <BulkTargetPicker
              active
              picks={picks}
              onPicksChange={setPicks}
              resolved={resolved}
              onOpenSessions={onOpenSessions}
            />
            <div className="flex flex-wrap items-center gap-6">
              <div className="flex items-center gap-2">
                <Checkbox id="push-trust" checked={trustNew} onCheckedChange={(v) => setTrustNew(v === true)} />
                <Label htmlFor="push-trust" className="font-normal">
                  Trust new host keys
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Label htmlFor="push-timeout" className="font-normal">
                  Time limit per host (s)
                </Label>
                <Input
                  id="push-timeout"
                  inputMode="numeric"
                  className="w-24"
                  value={timeout}
                  onChange={(e) => setTimeoutText(e.currentTarget.value)}
                  aria-invalid={!timeoutOk || undefined}
                />
              </div>
            </div>
            {shownPreview && (
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <TierBadge tier={shownPreview.tier} />
                <span className="text-muted-foreground">
                  {shownPreview.steps.length === 0
                    ? "Runs at once; logged."
                    : shownPreview.steps.some((s) => s.step === "reason")
                      ? "Needs the host count typed, a reason and a countdown."
                      : "Needs one confirm."}
                </span>
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
            <Button type="button" onClick={() => void push()} disabled={!command || reach === 0 || !timeoutOk || busy}>
              {reach > 0 ? `Push to ${plural(reach, "host")}…` : "Push…"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
