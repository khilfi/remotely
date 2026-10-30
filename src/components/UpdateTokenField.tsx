// FD-14: the optional GitHub update token in Settings. Remotely's releases are public, so update checks
// work without one; a read-only token has a limit of its own and reads the releases if the repository
// goes private again. It is write-only like every vault secret: typed or pasted here, sent to the core
// once, then cleared. Nothing can read it back, so it is never shown again.

import { useState } from "react";
import { KeyRoundIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { VaultUnlock } from "@/components/VaultUnlock";
import { HelpTip } from "@/components/HelpTip";
import { api, errorMessage, type Settings, type TokenReport, type VaultInfo } from "@/lib/api";

interface Props {
  settings: Settings | null;
  vault: VaultInfo | null;
  onSettings: (settings: Settings) => void;
  /** After the token was saved or removed, so the update banner checks again. */
  onChanged: () => void;
  onVaultChanged: (info: VaultInfo) => void;
  onOpenVault: () => void;
}

type Message = { ok: boolean; text: string } | null;

/** Days from today (local) to `date` (YYYY-MM-DD); negative once it has passed. */
function daysUntil(date: string) {
  const [y, m, d] = date.split("-").map(Number);
  const today = new Date();
  const start = Date.UTC(today.getFullYear(), today.getMonth(), today.getDate());
  return Math.round((Date.UTC(y, m - 1, d) - start) / 86_400_000);
}

function Expiry({ expiresOn }: { expiresOn: string | null }) {
  if (!expiresOn) return <span>GitHub reports its expiry date when it is first used.</span>;
  const days = daysUntil(expiresOn);
  if (days < 0) return <span className="text-destructive">It expired on {expiresOn}. Replace it.</span>;
  if (days <= 14) {
    return (
      <span className="text-destructive">
        It expires on {expiresOn}, in {days === 0 ? "less than a day" : `${days} days`}. Make a new one and replace it.
      </span>
    );
  }
  return <span>It expires on {expiresOn}.</span>;
}

/** Core messages start in lower case and end without a full stop, so they read well after a prefix. */
function sentence(text: string) {
  const capital = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

function works(report: TokenReport) {
  const release = report.latestRelease
    ? `the latest release is ${report.latestRelease}`
    : "nothing is published there yet";
  return `The token works: it can read ${report.repository}, and ${release}.`;
}

export function UpdateTokenField({ settings, vault, onSettings, onChanged, onVaultChanged, onOpenVault }: Props) {
  const [value, setValue] = useState("");
  const [replacing, setReplacing] = useState(false);
  // UX-10: without a token the form stays folded until "Add a token…".
  const [adding, setAdding] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<Message>(null);
  const token = settings?.updateToken;
  const editing = token?.stored ? replacing : adding;
  const stopEditing = () => {
    setReplacing(false);
    setAdding(false);
  };

  async function refresh() {
    onSettings(await api.settings());
  }

  async function test(prefix = "") {
    try {
      const report = await api.testUpdateToken();
      setMessage({ ok: true, text: prefix + works(report) });
    } catch (err) {
      setMessage({ ok: false, text: prefix + sentence(errorMessage(err)) });
    } finally {
      // GitHub reports the expiry date with every answer.
      await refresh().catch(() => undefined);
    }
  }

  async function save() {
    setBusy(true);
    setMessage(null);
    try {
      onSettings(await api.setUpdateToken(value));
      setValue("");
      stopEditing();
      onChanged();
      await test("Saved in the vault. ");
    } catch (err) {
      setMessage({ ok: false, text: sentence(errorMessage(err)) });
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setBusy(true);
    setMessage(null);
    await test();
    setBusy(false);
  }

  let form: React.ReactNode = null;
  if (editing && vault?.status === "notSetUp") {
    form = (
      <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
        The token is kept in the vault, which is not set up yet.
        <Button size="sm" variant="outline" onClick={onOpenVault}>
          Set up the vault
        </Button>
      </div>
    );
  } else if (editing && vault?.status === "locked") {
    form = (
      <div className="grid gap-2 rounded-md border p-3">
        <p className="text-sm text-muted-foreground">Unlock the vault to save the token there.</p>
        <VaultUnlock info={vault} onUnlocked={onVaultChanged} idPrefix="update-token-unlock" />
        <Button className="justify-self-start" variant="ghost" onClick={stopEditing}>
          Cancel
        </Button>
      </div>
    );
  } else if (editing) {
    form = (
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) void save();
        }}
      >
        <Input
          id="update-token"
          type="password"
          className="font-mono"
          autoComplete="off"
          spellCheck={false}
          placeholder="github_pat_…"
          value={value}
          onChange={(e) => setValue(e.currentTarget.value)}
          disabled={busy || !settings}
        />
        <Button type="submit" disabled={busy || !value.trim()}>
          {busy ? "Saving…" : "Save"}
        </Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => {
            setValue("");
            stopEditing();
          }}
        >
          Cancel
        </Button>
      </form>
    );
  }

  return (
    <div className="grid gap-3 border-t pt-4">
      <div className="grid gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <Label htmlFor="update-token">GitHub update token</Label>
          <HelpTip topic="updateToken" />
          {token?.stored ? (
            <Badge variant="secondary">
              <KeyRoundIcon />
              In the vault
            </Badge>
          ) : (
            <Badge variant="outline">Optional</Badge>
          )}
          {!token?.stored && !adding && (
            <Button
              variant="outline"
              size="sm"
              className="ml-auto"
              disabled={!settings}
              onClick={() => setAdding(true)}
            >
              Add a token…
            </Button>
          )}
        </div>
        {token?.stored && (
          <p className="text-sm text-muted-foreground">
            <Expiry expiresOn={token.expiresOn} /> Used while the vault is unlocked.
          </p>
        )}
      </div>
      {form}
      {token?.stored && !replacing && (
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={() => void runTest()} disabled={busy || vault?.status !== "unlocked"}>
            {busy ? "Testing…" : "Test"}
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              setMessage(null);
              setReplacing(true);
            }}
            disabled={busy}
          >
            Replace
          </Button>
          <Button
            variant="outline"
            onClick={() => setConfirmRemove(true)}
            disabled={busy || vault?.status !== "unlocked"}
          >
            Remove
          </Button>
          {vault?.status === "locked" && (
            <span className="self-center text-sm text-muted-foreground">Unlock the vault to test or remove it.</span>
          )}
        </div>
      )}
      {message && (
        <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
          {message.text}
        </p>
      )}
      {confirmRemove && (
        <ConfirmDialog
          title="Remove the GitHub update token?"
          description="Update checks go on without a token, which works while the repository is public. The token still works on GitHub: delete it there too if nothing else uses it."
          confirmLabel="Remove"
          onConfirm={async () => {
            onSettings(await api.removeUpdateToken());
            onChanged();
            setMessage({ ok: true, text: "Removed from the vault." });
          }}
          onClose={() => setConfirmRemove(false)}
        />
      )}
    </div>
  );
}
