// Adds a secret to the vault, or replaces one's value (SS-04). Values are write-only: typed or pasted
// here, sent to the core once, then cleared. They are never read back, so nothing here can show one.
// A private key can also come straight from a file the core reads, so it never passes through the UI.

import { useState } from "react";
import { FileKeyIcon, InfoIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
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
import { api, errorMessage, type SecretKind, type SecretMeta, type VaultInfo } from "@/lib/api";
import { SECRET_KIND_LABEL } from "./Badges";
import { VaultUnlock } from "./VaultUnlock";

interface Props {
  vault: VaultInfo;
  kind: SecretKind;
  /** Replace this secret's value; without it, add a new secret. */
  existing?: SecretMeta;
  /** A label to start from when adding, e.g. the session's name. */
  suggestedLabel?: string;
  onVaultChanged: (info: VaultInfo) => void;
  onSaved: (meta: SecretMeta) => void;
  onClose: () => void;
}

const HINT: Record<SecretKind, string> = {
  password: "The password a session logs in with.",
  privateKey: "An OpenSSH or PEM private key (-----BEGIN … PRIVATE KEY-----), or a PuTTY .ppk file.",
  passphrase: "The passphrase that opens an encrypted private key.",
};

export function SecretDialog({ vault, kind, existing, suggestedLabel, onVaultChanged, onSaved, onClose }: Props) {
  const [label, setLabel] = useState(suggestedLabel ?? "");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const noun = SECRET_KIND_LABEL[kind].toLowerCase();
  const unlocked = vault.status === "unlocked";

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const meta = existing ? await api.replaceSecret(existing.id, value) : await api.addSecret(kind, label, value);
      setValue("");
      onSaved(meta);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function fromFile() {
    setBusy(true);
    setError(null);
    try {
      const meta = await api.importKeyFile(label);
      if (meta) {
        onSaved(meta);
        onClose();
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  function close() {
    setValue("");
    onClose();
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && close()}>
      <DialogContent className="sm:max-w-lg">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (unlocked && value && (existing || label.trim())) void save();
          }}
        >
          <DialogHeader>
            <DialogTitle>{existing ? `Replace the ${noun} '${existing.label}'` : `Add a ${noun}`}</DialogTitle>
            <DialogDescription>
              {HINT[kind]} It is encrypted in the vault and never shown again
              {existing && existing.usedBy > 0 ? `; ${existing.usedBy} session(s) will use the new value` : ""}.
            </DialogDescription>
          </DialogHeader>

          {vault.status === "notSetUp" && (
            <Alert>
              <InfoIcon />
              <AlertTitle>Set up the vault first</AlertTitle>
              <AlertDescription>Open the Vault page to choose a vault password.</AlertDescription>
            </Alert>
          )}
          {vault.status === "locked" && (
            <div className="grid gap-2 rounded-lg border p-3">
              <p className="text-sm font-medium">The vault is locked</p>
              <VaultUnlock info={vault} onUnlocked={onVaultChanged} idPrefix="secret-unlock" />
            </div>
          )}

          {!existing && (
            <div className="grid gap-2">
              <Label htmlFor="secret-label">Label</Label>
              <Input
                id="secret-label"
                autoComplete="off"
                maxLength={80}
                placeholder={kind === "privateKey" ? "e.g. deploy key" : "e.g. web01 root"}
                value={label}
                onChange={(e) => setLabel(e.currentTarget.value)}
              />
            </div>
          )}

          <div className="grid gap-2">
            <Label htmlFor="secret-value">{existing ? `New ${noun}` : SECRET_KIND_LABEL[kind]}</Label>
            {kind === "privateKey" ? (
              <Textarea
                id="secret-value"
                rows={6}
                spellCheck={false}
                autoComplete="off"
                placeholder="Paste the private key"
                // Masked like a password field, so a pasted key is not on screen (screen sharing).
                className="font-mono text-xs [-webkit-text-security:disc]"
                value={value}
                onChange={(e) => setValue(e.currentTarget.value)}
                disabled={!unlocked}
              />
            ) : (
              <Input
                id="secret-value"
                type="password"
                autoComplete="new-password"
                value={value}
                onChange={(e) => setValue(e.currentTarget.value)}
                disabled={!unlocked}
              />
            )}
            {kind === "privateKey" && !existing && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="justify-self-start"
                disabled={!unlocked || busy}
                onClick={() => void fromFile()}
              >
                <FileKeyIcon data-icon="inline-start" />
                Load from a file…
              </Button>
            )}
          </div>

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={close} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={!unlocked || !value || (!existing && !label.trim()) || busy}>
              {existing ? "Replace" : "Add to the vault"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
