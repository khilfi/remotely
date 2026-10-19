// FD-07: export the session library to one encrypted file, to import it on another laptop. The core asks
// where to save (Documents by default, never a Git repository), encrypts the file with the passphrase
// typed here (Argon2id, AES-256-GCM) and audits the export. Vault secrets go along only when ticked, and
// that needs the vault password. Passphrase and password are sent once, then cleared.

import { useState } from "react";
import { FileLockIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { api, errorMessage, type ExportReport, type VaultInfo } from "@/lib/api";
import { plural } from "@/lib/format";
import { VaultUnlock } from "./VaultUnlock";

/** The passphrase's minimum length, as the core checks it. */
const MIN_PASSPHRASE = 10;

interface Props {
  sessions: number;
  folders: number;
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  onExported: (report: ExportReport) => void;
  onClose: () => void;
}

export function ExportDialog({ sessions, folders, vault, onVaultChanged, onExported, onClose }: Props) {
  const [knownHosts, setKnownHosts] = useState(true);
  const [secrets, setSecrets] = useState(false);
  const [vaultPassword, setVaultPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const unlocked = vault?.status === "unlocked";
  const tooShort = passphrase.length > 0 && passphrase.length < MIN_PASSPHRASE;
  const mismatch = repeat.length > 0 && repeat !== passphrase;
  const ready =
    passphrase.length >= MIN_PASSPHRASE && repeat === passphrase && (!secrets || (unlocked && vaultPassword !== ""));

  async function exportFile() {
    setBusy(true);
    setError(null);
    try {
      const report = await api.transferExport({
        passphrase,
        includeKnownHosts: knownHosts,
        includeSecrets: secrets,
        vaultPassword: secrets ? vaultPassword : null,
      });
      if (report) {
        setPassphrase("");
        setRepeat("");
        onExported(report);
        onClose();
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setVaultPassword("");
      setBusy(false);
    }
  }

  function close() {
    setPassphrase("");
    setRepeat("");
    setVaultPassword("");
    onClose();
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && close()}>
      <DialogContent className="sm:max-w-lg">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready && !busy) void exportFile();
          }}
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileLockIcon className="size-4" aria-hidden />
              Export to another laptop
            </DialogTitle>
            <DialogDescription>
              Writes {plural(sessions, "session")} and {plural(folders, "folder")}, with their tags, labels and colours,
              and your favourite commands to one encrypted file. Import it on the other laptop with the passphrase you
              choose here.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-3">
            <div className="flex items-start gap-3">
              <Checkbox
                id="export-known-hosts"
                checked={knownHosts}
                onCheckedChange={(v) => setKnownHosts(v === true)}
              />
              <div className="grid gap-1">
                <Label htmlFor="export-known-hosts">Trusted host keys</Label>
                <p className="text-sm text-muted-foreground">
                  So the other laptop doesn&apos;t ask about each host again.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <Checkbox
                id="export-secrets"
                checked={secrets}
                onCheckedChange={(v) => setSecrets(v === true)}
                disabled={vault?.status === "notSetUp"}
              />
              <div className="grid gap-1">
                <Label htmlFor="export-secrets">Vault secrets (passwords, keys, passphrases)</Label>
                <p className="text-sm text-muted-foreground">
                  Without them, sessions on the other laptop use the secrets with the same labels in its vault, or ask
                  when connecting.
                </p>
              </div>
            </div>
          </div>

          {secrets && !unlocked && vault && (
            <div className="grid gap-2 rounded-lg border p-3">
              <p className="text-sm font-medium">Unlock the vault to export its secrets</p>
              <VaultUnlock info={vault} onUnlocked={onVaultChanged} idPrefix="export-unlock" />
            </div>
          )}
          {secrets && unlocked && (
            <>
              <Alert>
                <TriangleAlertIcon />
                <AlertTitle>Anyone with the file and its passphrase gets these secrets</AlertTitle>
                <AlertDescription>
                  Keep the file somewhere private and delete it once it is imported. The vault password confirms that it
                  is you exporting them.
                </AlertDescription>
              </Alert>
              <div className="grid gap-2">
                <Label htmlFor="export-vault-password">Vault password</Label>
                <Input
                  id="export-vault-password"
                  type="password"
                  autoComplete="off"
                  value={vaultPassword}
                  onChange={(e) => setVaultPassword(e.currentTarget.value)}
                />
              </div>
            </>
          )}

          <div className="grid gap-2">
            <Label htmlFor="export-passphrase">Passphrase for the file</Label>
            <Input
              id="export-passphrase"
              type="password"
              autoComplete="new-password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.currentTarget.value)}
              aria-invalid={tooShort || undefined}
            />
            <p className={tooShort ? "text-sm text-destructive" : "text-sm text-muted-foreground"}>
              At least {MIN_PASSPHRASE} characters; a few unrelated words make a good one. It can&apos;t be recovered.
            </p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="export-repeat">Type it again</Label>
            <Input
              id="export-repeat"
              type="password"
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => setRepeat(e.currentTarget.value)}
              aria-invalid={mismatch || undefined}
            />
            {mismatch && <p className="text-sm text-destructive">The two passphrases differ.</p>}
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
            <Button type="submit" disabled={!ready || busy}>
              {busy ? "Exporting…" : "Choose where to save…"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
