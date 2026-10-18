// Unlocks the vault (SS-04): one click with the Windows login when that is on, or the vault password.
// The password field is cleared after every try; the value goes to the core and nowhere else.

import { useState } from "react";
import { MonitorIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api, errorMessage, type VaultInfo } from "@/lib/api";

interface Props {
  info: VaultInfo;
  onUnlocked: (info: VaultInfo) => void;
  /** Distinguishes the password field when two of these are on screen. */
  idPrefix?: string;
}

export function VaultUnlock({ info, onUnlocked, idPrefix = "vault-unlock" }: Props) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function unlock(withPassword: boolean) {
    setBusy(true);
    setError(null);
    try {
      onUnlocked(await api.vaultUnlock(withPassword ? password : undefined));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-3">
      {info.windowsLogin && (
        <Button className="justify-self-start" onClick={() => void unlock(false)} disabled={busy}>
          <MonitorIcon data-icon="inline-start" />
          Unlock with my Windows login
        </Button>
      )}
      <form
        className="grid gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (password) void unlock(true);
        }}
      >
        <Label htmlFor={`${idPrefix}-password`}>
          {info.windowsLogin ? "Or with the vault password" : "Vault password"}
        </Label>
        <div className="flex max-w-md gap-2">
          <Input
            id={`${idPrefix}-password`}
            type="password"
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <Button type="submit" variant={info.windowsLogin ? "outline" : "default"} disabled={!password || busy}>
            Unlock
          </Button>
        </div>
      </form>
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
