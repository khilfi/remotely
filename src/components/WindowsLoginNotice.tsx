// SS-04: says plainly when the Windows login (DPAPI) unlocks the vault, and turns it off in one click. New vaults
// have it off: any program running under this Windows account can unwrap a DPAPI copy of the vault key, from a copy
// of Remotely's database too, without the vault password. Turning it off needs no password (it only removes a way
// in); the core deletes that copy of the key and overwrites it on disk. Shown on the Vault page and in Settings.

import { useState } from "react";
import { toast } from "sonner";
import { ShieldAlertIcon, ShieldCheckIcon } from "lucide-react";
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { HelpTip } from "@/components/HelpTip";
import { api, errorMessage, type VaultInfo } from "@/lib/api";
import { useReadOnlyReason } from "./Presentation";

interface Props {
  vault: VaultInfo;
  onVaultChanged: (info: VaultInfo) => void;
  /** Also say so when it is off (Settings); the Vault page shows the notice only when it is on. */
  showWhenOff?: boolean;
}

export function WindowsLoginNotice({ vault, onVaultChanged, showWhenOff = false }: Props) {
  const [busy, setBusy] = useState(false);
  const readOnly = useReadOnlyReason();

  if (vault.status === "notSetUp") return null;
  if (!vault.windowsLogin) {
    if (!showWhenOff) return null;
    return (
      <Alert>
        <ShieldCheckIcon />
        <AlertTitle>Only the vault password unlocks the vault</AlertTitle>
        <AlertDescription className="flex items-center gap-1">
          A copy of Remotely&apos;s database is useless without the vault password.
          <HelpTip topic="windowsUnlock" />
        </AlertDescription>
      </Alert>
    );
  }

  async function turnOff() {
    setBusy(true);
    try {
      onVaultChanged(await api.vaultTurnOffWindowsLogin());
      toast.success("The Windows login no longer unlocks the vault");
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Alert className="border-amber-500/50">
      <ShieldAlertIcon className="text-amber-600 dark:text-amber-400" />
      <AlertTitle>Your Windows login unlocks this vault</AlertTitle>
      <AlertDescription className="flex items-center gap-1">
        On a shared PC or one you don&apos;t manage, turn it off.
        <HelpTip topic="windowsUnlock" />
      </AlertDescription>
      <AlertAction>
        <Button size="sm" variant="outline" disabled={busy || Boolean(readOnly)} onClick={() => void turnOff()}>
          Turn off
        </Button>
      </AlertAction>
    </Alert>
  );
}
