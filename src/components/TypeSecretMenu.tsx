// QL-06 "Type vault password": picks a password or passphrase from the vault and has the core type it into the
// current terminal, then Enter, for a sudo, su or key prompt. Only labels come here; the value goes from the vault to
// the shell without the clipboard or the UI. At a shell prompt the core holds it back (it would run as a command and
// stay in the history) unless the user confirms. Each use is audited with the label, never the value.

import { useState } from "react";
import { toast } from "sonner";
import { KeyRoundIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api, errorCode, errorMessage, type SecretMeta } from "@/lib/api";
import type { PaneSession } from "@/lib/terminal-session";

interface Props {
  pane: PaneSession | undefined;
  /** The secret the pane's session logs in with, listed first. */
  loginSecretId: string | null;
  terminalName: string;
  onOpenVault: () => void;
}

export function TypeSecretMenu({ pane, loginSecretId, terminalName, onOpenVault }: Props) {
  const [secrets, setSecrets] = useState<SecretMeta[] | null>(null);
  const [asking, setAsking] = useState<SecretMeta | null>(null);

  function load(open: boolean) {
    if (!open) return;
    api.secrets().then(
      (all) =>
        setSecrets(
          all
            .filter((s) => s.kind === "password" || s.kind === "passphrase")
            .sort((a, b) => Number(b.id === loginSecretId) - Number(a.id === loginSecretId)),
        ),
      (err) => {
        setSecrets([]);
        toast.error(errorMessage(err));
      },
    );
  }

  async function type(secret: SecretMeta, force: boolean) {
    if (!pane) return;
    try {
      await pane.typeSecret(secret.id, force);
      toast.success(`Typed '${secret.label}' into ${terminalName}`);
    } catch (err) {
      const code = errorCode(err);
      if (code === "no_password_prompt") setAsking(secret);
      else if (code === "vault_locked")
        toast.error("The vault is locked, so nothing was typed.", {
          action: { label: "Open the vault", onClick: onOpenVault },
        });
      else toast.error(`Typing the password failed: ${errorMessage(err)}`);
    }
  }

  const disabled = !pane?.terminalId;
  return (
    <>
      <DropdownMenu onOpenChange={load}>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-sm" aria-label="Type a vault password" disabled={disabled}>
                <KeyRoundIcon />
              </Button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent>Type a vault password at a sudo or su prompt</TooltipContent>
        </Tooltip>
        <DropdownMenuContent align="end" className="w-72">
          <DropdownMenuLabel className="font-normal text-muted-foreground">
            Typed into {terminalName}, then Enter. Never shown or copied.
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          {secrets === null ? (
            <DropdownMenuItem disabled>Loading…</DropdownMenuItem>
          ) : secrets.length === 0 ? (
            <DropdownMenuItem onSelect={onOpenVault}>No passwords in the vault. Open the vault…</DropdownMenuItem>
          ) : (
            secrets.map((s) => (
              <DropdownMenuItem key={s.id} onSelect={() => void type(s, false)}>
                <KeyRoundIcon />
                <span className="min-w-0 flex-1 truncate">{s.label}</span>
                {s.id === loginSecretId ? (
                  <span className="text-xs text-muted-foreground">this login</span>
                ) : (
                  s.kind === "passphrase" && <span className="text-xs text-muted-foreground">passphrase</span>
                )}
              </DropdownMenuItem>
            ))
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <AlertDialog open={asking !== null} onOpenChange={(open) => !open && setAsking(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>No password prompt is showing</AlertDialogTitle>
            <AlertDialogDescription>
              The last line in {terminalName} doesn&apos;t ask for a password. At a shell prompt, &apos;{asking?.label}
              &apos; would run as a command, show on screen and stay in the shell&apos;s history. Type it only if the
              terminal is waiting for a password Remotely doesn&apos;t recognise.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                const secret = asking;
                setAsking(null);
                if (secret) void type(secret, true);
              }}
            >
              Type it anyway
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
