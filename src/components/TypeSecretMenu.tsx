// QL-06 "Type a vault password": picks a password or passphrase from the vault and has the core type it into the
// current terminal, then Enter, for a sudo, su or key prompt. Only labels come here; the value goes from the vault to
// the shell without the clipboard or the UI. At a shell prompt the core holds it back (it would run as a command and
// stay in the history) unless the user confirms. Each use is audited with the label, never the value.
// SS-04, AP-06: a password typed where no saved session sends it yet, or typed anyway with no prompt showing, asks
// for the vault password first (the shared ReauthDialog); for a saved session it is then allowed there from now on.
// UX-03: it lives in the Terminal page's "⋯" menu as a submenu; the confirm sits outside the menu, which closes first.

import { useState } from "react";
import { toast } from "sonner";
import { KeyRoundIcon } from "lucide-react";
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
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
} from "@/components/ui/dropdown-menu";
import { ReasonLine } from "@/components/WhyDisabled";
import { api, errorCode, errorMessage, type SecretMeta } from "@/lib/api";
import { connectedReason } from "@/lib/disabled-reasons";
import { isReauthCancelled } from "@/lib/reauth";
import { withVaultPassword } from "@/lib/reauth-prompt";
import type { PaneSession } from "@/lib/terminal-session";

interface Target {
  pane: PaneSession | undefined;
  terminalName: string;
  onOpenVault: () => void;
}

/** Types the secret; at a line that doesn't ask for a password, `onNoPrompt` asks whether to type it anyway. */
async function typeSecret(
  { pane, terminalName, onOpenVault }: Target,
  secret: SecretMeta,
  force: boolean,
  onNoPrompt: (secret: SecretMeta) => void,
) {
  if (!pane) return;
  try {
    await withVaultPassword((password) => pane.typeSecret(secret.id, force, password));
    toast.success(`Typed '${secret.label}' into ${terminalName}`);
  } catch (err) {
    const code = errorCode(err);
    if (isReauthCancelled(err)) toast.info("Nothing was typed.");
    else if (code === "no_password_prompt") onNoPrompt(secret);
    else if (code === "vault_locked")
      toast.error("The vault is locked, so nothing was typed.", {
        action: { label: "Open the vault", onClick: onOpenVault },
      });
    else toast.error(`Typing the password failed: ${errorMessage(err)}`);
  }
}

/**
 * The "⋯" menu's "Type a vault password" submenu, and the confirm for a terminal that shows no password prompt. Render
 * `menu` inside the menu and `confirm` outside it.
 */
export function useTypeSecret({
  pane,
  loginSecretId,
  terminalName,
  onOpenVault,
}: Target & {
  /** The secret the pane's session logs in with, listed first. */
  loginSecretId: string | null;
}) {
  const [secrets, setSecrets] = useState<SecretMeta[] | null>(null);
  const [asking, setAsking] = useState<SecretMeta | null>(null);
  const target = { pane, terminalName, onOpenVault };

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

  // QL-08: a disabled item says why.
  const disabled = connectedReason({ open: Boolean(pane), connected: Boolean(pane?.terminalId) });
  const menu = disabled ? (
    <DropdownMenuItem disabled>
      <KeyRoundIcon />
      <span>
        Type a vault password
        <ReasonLine reason={disabled} />
      </span>
    </DropdownMenuItem>
  ) : (
    <DropdownMenuSub onOpenChange={load}>
      <DropdownMenuSubTrigger>
        <KeyRoundIcon />
        Type a vault password
      </DropdownMenuSubTrigger>
      <DropdownMenuSubContent className="w-72">
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
            <DropdownMenuItem key={s.id} onSelect={() => void typeSecret(target, s, false, setAsking)}>
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
      </DropdownMenuSubContent>
    </DropdownMenuSub>
  );

  const confirm = (
    <AlertDialog open={asking !== null} onOpenChange={(open) => !open && setAsking(null)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>No password prompt is showing</AlertDialogTitle>
          <AlertDialogDescription>
            The last line in {terminalName} doesn&apos;t ask for a password. At a shell prompt, &apos;{asking?.label}
            &apos; would run as a command, show on screen and stay in the shell&apos;s history. Typing it anyway asks
            for the vault password.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            onClick={() => {
              const secret = asking;
              setAsking(null);
              if (secret) void typeSecret(target, secret, true, setAsking);
            }}
          >
            Type it anyway
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );

  return { menu, confirm };
}
