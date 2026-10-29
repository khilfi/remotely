// Vault (SS-04, AP-06): set it up, unlock and lock it, change the vault password, choose whether the
// Windows login unlocks it, and add, replace, rename or delete secrets. Values are write-only: this page
// only ever holds labels, kinds and IDs. SS-09's SSH keys live here too (public keys only). UX-08: Known hosts (SS-05)
// is the page's second tab.

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  EllipsisIcon,
  KeyRoundIcon,
  LockIcon,
  LockOpenIcon,
  PlusIcon,
  ShieldCheckIcon,
  type LucideIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SECRET_KIND_LABEL } from "@/components/Badges";
import { PageHeader } from "@/components/PageHeader";
import { KnownHostsPage } from "@/pages/KnownHostsPage";
import { HelpTip } from "@/components/HelpTip";
import type { VaultTab } from "@/lib/navigation";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { NameDialog } from "@/components/NameDialog";
import { NewPasswordField } from "@/components/NewPasswordField";
import { SecretDialog } from "@/components/SecretDialog";
import { SshKeysCard } from "@/components/SshKeysCard";
import { VaultUnlock } from "@/components/VaultUnlock";
import { WindowsLoginNotice } from "@/components/WindowsLoginNotice";
import { api, errorMessage, type SecretKind, type SecretMeta, type SubmitOutcome, type VaultInfo } from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";
import { usePasswordStrength } from "@/hooks/use-password-strength";

/** The vault password's minimum length, as the core checks it (with how hard it is to guess). */
const MIN_PASSWORD = 10;

interface Props {
  vault: VaultInfo | null;
  onVaultChanged: (info: VaultInfo) => void;
  /** True while the page is shown, so the list is read again when the user comes back. */
  active: boolean;
  /** UX-08: Secrets, or Known hosts (a page of its own until 0.6.0). App keeps the tab, so links can open either. */
  tab: VaultTab;
  onTabChange: (tab: VaultTab) => void;
  /** SS-09: a key push goes through the app, which opens the approval dialog. */
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenSessions: () => void;
}

type DialogState =
  | { kind: "add"; secretKind: SecretKind }
  | { kind: "replace"; secret: SecretMeta }
  | { kind: "rename"; secret: SecretMeta }
  | { kind: "delete"; secret: SecretMeta }
  | { kind: "windowsLogin"; enable: boolean }
  | null;

const ADD: { kind: SecretKind; label: string }[] = [
  { kind: "password", label: "Password" },
  { kind: "privateKey", label: "Private key" },
  { kind: "passphrase", label: "Key passphrase" },
];

/** The page: its header with the Secrets and Known hosts tabs. Both stay mounted, as pages do while hidden. */
export function VaultPage({ tab, onTabChange, active, ...props }: Props) {
  return (
    <Tabs value={tab} onValueChange={(v) => onTabChange(v as VaultTab)} className="gap-4">
      <PageHeader
        page="vault"
        tabs={
          <TabsList>
            <TabsTrigger value="secrets">
              <KeyRoundIcon />
              Secrets
            </TabsTrigger>
            <TabsTrigger value="knownHosts">
              <ShieldCheckIcon />
              Known hosts
            </TabsTrigger>
          </TabsList>
        }
      />
      <TabsContent value="secrets" forceMount className="data-[state=inactive]:hidden">
        <VaultSecrets {...props} active={active && tab === "secrets"} />
      </TabsContent>
      <TabsContent value="knownHosts" forceMount className="data-[state=inactive]:hidden">
        <KnownHostsPage active={active && tab === "knownHosts"} />
      </TabsContent>
    </Tabs>
  );
}

function VaultSecrets({
  vault,
  onVaultChanged,
  active,
  onSubmitted,
  onOpenSessions,
}: Omit<Props, "tab" | "onTabChange">) {
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [listVersion, setListVersion] = useState(0);
  const [dialog, setDialog] = useState<DialogState>(null);

  const reload = useCallback(() => setListVersion((v) => v + 1), []);

  useEffect(() => {
    if (!active || !vault || vault.status === "notSetUp") return;
    api.secrets().then(setSecrets, (err) => toast.error(errorMessage(err)));
  }, [active, vault, listVersion]);

  if (!vault) return null;

  if (vault.status === "notSetUp") {
    return (
      <div className="max-w-3xl">
        <SetupCard vault={vault} onDone={onVaultChanged} />
      </div>
    );
  }

  const unlocked = vault.status === "unlocked";

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <WindowsLoginNotice vault={vault} onVaultChanged={onVaultChanged} />
      <StatusCard vault={vault} onVaultChanged={onVaultChanged} />

      <Card>
        <CardHeader>
          <CardTitle>Secrets</CardTitle>
          <CardDescription>
            Passwords, private keys and passphrases that sessions log in with. Each is encrypted with AES-256-GCM;
            values can be replaced but never shown.
          </CardDescription>
          <CardAction>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button disabled={!unlocked}>
                  <PlusIcon data-icon="inline-start" />
                  Add
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {ADD.map((a) => (
                  <DropdownMenuItem key={a.kind} onSelect={() => setDialog({ kind: "add", secretKind: a.kind })}>
                    {a.label}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          </CardAction>
        </CardHeader>
        <CardContent>
          {secrets.length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <KeyRoundIcon />
                </EmptyMedia>
                <EmptyTitle>No secrets yet</EmptyTitle>
                <EmptyDescription>
                  Add them here, or from the session editor when you choose how a session logs in.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Label</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>Used by</TableHead>
                    <TableHead>Changed</TableHead>
                    <TableHead className="w-10">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {secrets.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="font-medium">{s.label}</TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="font-normal">
                          {SECRET_KIND_LABEL[s.kind]}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {s.usedBy > 0 ? plural(s.usedBy, "session") : "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{formatWhen(s.updatedAt)}</TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${s.label}`}>
                              <EllipsisIcon />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              disabled={!unlocked}
                              onSelect={() => setDialog({ kind: "replace", secret: s })}
                            >
                              Replace the value…
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              disabled={!unlocked}
                              onSelect={() => setDialog({ kind: "rename", secret: s })}
                            >
                              Rename…
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              disabled={!unlocked}
                              onSelect={() => setDialog({ kind: "delete", secret: s })}
                            >
                              Delete…
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {!unlocked && secrets.length > 0 && (
            <p className="mt-3 text-sm text-muted-foreground">Unlock the vault to add, replace or delete secrets.</p>
          )}
        </CardContent>
      </Card>

      <SshKeysCard
        vault={vault}
        active={active}
        version={listVersion}
        onSubmit={onSubmitted}
        onOpenSessions={onOpenSessions}
      />

      <PasswordCard
        vault={vault}
        onVaultChanged={onVaultChanged}
        onWindowsLogin={(enable) => {
          // SS-04: turning it off removes a way in, so it needs no password; turning it on does.
          if (enable) setDialog({ kind: "windowsLogin", enable });
          else
            api.vaultTurnOffWindowsLogin().then(
              (info) => {
                onVaultChanged(info);
                toast.success("The Windows login no longer unlocks the vault");
              },
              (err) => toast.error(errorMessage(err)),
            );
        }}
      />

      {(dialog?.kind === "add" || dialog?.kind === "replace") && (
        <SecretDialog
          vault={vault}
          kind={dialog.kind === "add" ? dialog.secretKind : dialog.secret.kind}
          existing={dialog.kind === "replace" ? dialog.secret : undefined}
          onVaultChanged={onVaultChanged}
          onSaved={(meta) => {
            toast.success(dialog.kind === "add" ? `Added '${meta.label}' to the vault` : `Replaced '${meta.label}'`);
            reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "rename" && (
        <NameDialog
          title={`Rename '${dialog.secret.label}'`}
          description="Sessions keep using it under the new label."
          label="Label"
          submitLabel="Rename"
          initial={dialog.secret.label}
          maxLength={80}
          onSubmit={async (label) => {
            await api.renameSecret(dialog.secret.id, label);
            reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDialog
          title={`Delete '${dialog.secret.label}'?`}
          description={
            dialog.secret.usedBy > 0
              ? `${plural(dialog.secret.usedBy, "session")} log in with it and will have no ${SECRET_KIND_LABEL[dialog.secret.kind].toLowerCase()} afterwards. The value can't be recovered.`
              : "The value can't be recovered."
          }
          confirmLabel="Delete"
          onConfirm={async () => {
            await api.deleteSecret(dialog.secret.id);
            reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "windowsLogin" && (
        <ConfirmPasswordDialog
          title={dialog.enable ? "Unlock with the Windows login" : "Stop unlocking with the Windows login"}
          description={
            dialog.enable
              ? "Anyone signed in to this Windows account can then unlock the vault with one click, and so can any program running under it, even from a copy of Remotely's database, without the vault password. Critical actions still ask for the vault password. Leave it off on a shared PC or one you don't manage."
              : "Only the vault password will unlock the vault."
          }
          submitLabel={dialog.enable ? "Turn on" : "Turn off"}
          onSubmit={async (password) => onVaultChanged(await api.vaultSetWindowsLogin(password, dialog.enable))}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

/** SS-04: the vault's setup form; QL-23's first-run wizard shows it too. */
export function SetupCard({ vault, onDone }: { vault: VaultInfo; onDone: (info: VaultInfo) => void }) {
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  // SS-04: off unless the user turns it on (the trade-off is spelt out next to the switch).
  const [windowsLogin, setWindowsLogin] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const strength = usePasswordStrength(password);
  const weak = !strength?.acceptable;
  const mismatch = repeat.length > 0 && repeat !== password;

  async function setup() {
    setBusy(true);
    setError(null);
    try {
      const info = await api.vaultSetup(password, windowsLogin);
      setPassword("");
      setRepeat("");
      toast.success("The vault is set up and unlocked");
      onDone(info);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <form
        className="contents"
        onSubmit={(e) => {
          e.preventDefault();
          if (!weak && !mismatch && password && repeat) void setup();
        }}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4" aria-hidden />
            Set up the vault
          </CardTitle>
          <CardDescription>
            The vault keeps the passwords, private keys and passphrases your sessions log in with, encrypted on this PC.
            Choose a vault password: it unlocks the vault, and Critical actions, such as a hard power-off, ask for it
            again, as does sending a vault password to a host that doesn&apos;t get it yet.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <NewPasswordField
            id="vault-new-password"
            label="Vault password"
            className="max-w-sm"
            value={password}
            onChange={setPassword}
            onGenerated={setRepeat}
            strength={strength}
            description={`At least ${MIN_PASSWORD} characters and hard to guess. A few unrelated words make a good one. There is no way to recover it.`}
          />
          <div className="grid gap-2">
            <Label htmlFor="vault-repeat-password">Type it again</Label>
            <Input
              id="vault-repeat-password"
              type="password"
              autoComplete="new-password"
              className="max-w-sm"
              value={repeat}
              onChange={(e) => setRepeat(e.currentTarget.value)}
              aria-invalid={mismatch || undefined}
            />
            {mismatch && <p className="text-sm text-destructive">The two passwords differ.</p>}
          </div>
          <div className="flex items-start gap-3">
            <Switch
              id="vault-windows-login"
              checked={windowsLogin}
              onCheckedChange={setWindowsLogin}
              disabled={!vault.windowsLoginAvailable}
            />
            <div className="grid gap-1">
              <Label htmlFor="vault-windows-login">Also unlock with my Windows login</Label>
              <p className="text-sm text-muted-foreground">
                {vault.windowsLoginAvailable
                  ? "Off by default. One click would then unlock the vault while you are signed in to Windows (DPAPI), but so could any program running under your Windows account, even from a copy of Remotely's database, without the vault password. Turn it on only on a PC that is yours alone."
                  : "Not available on this PC; the vault password unlocks it."}
              </p>
            </div>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </CardContent>
        <CardFooter>
          <Button type="submit" disabled={!password || !repeat || weak || mismatch || busy}>
            Set up the vault
          </Button>
        </CardFooter>
      </form>
    </Card>
  );
}

function StatusCard({ vault, onVaultChanged }: { vault: VaultInfo; onVaultChanged: (info: VaultInfo) => void }) {
  const unlocked = vault.status === "unlocked";
  const Icon: LucideIcon = unlocked ? LockOpenIcon : LockIcon;

  async function lock() {
    try {
      onVaultChanged(await api.vaultLock());
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Icon className={unlocked ? "size-4 text-success" : "size-4"} aria-hidden />
          {unlocked ? "Unlocked" : "Locked"}
        </CardTitle>
        <CardDescription>
          {unlocked
            ? `Locks itself after ${vault.idleLockMinutes} minutes without you typing or clicking in Remotely (background reads don't count), and whenever you lock it.`
            : vault.windowsLogin
              ? "Unlock it with your Windows login or the vault password."
              : "Unlock it with the vault password."}
        </CardDescription>
        {unlocked && (
          <CardAction>
            <Button variant="outline" onClick={() => void lock()}>
              <LockIcon data-icon="inline-start" />
              Lock now
            </Button>
          </CardAction>
        )}
      </CardHeader>
      {!unlocked && (
        <CardContent>
          <VaultUnlock info={vault} onUnlocked={onVaultChanged} />
        </CardContent>
      )}
    </Card>
  );
}

function PasswordCard({
  vault,
  onVaultChanged,
  onWindowsLogin,
}: {
  vault: VaultInfo;
  onVaultChanged: (info: VaultInfo) => void;
  onWindowsLogin: (enable: boolean) => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const strength = usePasswordStrength(next);
  const weak = !strength?.acceptable;
  const mismatch = repeat.length > 0 && repeat !== next;

  async function change() {
    setBusy(true);
    setMessage(null);
    try {
      onVaultChanged(await api.vaultChangePassword(current, next));
      setNext("");
      setRepeat("");
      setMessage({ ok: true, text: "The vault password is changed. Critical actions ask for the new one." });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err) });
    } finally {
      setCurrent("");
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Vault password
          <HelpTip topic="vaultReauth" />
        </CardTitle>
        <CardDescription>
          Changing it needs the current one, so nobody can replace it from an unlocked PC.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <form
          className="grid max-w-sm gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (current && next && !weak && !mismatch && repeat) void change();
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor="vault-current">Current password</Label>
            <Input
              id="vault-current"
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.currentTarget.value)}
            />
          </div>
          <NewPasswordField
            id="vault-next"
            label="New password"
            value={next}
            onChange={setNext}
            onGenerated={setRepeat}
            strength={strength}
            description={`At least ${MIN_PASSWORD} characters and hard to guess.`}
          />
          <div className="grid gap-2">
            <Label htmlFor="vault-next-repeat">Type it again</Label>
            <Input
              id="vault-next-repeat"
              type="password"
              autoComplete="new-password"
              value={repeat}
              onChange={(e) => setRepeat(e.currentTarget.value)}
              aria-invalid={mismatch || undefined}
            />
            {mismatch && <p className="text-sm text-destructive">The two passwords differ.</p>}
          </div>
          <Button
            type="submit"
            variant="outline"
            className="justify-self-start"
            disabled={!current || !next || !repeat || weak || mismatch || busy}
          >
            Change the password
          </Button>
          {message && (
            <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
              {message.text}
            </p>
          )}
        </form>
        <div className="flex items-start gap-3 border-t pt-4">
          <Switch
            id="vault-windows-login-toggle"
            checked={vault.windowsLogin}
            onCheckedChange={(enable) => onWindowsLogin(enable)}
            disabled={!vault.windowsLoginAvailable && !vault.windowsLogin}
          />
          <div className="grid gap-1">
            <Label htmlFor="vault-windows-login-toggle">Unlock with my Windows login</Label>
            <p className="text-sm text-muted-foreground">
              {vault.windowsLoginAvailable
                ? "One click unlocks the vault while you are signed in to this Windows account, and any program running under it could too, without the vault password. Turning it on asks for the vault password; turning it off doesn't."
                : "Not available on this PC."}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/** Asks for the vault password to confirm a change to the vault itself. */
function ConfirmPasswordDialog({
  title,
  description,
  submitLabel,
  onSubmit,
  onClose,
}: {
  title: string;
  description: string;
  submitLabel: string;
  onSubmit: (password: string) => Promise<void>;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(password);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPassword("");
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (password) void submit();
          }}
        >
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="confirm-vault-password">Vault password</Label>
            <Input
              id="confirm-vault-password"
              type="password"
              autoComplete="off"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={!password || busy}>
              {submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
