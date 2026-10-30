// Vault (SS-04, AP-06): set it up, unlock and lock it, change the vault password, choose whether the
// Windows login unlocks it, and add, replace, rename or delete secrets. Values are write-only: this page
// only ever holds labels, kinds and IDs. SS-09's SSH keys live here too (public keys only). UX-08: Known hosts (SS-05)
// is the page's second tab.
//
// UX-07: one primary action, "Add", in the header (a secret or a generated SSH key); Lock now, the password change
// and pushing a pasted key are in its "⋯". The vault's state shows once, in the status bar: the page shows it only
// when it is locked, with the unlock form. The Windows-login switch and its warning are in one place, the Unlocking
// card; how secrets are kept (AES-256-GCM, Argon2id) is behind "?".

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ChevronDownIcon,
  KeyRoundIcon,
  KeySquareIcon,
  LockIcon,
  PlusIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UploadIcon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SECRET_KIND_LABEL } from "@/components/Badges";
import { PageHeader } from "@/components/PageHeader";
import { KnownHostsPage } from "@/pages/KnownHostsPage";
import { HelpTip } from "@/components/HelpTip";
import { EmptyState } from "@/components/EmptyState";
import type { VaultTab } from "@/lib/navigation";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { NameDialog } from "@/components/NameDialog";
import { NewPasswordField } from "@/components/NewPasswordField";
import { useReadOnlyReason } from "@/components/Presentation";
import { RowMenu } from "@/components/RowMenu";
import { SecretDialog } from "@/components/SecretDialog";
import { SshKeysCard, type SshKeyRequest } from "@/components/SshKeysCard";
import { VaultUnlock } from "@/components/VaultUnlock";
import { WhyDisabled } from "@/components/WhyDisabled";
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
  | { kind: "password" }
  | null;

const ADD: { kind: SecretKind; label: string }[] = [
  { kind: "password", label: "Password" },
  { kind: "privateKey", label: "Private key" },
  { kind: "passphrase", label: "Key passphrase" },
];

/** What the header asks the Secrets tab to open. */
type Ask = { what: DialogState | SshKeyRequest["kind"]; n: number };

/** The page: its header with the Secrets and Known hosts tabs. Both stay mounted, as pages do while hidden. */
export function VaultPage({ tab, onTabChange, active, ...props }: Props) {
  const { vault, onVaultChanged } = props;
  const readOnly = useReadOnlyReason();
  const [ask, setAsk] = useState<Ask | null>(null);
  const open = (what: Ask["what"]) => setAsk((a) => ({ what, n: (a?.n ?? 0) + 1 }));
  const set = vault !== null && vault.status !== "notSetUp";
  const unlocked = vault?.status === "unlocked";
  const lockedReason = readOnly ?? (unlocked ? null : "Unlock the vault first");

  async function lock() {
    try {
      onVaultChanged(await api.vaultLock());
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const secrets = tab === "secrets" && set;
  return (
    <Tabs value={tab} onValueChange={(v) => onTabChange(v as VaultTab)} className="gap-4">
      <PageHeader
        page="vault"
        primary={
          secrets ? (
            <WhyDisabled reason={lockedReason}>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button disabled={lockedReason !== null}>
                    <PlusIcon data-icon="inline-start" />
                    Add
                    <ChevronDownIcon data-icon="inline-end" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="min-w-52">
                  {ADD.map((a) => (
                    <DropdownMenuItem key={a.kind} onSelect={() => open({ kind: "add", secretKind: a.kind })}>
                      <KeyRoundIcon />
                      {a.label}…
                    </DropdownMenuItem>
                  ))}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => open("generate")}>
                    <KeySquareIcon />
                    Generate an SSH key…
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </WhyDisabled>
          ) : undefined
        }
        tools={
          secrets ? (
            <>
              <DropdownMenuItem disabled={!unlocked} onSelect={() => void lock()}>
                <LockIcon />
                Lock now
              </DropdownMenuItem>
              <DropdownMenuItem disabled={readOnly !== null} onSelect={() => open({ kind: "password" })}>
                <KeyRoundIcon />
                Change the vault password…
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => open("push")}>
                <UploadIcon />
                Push a pasted public key…
              </DropdownMenuItem>
            </>
          ) : undefined
        }
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
        <VaultSecrets {...props} active={active && tab === "secrets"} ask={ask} />
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
  ask,
}: Omit<Props, "tab" | "onTabChange"> & { ask: Ask | null }) {
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [listVersion, setListVersion] = useState(0);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [keyRequest, setKeyRequest] = useState<SshKeyRequest | null>(null);
  const readOnly = useReadOnlyReason();

  // The header's Add and "⋯" menus.
  const [asked, setAsked] = useState(ask?.n ?? 0);
  if (ask && ask.n !== asked) {
    setAsked(ask.n);
    if (ask.what === "generate" || ask.what === "push") setKeyRequest({ kind: ask.what, n: ask.n });
    else setDialog(ask.what);
  }

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
  const lockedReason = readOnly ?? (unlocked ? null : "Unlock the vault first");

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      {!unlocked && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <LockIcon className="size-4" aria-hidden />
              Unlock the vault
            </CardTitle>
            <CardDescription>
              {vault.windowsLogin
                ? "With your Windows login or the vault password."
                : "Sessions that log in with a saved password or key need it."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <VaultUnlock info={vault} onUnlocked={onVaultChanged} />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1">
            Secrets
            <HelpTip topic="vaultEncryption" />
          </CardTitle>
          <CardDescription>What sessions log in with. A value can be replaced but never shown.</CardDescription>
        </CardHeader>
        <CardContent>
          {secrets.length === 0 ? (
            <EmptyState
              icon={KeyRoundIcon}
              title="No secrets yet"
              description="Add them here, or from the session editor when you choose how a session logs in."
              action={
                <WhyDisabled reason={lockedReason}>
                  <Button
                    variant="outline"
                    disabled={lockedReason !== null}
                    onClick={() => setDialog({ kind: "add", secretKind: "password" })}
                  >
                    <PlusIcon data-icon="inline-start" />
                    Add a password
                  </Button>
                </WhyDisabled>
              }
            />
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
                        <RowMenu label={s.label} disabled={lockedReason !== null}>
                          <DropdownMenuItem onSelect={() => setDialog({ kind: "replace", secret: s })}>
                            Replace the value…
                          </DropdownMenuItem>
                          <DropdownMenuItem onSelect={() => setDialog({ kind: "rename", secret: s })}>
                            Rename…
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            variant="destructive"
                            onSelect={() => setDialog({ kind: "delete", secret: s })}
                          >
                            Delete…
                          </DropdownMenuItem>
                        </RowMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <SshKeysCard
        vault={vault}
        active={active}
        version={listVersion}
        request={keyRequest}
        onSubmit={onSubmitted}
        onOpenSessions={onOpenSessions}
      />

      <UnlockingCard
        vault={vault}
        onChangePassword={() => setDialog({ kind: "password" })}
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
          title="Unlock with your Windows login?"
          description="Anyone signed in to this Windows account, and any program running under it, can then unlock the vault without its password. Critical actions still ask for it."
          submitLabel="Turn on"
          onSubmit={async (password) => onVaultChanged(await api.vaultSetWindowsLogin(password, true))}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "password" && (
        <ChangePasswordDialog onVaultChanged={onVaultChanged} onClose={() => setDialog(null)} />
      )}
    </div>
  );
}

/** SS-04: the vault's setup form; QL-23's first-run wizard shows it too. */
export function SetupCard({ vault, onDone }: { vault: VaultInfo; onDone: (info: VaultInfo) => void }) {
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  // SS-04: off unless the user turns it on (the trade-off is behind its "?").
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
          <CardTitle className="flex items-center gap-1">
            <ShieldCheckIcon className="mr-1 size-4" aria-hidden />
            Set up the vault
            <HelpTip topic="vaultEncryption" />
          </CardTitle>
          <CardDescription>
            Passwords and keys your sessions log in with, encrypted on this PC. The vault password unlocks them.
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
            description={`At least ${MIN_PASSWORD} characters. It can't be recovered.`}
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
          <div className="flex items-center gap-3">
            <Switch
              id="vault-windows-login"
              checked={windowsLogin}
              onCheckedChange={setWindowsLogin}
              disabled={!vault.windowsLoginAvailable}
            />
            <Label htmlFor="vault-windows-login">Also unlock with my Windows login</Label>
            <HelpTip topic="windowsUnlock" />
            {!vault.windowsLoginAvailable && (
              <span className="text-sm text-muted-foreground">Not available on this PC</span>
            )}
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

/** SS-04, AP-06: how the vault unlocks and locks, in one place: the Windows login with its warning, the idle lock, and
 * the vault password. */
function UnlockingCard({
  vault,
  onChangePassword,
  onWindowsLogin,
}: {
  vault: VaultInfo;
  onChangePassword: () => void;
  onWindowsLogin: (enable: boolean) => void;
}) {
  const readOnly = useReadOnlyReason();
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1">
          Unlocking
          <HelpTip topic="vaultIdleLock" />
        </CardTitle>
        <CardDescription>
          Locks itself after {vault.idleLockMinutes} minutes without you typing or clicking in Remotely.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid gap-1">
          <div className="flex items-center gap-3">
            <WhyDisabled reason={vault.windowsLogin ? null : readOnly}>
              <Switch
                id="vault-windows-login-toggle"
                checked={vault.windowsLogin}
                onCheckedChange={(enable) => onWindowsLogin(enable)}
                disabled={(!vault.windowsLoginAvailable && !vault.windowsLogin) || (!vault.windowsLogin && !!readOnly)}
              />
            </WhyDisabled>
            <Label htmlFor="vault-windows-login-toggle">Unlock with my Windows login</Label>
            <HelpTip topic="windowsUnlock" />
          </div>
          {vault.windowsLogin ? (
            <p className="flex items-center gap-1.5 pl-12 text-sm text-amber-700 dark:text-amber-400">
              <ShieldAlertIcon className="size-4 shrink-0" aria-hidden />
              On: any program under your Windows account can unlock the vault too.
            </p>
          ) : (
            !vault.windowsLoginAvailable && (
              <p className="pl-12 text-sm text-muted-foreground">Not available on this PC.</p>
            )
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3 border-t pt-4">
          <span className="flex items-center gap-1 text-sm">
            Vault password
            <HelpTip topic="vaultReauth" />
          </span>
          <WhyDisabled reason={readOnly}>
            <Button
              variant="outline"
              size="sm"
              className="ml-auto"
              disabled={readOnly !== null}
              onClick={onChangePassword}
            >
              Change the password…
            </Button>
          </WhyDisabled>
        </div>
      </CardContent>
    </Card>
  );
}

/** SS-04: a new vault password; the current one is asked, so nobody can replace it from an unlocked PC. */
function ChangePasswordDialog({
  onVaultChanged,
  onClose,
}: {
  onVaultChanged: (info: VaultInfo) => void;
  onClose: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const strength = usePasswordStrength(next);
  const weak = !strength?.acceptable;
  const mismatch = repeat.length > 0 && repeat !== next;

  async function change() {
    setBusy(true);
    setError(null);
    try {
      onVaultChanged(await api.vaultChangePassword(current, next));
      setNext("");
      setRepeat("");
      toast.success("The vault password is changed");
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCurrent("");
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
            if (current && next && !weak && !mismatch && repeat) void change();
          }}
        >
          <DialogHeader>
            <DialogTitle>Change the vault password</DialogTitle>
            <DialogDescription>Critical actions ask for the new one from then on.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="vault-current">Current password</Label>
            <Input
              id="vault-current"
              type="password"
              autoComplete="current-password"
              autoFocus
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
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={!current || !next || !repeat || weak || mismatch || busy}>
              Change the password
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
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
