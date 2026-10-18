// Session editor (SS-01, SS-06): where to connect, how to log in (a password or key from the vault, or
// the SSH agent), a jump host, a startup command, folder, tags, colour and environment label. Saving
// changes only the app's own data: the core checks it and audits it, with no approval step. Taking the
// Prod label off asks first, since it lowers the tier of later actions on the session.

import { useEffect, useState } from "react";
import { PlusIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  api,
  errorMessage,
  type Environment,
  type SecretKind,
  type SecretMeta,
  type SessionAuth,
  type SessionColor,
  type SessionFolder,
  type SessionInput,
  type SessionRecord,
  type VaultInfo,
} from "@/lib/api";
import { flattenFolders, folderPath } from "@/lib/folders";
import { cn } from "@/lib/utils";
import { ColorDot, SESSION_COLORS } from "./Badges";
import { ConfirmDialog } from "./ConfirmDialog";
import { SecretDialog } from "./SecretDialog";

/** Radix Select can't hold an empty value, so "none" stands for no choice. */
const NONE = "none";

const ENVIRONMENTS: { value: Environment; label: string; className?: string }[] = [
  { value: "none", label: "None" },
  { value: "lab", label: "Lab", className: "data-[state=on]:text-env-lab" },
  { value: "staging", label: "Staging", className: "data-[state=on]:text-env-staging" },
  { value: "prod", label: "Prod", className: "data-[state=on]:text-env-prod" },
];

type Method = SessionAuth["method"];

interface Props {
  vault: VaultInfo | null;
  /** The session to edit; without it, a new one. */
  session?: SessionRecord;
  /** Where a new session goes. */
  folderId: string | null;
  folders: SessionFolder[];
  /** Candidates for the jump host. */
  sessions: SessionRecord[];
  tagSuggestions: string[];
  onVaultChanged: (info: VaultInfo) => void;
  onSaved: (session: SessionRecord) => void;
  onClose: () => void;
}

function idOf(auth: SessionAuth, which: "credential" | "passphrase"): string | null {
  if (auth.method === "password") return which === "credential" ? auth.passwordId : null;
  if (auth.method === "key") return which === "credential" ? auth.keyId : auth.passphraseId;
  return null;
}

function labelName(env: Environment) {
  return ENVIRONMENTS.find((e) => e.value === env)?.label ?? env;
}

/** What the confirm says before a Prod session loses the label. */
function lowerProdText(name: string, environment: Environment) {
  const change =
    environment === "none" ? "will lose the Prod label" : `will be labelled ${labelName(environment)} instead of Prod`;
  return `'${name}' ${change}. Actions on it will no longer move up one approval tier, so they need fewer approval steps. The change is logged.`;
}

export function SessionDialog({
  vault,
  session,
  folderId,
  folders,
  sessions,
  tagSuggestions,
  onVaultChanged,
  onSaved,
  onClose,
}: Props) {
  const [name, setName] = useState(session?.name ?? "");
  const [folder, setFolder] = useState<string>(session ? (session.folderId ?? NONE) : (folderId ?? NONE));
  const [host, setHost] = useState(session?.host ?? "");
  const [port, setPort] = useState(String(session?.port ?? 22));
  const [username, setUsername] = useState(session?.username ?? "");
  const [method, setMethod] = useState<Method>(session?.auth.method ?? "password");
  const [password, setPassword] = useState(session ? (idOf(session.auth, "credential") ?? NONE) : NONE);
  const [key, setKey] = useState(session?.auth.method === "key" ? (session.auth.keyId ?? NONE) : NONE);
  const [passphrase, setPassphrase] = useState(session ? (idOf(session.auth, "passphrase") ?? NONE) : NONE);
  const [jump, setJump] = useState(session?.jumpSessionId ?? NONE);
  const [startup, setStartup] = useState(session?.startupCommand ?? "");
  const [environment, setEnvironment] = useState<Environment>(session?.environment ?? "none");
  const [color, setColor] = useState<SessionColor | null>(session?.color ?? null);
  const [tags, setTags] = useState((session?.tags ?? []).join(", "));
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [adding, setAdding] = useState<SecretKind | null>(null);
  /** Taking the Prod label off lowers the tier of later actions on the session, so saving asks first. */
  const [lowerProd, setLowerProd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.secrets().then(setSecrets, () => setSecrets([]));
  }, []);

  const of = (kind: SecretKind) => secrets.filter((s) => s.kind === kind);
  const portNumber = Number(port);
  const portOk = Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535;
  const tagList = tags
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const jumpChoices = sessions.filter((s) => s.id !== session?.id);
  const vaultReady = vault !== null && vault.status !== "notSetUp";

  function auth(): SessionAuth {
    const pick = (v: string) => (v === NONE ? null : v);
    if (method === "password") return { method, passwordId: pick(password) };
    if (method === "key") return { method, keyId: pick(key), passphraseId: pick(key) ? pick(passphrase) : null };
    return { method: "agent" };
  }

  /** Throws, so the Prod confirm can show the error. */
  async function persist() {
    const input: SessionInput = {
      name,
      folderId: folder === NONE ? null : folder,
      host,
      port: portNumber,
      username: username.trim() || null,
      auth: auth(),
      jumpSessionId: jump === NONE ? null : jump,
      startupCommand: startup.trim() || null,
      environment,
      color,
      tags: tagList,
    };
    onSaved(session ? await api.updateSession(session.id, input) : await api.createSession(input));
    onClose();
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await persist();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  /** SS-06: saves at once, unless the edit takes the Prod label off. */
  function submit() {
    if (session?.environment === "prod" && environment !== "prod") {
      setLowerProd(true);
      return;
    }
    void save();
  }

  function secretPicker(kind: SecretKind, value: string, onChange: (v: string) => void, noneLabel: string) {
    const id = `session-${kind}`;
    return (
      <div className="flex gap-2">
        <Select value={value} onValueChange={onChange}>
          <SelectTrigger id={id} className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NONE}>{noneLabel}</SelectItem>
            {of(kind).length > 0 && <SelectSeparator />}
            {of(kind).map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.label}
              </SelectItem>
            ))}
            {value !== NONE && !secrets.some((s) => s.id === value) && (
              <SelectItem value={value} disabled>
                Not in the vault any more
              </SelectItem>
            )}
          </SelectContent>
        </Select>
        <Button
          type="button"
          variant="outline"
          onClick={() => setAdding(kind)}
          disabled={!vaultReady}
          title={vaultReady ? undefined : "Set up the vault on the Vault page first"}
        >
          <PlusIcon data-icon="inline-start" />
          New
        </Button>
      </div>
    );
  }

  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (host.trim() && portOk) submit();
            }}
          >
            <DialogHeader>
              <DialogTitle>{session ? `Edit '${session.name}'` : "New session"}</DialogTitle>
              <DialogDescription>
                Connect opens it in a terminal tab. Passwords and keys stay in the vault: the session points to them,
                and a password left out is asked in the terminal.
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
              <div className="grid gap-2">
                <Label htmlFor="session-host">Host</Label>
                <Input
                  id="session-host"
                  autoFocus={!session}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="web01.example.com or 192.0.2.10"
                  className="font-mono"
                  value={host}
                  onChange={(e) => setHost(e.currentTarget.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="session-port">Port</Label>
                <Input
                  id="session-port"
                  inputMode="numeric"
                  value={port}
                  onChange={(e) => setPort(e.currentTarget.value)}
                  aria-invalid={!portOk || undefined}
                />
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="session-user">User</Label>
                <Input
                  id="session-user"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="alice"
                  value={username}
                  onChange={(e) => setUsername(e.currentTarget.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="session-name">Name</Label>
                <Input
                  id="session-name"
                  autoComplete="off"
                  maxLength={100}
                  placeholder={host.trim() || "The host, if left empty"}
                  value={name}
                  onChange={(e) => setName(e.currentTarget.value)}
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label>Log in with</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                className="justify-self-start"
                value={method}
                onValueChange={(v) => v && setMethod(v as Method)}
              >
                <ToggleGroupItem value="password">Password</ToggleGroupItem>
                <ToggleGroupItem value="key">Private key</ToggleGroupItem>
                <ToggleGroupItem value="agent">SSH agent</ToggleGroupItem>
              </ToggleGroup>
              {method === "password" && (
                <div className="grid gap-2">
                  <Label htmlFor="session-password" className="font-normal text-muted-foreground">
                    Password from the vault
                  </Label>
                  {secretPicker("password", password, setPassword, "None: ask when connecting")}
                </div>
              )}
              {method === "key" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="grid gap-2">
                    <Label htmlFor="session-privateKey" className="font-normal text-muted-foreground">
                      Private key from the vault
                    </Label>
                    {secretPicker("privateKey", key, setKey, "None chosen")}
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="session-passphrase" className="font-normal text-muted-foreground">
                      Its passphrase
                    </Label>
                    {secretPicker("passphrase", passphrase, setPassphrase, "None: the key is not encrypted")}
                  </div>
                </div>
              )}
              {method === "agent" && (
                <p className="text-sm text-muted-foreground">
                  Uses the keys loaded in a running OpenSSH agent or Pageant. Nothing is stored here.
                </p>
              )}
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="session-jump">Jump host</Label>
                <Select value={jump} onValueChange={setJump}>
                  <SelectTrigger id="session-jump" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>None: connect directly</SelectItem>
                    {jumpChoices.length > 0 && <SelectSeparator />}
                    {jumpChoices.map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {jump !== NONE && (
                  <p className="text-xs text-muted-foreground">
                    Saved for later: connecting through a jump host arrives in a later version (SS-07). Until then
                    Remotely won't connect this session.
                  </p>
                )}
              </div>
              <div className="grid gap-2">
                <Label htmlFor="session-folder">Folder</Label>
                <Select value={folder} onValueChange={setFolder}>
                  <SelectTrigger id="session-folder" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value={NONE}>Top level</SelectItem>
                    {folders.length > 0 && <SelectSeparator />}
                    {flattenFolders(folders).map(({ folder: f }) => (
                      <SelectItem key={f.id} value={f.id}>
                        {folderPath(folders, f.id)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="session-startup">Startup command</Label>
              <Textarea
                id="session-startup"
                rows={2}
                spellCheck={false}
                className="font-mono text-xs"
                placeholder="Runs after login, e.g. cd /srv/app"
                value={startup}
                onChange={(e) => setStartup(e.currentTarget.value)}
              />
              <p className="text-xs text-muted-foreground">
                Kept in the session, not the vault: don&apos;t put passwords here.
              </p>
            </div>

            <div className="grid gap-2">
              <Label>Environment</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                className="justify-self-start"
                value={environment}
                onValueChange={(v) => v && setEnvironment(v as Environment)}
              >
                {ENVIRONMENTS.map((e) => (
                  <ToggleGroupItem key={e.value} value={e.value} className={cn("font-medium", e.className)}>
                    {e.label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
              <p className="text-xs text-muted-foreground">
                {environment === "prod"
                  ? "Prod raises the approval tier of every action on this session by one."
                  : "Shown on the session's tab. Prod raises the approval tier of actions on it."}
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-2">
                <Label>Colour</Label>
                <ToggleGroup
                  type="single"
                  variant="outline"
                  size="sm"
                  className="flex-wrap justify-self-start"
                  value={color ?? NONE}
                  onValueChange={(v) => v && setColor(v === NONE ? null : (v as SessionColor))}
                >
                  <ToggleGroupItem value={NONE} aria-label="No colour" className="text-xs">
                    None
                  </ToggleGroupItem>
                  {SESSION_COLORS.map((c) => (
                    <ToggleGroupItem key={c} value={c} aria-label={c} title={c}>
                      <ColorDot color={c} className="size-3" />
                    </ToggleGroupItem>
                  ))}
                </ToggleGroup>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="session-tags">Tags</Label>
                <Input
                  id="session-tags"
                  autoComplete="off"
                  placeholder="Separate with commas"
                  value={tags}
                  onChange={(e) => setTags(e.currentTarget.value)}
                />
                {tagSuggestions.filter((t) => !tagList.some((x) => x.toLowerCase() === t.toLowerCase())).length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {tagSuggestions
                      .filter((t) => !tagList.some((x) => x.toLowerCase() === t.toLowerCase()))
                      .slice(0, 12)
                      .map((t) => (
                        <Badge key={t} asChild variant="outline" className="font-normal">
                          <button type="button" onClick={() => setTags([...tagList, t].join(", "))}>
                            {t}
                          </button>
                        </Badge>
                      ))}
                  </div>
                )}
              </div>
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
              <Button type="submit" disabled={!host.trim() || !portOk || busy}>
                {session ? "Save" : "Create session"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {adding && vault && (
        <SecretDialog
          vault={vault}
          kind={adding}
          suggestedLabel={
            adding === "passphrase"
              ? ""
              : [username.trim(), host.trim()].filter(Boolean).join("@") || name.trim() || undefined
          }
          onVaultChanged={onVaultChanged}
          onSaved={(meta) => {
            setSecrets((list) => [...list.filter((s) => s.id !== meta.id), meta]);
            if (meta.kind === "password") setPassword(meta.id);
            if (meta.kind === "privateKey") setKey(meta.id);
            if (meta.kind === "passphrase") setPassphrase(meta.id);
          }}
          onClose={() => setAdding(null)}
        />
      )}
      {lowerProd && session && (
        <ConfirmDialog
          title="Remove the Prod label?"
          description={lowerProdText(session.name, environment)}
          confirmLabel={environment === "none" ? "Remove label" : `Label ${labelName(environment)}`}
          onConfirm={persist}
          onClose={() => setLowerProd(false)}
        />
      )}
    </>
  );
}
