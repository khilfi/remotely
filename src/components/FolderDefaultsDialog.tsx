// QL-16 folder defaults: what a folder gives the sessions in it and in its subfolders (user, login, jump host,
// environment label, tags). A session uses its own value first, then the nearest folder up the path, then the app's
// default; the core resolves it everywhere a session is used. Saving is audited like a session edit and refused by the
// read-only lock; a login that would send a vault password to hosts that never got it asks for the vault password
// (SS-04), as editing those sessions would. Taking a Prod label off asks first, as in the session editor.

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
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
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  api,
  errorMessage,
  type Environment,
  type FolderDefaults,
  type SecretKind,
  type SecretMeta,
  type SessionAuth,
  type SessionFolder,
  type SessionRecord,
} from "@/lib/api";
import { folderPath, subtree } from "@/lib/folders";
import { plural } from "@/lib/format";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { cn } from "@/lib/utils";
import { ConfirmDialog } from "./ConfirmDialog";
import { useReadOnlyReason } from "./Presentation";
import { WhyDisabled } from "./WhyDisabled";

/** Radix Select can't hold an empty value. */
const NOT_SET = "notSet";
const ASK = "ask";
const DIRECT = "direct";

type Login = typeof NOT_SET | "password" | "key" | "agent";

const LABELS: { value: Environment | typeof NOT_SET; label: string; className?: string }[] = [
  { value: NOT_SET, label: "Not set" },
  { value: "lab", label: "Lab", className: "data-[state=on]:text-env-lab" },
  { value: "staging", label: "Staging", className: "data-[state=on]:text-env-staging" },
  { value: "prod", label: "Prod", className: "data-[state=on]:text-env-prod" },
];

interface Props {
  folder: SessionFolder;
  folders: SessionFolder[];
  /** Candidates for the jump host, and the sessions the defaults reach. */
  sessions: SessionRecord[];
  onSaved: (folder: SessionFolder) => void;
  onClose: () => void;
}

export function FolderDefaultsDialog({ folder, folders, sessions, onSaved, onClose }: Props) {
  const readOnly = useReadOnlyReason();
  const d = folder.defaults;
  const [username, setUsername] = useState(d.username ?? "");
  const [login, setLogin] = useState<Login>(d.auth && d.auth.method !== "folder" ? d.auth.method : NOT_SET);
  const [password, setPassword] = useState(d.auth?.method === "password" ? (d.auth.passwordId ?? ASK) : ASK);
  const [key, setKey] = useState(d.auth?.method === "key" ? (d.auth.keyId ?? NOT_SET) : NOT_SET);
  const [passphrase, setPassphrase] = useState(d.auth?.method === "key" ? (d.auth.passphraseId ?? NOT_SET) : NOT_SET);
  const [jump, setJump] = useState(d.jumpSessionId ?? (d.jumpDirect ? DIRECT : NOT_SET));
  const [label, setLabel] = useState<Environment | typeof NOT_SET>(d.environment ?? NOT_SET);
  const [tags, setTags] = useState(d.tags.join(", "));
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [lowerProd, setLowerProd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.secrets().then(setSecrets, () => setSecrets([]));
  }, []);

  /** The sessions in the folder and its subfolders: the ones the defaults reach. */
  const reached = useMemo(() => {
    const ids = subtree(folders, folder.id);
    return sessions.filter((s) => s.folderId !== null && ids.has(s.folderId));
  }, [folders, folder.id, sessions]);
  const of = (kind: SecretKind) => secrets.filter((s) => s.kind === kind);

  function auth(): SessionAuth | null {
    const pick = (v: string) => (v === NOT_SET || v === ASK ? null : v);
    if (login === "password") return { method: "password", passwordId: pick(password) };
    if (login === "key") return { method: "key", keyId: pick(key), passphraseId: pick(key) ? pick(passphrase) : null };
    if (login === "agent") return { method: "agent" };
    return null;
  }

  function defaults(): FolderDefaults {
    return {
      username: username.trim() || null,
      auth: auth(),
      jumpSessionId: jump === NOT_SET || jump === DIRECT ? null : jump,
      jumpDirect: jump === DIRECT,
      environment: label === NOT_SET ? null : label,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    };
  }

  /** Throws, so the Prod confirm can show the error. */
  async function persist() {
    const saved = await withVaultPassword((vaultPassword) =>
      api.setFolderDefaults(folder.id, defaults(), vaultPassword),
    );
    toast.success(`Saved the defaults of '${folder.name}'`);
    onSaved(saved);
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

  function submit() {
    if (d.environment === "prod" && label !== "prod" && reached.some((s) => s.own.environment === "none")) {
      setLowerProd(true);
      return;
    }
    void save();
  }

  function picker(
    kind: SecretKind,
    value: string,
    onChange: (v: string) => void,
    first: { value: string; label: string },
  ) {
    return (
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={`folder-${kind}`} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={first.value}>{first.label}</SelectItem>
          {of(kind).length > 0 && <SelectSeparator />}
          {of(kind).map((s) => (
            <SelectItem key={s.id} value={s.id}>
              {s.label}
            </SelectItem>
          ))}
          {value !== first.value && !secrets.some((s) => s.id === value) && (
            <SelectItem value={value} disabled>
              Not in the vault any more
            </SelectItem>
          )}
        </SelectContent>
      </Select>
    );
  }

  const jumpChoices = sessions;

  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
        <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-xl">
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              submit();
            }}
          >
            <DialogHeader>
              <DialogTitle>Defaults of {folderPath(folders, folder.id)}</DialogTitle>
              <DialogDescription>
                {plural(reached.length, "session")} in this folder and its subfolders use these unless they set their
                own. Values left not set come from the folder above.
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-2">
              <Label htmlFor="folder-user">User</Label>
              <Input
                id="folder-user"
                data-mask="user"
                autoComplete="off"
                spellCheck={false}
                placeholder="Not set"
                value={username}
                onChange={(e) => setUsername(e.currentTarget.value)}
              />
            </div>

            <div className="grid gap-2">
              <Label>Log in with</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                className="justify-self-start"
                value={login}
                onValueChange={(v) => v && setLogin(v as Login)}
              >
                <ToggleGroupItem value={NOT_SET}>Not set</ToggleGroupItem>
                <ToggleGroupItem value="password">Password</ToggleGroupItem>
                <ToggleGroupItem value="key">Private key</ToggleGroupItem>
                <ToggleGroupItem value="agent">SSH agent</ToggleGroupItem>
              </ToggleGroup>
              {login === "password" &&
                picker("password", password, setPassword, { value: ASK, label: "None: ask when connecting" })}
              {login === "key" && (
                <div className="grid gap-3 sm:grid-cols-2">
                  {picker("privateKey", key, setKey, { value: NOT_SET, label: "None chosen" })}
                  {picker("passphrase", passphrase, setPassphrase, {
                    value: NOT_SET,
                    label: "No passphrase",
                  })}
                </div>
              )}
              {login === "password" && password !== ASK && (
                <p className="text-xs text-muted-foreground">
                  Sessions here send this password to their hosts. A host that never got it asks for the vault password
                  first.
                </p>
              )}
              <p className="text-xs text-muted-foreground">Add passwords and keys on the Vault page.</p>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="folder-jump">Jump host</Label>
              <Select value={jump} onValueChange={setJump}>
                <SelectTrigger id="folder-jump" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NOT_SET}>Not set</SelectItem>
                  <SelectItem value={DIRECT}>No jump host (whatever the folders above set)</SelectItem>
                  {jumpChoices.length > 0 && <SelectSeparator />}
                  {jumpChoices.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                The jump host itself, when it is in this folder, connects as the folders above say.
              </p>
            </div>

            <div className="grid gap-2">
              <Label>Environment</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                className="justify-self-start"
                value={label}
                onValueChange={(v) => v && setLabel(v as Environment | typeof NOT_SET)}
              >
                {LABELS.map((e) => (
                  <ToggleGroupItem key={e.value} value={e.value} className={cn("font-medium", e.className)}>
                    {e.label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
              <p className="text-xs text-muted-foreground">
                {label === "prod"
                  ? "Prod raises the approval tier of actions on every session here without an environment of its own."
                  : "Sessions with an environment of their own keep it."}
              </p>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="folder-tags">Tags</Label>
              <Input
                id="folder-tags"
                autoComplete="off"
                placeholder="Separate with commas"
                value={tags}
                onChange={(e) => setTags(e.currentTarget.value)}
              />
              <p className="text-xs text-muted-foreground">Added to each session&apos;s own tags.</p>
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
              <WhyDisabled reason={readOnly}>
                <Button type="submit" disabled={busy || readOnly !== null}>
                  Save
                </Button>
              </WhyDisabled>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      {lowerProd && (
        <ConfirmDialog
          title="Change this folder's environment from Prod?"
          description={`Sessions here without an environment of their own will no longer be Prod, so actions on them need fewer approval steps. The change is logged.`}
          confirmLabel="Save"
          onConfirm={persist}
          onClose={() => setLowerProd(false)}
        />
      )}
    </>
  );
}
