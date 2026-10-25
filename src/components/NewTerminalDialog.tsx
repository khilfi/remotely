// QL-02 "New terminal": a quick connection typed in a form (host, port, user, how to log in: a vault item
// or a typed password, or the SSH agent), optionally saved as a session in a folder with a label. Beside
// it, the recently opened sessions and the history of quick connections that were not saved.
//
// A typed password goes to the core with the request and is cleared from the form at once: it never
// stays in the UI state, and the core uses it for that terminal's logins only, never saving it.

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ClockIcon, HistoryIcon, LoaderCircleIcon, TerminalIcon, XIcon } from "lucide-react";
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
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ColorDot, EnvBadge } from "@/components/Badges";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type Environment,
  type QuickConnectEntry,
  type QuickConnectRequest,
  type SecretKind,
  type SecretMeta,
  type SessionAuth,
  type SessionFolder,
  type SessionRecord,
} from "@/lib/api";
import { flattenFolders, folderPath } from "@/lib/folders";
import { formatWhen } from "@/lib/format";
import { sessionAddress } from "@/lib/terminal-session";

/** Radix Select can't hold an empty value. */
const NONE = "none";

type Method = SessionAuth["method"];

const LABELS: { value: Environment; label: string }[] = [
  { value: "none", label: "No label" },
  { value: "lab", label: "Lab" },
  { value: "staging", label: "Staging" },
  { value: "prod", label: "Prod" },
];

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Opens the terminal; rejects with the core's reason when it could not. */
  onConnect: (request: QuickConnectRequest, label: string) => Promise<void>;
  onOpenSession: (session: SessionRecord) => void;
}

function historyAddress(e: QuickConnectEntry) {
  return sessionAddress({ username: e.username, host: e.host, port: e.port });
}

function authText(auth: SessionAuth, labels: Map<string, string>) {
  const name = (id: string | null) => (id ? (labels.get(id) ?? "a vault item that is gone") : null);
  switch (auth.method) {
    case "password":
      return auth.passwordId ? `password ${name(auth.passwordId)}` : "password, typed";
    case "key":
      return auth.keyId ? `key ${name(auth.keyId)}` : "key";
    case "agent":
      return "SSH agent";
  }
}

export function NewTerminalDialog({ open, onOpenChange, onConnect, onOpenSession }: Props) {
  const [host, setHost] = useState("");
  // Empty: 22, or the port typed with the host (host:2222).
  const [port, setPort] = useState("");
  const [user, setUser] = useState("");
  const [method, setMethod] = useState<Method>("password");
  const [secretId, setSecretId] = useState(NONE);
  const [passphraseId, setPassphraseId] = useState(NONE);
  const [password, setPassword] = useState("");
  const [saveTicked, setSave] = useState(false);
  // FD-03: the read-only lock keeps quick connections unsaved (connecting stays possible).
  const readOnly = useReadOnlyReason();
  const save = saveTicked && !readOnly;
  const [name, setName] = useState("");
  const [folderId, setFolderId] = useState(NONE);
  const [label, setLabel] = useState<Environment>("none");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [folders, setFolders] = useState<SessionFolder[]>([]);
  const [recent, setRecent] = useState<SessionRecord[]>([]);
  const [history, setHistory] = useState<QuickConnectEntry[]>([]);

  useEffect(() => {
    if (!open) return;
    Promise.all([api.secrets(), api.sessionFolders(), api.recentSessions(8), api.quickConnectHistory()]).then(
      ([s, f, r, h]) => {
        setSecrets(s);
        setFolders(f);
        setRecent(r);
        setHistory(h);
      },
      (err) => setError(errorMessage(err)),
    );
  }, [open]);

  const labels = useMemo(() => new Map(secrets.map((s) => [s.id, s.label])), [secrets]);
  const of = (kind: SecretKind) => secrets.filter((s) => s.kind === kind);

  function reset() {
    setHost("");
    setPort("");
    setUser("");
    setMethod("password");
    setSecretId(NONE);
    setPassphraseId(NONE);
    setPassword("");
    setSave(false);
    setName("");
    setFolderId(NONE);
    setLabel("none");
    setError(null);
  }

  function fill(entry: QuickConnectEntry) {
    setHost(entry.host);
    setPort(String(entry.port));
    setUser(entry.username ?? "");
    setMethod(entry.auth.method);
    setPassword("");
    if (entry.auth.method === "password") setSecretId(entry.auth.passwordId ?? NONE);
    if (entry.auth.method === "key") {
      setSecretId(entry.auth.keyId ?? NONE);
      setPassphraseId(entry.auth.passphraseId ?? NONE);
    }
    setError(null);
  }

  async function forget(id: string | null) {
    try {
      await api.quickConnectForget(id);
      setHistory(id ? history.filter((h) => h.id !== id) : []);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  function auth(): SessionAuth {
    const id = secretId === NONE ? null : secretId;
    switch (method) {
      case "password":
        return { method, passwordId: id };
      case "key":
        return { method, keyId: id, passphraseId: passphraseId === NONE ? null : passphraseId };
      case "agent":
        return { method };
      // QL-16: the form never offers "as its folders say"; a saved session can be switched to it in the editor.
      case "folder":
        return { method };
    }
  }

  async function connect() {
    if (!host.trim()) {
      setError("Enter the host name or IP address.");
      return;
    }
    if (method === "key" && secretId === NONE) {
      setError("Choose the key to log in with.");
      return;
    }
    const portNumber = port.trim() === "" ? null : Number(port);
    if (portNumber !== null && !(Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535)) {
      setError("The port must be 1 to 65535.");
      return;
    }
    const request: QuickConnectRequest = {
      host: host.trim(),
      port: portNumber,
      username: user.trim() || null,
      auth: auth(),
      password: method === "password" && secretId === NONE && password !== "" ? password : null,
      save: save
        ? { name: name.trim(), folderId: folderId === NONE ? null : folderId, environment: label, color: null }
        : null,
    };
    // The typed password leaves the form now, whatever happens next.
    setPassword("");
    setBusy(true);
    setError(null);
    try {
      await onConnect(request, request.username ? `${request.username}@${request.host}` : request.host);
      reset();
      onOpenChange(false);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const folderRows = flattenFolders(folders);

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setPassword("");
        onOpenChange(next);
      }}
    >
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>New terminal</DialogTitle>
          <DialogDescription>
            Connect to any host without saving it first, or tick Save as session to keep it in the library.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-6 md:grid-cols-[1fr_15rem]">
          <form
            id="quick-connect"
            className="grid content-start gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void connect();
            }}
          >
            <div className="grid grid-cols-[1fr_6rem] gap-3">
              <div className="grid gap-2">
                <Label htmlFor="qc-host">Host</Label>
                <Input
                  id="qc-host"
                  data-mask="address"
                  autoFocus
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="web01.example.com, 192.0.2.10 or alice@host:2222"
                  value={host}
                  onChange={(e) => setHost(e.currentTarget.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="qc-port">Port</Label>
                <Input
                  id="qc-port"
                  inputMode="numeric"
                  placeholder="22"
                  value={port}
                  onChange={(e) => setPort(e.currentTarget.value)}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-2">
                <Label htmlFor="qc-user">User</Label>
                <Input
                  id="qc-user"
                  data-mask="user"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="Asked when empty"
                  value={user}
                  onChange={(e) => setUser(e.currentTarget.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="qc-method">Log in with</Label>
                <Select
                  value={method}
                  onValueChange={(v) => {
                    setMethod(v as Method);
                    setSecretId(NONE);
                    setPassphraseId(NONE);
                    setPassword("");
                  }}
                >
                  <SelectTrigger id="qc-method" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="password">Password</SelectItem>
                    <SelectItem value="key">Key from the vault</SelectItem>
                    <SelectItem value="agent">SSH agent or Pageant</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            {method === "password" && (
              <div className="grid grid-cols-2 gap-3">
                <SecretSelect
                  id="qc-secret"
                  label="Password from the vault"
                  noneLabel="None: type it or be asked"
                  value={secretId}
                  items={of("password")}
                  onChange={(v) => {
                    setSecretId(v);
                    setPassword("");
                  }}
                />
                <div className="grid gap-2">
                  <Label htmlFor="qc-password">Password</Label>
                  <Input
                    id="qc-password"
                    type="password"
                    autoComplete="off"
                    disabled={secretId !== NONE}
                    placeholder={secretId !== NONE ? "From the vault" : "Optional; asked when empty"}
                    value={password}
                    onChange={(e) => setPassword(e.currentTarget.value)}
                  />
                </div>
              </div>
            )}
            {method === "key" && (
              <div className="grid grid-cols-2 gap-3">
                <SecretSelect
                  id="qc-key"
                  label="Key"
                  noneLabel="Choose a key"
                  value={secretId}
                  items={of("privateKey")}
                  onChange={setSecretId}
                />
                <SecretSelect
                  id="qc-passphrase"
                  label="Passphrase"
                  noneLabel="None, or asked"
                  value={passphraseId}
                  items={of("passphrase")}
                  onChange={setPassphraseId}
                />
              </div>
            )}
            {method === "password" && secretId === NONE && password !== "" && (
              <p className="text-xs text-muted-foreground">
                The typed password is used for this terminal only. It is never saved, even with Save as session.
              </p>
            )}

            <div className="grid gap-3 rounded-lg border p-3">
              <div className="flex items-center gap-2">
                <WhyDisabled reason={readOnly}>
                  <Checkbox
                    id="qc-save"
                    checked={save}
                    disabled={readOnly !== null}
                    onCheckedChange={(v) => setSave(v === true)}
                  />
                </WhyDisabled>
                <Label htmlFor="qc-save" className="font-normal">
                  Save as session
                </Label>
              </div>
              {save && (
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="grid gap-2">
                    <Label htmlFor="qc-name">Name</Label>
                    <Input
                      id="qc-name"
                      placeholder="The host"
                      value={name}
                      onChange={(e) => setName(e.currentTarget.value)}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="qc-folder">Folder</Label>
                    <Select value={folderId} onValueChange={setFolderId}>
                      <SelectTrigger id="qc-folder" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={NONE}>Top level</SelectItem>
                        {folderRows.length > 0 && <SelectSeparator />}
                        {folderRows.map(({ folder }) => (
                          <SelectItem key={folder.id} value={folder.id}>
                            {folderPath(folders, folder.id)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="qc-label">Label</Label>
                    <Select value={label} onValueChange={(v) => setLabel(v as Environment)}>
                      <SelectTrigger id="qc-label" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {LABELS.map((l) => (
                          <SelectItem key={l.value} value={l.value}>
                            {l.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              )}
            </div>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
          </form>

          <aside className="grid content-start gap-4 text-sm">
            <section className="grid gap-1">
              <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                <ClockIcon className="size-3.5" /> Recent sessions
              </h3>
              {recent.length === 0 && <p className="text-xs text-muted-foreground">None opened yet.</p>}
              {recent.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  className="flex min-w-0 items-center gap-2 rounded-md px-2 py-1 text-left hover:bg-accent"
                  title={`Open ${s.name} (${sessionAddress(s)})`}
                  onClick={() => {
                    onOpenSession(s);
                    onOpenChange(false);
                  }}
                >
                  {s.color ? <ColorDot color={s.color} /> : <TerminalIcon className="size-3 text-muted-foreground" />}
                  <span className="grid min-w-0 flex-1">
                    <span className="truncate">{s.name}</span>
                    <span className="truncate text-xs text-muted-foreground">
                      {s.lastHostname || s.lastIp
                        ? [s.lastHostname, s.lastIp].filter(Boolean).join(" · ")
                        : sessionAddress(s)}
                    </span>
                  </span>
                  {s.environment !== "none" && <EnvBadge env={s.environment} />}
                </button>
              ))}
            </section>
            <section className="grid gap-1">
              <div className="flex items-center justify-between">
                <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                  <HistoryIcon className="size-3.5" /> Quick connections
                </h3>
                {history.length > 0 && (
                  <Button variant="link" size="xs" className="h-auto p-0 text-xs" onClick={() => void forget(null)}>
                    Clear
                  </Button>
                )}
              </div>
              {history.length === 0 && (
                <p className="text-xs text-muted-foreground">Connections you don't save show up here.</p>
              )}
              {history.map((h) => (
                <div key={h.id} className="group/h flex min-w-0 items-center gap-1 rounded-md hover:bg-accent">
                  <button
                    type="button"
                    className="grid min-w-0 flex-1 px-2 py-1 text-left"
                    title={`Fill in ${historyAddress(h)}, last used ${formatWhen(h.usedAt)}`}
                    onClick={() => fill(h)}
                  >
                    <span className="truncate font-mono text-xs">{historyAddress(h)}</span>
                    <span className="truncate text-xs text-muted-foreground">{authText(h.auth, labels)}</span>
                  </button>
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    className="opacity-0 group-hover/h:opacity-100 focus-visible:opacity-100"
                    aria-label={`Remove ${historyAddress(h)} from the history`}
                    onClick={() => void forget(h.id)}
                  >
                    <XIcon />
                  </Button>
                </div>
              ))}
            </section>
          </aside>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <WhyDisabled reason={busy ? "Connecting…" : null}>
            <Button type="submit" form="quick-connect" disabled={busy}>
              {busy ? <LoaderCircleIcon className="animate-spin" /> : <TerminalIcon />}
              Connect
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SecretSelect({
  id,
  label,
  noneLabel,
  value,
  items,
  onChange,
}: {
  id: string;
  label: string;
  noneLabel: string;
  value: string;
  items: SecretMeta[];
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NONE}>{noneLabel}</SelectItem>
          {items.length > 0 && <SelectSeparator />}
          {items.map((s) => (
            <SelectItem key={s.id} value={s.id}>
              {s.label}
            </SelectItem>
          ))}
          {value !== NONE && !items.some((s) => s.id === value) && (
            <SelectItem value={value} disabled>
              A vault item that is gone
            </SelectItem>
          )}
        </SelectContent>
      </Select>
    </div>
  );
}
