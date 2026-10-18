// SS-09 SSH key manager, on the Vault page: generate keys straight into the vault (Ed25519 by default,
// RSA 4096 for older hosts), show and copy the public key in OpenSSH format, use a key for sessions, and
// push its public key to hosts (a command through the bus, see PushKeyDialog). Private keys never reach
// this page: it holds labels, IDs and public keys only.

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { CopyIcon, EllipsisIcon, KeySquareIcon, PlusIcon, SearchIcon, UploadIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { PushKeyDialog } from "@/components/PushKeyDialog";
import {
  api,
  errorMessage,
  type KeyType,
  type PublicKeyInfo,
  type SessionRecord,
  type SshKey,
  type SubmitOutcome,
  type VaultInfo,
} from "@/lib/api";
import { plural } from "@/lib/format";

interface Props {
  vault: VaultInfo;
  /** True while the page is shown, so the list is read again when the user comes back. */
  active: boolean;
  /** Bumped when the vault's secrets change elsewhere on the page. */
  version: number;
  onSubmit: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onOpenSessions: () => void;
}

type DialogState =
  | { kind: "generate" }
  | { kind: "show"; key: SshKey }
  | { kind: "attach"; key: SshKey }
  | { kind: "push"; key: SshKey | null }
  | null;

/** "Ed25519", "RSA 4096", "ECDSA P-256", or the algorithm as OpenSSH names it. */
export function keyTypeLabel(key: PublicKeyInfo | null) {
  if (!key) return "—";
  switch (key.algorithm) {
    case "ssh-ed25519":
      return "Ed25519";
    case "ssh-rsa":
      return key.bits ? `RSA ${key.bits}` : "RSA";
    case "ecdsa-sha2-nistp256":
      return "ECDSA P-256";
    case "ecdsa-sha2-nistp384":
      return "ECDSA P-384";
    case "ecdsa-sha2-nistp521":
      return "ECDSA P-521";
    default:
      return key.algorithm;
  }
}

async function copy(key: PublicKeyInfo) {
  try {
    await navigator.clipboard.writeText(key.line);
    toast.success("Copied the public key");
  } catch (err) {
    toast.error(`Could not copy: ${errorMessage(err)}`);
  }
}

export function SshKeysCard({ vault, active, version, onSubmit, onOpenSessions }: Props) {
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [listVersion, setListVersion] = useState(0);
  const [dialog, setDialog] = useState<DialogState>(null);
  const unlocked = vault.status === "unlocked";
  const reload = useCallback(() => setListVersion((v) => v + 1), []);

  useEffect(() => {
    if (!active) return;
    api.sshKeys().then(setKeys, (err) => toast.error(errorMessage(err)));
  }, [active, version, listVersion, vault.status]);

  /** The key with its public half, read from the private key when it is not known yet. */
  async function withPublic(key: SshKey): Promise<SshKey | null> {
    if (key.public) return key;
    try {
      const read = await api.sshKeyPublic(key.id);
      reload();
      return read;
    } catch (err) {
      toast.error(errorMessage(err));
      return null;
    }
  }

  async function open(key: SshKey, kind: "show" | "push" | "copy") {
    const full = await withPublic(key);
    if (!full?.public) return;
    if (kind === "copy") void copy(full.public);
    else setDialog({ kind, key: full });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>SSH keys</CardTitle>
        <CardDescription>
          Private keys in the vault. Generate one here, copy its public key, use it for sessions, and push it to hosts
          (added to ~/.ssh/authorized_keys, with the approval its tier needs).
        </CardDescription>
        <CardAction className="flex gap-2">
          <Button variant="outline" onClick={() => setDialog({ kind: "push", key: null })}>
            <UploadIcon data-icon="inline-start" />
            Push a pasted key…
          </Button>
          <Button disabled={!unlocked} onClick={() => setDialog({ kind: "generate" })}>
            <PlusIcon data-icon="inline-start" />
            Generate key
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {keys.length === 0 ? (
          <Empty className="border">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <KeySquareIcon />
              </EmptyMedia>
              <EmptyTitle>No SSH keys yet</EmptyTitle>
              <EmptyDescription>
                Generate an Ed25519 key{unlocked ? "" : " once the vault is unlocked"}, push its public key to your
                hosts, then let sessions log in with it instead of a password.
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Fingerprint</TableHead>
                  <TableHead>Used by</TableHead>
                  <TableHead className="w-10">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((k) => (
                  <TableRow key={k.id}>
                    <TableCell className="font-medium">
                      {k.label}
                      {k.generated && (
                        <Badge variant="secondary" className="ml-2 font-normal">
                          generated
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{keyTypeLabel(k.public)}</TableCell>
                    <TableCell className="max-w-48 truncate font-mono text-xs" title={k.public?.fingerprint}>
                      {k.public?.fingerprint ?? (
                        <span className="font-sans text-muted-foreground">
                          {unlocked ? "not read yet" : "unlock to read"}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {k.usedBy > 0 ? plural(k.usedBy, "session") : "—"}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${k.label}`}>
                            <EllipsisIcon />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem disabled={!k.public && !unlocked} onSelect={() => void open(k, "show")}>
                            Show the public key
                          </DropdownMenuItem>
                          <DropdownMenuItem disabled={!k.public && !unlocked} onSelect={() => void open(k, "copy")}>
                            Copy the public key
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem onSelect={() => setDialog({ kind: "attach", key: k })}>
                            Use for sessions…
                          </DropdownMenuItem>
                          <DropdownMenuItem disabled={!k.public && !unlocked} onSelect={() => void open(k, "push")}>
                            Push to hosts…
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
      </CardContent>

      {dialog?.kind === "generate" && (
        <GenerateKeyDialog
          onGenerated={(key) => {
            reload();
            setDialog({ kind: "show", key });
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "show" && dialog.key.public && (
        <PublicKeyDialog
          sshKey={dialog.key}
          publicKey={dialog.key.public}
          onPush={() => setDialog({ kind: "push", key: dialog.key })}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "attach" && (
        <AttachKeyDialog
          sshKey={dialog.key}
          onAttached={reload}
          onOpenSessions={onOpenSessions}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "push" && (
        <PushKeyDialog
          sshKey={dialog.key}
          onSubmit={onSubmit}
          onOpenSessions={onOpenSessions}
          onClose={() => setDialog(null)}
        />
      )}
    </Card>
  );
}

function GenerateKeyDialog({ onGenerated, onClose }: { onGenerated: (key: SshKey) => void; onClose: () => void }) {
  const [label, setLabel] = useState("");
  const [keyType, setKeyType] = useState<KeyType>("ed25519");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function generate() {
    setBusy(true);
    setError(null);
    try {
      const key = await api.generateSshKey({ label, keyType, comment });
      toast.success(`Generated '${key.label}'`);
      onGenerated(key);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
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
            if (label.trim() && !busy) void generate();
          }}
        >
          <DialogHeader>
            <DialogTitle>Generate an SSH key</DialogTitle>
            <DialogDescription>
              The private key goes straight into the vault and never leaves it, except to log in.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="key-label">Label</Label>
            <Input
              id="key-label"
              autoComplete="off"
              maxLength={80}
              placeholder="e.g. laptop key"
              value={label}
              onChange={(e) => setLabel(e.currentTarget.value)}
              autoFocus
            />
          </div>
          <div className="grid gap-2">
            <Label>Type</Label>
            <RadioGroup value={keyType} onValueChange={(v) => setKeyType(v as KeyType)}>
              <div className="flex items-start gap-3">
                <RadioGroupItem id="key-ed25519" value="ed25519" />
                <div className="grid gap-0.5">
                  <Label htmlFor="key-ed25519" className="font-normal">
                    Ed25519 (recommended)
                  </Label>
                  <p className="text-sm text-muted-foreground">Short and fast; every OpenSSH since 2014 takes it.</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <RadioGroupItem id="key-rsa" value="rsa" />
                <div className="grid gap-0.5">
                  <Label htmlFor="key-rsa" className="font-normal">
                    RSA 4096
                  </Label>
                  <p className="text-sm text-muted-foreground">For older hosts and appliances without Ed25519.</p>
                </div>
              </div>
            </RadioGroup>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="key-comment">Comment</Label>
            <Input
              id="key-comment"
              autoComplete="off"
              maxLength={100}
              placeholder={label.trim() || "e.g. alice@laptop"}
              value={comment}
              onChange={(e) => setComment(e.currentTarget.value)}
            />
            <p className="text-sm text-muted-foreground">
              Written after the key in authorized_keys, to tell keys apart there. Empty: the label.
            </p>
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
            <Button type="submit" disabled={!label.trim() || busy}>
              {busy ? "Generating…" : "Generate"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function PublicKeyDialog({
  sshKey,
  publicKey,
  onPush,
  onClose,
}: {
  sshKey: SshKey;
  publicKey: PublicKeyInfo;
  onPush: () => void;
  onClose: () => void;
}) {
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Public key of &lsquo;{sshKey.label}&rsquo;</DialogTitle>
          <DialogDescription>
            {keyTypeLabel(publicKey)}, {publicKey.fingerprint}. Not secret: add it to a host&apos;s
            ~/.ssh/authorized_keys, or push it from here.
          </DialogDescription>
        </DialogHeader>
        <Textarea
          readOnly
          aria-label="Public key"
          rows={publicKey.line.length > 200 ? 8 : 3}
          spellCheck={false}
          className="font-mono text-xs break-all"
          value={publicKey.line}
          onFocus={(e) => e.currentTarget.select()}
        />
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => void copy(publicKey)}>
            <CopyIcon data-icon="inline-start" />
            Copy
          </Button>
          <Button type="button" variant="outline" onClick={onPush}>
            <UploadIcon data-icon="inline-start" />
            Push to hosts…
          </Button>
          <Button type="button" onClick={onClose}>
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AttachKeyDialog({
  sshKey,
  onAttached,
  onOpenSessions,
  onClose,
}: {
  sshKey: SshKey;
  onAttached: () => void;
  onOpenSessions: () => void;
  onClose: () => void;
}) {
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.sessions().then(setSessions, (err) => setError(errorMessage(err)));
  }, []);

  const uses = (s: SessionRecord) => s.auth.method === "key" && s.auth.keyId === sshKey.id;
  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return sessions.filter(
      (s) => !needle || [s.name, s.host, s.username ?? ""].some((f) => f.toLowerCase().includes(needle)),
    );
  }, [sessions, text]);

  async function attach() {
    setBusy(true);
    setError(null);
    try {
      const changed = await api.attachSshKey(sshKey.id, [...picked]);
      const who = changed.length === 1 ? "1 session logs" : `${changed.length} sessions log`;
      toast.success(`${who} in with '${sshKey.label}' now`);
      onAttached();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Use &lsquo;{sshKey.label}&rsquo; for sessions</DialogTitle>
          <DialogDescription>
            The sessions log in with this key from now on. Push its public key to their hosts first, or the login fails.
          </DialogDescription>
        </DialogHeader>
        {sessions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No saved sessions on this computer yet.{" "}
            <Button
              variant="link"
              className="h-auto p-0"
              onClick={() => {
                onClose();
                onOpenSessions();
              }}
            >
              Open Sessions
            </Button>
          </p>
        ) : (
          <div className="grid gap-2">
            <div className="relative">
              <SearchIcon className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                aria-label="Search sessions"
                placeholder="Search name, host, user"
                className="pl-8"
                value={text}
                onChange={(e) => setText(e.currentTarget.value)}
              />
            </div>
            <ScrollArea className="h-64 rounded-md border">
              <div className="grid gap-1 p-2">
                {shown.map((s) => (
                  <label key={s.id} className="flex items-center gap-3 rounded-md px-2 py-1.5 text-sm hover:bg-accent">
                    <Checkbox
                      checked={uses(s) || picked.has(s.id)}
                      disabled={uses(s)}
                      onCheckedChange={(v) =>
                        setPicked((p) => {
                          const next = new Set(p);
                          if (v === true) next.add(s.id);
                          else next.delete(s.id);
                          return next;
                        })
                      }
                    />
                    <span className="font-medium">{s.name}</span>
                    <span className="truncate text-muted-foreground">
                      {s.username ? `${s.username}@` : ""}
                      {s.host}
                    </span>
                    {uses(s) && <span className="ml-auto text-xs text-muted-foreground">uses it</span>}
                  </label>
                ))}
              </div>
            </ScrollArea>
          </div>
        )}
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button type="button" onClick={() => void attach()} disabled={picked.size === 0 || busy}>
            {picked.size > 0 ? `Use for ${plural(picked.size, "session")}` : "Use for sessions"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
