// Session editor (SS-01, SS-06): where to connect, how to log in (a password or key from the vault, or
// the SSH agent), a jump host (SS-07: its own jump host in turn makes a chain, shown here), the VM it reaches
// (BX-01), a startup command, saved port forwards (SS-07), folder, tags, colour and environment label. Saving
// changes only the app's own data: the core checks it and audits it, with no approval step. Taking the
// Prod label off asks first, since it lowers the tier of later actions on the session.
// QL-16: the user, login, jump host, label and tags a session leaves empty come from its folders; the editor shows
// each as "from folder X" (asked from the core for the folder chosen), and setting a value overrides it.
// UX-04, UX-12: the basics first (name, host, port, user, login, folder, environment), the rest under Advanced (its
// folded line says what is set inside); under Environment, one line says which environment applies and where from (a
// Prod VM the session reaches makes it Prod). Taking Prod away, by the environment or by unlinking a Prod VM, asks first.
// SS-12: the kind comes first (SSH, remote desktop, VNC, Telnet, serial), and each kind's own fields go under Advanced
// (kind-fields in SessionKindFields). Only SSH and WinRM log in with a login of the app's (WinRM: a user and a vault
// password, or this PC's Windows sign-in); RDP's mstsc and the VNC viewer ask for the password themselves, and Telnet
// and serial log in at the prompt. A serial session's host is its COM port. SSH and WinRM sessions may be linked to a VM.

import { useEffect, useMemo, useState } from "react";
import { ChevronRightIcon, PlusIcon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
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
  type Effective,
  type Environment,
  type ForwardInput,
  type SecretKind,
  type SecretMeta,
  type SessionAuth,
  type SessionColor,
  type SessionFolder,
  type SessionInput,
  type SessionKind,
  type SessionProtocol,
  type SessionRecord,
  type StartupRating,
  type VaultInfo,
  type VmRecord,
} from "@/lib/api";
import {
  defaultKind,
  kindOf,
  kindSummary,
  KINDS,
  portAfterKindChange,
  logsInWithVault,
  rdpProblem,
  readsGuest,
  serialProblem,
  takesJumpHost,
  winrmPortAfterTransport,
  winrmProblem,
} from "@/lib/session-kinds";
import { SessionKindFields, SerialPortField } from "./SessionKindFields";
import { HelpTip } from "@/components/HelpTip";
import { Term } from "@/components/Term";
import { flattenFolders, folderPath } from "@/lib/folders";
import { withVaultPassword } from "@/lib/reauth-prompt";
import { advancedSummary, environmentNote } from "@/lib/session-editor";
import { appliedEnvironment, vmsById } from "@/lib/session-environment";
import { forwardsProblem, jumpChain, routeText, toInput } from "@/lib/tunnels";
import { cn } from "@/lib/utils";
import { ColorDot, SESSION_COLORS, StartupRatingBadges } from "./Badges";
import { ConfirmDialog } from "./ConfirmDialog";
import { ForwardsEditor } from "./ForwardsEditor";
import { SecretDialog } from "./SecretDialog";
import { useReadOnlyReason } from "./Presentation";
import { WhyDisabled } from "./WhyDisabled";

/** Radix Select can't hold an empty value, so "none" stands for no choice. */
const NONE = "none";
/** QL-16: the jump host choice "no jump host, whatever the folders set". */
const DIRECT = "direct";

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
  /** BX-01: the VM a new session reaches, e.g. when linking one from a target picker. */
  vmId?: string | null;
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
    environment === "none" ? "will no longer be Prod" : `will be ${labelName(environment)} instead of Prod`;
  return `'${name}' ${change}. Actions on it will no longer move up one approval tier, so they need fewer approval steps. The change is logged.`;
}

export function SessionDialog({
  vault,
  session,
  folderId,
  vmId: presetVm,
  folders,
  sessions,
  tagSuggestions,
  onVaultChanged,
  onSaved,
  onClose,
}: Props) {
  // FD-03: saving is blocked by the read-only lock (the core refuses it too).
  const readOnly = useReadOnlyReason();
  // QL-16: what the session sets itself; what it has from its folders is `inherited`.
  const own = session?.own;
  /** SS-12: what it opens, with that kind's own fields. */
  const [kind, setKind] = useState<SessionKind>(session ? kindOf(session) : defaultKind("ssh"));
  const protocol = kind.protocol;
  const ssh = protocol === "ssh";
  /** F4: WinRM signs in with a user and a vault password, unless it uses this PC's Windows sign-in. */
  const winrmVault = protocol === "winrm" && logsInWithVault(kind);
  /** SSH and WinRM sessions may be linked to the VM they reach (its guest metrics and facts). */
  const guest = readsGuest(kind);
  const [name, setName] = useState(session?.name ?? "");
  const [folder, setFolder] = useState<string>(session ? (session.folderId ?? NONE) : (folderId ?? NONE));
  const [host, setHost] = useState(session?.host ?? "");
  const [port, setPort] = useState(String(session?.port ?? 22));
  const [username, setUsername] = useState(own?.username ?? "");
  const [method, setMethod] = useState<Method>(own?.auth.method ?? (folderId ? "folder" : "password"));
  const [password, setPassword] = useState(own ? (idOf(own.auth, "credential") ?? NONE) : NONE);
  const [key, setKey] = useState(own?.auth.method === "key" ? (own.auth.keyId ?? NONE) : NONE);
  const [passphrase, setPassphrase] = useState(own ? (idOf(own.auth, "passphrase") ?? NONE) : NONE);
  const [jump, setJump] = useState(own?.jumpSessionId ?? (own?.jumpDirect ? DIRECT : NONE));
  const [startup, setStartup] = useState(session?.startupCommand ?? "");
  /** SS-01: typed again after an automatic reconnect. */
  const [startupAgain, setStartupAgain] = useState(session?.startupOnReconnect ?? false);
  /** SS-01: the last rating read, for the command and label it was read for. */
  const [rated, setRated] = useState<{ command: string; environment: Environment; rating: StartupRating | null }>();
  /** SS-08: the folder prompt hook: as Settings say, on, or off. */
  const [hook, setHook] = useState<string>(session?.promptHook == null ? NONE : session.promptHook ? "on" : "off");
  const [environment, setEnvironment] = useState<Environment>(own?.environment ?? "none");
  const [color, setColor] = useState<SessionColor | null>(session?.color ?? null);
  const [tags, setTags] = useState((own?.tags ?? []).join(", "));
  /** QL-16: what a session in the chosen folder gets when it sets nothing itself, for the folder it was asked for. */
  const [inheritedFor, setInheritedFor] = useState<{ folder: string; values: Effective | null } | null>(null);
  const [vm, setVm] = useState(session ? (session.vmId ?? NONE) : (presetVm ?? NONE));
  const [vms, setVms] = useState<VmRecord[]>([]);
  /** SS-07: the saved port forwards; null while an edited session's are loading. */
  const [forwards, setForwards] = useState<ForwardInput[] | null>(session ? null : []);
  const [forwardsError, setForwardsError] = useState<string | null>(null);
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [adding, setAdding] = useState<SecretKind | null>(null);
  /** Taking the Prod label off lowers the tier of later actions on the session, so saving asks first. */
  const [lowerProd, setLowerProd] = useState(false);
  /** UX-04: Advanced is folded until opened. */
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.secrets().then(setSecrets, () => setSecrets([]));
    api.vmList().then(setVms, () => setVms([]));
  }, []);

  // QL-16: asked again whenever the folder changes; a stale answer is dropped.
  const editedSession = session?.id ?? null;
  useEffect(() => {
    let stale = false;
    api.sessionInherited(folder === NONE ? null : folder, editedSession).then(
      (values) => !stale && setInheritedFor({ folder, values }),
      () => !stale && setInheritedFor({ folder, values: null }),
    );
    return () => {
      stale = true;
    };
  }, [folder, editedSession]);
  const inherited = inheritedFor?.folder === folder ? inheritedFor.values : null;
  /** The label that will apply: its own, else its folders'. */
  const effectiveEnvironment: Environment =
    environment !== "none" ? environment : (inherited?.environment ?? session?.environment ?? "none");

  // Loaded once per session edited, so a refreshed session list never resets what is being typed.
  const editedId = session?.id ?? null;
  useEffect(() => {
    if (!editedId) return;
    api.forwards(editedId).then(
      (saved) => setForwards(saved.map(toInput)),
      (err) => setForwardsError(errorMessage(err)),
    );
  }, [editedId]);

  // SS-01: the startup command rated as it is typed, for this session's label (QL-16: its folders' included).
  useEffect(() => {
    const command = startup.trim();
    if (!command) return;
    let stale = false;
    const timer = window.setTimeout(() => {
      api.sessionStartupRating(command, effectiveEnvironment).then(
        (rating) => !stale && setRated({ command, environment: effectiveEnvironment, rating }),
        () => !stale && setRated({ command, environment: effectiveEnvironment, rating: null }),
      );
    }, 250);
    return () => {
      stale = true;
      window.clearTimeout(timer);
    };
  }, [startup, effectiveEnvironment]);
  const startupRating =
    rated && rated.command === startup.trim() && rated.environment === effectiveEnvironment ? rated.rating : null;

  const of = (kind: SecretKind) => secrets.filter((s) => s.kind === kind);
  // SS-12: a serial session has no network port (the core keeps its column at 1).
  const portNumber = protocol === "serial" ? 1 : Number(port);
  const portOk = Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535;
  /** SS-12: what the kind's own fields refuse, if anything. */
  const kindIssue =
    kind.protocol === "serial"
      ? serialProblem(kind)
      : kind.protocol === "rdp"
        ? rdpProblem(kind)
        : kind.protocol === "winrm"
          ? winrmProblem(kind)
          : null;
  /** What saving waits for: the kind's fields right, and an SSH session's forwards loaded and right. */
  const savable = kindIssue === null && (!ssh || (forwards !== null && forwardsProblem(forwards) === null));
  /** SS-12: picks a kind, keeping the fields of the one it had; the port follows unless one was typed. */
  function chooseKind(next: SessionProtocol) {
    if (next === protocol) return;
    setPort(portAfterKindChange(port, protocol, next));
    setKind(session && session.kind.protocol === next ? session.kind : defaultKind(next));
  }
  const tagList = tags
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const jumpChoices = sessions.filter((s) => s.id !== session?.id);
  const vaultReady = vault !== null && vault.status !== "notSetUp";
  /** QL-16: the jump host that will apply: the one chosen, none, or the folders'. */
  const jumpApplied = jump === DIRECT ? null : jump === NONE ? (inherited?.jumpSessionId ?? null) : jump;
  /** SS-07: the jump host that applies and the ones before it, in the order they are connected. */
  const chain = useMemo(() => {
    if (!jumpApplied) return null;
    const byId = new Map(sessions.map((s) => [s.id, s]));
    const chosen = byId.get(jumpApplied);
    if (!chosen) return null;
    // As if saved: this session goes through the chosen one.
    if (session) byId.set(session.id, { ...session, jumpSessionId: jumpApplied });
    const before = jumpChain(jumpApplied, byId);
    return { names: [...before.names, chosen.name], loops: before.loop };
  }, [jumpApplied, sessions, session]);
  /** QL-16: "password 'web root'" for a login a folder gives. */
  const loginText = (login: SessionAuth | null | undefined) => {
    const label = (id: string | null) => (id ? secrets.find((x) => x.id === id)?.label : undefined);
    if (!login || login.method === "folder") return "a password asked when connecting";
    if (login.method === "agent") return "the SSH agent";
    if (login.method === "key") {
      const name = label(login.keyId);
      return name ? `the key '${name}'` : "a key (none chosen)";
    }
    const name = label(login.passwordId);
    return name ? `the password '${name}'` : "a password asked when connecting";
  };
  /** The folders' own tags, which the session has on top of its own. */
  const folderTags = (inherited?.inherited.tags ?? []).filter(
    (t) => !tags.split(",").some((x) => x.trim().toLowerCase() === t.tag.toLowerCase()),
  );
  const forwardsIssue = forwards ? forwardsProblem(forwards) : null;
  /** SS-07: why the forwards keep it from saving (SSH sessions only have them). */
  const forwardsReason = !ssh ? null : forwards ? forwardsIssue : "The port forwards are still loading.";

  // UX-12: the environment that will apply, and where it comes from: its own, its folders', or a Prod VM it reaches.
  const vmMap = useMemo(() => vmsById(vms), [vms]);
  const applied = appliedEnvironment(
    {
      environment: effectiveEnvironment,
      inherited: { environment: environment === "none" ? (inherited?.inherited.environment ?? null) : null },
      vmId: vm === NONE ? null : vm,
    },
    vmMap,
  );
  const overrides =
    environment !== "none" && inherited?.inherited.environment
      ? { environment: inherited.environment, folder: inherited.inherited.environment.name }
      : null;
  /** What applied when the editor opened (a saved session's own, folders' and VM's). */
  const wasProd = session ? appliedEnvironment(session, vmMap).environment === "prod" : false;
  const summary = advancedSummary({
    kind: kindSummary(kind),
    jumpHost: takesJumpHost(kind) && chain ? (chain.names[chain.names.length - 1] ?? null) : null,
    vm: !guest || vm === NONE ? null : (vms.find((v) => v.id === vm)?.displayName ?? "not listed"),
    startupCommand: ssh && startup.trim() !== "",
    promptHook: !ssh || hook === NONE ? null : hook === "on",
    portForwards: ssh ? (forwards?.length ?? 0) : 0,
    colour: color !== null,
    tags: tagList.length,
    protocol,
  });
  /** Advanced opens by itself when something in it needs fixing. */
  const showAdvanced =
    advancedOpen ||
    (ssh && forwardsIssue !== null) ||
    (takesJumpHost(kind) && Boolean(chain?.loops)) ||
    kindIssue !== null;

  function auth(): SessionAuth {
    const pick = (v: string) => (v === NONE ? null : v);
    if (method === "password") return { method, passwordId: pick(password) };
    if (method === "key") return { method, keyId: pick(key), passphraseId: pick(key) ? pick(passphrase) : null };
    if (method === "folder") return { method: "folder" };
    return { method: "agent" };
  }

  /** QL-01: how the VM choice will be kept. */
  function linkNote() {
    if (session?.vmLink === "auto" && vm === session.vmId) {
      return "Linked automatically by its IP address; choosing another makes the choice yours.";
    }
    if (vm !== NONE) return "";
    const decided = session && (session.vmId !== null || session.vmLink === "manual");
    if (decided && host.trim().toLowerCase() === session.host.toLowerCase()) {
      return "Stays unlinked until its host changes.";
    }
    return "";
  }

  /** Throws, so the Prod confirm can show the error. */
  async function persist() {
    // SS-12: only SSH logs in with a login of the app's and has a startup command, prompt hook and VM link; Telnet
    // and serial take no jump host. The core tidies the same way.
    const jumps = takesJumpHost(kind);
    const input: SessionInput = {
      name,
      folderId: folder === NONE ? null : folder,
      host,
      port: portNumber,
      username:
        protocol === "vnc" || protocol === "serial" || (protocol === "winrm" && !winrmVault)
          ? null
          : username.trim() || null,
      auth: ssh ? auth() : { method: "password", passwordId: winrmVault && password !== NONE ? password : null },
      jumpSessionId: !jumps || jump === NONE || jump === DIRECT ? null : jump,
      jumpDirect: !jumps || jump === DIRECT,
      startupCommand: ssh ? startup.trim() || null : null,
      startupOnReconnect: ssh && startupAgain,
      promptHook: !ssh || hook === NONE ? null : hook === "on",
      environment,
      color,
      tags: tagList,
      vmId: !guest || vm === NONE ? null : vm,
      kind,
    };
    // SS-04, AP-06: a vault password sent to a host where no saved session sends it yet asks for the vault password.
    const saved = await withVaultPassword((password) =>
      session ? api.updateSession(session.id, input, password) : api.createSession(input, password),
    );
    // SS-07: the forwards are saved after the session (a new one needs its id); the core skips an unchanged list.
    if (forwards && ssh) {
      try {
        await api.saveForwards(saved.id, forwards);
      } catch (err) {
        toast.error(`'${saved.name}' was saved, but its port forwards were not`, {
          description: `${errorMessage(err)} Edit the session to fix them.`,
        });
      }
    }
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

  /** SS-06: saves at once, unless the edit takes Prod away (QL-16, UX-12: the environment that applies). */
  function submit() {
    if (wasProd && applied.environment !== "prod") {
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
              if (host.trim() && portOk && savable) submit();
            }}
          >
            <DialogHeader>
              <DialogTitle>{session ? `Edit '${session.name}'` : "New session"}</DialogTitle>
              <DialogDescription>
                {ssh
                  ? "Passwords and keys stay in the vault; one left out is asked when connecting."
                  : protocol === "rdp"
                    ? "Opens Remote Desktop Connection, which asks for the password."
                    : protocol === "vnc"
                      ? "Opens your VNC viewer, which asks for the password."
                      : "Opens a terminal tab; log in at the prompt."}
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-2">
              <Label>Kind</Label>
              <ToggleGroup
                type="single"
                variant="outline"
                className="flex-wrap justify-self-start"
                value={protocol}
                onValueChange={(v) => v && chooseKind(v as SessionProtocol)}
              >
                {KINDS.map((k) => (
                  <ToggleGroupItem key={k.protocol} value={k.protocol}>
                    {k.label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
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

            {protocol === "serial" ? (
              <SerialPortField value={host} onChange={setHost} autoFocus={!session} />
            ) : (
              <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
                <div className="grid gap-2">
                  <Label htmlFor="session-host">Host</Label>
                  <Input
                    id="session-host"
                    data-mask="host"
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
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              {protocol !== "vnc" && protocol !== "serial" && !(protocol === "winrm" && !winrmVault) && (
                <div className="grid content-start gap-2">
                  <Label htmlFor="session-user">User</Label>
                  <Input
                    id="session-user"
                    data-mask="user"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={inherited?.username ? "From its folder" : "alice"}
                    value={username}
                    onChange={(e) => setUsername(e.currentTarget.value)}
                  />
                  {inherited?.username && inherited.inherited.username && (
                    <p className="text-xs text-muted-foreground">
                      {username.trim() ? "Overrides " : "Empty: "}
                      <span data-mask="user">{inherited.username}</span> from folder {inherited.inherited.username.name}
                    </p>
                  )}
                </div>
              )}
              <div className="grid content-start gap-2">
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

            {winrmVault && (
              <div className="grid gap-2">
                <Label htmlFor="session-password">Password from the vault</Label>
                {secretPicker("password", password, setPassword, "None: ask when connecting")}
              </div>
            )}

            {ssh && (
              <div className="grid gap-2">
                <Label>Log in with</Label>
                <ToggleGroup
                  type="single"
                  variant="outline"
                  className="justify-self-start"
                  value={method}
                  onValueChange={(v) => v && setMethod(v as Method)}
                >
                  {(folder !== NONE || method === "folder") && (
                    <ToggleGroupItem value="folder">From folder</ToggleGroupItem>
                  )}
                  <ToggleGroupItem value="password">Password</ToggleGroupItem>
                  <ToggleGroupItem value="key">Private key</ToggleGroupItem>
                  <ToggleGroupItem value="agent">SSH agent</ToggleGroupItem>
                </ToggleGroup>
                {method === "folder" && (
                  <p className="text-sm text-muted-foreground">
                    {inherited?.inherited.auth
                      ? `Logs in with ${loginText(inherited.auth)}, from folder ${inherited.inherited.auth.name}.`
                      : "No folder above sets a login yet, so a password is asked when connecting."}
                  </p>
                )}
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
                    Uses the keys in a running OpenSSH agent or Pageant. Nothing is stored here.
                  </p>
                )}
              </div>
            )}
            {protocol === "telnet" && (
              <p className="text-sm text-muted-foreground" role="note">
                Telnet sends everything, passwords too, in clear text.
              </p>
            )}
            {protocol === "vnc" && (
              <p className="text-sm text-muted-foreground" role="note">
                Many VNC servers don&apos;t encrypt the connection. Use a jump host or a VPN across networks you
                don&apos;t trust.
              </p>
            )}

            <div className="grid gap-2">
              <Label>
                <Term id="environment" />
              </Label>
              <ToggleGroup
                type="single"
                variant="outline"
                className="justify-self-start"
                value={environment}
                onValueChange={(v) => v && setEnvironment(v as Environment)}
              >
                {ENVIRONMENTS.map((e) => (
                  <ToggleGroupItem key={e.value} value={e.value} className={cn("font-medium", e.className)}>
                    {e.value === "none" && inherited?.inherited.environment ? "From folder" : e.label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
              <p className="flex items-center gap-1 text-xs text-muted-foreground" data-environment-note>
                {environmentNote(applied, overrides)}
                <HelpTip topic="prodTier" />
              </p>
            </div>

            <Collapsible open={showAdvanced} onOpenChange={setAdvancedOpen} className="rounded-lg border">
              <CollapsibleTrigger asChild>
                <button
                  type="button"
                  className="flex w-full min-w-0 items-center gap-2 rounded-lg px-3 py-2 text-left text-sm hover:bg-muted/60"
                >
                  <ChevronRightIcon
                    className={cn("size-4 shrink-0 transition-transform", showAdvanced && "rotate-90")}
                    aria-hidden
                  />
                  <span className="font-medium">Advanced</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{summary}</span>
                </button>
              </CollapsibleTrigger>
              <CollapsibleContent className="grid gap-4 border-t p-3">
                {!ssh && (
                  <SessionKindFields
                    kind={kind}
                    onChange={(next) => {
                      // F4: the port follows HTTPS and HTTP unless one was typed.
                      if (next.protocol === "winrm" && kind.protocol === "winrm" && next.transport !== kind.transport) {
                        setPort(winrmPortAfterTransport(port, next.transport));
                      }
                      setKind(next);
                    }}
                    problem={kindIssue}
                  />
                )}
                {takesJumpHost(kind) && (
                  <div className="grid gap-2">
                    <Label htmlFor="session-jump">
                      <Term id="jumpHost" />
                    </Label>
                    <Select value={jump} onValueChange={setJump}>
                      <SelectTrigger id="session-jump" className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value={NONE}>
                          {inherited?.inherited.jump
                            ? inherited.jumpSessionId
                              ? `From folder ${inherited.inherited.jump.name}: ${sessions.find((x) => x.id === inherited.jumpSessionId)?.name ?? "a session"}`
                              : `From folder ${inherited.inherited.jump.name}: connect directly`
                            : "None: connect directly"}
                        </SelectItem>
                        {(inherited?.jumpSessionId || jump === DIRECT) && (
                          <SelectItem value={DIRECT}>No jump host (overrides the folder)</SelectItem>
                        )}
                        {jumpChoices.length > 0 && <SelectSeparator />}
                        {jumpChoices.map((s) => (
                          <SelectItem key={s.id} value={s.id}>
                            {s.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    {chain && (
                      <p
                        className={cn("text-xs", chain.loops ? "text-destructive" : "text-muted-foreground")}
                        title={
                          chain.loops
                            ? undefined
                            : "Each hop checks its host key and logs in with its own session's login; tunnels start from this host."
                        }
                      >
                        {chain.loops
                          ? "That jump host leads back to this session through its own jump hosts, so it can't be saved."
                          : ssh
                            ? `Connects through ${routeText(chain.names)}.`
                            : `Opens a tunnel through ${routeText(chain.names)} first.`}
                      </p>
                    )}
                  </div>
                )}

                {guest && (
                  <>
                    <div className="grid gap-2">
                      <Label htmlFor="session-vm" className="flex items-center gap-1">
                        VM it reaches
                        <HelpTip topic="vmLink" />
                      </Label>
                      <Select value={vm} onValueChange={setVm}>
                        <SelectTrigger id="session-vm" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>None</SelectItem>
                          {vms.length > 0 && <SelectSeparator />}
                          {vms.map((v) => (
                            <SelectItem key={v.id} value={v.id}>
                              {v.displayName}
                            </SelectItem>
                          ))}
                          {vm !== NONE && !vms.some((v) => v.id === vm) && (
                            <SelectItem value={vm} disabled>
                              Not in the VM list now
                            </SelectItem>
                          )}
                        </SelectContent>
                      </Select>
                      {linkNote() && <p className="text-xs text-muted-foreground">{linkNote()}</p>}
                    </div>
                  </>
                )}

                {ssh && (
                  <>
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
                      {startupRating && (
                        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          <StartupRatingBadges rating={startupRating} />
                          <span>
                            {startupRating.action === "execReadOnly"
                              ? "Only reads, as a command on this session."
                              : "Typed without asking: as a command on this session it would need this approval."}
                          </span>
                        </div>
                      )}
                      <p className="text-xs text-muted-foreground">
                        Typed at the first prompt of each connection. Don&apos;t put passwords here.
                      </p>
                      <div className="flex items-center gap-2">
                        <Checkbox
                          id="session-startup-again"
                          checked={startupAgain}
                          disabled={!startup.trim()}
                          onCheckedChange={(v) => setStartupAgain(v === true)}
                        />
                        <Label htmlFor="session-startup-again" className="font-normal">
                          Type it again when the terminal reconnects by itself
                        </Label>
                      </div>
                    </div>

                    <div className="grid gap-2">
                      <Label htmlFor="session-hook" className="flex items-center gap-1">
                        Folder tracking (prompt hook)
                        <HelpTip topic="promptHook" />
                      </Label>
                      <Select value={hook} onValueChange={setHook}>
                        <SelectTrigger id="session-hook" className="w-full sm:w-80">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>
                            As in Settings{applied.environment === "prod" ? " (off for Prod)" : ""}
                          </SelectItem>
                          <SelectItem value="on">On</SelectItem>
                          <SelectItem value="off">Off</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="grid gap-2">
                      <Label>Port forwards</Label>
                      {forwards ? (
                        <ForwardsEditor forwards={forwards} onChange={setForwards} disabled={busy} />
                      ) : (
                        <p className="text-sm text-muted-foreground">{forwardsError ?? "Loading…"}</p>
                      )}
                      <p className="text-xs text-muted-foreground">
                        Start and stop them from the terminal&apos;s ⋯ menu, Tunnels.
                      </p>
                    </div>
                  </>
                )}

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="grid content-start gap-2">
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
                  <div className="grid content-start gap-2">
                    <Label htmlFor="session-tags">Tags</Label>
                    <Input
                      id="session-tags"
                      autoComplete="off"
                      placeholder="Separate with commas"
                      value={tags}
                      onChange={(e) => setTags(e.currentTarget.value)}
                    />
                    {folderTags.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
                        <span>Also from its folders:</span>
                        {folderTags.map((t) => (
                          <Badge
                            key={t.tag}
                            variant="secondary"
                            className="font-normal"
                            title={`From folder ${t.folder.name}`}
                          >
                            {t.tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                    {tagSuggestions.filter((t) => !tagList.some((x) => x.toLowerCase() === t.toLowerCase())).length >
                      0 && (
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
              </CollapsibleContent>
            </Collapsible>

            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <WhyDisabled reason={readOnly ?? kindIssue ?? forwardsReason}>
                <Button type="submit" disabled={!host.trim() || !portOk || busy || !savable || readOnly !== null}>
                  {session ? "Save" : "Create session"}
                </Button>
              </WhyDisabled>
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
          title="Change the environment from Prod?"
          description={lowerProdText(session.name, applied.environment)}
          confirmLabel={`Save as ${labelName(applied.environment)}`}
          onConfirm={persist}
          onClose={() => setLowerProd(false)}
        />
      )}
    </>
  );
}
