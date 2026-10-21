// CT-01: marks a saved session as a container host (Docker, Podman or both) and says how each engine's CLI runs: as the
// login user, or under sudo with the session's login password, a vault password or none (NOPASSWD). "Detect" asks the
// host which CLIs it has and whether they need sudo (a read; nothing is saved until Save). Saving is the app's own data:
// audited like a session edit, refused by the read-only lock.

import { useEffect, useMemo, useState } from "react";
import { SearchIcon } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type ContainerMark,
  type Detection,
  type EngineKind,
  type MarkInput,
  type SecretMeta,
  type SessionRecord,
  type SudoMode,
} from "@/lib/api";
import { ENGINE_LABEL } from "@/lib/containers";

interface Props {
  /** The session to edit; null: pick one. */
  sessionId: string | null;
  sessions: SessionRecord[];
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  onSaved: (sessionId: string, marks: ContainerMark[]) => void;
  onClose: () => void;
}

const ENGINES: EngineKind[] = ["docker", "podman"];

/** The Select's value for each sudo choice; a vault password is `vault:<id>`. */
type SudoChoice = string;

function choiceOf(sudo: SudoMode): SudoChoice {
  switch (sudo.kind) {
    case "off":
      return "off";
    case "noPassword":
      return "noPassword";
    case "password":
      return sudo.passwordId ? `vault:${sudo.passwordId}` : "login";
  }
}

function sudoOf(choice: SudoChoice): SudoMode {
  if (choice === "off") return { kind: "off" };
  if (choice === "noPassword") return { kind: "noPassword" };
  if (choice === "login") return { kind: "password", passwordId: null };
  return { kind: "password", passwordId: choice.slice("vault:".length) };
}

interface EngineChoice {
  on: boolean;
  sudo: SudoChoice;
}

export function ContainerHostDialog({ sessionId, sessions, readOnly, onSaved, onClose }: Props) {
  const [picked, setPicked] = useState<string | null>(sessionId);
  const [choices, setChoices] = useState<Record<EngineKind, EngineChoice>>({
    docker: { on: true, sudo: "off" },
    podman: { on: false, sudo: "off" },
  });
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [detection, setDetection] = useState<Detection | null>(null);
  const [detecting, setDetecting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const editing = sessionId !== null;
  const session = sessions.find((s) => s.id === picked);
  const passwords = useMemo(() => secrets.filter((s) => s.kind === "password"), [secrets]);

  useEffect(() => {
    api.secrets().then(setSecrets, () => setSecrets([]));
  }, []);

  // An existing host: its marks.
  useEffect(() => {
    if (!picked) return;
    let stale = false;
    api.containerMarks(picked).then(
      (marks) => {
        if (stale || marks.length === 0) return;
        setChoices({
          docker: markChoice(marks, "docker"),
          podman: markChoice(marks, "podman"),
        });
      },
      () => {},
    );
    return () => {
      stale = true;
    };
  }, [picked]);

  async function detect() {
    if (!picked) return;
    setDetecting(true);
    setError(null);
    try {
      const chosen = choices.docker.sudo.startsWith("vault:") ? choices.docker.sudo.slice(6) : null;
      const found = await api.detectContainers(picked, chosen);
      setDetection(found);
      setChoices((prev) => {
        const next = { ...prev };
        for (const engine of found.engines) {
          next[engine.engine] = {
            on: engine.installed && engine.suggested !== null,
            sudo: engine.suggested ? choiceOf(engine.suggested) : prev[engine.engine].sudo,
          };
        }
        return next;
      });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setDetecting(false);
    }
  }

  async function save() {
    if (!picked) return;
    setBusy(true);
    setError(null);
    try {
      const marks: MarkInput[] = ENGINES.filter((e) => choices[e].on).map((engine) => ({
        engine,
        sudo: sudoOf(choices[engine].sudo),
      }));
      const saved = await api.setContainerMarks(picked, marks);
      onSaved(picked, saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const saveReason =
    readOnly ??
    (!picked
      ? "Choose a session first"
      : !editing && !ENGINES.some((e) => choices[e].on)
        ? "Tick Docker or Podman"
        : busy
          ? "Saving…"
          : null);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>
            {editing ? `Container engines of ${session?.name ?? "the host"}` : "Add a container host"}
          </DialogTitle>
          <DialogDescription>
            Remotely runs the host&apos;s docker or podman command over the session&apos;s SSH connection (through its
            jump hosts), only when you open the host here. Saved logins only: a session whose password is typed in the
            terminal needs it saved in the vault first.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          {!editing && (
            <div className="grid gap-2">
              <Label htmlFor="container-host-session">Session</Label>
              <Select value={picked ?? undefined} onValueChange={(v) => setPicked(v)}>
                <SelectTrigger id="container-host-session" className="w-full">
                  <SelectValue placeholder="Choose a saved session" />
                </SelectTrigger>
                <SelectContent>
                  {sessions.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                      <span className="text-xs text-muted-foreground" data-mask="host">
                        {s.host}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="flex items-center gap-2">
            <WhyDisabled reason={!picked ? "Choose a session first" : detecting ? "Asking the host…" : null}>
              <Button variant="outline" onClick={() => void detect()} disabled={!picked || detecting}>
                <SearchIcon data-icon="inline-start" />
                {detecting ? "Detecting…" : "Detect"}
              </Button>
            </WhyDisabled>
            <span className="text-xs text-muted-foreground">
              Logs in and looks for docker and podman, and whether docker needs sudo. Nothing is changed.
            </span>
          </div>

          {detection && (
            <ul className="grid gap-1 rounded-md border p-2 text-sm" aria-label="What the host has">
              {detection.engines.map((e) => (
                <li key={e.engine}>
                  <span className="font-medium">{ENGINE_LABEL[e.engine]}:</span>{" "}
                  {!e.installed
                    ? "not installed"
                    : e.version
                      ? `version ${e.version.server ?? e.version.client ?? "?"}${e.suggested?.kind === "off" ? ", works as the login user" : ", works with sudo"}`
                      : (e.problem ?? "installed, but not usable yet")}
                </li>
              ))}
            </ul>
          )}

          {ENGINES.map((engine) => (
            <div key={engine} className="grid gap-2 rounded-md border p-3">
              <div className="flex items-center gap-2">
                <Checkbox
                  id={`container-engine-${engine}`}
                  checked={choices[engine].on}
                  onCheckedChange={(on) => setChoices((p) => ({ ...p, [engine]: { ...p[engine], on: on === true } }))}
                />
                <Label htmlFor={`container-engine-${engine}`}>{ENGINE_LABEL[engine]}</Label>
              </div>
              <div className="grid gap-1.5 pl-6">
                <Label htmlFor={`container-sudo-${engine}`} className="text-xs text-muted-foreground">
                  Runs
                </Label>
                <Select
                  value={choices[engine].sudo}
                  onValueChange={(sudo) => setChoices((p) => ({ ...p, [engine]: { ...p[engine], sudo } }))}
                  disabled={!choices[engine].on}
                >
                  <SelectTrigger id={`container-sudo-${engine}`} className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="off">
                      As the login user ({engine === "docker" ? "in the docker group" : "rootless"})
                    </SelectItem>
                    <SelectItem value="login">With sudo, the session&apos;s login password</SelectItem>
                    <SelectItem value="noPassword">With sudo, no password (NOPASSWD)</SelectItem>
                    {passwords.length > 0 && <SelectSeparator />}
                    {passwords.map((s) => (
                      <SelectItem key={s.id} value={`vault:${s.id}`}>
                        With sudo, vault password &apos;{s.label}&apos;
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {engine === "podman" && choices.podman.sudo !== "off" && (
                  <p className="text-xs text-muted-foreground">
                    Podman under sudo shows root&apos;s containers, not the login user&apos;s.
                  </p>
                )}
              </div>
            </div>
          ))}

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <WhyDisabled reason={saveReason}>
            <Button onClick={() => void save()} disabled={saveReason !== null}>
              {editing && !ENGINES.some((e) => choices[e].on) ? "Remove from container hosts" : "Save"}
            </Button>
          </WhyDisabled>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function markChoice(marks: ContainerMark[], engine: EngineKind): EngineChoice {
  const mark = marks.find((m) => m.engine === engine);
  return mark ? { on: true, sudo: choiceOf(mark.sudo) } : { on: false, sudo: "off" };
}
