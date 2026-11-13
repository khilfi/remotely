// VM-28: the install config editor. The form for the common parts and the file beside it edit the same file: a form
// change goes to the core, which writes only that field's lines into the file (install_config_apply_form); a change in
// the file reads back into the form through the core's check, which also lists the problems with their lines. Vault
// picks name a password or key for each {{password.<name>}} and {{ssh_key.<name>}}; the file never holds a secret, and
// the preview shows one VM's file with every secret masked. A starter opens read only, with Make a copy.

import { useEffect, useMemo, useRef, useState } from "react";
import { CopyIcon, PlusIcon, XIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { HelpTip } from "@/components/HelpTip";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import { api, errorMessage, type SecretMeta, type Size, type SshKey } from "@/lib/api";
import {
  installConfigsApi,
  type ConfigCheck,
  type FieldState,
  type FormField,
  type InstallConfig,
  type InstallConfigInput,
  type InstallForm,
  type NetworkForm,
  type SecretRefKind,
  type Swap,
  type Updates,
  type UserForm,
} from "@/lib/install-configs-api";
import {
  blankConfig,
  copyOf,
  diskText,
  KIND_HINT,
  KIND_LABEL,
  KIND_ORDER,
  lineRange,
  MAX_CONFIG_NAME,
  missingVariables,
  parseLines,
  parseWords,
  placeholder,
  problemSummary,
  refOf,
  refSlug,
  syncSecrets,
} from "@/lib/install-configs";
import { cn } from "@/lib/utils";

interface Props {
  /** An own config to edit, or a starter to view; without it, a new one from `initial`. */
  existing?: InstallConfig;
  initial?: InstallConfigInput;
  /** The starters, for a new config's "Start from". */
  starters: InstallConfig[];
  sizes: Size[];
  /** The names taken, for copies. */
  taken: string[];
  /** Why edits are off (the read-only lock), or null. */
  readOnly: string | null;
  onSaved: (config: InstallConfig) => void;
  onCopy: (copy: InstallConfigInput) => void;
  onClose: () => void;
}

const NONE = "none";

const FIELD_LABEL: Record<FormField, string> = {
  hostname: "Hostname",
  locale: "Locale",
  keyboard: "Keyboard",
  timezone: "Time zone",
  storage: "Disk layout",
  network: "Network",
  users: "Users",
  ssh: "SSH",
  packages: "Packages",
  updates: "Updates",
  proxy: "Proxy",
  mirror: "Mirror",
  lateCommands: "Commands after the install",
};

export function InstallConfigDialog({
  existing,
  initial,
  starters,
  sizes,
  taken,
  readOnly,
  onSaved,
  onCopy,
  onClose,
}: Props) {
  const starter = existing?.builtIn === true;
  const [input, setInput] = useState<InstallConfigInput>(() =>
    existing
      ? {
          name: existing.name,
          kind: existing.kind,
          body: existing.body,
          variables: existing.variables,
          secrets: existing.secrets,
          notes: existing.notes,
        }
      : (initial ?? blankConfig("autoinstall")),
  );
  const [startFrom, setStartFrom] = useState<string>(NONE);
  const [check, setCheck] = useState<ConfigCheck | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  // A form edit not yet in the file, then the one written until the next check reads it back.
  const [draft, setDraft] = useState<InstallForm | null>(null);
  const [applied, setApplied] = useState<InstallForm | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [sizeId, setSizeId] = useState<string>(NONE);
  const [tab, setTab] = useState("form");
  const [previewVm, setPreviewVm] = useState({ hostname: "web-1", ip: "192.0.2.10" });
  const [preview, setPreview] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [passwords, setPasswords] = useState<SecretMeta[]>([]);
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [newVariable, setNewVariable] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLTextAreaElement>(null);
  const locked = starter || readOnly !== null;

  useEffect(() => {
    api.secrets().then(
      (s) => setPasswords(s.filter((x) => x.kind === "password")),
      () => setPasswords([]),
    );
    api.sshKeys().then(setKeys, () => setKeys([]));
  }, []);

  // The core's check of the file as it is: problems, the form's values, the placeholders.
  const checked = useDebounced(input, 300);
  const checkSize = sizeId === NONE ? null : sizeId;
  useEffect(() => {
    let stopped = false;
    installConfigsApi.check(checked, checkSize).then(
      (c) => {
        if (stopped) return;
        setCheck(c);
        setCheckError(null);
        setApplied(null);
      },
      (err) => {
        if (!stopped) setCheckError(errorMessage(err));
      },
    );
    return () => {
      stopped = true;
    };
  }, [checked, checkSize]);

  // A form edit, written into the file by the core once typing pauses.
  const pending = useDebounced(draft, 400);
  const kind = input.kind;
  const body = input.body;
  useEffect(() => {
    if (!pending) return;
    let stopped = false;
    installConfigsApi.applyForm(kind, body, pending).then(
      (next) => {
        if (stopped) return;
        setFormError(null);
        setApplied(pending);
        setDraft((d) => (d === pending ? null : d));
        if (next !== body) setInput((i) => ({ ...i, body: next }));
      },
      (err) => {
        if (stopped) return;
        setFormError(errorMessage(err));
        setDraft(null);
      },
    );
    return () => {
      stopped = true;
    };
  }, [pending, kind, body]);

  // One VM's file, every secret masked.
  const previewInput = useDebounced(input, 400);
  useEffect(() => {
    if (tab !== "preview") return;
    let stopped = false;
    installConfigsApi.preview(previewInput, previewVm).then(
      (text) => {
        if (stopped) return;
        setPreview(text);
        setPreviewError(null);
      },
      (err) => {
        if (!stopped) setPreviewError(errorMessage(err));
      },
    );
    return () => {
      stopped = true;
    };
  }, [tab, previewInput, previewVm]);

  const read = check?.form ?? null;
  const form = draft ?? applied ?? read?.form ?? null;
  const fields = read?.fields ?? [];
  const used = useMemo(() => check?.used ?? { builtIns: [], variables: [], passwords: [], sshKeys: [] }, [check]);
  const refs = useMemo(() => syncSecrets(used, input.secrets), [used, input.secrets]);
  const missing = missingVariables(used, input.variables);
  const problems = check?.problems ?? [];
  const errors = problems.filter((p) => p.severity === "error").length;

  const edit = (change: Partial<InstallForm>) => {
    if (!form || locked) return;
    setDraft({ ...form, ...change });
  };

  function pickSecret(kind: SecretRefKind, name: string, secretId: string | null) {
    setInput((i) => {
      const others = i.secrets.filter((s) => !(s.kind === kind && s.name === name));
      return { ...i, secrets: [...others, { name, kind, secretId }] };
    });
  }

  function dropSecret(kind: SecretRefKind, name: string) {
    setInput((i) => ({ ...i, secrets: i.secrets.filter((s) => !(s.kind === kind && s.name === name)) }));
  }

  function jumpTo(line: number) {
    const area = fileRef.current;
    if (!area) return;
    const [start, end] = lineRange(input.body, line);
    area.focus();
    area.setSelectionRange(start, end);
  }

  function startFromChoice(choice: string) {
    setStartFrom(choice);
    const from = starters.find((s) => s.id === choice);
    const next = from ? copyOf(from, taken) : blankConfig(choice as InstallConfigInput["kind"]);
    setDraft(null);
    setApplied(null);
    setInput((i) => ({ ...next, name: i.name.trim() ? i.name : from ? next.name : "" }));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const saved = existing ? await installConfigsApi.update(existing.id, input) : await installConfigsApi.add(input);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const reason =
    readOnly ??
    (busy
      ? "Saving…"
      : !input.name.trim()
        ? "Give the install config a name"
        : draft
          ? "Writing the form's change into the file…"
          : null);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="flex max-h-[92vh] flex-col sm:max-w-6xl">
        <DialogHeader>
          <DialogTitle>
            {starter ? `Starter: ${existing?.name}` : existing ? `Edit ${existing.name}` : "New install config"}
          </DialogTitle>
          <DialogDescription className="flex items-center gap-1">
            {KIND_LABEL[input.kind]}: {KIND_HINT[input.kind]}
            <HelpTip topic="installConfig.placeholders" />
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-[2fr_1fr_1fr]">
          <div className="grid gap-2">
            <Label htmlFor="ic-name">Name</Label>
            <Input
              id="ic-name"
              value={input.name}
              maxLength={MAX_CONFIG_NAME}
              placeholder="Web servers"
              disabled={locked}
              onChange={(e) => {
                const name = e.currentTarget.value;
                setInput((i) => ({ ...i, name }));
              }}
            />
          </div>
          {!existing && (
            <div className="grid gap-2 sm:col-span-2">
              <Label>Start from</Label>
              <Select value={startFrom} onValueChange={startFromChoice}>
                <SelectTrigger aria-label="Start from">
                  <SelectValue placeholder="A starter or a blank file" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE} disabled>
                    A starter or a blank file
                  </SelectItem>
                  {starters.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                  {KIND_ORDER.map((k) => (
                    <SelectItem key={k} value={k}>
                      Blank {KIND_LABEL[k]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {existing && (
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="ic-notes">Notes</Label>
              <Input
                id="ic-notes"
                value={input.notes ?? ""}
                maxLength={1000}
                disabled={locked}
                onChange={(e) => {
                  const notes = e.currentTarget.value;
                  setInput((i) => ({ ...i, notes: notes || null }));
                }}
              />
            </div>
          )}
        </div>

        <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-hidden lg:grid-cols-2">
          <Tabs value={tab} onValueChange={setTab} className="flex min-h-0 flex-col gap-2">
            <TabsList>
              <TabsTrigger value="form">Form</TabsTrigger>
              <TabsTrigger value="values">
                Values and vault
                {refs.some((r) => r.used && !r.secretId) || missing.length > 0 ? (
                  <Badge variant="outline" className="ml-1">
                    !
                  </Badge>
                ) : null}
              </TabsTrigger>
              <TabsTrigger value="preview">Preview</TabsTrigger>
            </TabsList>

            <TabsContent value="form" className="min-h-0 overflow-y-auto pr-1">
              {read?.unreadable ? (
                <p className="text-sm text-muted-foreground">
                  The form reads the file once it is valid. {read.unreadable}
                </p>
              ) : !form ? (
                <p className="text-sm text-muted-foreground">Reading the file…</p>
              ) : (
                <FormFields
                  form={form}
                  fields={fields}
                  maxUsers={read?.maxUsers ?? null}
                  kind={input.kind}
                  locked={locked}
                  passwords={passwords}
                  keys={keys}
                  secrets={input.secrets}
                  onEdit={edit}
                  onPick={pickSecret}
                />
              )}
              {formError && <p className="mt-2 text-sm text-destructive">{formError}</p>}
            </TabsContent>

            <TabsContent value="values" className="grid min-h-0 content-start gap-4 overflow-y-auto pr-1">
              <section className="grid gap-2" aria-label="From the vault">
                <h3 className="text-sm font-medium">From the vault</h3>
                {refs.length === 0 ? (
                  <p className="text-sm text-muted-foreground">The file names no password or key from the vault.</p>
                ) : (
                  refs.map((r) => (
                    <div key={`${r.kind}.${r.name}`} className="grid grid-cols-[1fr_1fr_auto] items-center gap-2">
                      <code className="truncate font-mono text-xs">{placeholder(r.kind, r.name)}</code>
                      <Select
                        value={r.secretId ?? NONE}
                        disabled={locked}
                        onValueChange={(v) => pickSecret(r.kind, r.name, v === NONE ? null : v)}
                      >
                        <SelectTrigger aria-label={`Vault item for ${placeholder(r.kind, r.name)}`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>Not picked yet</SelectItem>
                          {(r.kind === "password" ? passwords : keys).map((item) => (
                            <SelectItem key={item.id} value={item.id}>
                              {item.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      {r.used ? (
                        <span className="text-xs text-muted-foreground">{r.secretId ? "Picked" : "Pick one"}</span>
                      ) : (
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Remove ${placeholder(r.kind, r.name)}`}
                          title="Not in the file: remove"
                          disabled={locked}
                          onClick={() => dropSecret(r.kind, r.name)}
                        >
                          <XIcon />
                        </Button>
                      )}
                    </div>
                  ))
                )}
              </section>

              <section className="grid gap-2" aria-label="Variables">
                <h3 className="text-sm font-medium">Variables</h3>
                <p className="text-xs text-muted-foreground">
                  A default each VM starts with; the deploy dialog can change it per VM.
                </p>
                {input.variables.map((v, index) => (
                  <div key={v.name} className="grid grid-cols-[1fr_1fr_auto] items-center gap-2">
                    <code className="truncate font-mono text-xs">{`{{${v.name}}}`}</code>
                    <Input
                      aria-label={`Default for ${v.name}`}
                      value={v.default ?? ""}
                      placeholder="No default"
                      disabled={locked}
                      onChange={(e) => {
                        const value = e.currentTarget.value;
                        setInput((i) => ({
                          ...i,
                          variables: i.variables.map((x, j) => (j === index ? { ...x, default: value || null } : x)),
                        }));
                      }}
                    />
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label={`Remove ${v.name}`}
                      title="Remove"
                      disabled={locked}
                      onClick={() => setInput((i) => ({ ...i, variables: i.variables.filter((_, j) => j !== index) }))}
                    >
                      <XIcon />
                    </Button>
                  </div>
                ))}
                {missing.map((name) => (
                  <div key={name} className="flex items-center gap-2 text-sm">
                    <code className="font-mono text-xs">{`{{${name}}}`}</code>
                    <span className="text-muted-foreground">is in the file but not declared.</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={locked}
                      onClick={() => setInput((i) => ({ ...i, variables: [...i.variables, { name, default: null }] }))}
                    >
                      <PlusIcon data-icon="inline-start" />
                      Add it
                    </Button>
                  </div>
                ))}
                {!locked && (
                  <div className="flex gap-2">
                    <Input
                      aria-label="New variable's name"
                      value={newVariable}
                      placeholder="domain"
                      className="font-mono"
                      onChange={(e) => setNewVariable(e.currentTarget.value)}
                    />
                    <Button
                      variant="outline"
                      disabled={!/^[a-z][a-z0-9_]{0,31}$/.test(newVariable)}
                      onClick={() => {
                        const name = newVariable;
                        setInput((i) =>
                          i.variables.some((v) => v.name === name)
                            ? i
                            : { ...i, variables: [...i.variables, { name, default: null }] },
                        );
                        setNewVariable("");
                      }}
                    >
                      <PlusIcon data-icon="inline-start" />
                      Add a variable
                    </Button>
                  </div>
                )}
              </section>
            </TabsContent>

            <TabsContent value="preview" className="grid min-h-0 content-start gap-2 overflow-y-auto pr-1">
              <div className="grid grid-cols-2 gap-2">
                <div className="grid gap-1">
                  <Label htmlFor="ic-pv-host">Hostname</Label>
                  <Input
                    id="ic-pv-host"
                    data-mask="host"
                    value={previewVm.hostname}
                    onChange={(e) => {
                      const hostname = e.currentTarget.value;
                      setPreviewVm((p) => ({ ...p, hostname }));
                    }}
                  />
                </div>
                <div className="grid gap-1">
                  <Label htmlFor="ic-pv-ip">IP address</Label>
                  <Input
                    id="ic-pv-ip"
                    data-mask="ip"
                    value={previewVm.ip}
                    onChange={(e) => {
                      const ip = e.currentTarget.value;
                      setPreviewVm((p) => ({ ...p, ip }));
                    }}
                  />
                </div>
              </div>
              <p className="text-xs text-muted-foreground">One VM's file, every password masked.</p>
              {previewError ? (
                <p className="text-sm text-destructive">{previewError}</p>
              ) : (
                <pre className="max-h-[50vh] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre">
                  {preview ?? "…"}
                </pre>
              )}
            </TabsContent>
          </Tabs>

          <div className="flex min-h-0 flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="ic-file" className="flex items-center gap-1">
                The file
                <HelpTip topic="installConfig.form" />
              </Label>
              <Badge variant="outline" className="font-mono text-xs font-normal">
                {input.kind === "unattend"
                  ? "autounattend.xml"
                  : input.kind === "kickstart"
                    ? "ks.cfg"
                    : input.kind === "preseed"
                      ? "preseed.cfg"
                      : "user-data"}
              </Badge>
            </div>
            <Textarea
              id="ic-file"
              ref={fileRef}
              value={input.body}
              readOnly={locked}
              spellCheck={false}
              className="min-h-64 flex-1 resize-none font-mono text-xs leading-5 whitespace-pre"
              onChange={(e) => {
                const text = e.currentTarget.value;
                setDraft(null);
                setInput((i) => ({ ...i, body: text }));
              }}
            />
            <div className="flex items-center justify-between gap-2">
              <span className={cn("text-xs", errors ? "text-destructive" : "text-muted-foreground")}>
                {check ? problemSummary(problems) : "Checking…"}
                {check?.diskNeedMb ? ` · the disk layout needs ${diskText(check.diskNeedMb)}` : ""}
              </span>
              <Select value={sizeId} onValueChange={setSizeId}>
                <SelectTrigger size="sm" className="w-48" aria-label="Check the disk against a size">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={NONE}>Any size</SelectItem>
                  {sizes.map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      Fits {s.name}?
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {checkError && <p className="text-sm text-destructive">{checkError}</p>}
            {problems.length > 0 && (
              <ul className="max-h-40 overflow-y-auto rounded-md border text-sm" aria-label="Problems">
                {problems.map((p, index) => (
                  <li key={index} className="flex gap-2 border-b px-2 py-1 last:border-b-0">
                    <Badge
                      variant="outline"
                      className={cn(
                        "shrink-0",
                        p.severity === "error" ? "border-destructive/40 text-destructive" : "text-muted-foreground",
                      )}
                    >
                      {p.severity === "error" ? "Error" : "Warning"}
                    </Badge>
                    {p.line ? (
                      <button
                        type="button"
                        className="shrink-0 font-mono text-xs text-muted-foreground underline-offset-2 hover:underline"
                        onClick={() => jumpTo(p.line ?? 1)}
                      >
                        Line {p.line}
                      </button>
                    ) : null}
                    <span>{p.message}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>

        {error && <p className="text-sm text-destructive">{error}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            {starter ? "Close" : "Cancel"}
          </Button>
          {starter && existing ? (
            <WhyDisabled reason={readOnly}>
              <Button disabled={readOnly !== null} onClick={() => onCopy(copyOf(existing, taken))}>
                <CopyIcon data-icon="inline-start" />
                Make a copy
              </Button>
            </WhyDisabled>
          ) : (
            <WhyDisabled reason={reason}>
              <Button disabled={reason !== null} onClick={() => void save()}>
                {existing ? "Save" : "Add the install config"}
              </Button>
            </WhyDisabled>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---- The form's fields --------------------------------------------------------------------------------------------

interface FieldsProps {
  form: InstallForm;
  fields: FieldState[];
  maxUsers: number | null;
  kind: InstallConfigInput["kind"];
  locked: boolean;
  passwords: SecretMeta[];
  keys: SshKey[];
  secrets: InstallConfigInput["secrets"];
  onEdit: (change: Partial<InstallForm>) => void;
  onPick: (kind: SecretRefKind, name: string, secretId: string | null) => void;
}

function FormFields({ form, fields, maxUsers, kind, locked, passwords, keys, secrets, onEdit, onPick }: FieldsProps) {
  const state = (field: FormField) => fields.find((f) => f.field === field);
  const shown = fields.map((f) => f.field);
  const off = (field: FormField) => locked || !state(field)?.editable;
  const text = (
    field: "hostname" | "locale" | "keyboard" | "timezone" | "proxy" | "mirror",
    placeholderText: string,
  ) => (
    <Field key={field} state={state(field)}>
      <Input
        id={`ic-${field}`}
        value={form[field] ?? ""}
        placeholder={placeholderText}
        disabled={off(field)}
        className={field === "hostname" ? "font-mono" : undefined}
        onChange={(e) => {
          const value = e.currentTarget.value;
          onEdit({ [field]: value || null } as Partial<InstallForm>);
        }}
      />
    </Field>
  );
  const pickOf = (value: string | null, refKind: SecretRefKind) => {
    const name = refOf(value, refKind);
    return name ? (secrets.find((s) => s.kind === refKind && s.name === name)?.secretId ?? null) : null;
  };
  const keysInUsers = kind !== "preseed" && kind !== "unattend";

  function setUser(index: number, change: Partial<UserForm>) {
    onEdit({ users: form.users.map((u, i) => (i === index ? { ...u, ...change } : u)) });
  }

  return (
    <div className="grid gap-3">
      {shown.includes("hostname") && text("hostname", "{{hostname}}")}
      <div className="grid grid-cols-3 gap-2">
        {shown.includes("locale") && text("locale", kind === "unattend" ? "en-US" : "en_US.UTF-8")}
        {shown.includes("keyboard") && text("keyboard", kind === "unattend" ? "en-US" : "us")}
        {shown.includes("timezone") && text("timezone", kind === "unattend" ? "UTC" : "Etc/UTC")}
      </div>

      {shown.includes("storage") && (
        <Field state={state("storage")}>
          <div className="grid grid-cols-2 gap-2">
            <Select
              value={form.storage?.layout ?? NONE}
              disabled={off("storage")}
              onValueChange={(v) =>
                onEdit({
                  storage:
                    v === NONE ? null : { layout: v as "lvm" | "plain", swap: form.storage?.swap ?? { kind: "auto" } },
                })
              }
            >
              <SelectTrigger aria-label="Disk layout">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NONE}>The installer's default</SelectItem>
                <SelectItem value="lvm">LVM over the whole disk</SelectItem>
                <SelectItem value="plain">Plain partitions over the whole disk</SelectItem>
                {form.storage?.layout === "custom" && <SelectItem value="custom">The file's own layout</SelectItem>}
              </SelectContent>
            </Select>
            <Select
              value={form.storage?.swap.kind ?? "auto"}
              disabled={off("storage") || !form.storage}
              onValueChange={(v) => {
                if (!form.storage) return;
                const swap: Swap = v === "sizeMb" ? { kind: "sizeMb", mb: 4096 } : { kind: v as "auto" | "none" };
                onEdit({ storage: { ...form.storage, swap } });
              }}
            >
              <SelectTrigger aria-label="Swap">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Swap: the installer's choice</SelectItem>
                <SelectItem value="none">No swap</SelectItem>
                <SelectItem value="sizeMb">Swap of a size</SelectItem>
              </SelectContent>
            </Select>
            {form.storage?.swap.kind === "sizeMb" && (
              <Input
                aria-label="Swap in MB"
                type="number"
                min={0}
                value={form.storage.swap.mb}
                disabled={off("storage")}
                onChange={(e) => {
                  const mb = Number(e.currentTarget.value);
                  if (form.storage && Number.isFinite(mb))
                    onEdit({ storage: { ...form.storage, swap: { kind: "sizeMb", mb } } });
                }}
              />
            )}
          </div>
        </Field>
      )}

      {shown.includes("network") && (
        <Field state={state("network")}>
          <NetworkFields value={form.network} disabled={off("network")} onChange={(network) => onEdit({ network })} />
        </Field>
      )}

      {shown.includes("users") && (
        <Field state={state("users")}>
          <div className="grid gap-2">
            {form.users.map((u, index) => (
              <div key={index} className="grid gap-2 rounded-md border p-2">
                <div className="grid grid-cols-[1fr_1fr_auto_auto] items-center gap-2">
                  <Input
                    aria-label="User name"
                    data-mask="user"
                    value={u.name}
                    disabled={off("users") || kind === "unattend"}
                    onChange={(e) => {
                      const name = e.currentTarget.value;
                      setUser(index, { name });
                    }}
                  />
                  <Select
                    value={pickOf(u.password, "password") ?? (u.password ? "file" : NONE)}
                    disabled={off("users")}
                    onValueChange={(v) => {
                      if (v === NONE) return setUser(index, { password: null });
                      if (v === "file") return;
                      const name = refSlug(u.name);
                      onPick("password", name, v);
                      setUser(index, { password: placeholder("password", name) });
                    }}
                  >
                    <SelectTrigger aria-label={`${u.name}'s password`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>No password (locked)</SelectItem>
                      {u.password && !pickOf(u.password, "password") && (
                        <SelectItem value="file">As the file says</SelectItem>
                      )}
                      {passwords.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          Password: {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Label className="flex items-center gap-1 font-normal">
                    <Checkbox
                      checked={u.sudo}
                      disabled={off("users") || kind === "unattend" || kind === "autoinstall"}
                      onCheckedChange={(v) => setUser(index, { sudo: v === true })}
                    />
                    sudo
                  </Label>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Remove ${u.name}`}
                    title="Remove"
                    disabled={off("users") || kind === "unattend"}
                    onClick={() => onEdit({ users: form.users.filter((_, i) => i !== index) })}
                  >
                    <XIcon />
                  </Button>
                </div>
                {keysInUsers && (
                  <div className="flex flex-wrap items-center gap-1">
                    {u.sshKeys.map((k, ki) => {
                      const ref = refOf(k, "sshKey");
                      const label = ref
                        ? (keys.find((key) => key.id === pickOf(k, "sshKey"))?.label ?? `{{ssh_key.${ref}}}`)
                        : `${k.slice(0, 24)}…`;
                      return (
                        <Badge key={ki} variant="secondary" className="gap-1 font-normal">
                          {label}
                          {!off("users") && (
                            <button
                              type="button"
                              aria-label={`Remove the key ${label}`}
                              onClick={() => setUser(index, { sshKeys: u.sshKeys.filter((_, j) => j !== ki) })}
                            >
                              <XIcon className="size-3" />
                            </button>
                          )}
                        </Badge>
                      );
                    })}
                    {!off("users") && keys.length > 0 && (
                      <Select
                        value={NONE}
                        onValueChange={(v) => {
                          const key = keys.find((k) => k.id === v);
                          if (!key) return;
                          const name = refSlug(key.label);
                          onPick("sshKey", name, key.id);
                          const value = placeholder("sshKey", name);
                          if (!u.sshKeys.includes(value)) setUser(index, { sshKeys: [...u.sshKeys, value] });
                        }}
                      >
                        <SelectTrigger size="sm" className="w-44" aria-label={`Add an SSH key for ${u.name}`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE} disabled>
                            Add an SSH key
                          </SelectItem>
                          {keys
                            .filter((k) => k.public !== null)
                            .map((k) => (
                              <SelectItem key={k.id} value={k.id}>
                                {k.label}
                              </SelectItem>
                            ))}
                        </SelectContent>
                      </Select>
                    )}
                  </div>
                )}
              </div>
            ))}
            {!off("users") && (maxUsers === null || form.users.length < maxUsers) && (
              <Button
                variant="outline"
                size="sm"
                className="justify-self-start"
                onClick={() =>
                  onEdit({ users: [...form.users, { name: "admin", password: null, sshKeys: [], sudo: true }] })
                }
              >
                <PlusIcon data-icon="inline-start" />
                Add a user
              </Button>
            )}
          </div>
        </Field>
      )}

      {shown.includes("ssh") && (
        <Field state={state("ssh")}>
          <div className="flex gap-4">
            <Label className="flex items-center gap-2 font-normal">
              <Checkbox
                checked={form.ssh?.installServer ?? false}
                disabled={off("ssh") || kind === "cloudInit"}
                onCheckedChange={(v) =>
                  onEdit({
                    ssh: { installServer: v === true, passwordLogins: form.ssh?.passwordLogins ?? false },
                  })
                }
              />
              Install the SSH server
            </Label>
            <Label className="flex items-center gap-2 font-normal">
              <Checkbox
                checked={form.ssh?.passwordLogins ?? false}
                disabled={off("ssh")}
                onCheckedChange={(v) =>
                  onEdit({
                    ssh: { installServer: form.ssh?.installServer ?? true, passwordLogins: v === true },
                  })
                }
              />
              Password logins over SSH
            </Label>
          </div>
        </Field>
      )}

      {shown.includes("packages") && (
        <Field state={state("packages")}>
          <Input
            id="ic-packages"
            className="font-mono"
            defaultValue={form.packages.join(" ")}
            key={form.packages.join(" ")}
            placeholder="curl git"
            disabled={off("packages")}
            onBlur={(e) => onEdit({ packages: parseWords(e.currentTarget.value) })}
          />
        </Field>
      )}

      {shown.includes("updates") && (
        <Field state={state("updates")}>
          <Select
            value={form.updates ?? NONE}
            disabled={off("updates")}
            onValueChange={(v) => onEdit({ updates: v === NONE ? null : (v as Updates) })}
          >
            <SelectTrigger aria-label="Updates">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={NONE}>The installer's default</SelectItem>
              {kind !== "autoinstall" && <SelectItem value="none">None</SelectItem>}
              {kind !== "cloudInit" && <SelectItem value="security">Security updates</SelectItem>}
              <SelectItem value="all">Every update</SelectItem>
            </SelectContent>
          </Select>
        </Field>
      )}

      <div className="grid grid-cols-2 gap-2">
        {shown.includes("proxy") && text("proxy", "http://proxy.example.com:3128")}
        {shown.includes("mirror") && text("mirror", "http://mirror.example.com/")}
      </div>

      {shown.includes("lateCommands") && (
        <Field state={state("lateCommands")}>
          <Textarea
            id="ic-lateCommands"
            className="min-h-24 font-mono text-xs"
            defaultValue={form.lateCommands.join("\n")}
            key={form.lateCommands.join("\n")}
            placeholder="One command a line"
            disabled={off("lateCommands")}
            onBlur={(e) => onEdit({ lateCommands: parseLines(e.currentTarget.value) })}
          />
        </Field>
      )}
    </div>
  );
}

function Field({ state, children }: { state: FieldState | undefined; children: React.ReactNode }) {
  if (!state) return null;
  return (
    <div className="grid gap-1">
      <Label htmlFor={`ic-${state.field}`}>{FIELD_LABEL[state.field]}</Label>
      {children}
      {state.note && <p className="text-xs text-muted-foreground">{state.note}</p>}
    </div>
  );
}

function NetworkFields({
  value,
  disabled,
  onChange,
}: {
  value: NetworkForm | null;
  disabled: boolean;
  onChange: (value: NetworkForm | null) => void;
}) {
  return (
    <div className="grid gap-2">
      <Select
        value={value?.kind ?? NONE}
        disabled={disabled}
        onValueChange={(v) =>
          onChange(
            v === NONE
              ? null
              : v === "dhcp"
                ? { kind: "dhcp" }
                : { kind: "static", address: "{{ip}}", prefix: 24, gateway: null, dns: [] },
          )
        }
      >
        <SelectTrigger aria-label="Network">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={NONE}>The installer's default</SelectItem>
          <SelectItem value="dhcp">DHCP</SelectItem>
          <SelectItem value="static">A static address</SelectItem>
        </SelectContent>
      </Select>
      {value?.kind === "static" && (
        <div className="grid grid-cols-[2fr_1fr] gap-2">
          <Input
            aria-label="Address"
            className="font-mono"
            data-mask="ip"
            defaultValue={value.address}
            key={`a${value.address}`}
            disabled={disabled}
            onBlur={(e) => onChange({ ...value, address: e.currentTarget.value })}
          />
          <Input
            aria-label="Prefix length"
            type="number"
            min={1}
            max={32}
            defaultValue={value.prefix}
            key={`p${value.prefix}`}
            disabled={disabled}
            onBlur={(e) => onChange({ ...value, prefix: Number(e.currentTarget.value) || 24 })}
          />
          <Input
            aria-label="Gateway"
            className="font-mono"
            data-mask="ip"
            placeholder="Gateway"
            defaultValue={value.gateway ?? ""}
            key={`g${value.gateway}`}
            disabled={disabled}
            onBlur={(e) => onChange({ ...value, gateway: e.currentTarget.value || null })}
          />
          <Input
            aria-label="DNS servers"
            className="font-mono"
            placeholder="DNS servers"
            defaultValue={value.dns.join(" ")}
            key={`d${value.dns.join(" ")}`}
            disabled={disabled}
            onBlur={(e) => onChange({ ...value, dns: parseWords(e.currentTarget.value) })}
          />
        </div>
      )}
    </div>
  );
}
