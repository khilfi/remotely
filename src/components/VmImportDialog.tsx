// CV-01: Import a foreign VM or disk as a new local VM. Pick an OVA or OVF from any vendor, a disk image (VHD and
// VHDX from Hyper-V or Azure; qcow2, raw and .img from KVM, Proxmox or OpenStack; a VDI for Workstation, a VMDK for
// VirtualBox), or a VM's own description (a libvirt domain XML, a Proxmox .conf) with its disks beside it. The core
// reads what it is (specs from its description where there is one), and the import is a deploy: the same AP-02
// preview, approval (Medium; a Prod label High), job with its step, and cleanup as every deploy. The source is only
// read: each disk is copied or converted into the new VM's folder.

import { useEffect, useState } from "react";
import { ExternalLinkIcon, FileSearchIcon } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { DeployProgressView, useDeployProgress } from "@/components/DeployDialog";
import { DeployPreviewView } from "@/components/DeployPreviewView";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { useDebounced } from "@/hooks/use-debounced";
import {
  api,
  errorMessage,
  type DeployCheck,
  type Environment,
  type Firmware,
  type Hypervisor,
  type OsProfile,
  type Size,
  type SshKey,
  type SubmitOutcome,
  type TemplateNetwork,
} from "@/lib/api";
import { HYPERVISOR_LABEL } from "@/lib/catalog";
import { convertApi, type ImportAnalysis, type ImportRequest, type ToolsReport } from "@/lib/convert-api";
import { describedText, FORMAT_LABEL, importKindText, importReasons, qemuNote, sizeText } from "@/lib/convert";
import { deployReason, newVmKey, parsePackages, startProgress } from "@/lib/deploy";

interface Props {
  /** A file picked already (Image tools' Inspect); none: the dialog asks. */
  initialPath?: string | null;
  /** Goes through the app, which opens the approval dialog; `onJob` gets the job id once queued. */
  onSubmitted: (outcome: SubmitOutcome, onJob: (jobId: string) => void) => void;
  onClose: () => void;
}

type NetworkKind = "nat" | "hostOnly" | "bridged";

function positive(text: string): number | null {
  const n = Number(text.trim());
  return Number.isInteger(n) && n > 0 ? n : null;
}

export function VmImportDialog({ initialPath, onSubmitted, onClose }: Props) {
  const readOnly = useReadOnlyReason();
  const [path, setPath] = useState<string | null>(initialPath ?? null);
  const [read, setRead] = useState<{ path: string; analysis?: ImportAnalysis; error?: string } | null>(null);
  const [tools, setTools] = useState<ToolsReport | null>(null);
  const [profiles, setProfiles] = useState<OsProfile[]>([]);
  const [sizes, setSizes] = useState<Size[]>([]);
  const [keys, setKeys] = useState<SshKey[]>([]);
  const [name, setName] = useState("");
  const [hypervisor, setHypervisor] = useState<Hypervisor>("vmware");
  const [folder, setFolder] = useState("");
  const [profileId, setProfileId] = useState("other-linux");
  const [firmware, setFirmware] = useState<Firmware | "auto">("auto");
  const [sizeId, setSizeId] = useState<string>("source");
  const [vcpus, setVcpus] = useState("2");
  const [memory, setMemory] = useState("2048");
  const [thick, setThick] = useState(false);
  const [network, setNetwork] = useState<NetworkKind>("nat");
  const [adapters, setAdapters] = useState<string[]>([]);
  const [adapter, setAdapter] = useState<string | null>(null);
  const [environment, setEnvironment] = useState<Environment>("lab");
  const [openConsole, setOpenConsole] = useState(false);
  const [cleanSnapshot, setCleanSnapshot] = useState(false);
  const [cloudInit, setCloudInit] = useState(false);
  const [guestUser, setGuestUser] = useState("");
  const [keyId, setKeyId] = useState<string | null>(null);
  const [packages, setPackages] = useState("");
  const [check, setCheck] = useState<{ key: string; check: DeployCheck } | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setStarted] = useDeployProgress();

  useEffect(() => {
    let stopped = false;
    Promise.all([api.catalogProfiles(), api.catalogSizes(), convertApi.tools()]).then(
      ([p, s, t]) => {
        if (stopped) return;
        setProfiles(p);
        setSizes(s);
        setTools(t);
      },
      (err) => !stopped && setError(errorMessage(err)),
    );
    api.sshKeys().then(
      (k) => !stopped && setKeys(k.filter((x) => x.public !== null)),
      () => {},
    );
    return () => {
      stopped = true;
    };
  }, []);

  // What the picked file is: read once per file, the dialog's fields starting from what it says.
  useEffect(() => {
    if (!path) return;
    let stopped = false;
    convertApi.importAnalyze(path).then(
      (a) => {
        if (stopped) return;
        setRead({ path, analysis: a });
        setName(a.suggestedName);
        if (a.profile) setProfileId(a.profile);
        if (a.described.vcpus) setVcpus(String(a.described.vcpus));
        if (a.described.memoryMb) setMemory(String(a.described.memoryMb));
        const reasons = importReasons(a);
        if (reasons.vmware && !reasons.virtualbox) setHypervisor("virtualbox");
      },
      (err) => !stopped && setRead({ path, error: errorMessage(err) }),
    );
    return () => {
      stopped = true;
    };
  }, [path]);
  const analysis = read?.path === path ? (read.analysis ?? null) : null;
  const analyzing = path !== null && read?.path !== path;
  const analyzeError = read?.path === path ? (read.error ?? null) : null;

  const needsAdapter = hypervisor === "virtualbox" && network !== "nat";
  useEffect(() => {
    if (!needsAdapter) return;
    let stopped = false;
    api.deployHostAdapters(network === "bridged").then(
      (list) => {
        if (stopped) return;
        setAdapters(list);
        setAdapter((a) => (a && list.includes(a) ? a : (list[0] ?? null)));
      },
      () => !stopped && setAdapters([]),
    );
    return () => {
      stopped = true;
    };
  }, [needsAdapter, network]);

  async function choose() {
    try {
      const picked = await convertApi.pick("import");
      if (picked) setPath(picked);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function chooseFolder() {
    try {
      const picked = await api.catalogFolderPick();
      if (picked) setFolder(picked);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const fromSource = sizeId === "source";
  const request: ImportRequest | null =
    path && analysis
      ? {
          source: path,
          hypervisor,
          name: name.trim(),
          folder: folder.trim() || null,
          profileId,
          firmware: firmware === "auto" ? null : firmware,
          sizeId: fromSource ? null : sizeId,
          vcpus: fromSource ? positive(vcpus) : null,
          coresPerSocket: null,
          memoryMb: fromSource ? positive(memory) : null,
          thick,
          network: { kind: network } as TemplateNetwork,
          hostAdapter: needsAdapter ? adapter : null,
          environment,
          tags: [],
          afterDeploy: { createSession: false, linkSession: false, cleanSnapshot, openConsole },
          cloudInit:
            cloudInit && analysis.kind !== "appliance"
              ? { guestUser: guestUser.trim() || null, sshKeyId: keyId, packages: parsePackages(packages) }
              : null,
        }
      : null;
  const requestKey = JSON.stringify(request);
  const checkedKey = useDebounced(requestKey, 300);
  const following = progress !== null;

  useEffect(() => {
    if (checkedKey === "null" || following) return;
    const asked = JSON.parse(checkedKey) as ImportRequest;
    let stopped = false;
    convertApi.importCheck(asked).then(
      (c) => {
        if (stopped) return;
        setCheck({ key: checkedKey, check: c });
        setCheckError(null);
      },
      (err) => {
        if (stopped) return;
        setCheck(null);
        setCheckError(errorMessage(err));
      },
    );
    return () => {
      stopped = true;
    };
  }, [checkedKey, following]);

  const current = check?.key === requestKey ? check.check : null;
  const reasons = importReasons(analysis);
  const reason =
    readOnly ??
    (!path ? "Choose a file to import" : null) ??
    (analysis ? null : analyzing ? "Reading it…" : "It couldn't be read") ??
    (hypervisor === "vmware" ? reasons.vmware : reasons.virtualbox) ??
    deployReason({
      busy,
      count: 1,
      checking: requestKey !== checkedKey || (!current && !checkError),
      check: current,
      error: checkError,
    });
  const note = analysis?.needsQemuImg ? qemuNote(tools) : null;

  async function importIt() {
    if (!request || !current?.preview) return;
    setBusy(true);
    setError(null);
    try {
      const target = newVmKey(hypervisor, request.name);
      onSubmitted(await convertApi.importSubmit(request), (jobId) =>
        setStarted(startProgress(jobId, [{ name: request.name, target }])),
      );
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const running = progress !== null && progress.finished === null;
  const specs = analysis ? describedText(analysis) : null;

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle>{progress ? `Import ${name}` : "Import a VM or disk"}</DialogTitle>
          <DialogDescription>
            {progress
              ? "Cancel stops the job: the VM being made is removed with everything it made. The source stays as it was."
              : "From another hypervisor or a cloud: an OVA or OVF, a VHD or VHDX, a qcow2 or raw disk, or a KVM or Proxmox VM's own description. It becomes a new VM here, through the same preview and approval as a deploy."}
          </DialogDescription>
        </DialogHeader>

        {progress ? (
          <DeployProgressView progress={progress} />
        ) : (
          <div className="-mx-1 grid max-h-[65vh] gap-4 overflow-x-hidden overflow-y-auto px-1">
            <div className="flex flex-wrap items-center gap-2">
              <Button variant="outline" onClick={() => void choose()}>
                <FileSearchIcon data-icon="inline-start" />
                {path ? "Choose another file…" : "Choose a file…"}
              </Button>
              {path && <code className="min-w-0 truncate font-mono text-xs">{path}</code>}
            </div>

            {analysis && (
              <div className="grid gap-1 rounded-md border p-3 text-sm">
                <div>{importKindText(analysis)}</div>
                {specs && <div className="text-muted-foreground">It says: {specs}.</div>}
                {analysis.disks.length > 0 && (
                  <ul className="grid gap-0.5">
                    {analysis.disks.map((d, i) => (
                      <li key={`${d.name}-${i}`} className="text-xs">
                        Disk {i + 1}: <code className="font-mono">{d.name}</code>
                        {d.info ? `, ${FORMAT_LABEL[d.info.format]}` : ""}
                        {d.virtualBytes !== null ? `, ${sizeText(d.virtualBytes)}` : ""}
                        {d.problem && <span className="text-destructive"> ({d.problem})</span>}
                      </li>
                    ))}
                  </ul>
                )}
                {analysis.problems.map((p) => (
                  <p key={p} className="text-destructive" role="alert">
                    {p}
                  </p>
                ))}
                {analysis.notes.map((n) => (
                  <p key={n} className="text-xs text-muted-foreground">
                    {n}
                  </p>
                ))}
              </div>
            )}

            {analysis && (
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                <div className="grid gap-2">
                  <Label htmlFor="import-name">Name</Label>
                  <Input
                    id="import-name"
                    value={name}
                    maxLength={60}
                    onChange={(e) => setName(e.currentTarget.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="import-hypervisor">Hypervisor</Label>
                  <Select value={hypervisor} onValueChange={(v) => setHypervisor(v as Hypervisor)}>
                    <SelectTrigger id="import-hypervisor" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(["vmware", "virtualbox"] as Hypervisor[]).map((h) => {
                        const why = h === "vmware" ? reasons.vmware : reasons.virtualbox;
                        return (
                          <SelectItem key={h} value={h} disabled={why !== null}>
                            {HYPERVISOR_LABEL[h]}
                            {why ? `: ${why}` : ""}
                          </SelectItem>
                        );
                      })}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="import-profile">OS profile</Label>
                  <Select value={profileId} onValueChange={setProfileId}>
                    <SelectTrigger id="import-profile" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {profiles.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          {p.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="import-firmware">Firmware</Label>
                  <Select value={firmware} onValueChange={(v) => setFirmware(v as Firmware | "auto")}>
                    <SelectTrigger id="import-firmware" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">
                        {analysis.described.efi === null
                          ? "The OS profile's"
                          : `As the source says (${analysis.described.efi ? "UEFI" : "BIOS"})`}
                      </SelectItem>
                      <SelectItem value="bios">BIOS</SelectItem>
                      <SelectItem value="efi">UEFI</SelectItem>
                      <SelectItem value="efiSecureBoot">UEFI with Secure Boot</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="import-size">Size</Label>
                  <Select value={sizeId} onValueChange={setSizeId}>
                    <SelectTrigger id="import-size" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="source">The source&apos;s own (its disks, CPU and memory below)</SelectItem>
                      {sizes.map((s) => (
                        <SelectItem key={s.id} value={s.id}>
                          {s.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                {fromSource && (
                  <div className="grid grid-cols-2 gap-2">
                    <div className="grid gap-2">
                      <Label htmlFor="import-vcpus">vCPU</Label>
                      <Input
                        id="import-vcpus"
                        inputMode="numeric"
                        value={vcpus}
                        onChange={(e) => setVcpus(e.currentTarget.value)}
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="import-memory">Memory (MB)</Label>
                      <Input
                        id="import-memory"
                        inputMode="numeric"
                        value={memory}
                        onChange={(e) => setMemory(e.currentTarget.value)}
                      />
                    </div>
                  </div>
                )}
                <div className="grid gap-2">
                  <Label htmlFor="import-network">Network</Label>
                  <Select value={network} onValueChange={(v) => setNetwork(v as NetworkKind)}>
                    <SelectTrigger id="import-network" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="nat">NAT</SelectItem>
                      <SelectItem value="hostOnly">Host-only</SelectItem>
                      <SelectItem value="bridged">Bridged</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {needsAdapter && (
                  <div className="grid gap-2">
                    <Label htmlFor="import-adapter">{network === "bridged" ? "Bridge to" : "Host-only network"}</Label>
                    <Select value={adapter ?? ""} onValueChange={setAdapter}>
                      <SelectTrigger id="import-adapter" className="w-full">
                        <SelectValue placeholder="VirtualBox lists none" />
                      </SelectTrigger>
                      <SelectContent>
                        {adapters.map((a) => (
                          <SelectItem key={a} value={a}>
                            {a}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}
                <div className="grid gap-2">
                  <Label htmlFor="import-env">Label</Label>
                  <Select value={environment} onValueChange={(v) => setEnvironment(v as Environment)}>
                    <SelectTrigger id="import-env" className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="none">None</SelectItem>
                      <SelectItem value="lab">Lab</SelectItem>
                      <SelectItem value="staging">Staging</SelectItem>
                      <SelectItem value="prod">Prod</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="col-span-2 grid gap-2 sm:col-span-3">
                  <Label htmlFor="import-folder">VM folder</Label>
                  <div className="flex gap-2">
                    <Input
                      id="import-folder"
                      value={folder}
                      placeholder={`${HYPERVISOR_LABEL[hypervisor]}'s default folder`}
                      onChange={(e) => setFolder(e.currentTarget.value)}
                    />
                    <Button variant="outline" onClick={() => void chooseFolder()}>
                      Browse…
                    </Button>
                  </div>
                </div>
                <div className="col-span-2 flex flex-wrap gap-4 text-sm sm:col-span-3">
                  <label className="flex items-center gap-2">
                    <Checkbox checked={thick} onCheckedChange={(v) => setThick(v === true)} />
                    Thick disks (their full size at once)
                  </label>
                  <label className="flex items-center gap-2">
                    <Checkbox checked={cleanSnapshot} onCheckedChange={(v) => setCleanSnapshot(v === true)} />A
                    &quot;clean&quot; snapshot before its first boot
                  </label>
                  <label className="flex items-center gap-2">
                    <Checkbox checked={openConsole} onCheckedChange={(v) => setOpenConsole(v === true)} />
                    Open its console
                  </label>
                  {analysis.kind !== "appliance" && (
                    <label className="flex items-center gap-2">
                      <Checkbox checked={cloudInit} onCheckedChange={(v) => setCloudInit(v === true)} />
                      It&apos;s a cloud image: set it up with cloud-init on first boot
                    </label>
                  )}
                </div>
                {cloudInit && analysis.kind !== "appliance" && (
                  <>
                    <div className="grid gap-2">
                      <Label htmlFor="import-user">Guest user</Label>
                      <Input
                        id="import-user"
                        placeholder="The image's default user"
                        value={guestUser}
                        onChange={(e) => setGuestUser(e.currentTarget.value)}
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="import-key">SSH key</Label>
                      <Select value={keyId ?? "none"} onValueChange={(v) => setKeyId(v === "none" ? null : v)}>
                        <SelectTrigger id="import-key" className="w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">None</SelectItem>
                          {keys.map((k) => (
                            <SelectItem key={k.id} value={k.id}>
                              {k.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="import-packages">Packages</Label>
                      <Input
                        id="import-packages"
                        placeholder="nginx, htop"
                        value={packages}
                        onChange={(e) => setPackages(e.currentTarget.value)}
                      />
                    </div>
                  </>
                )}
              </div>
            )}

            {note && (
              <Alert>
                <AlertTitle>This needs qemu-img</AlertTitle>
                <AlertDescription className="grid gap-2">
                  <span>{note}</span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-fit"
                    onClick={() => tools && void convertApi.openQemuSite(tools.downloadPage)}
                  >
                    <ExternalLinkIcon data-icon="inline-start" />
                    QEMU&apos;s download page
                  </Button>
                </AlertDescription>
              </Alert>
            )}
            {current?.problems.length ? (
              <ul className="grid gap-1 text-sm text-destructive" role="alert">
                {current.problems.map((p) => (
                  <li key={p.code + p.message}>{p.message}</li>
                ))}
              </ul>
            ) : null}
            {checkError && (
              <p className="text-sm text-destructive" role="alert">
                {checkError}
              </p>
            )}
            {current?.preview && <DeployPreviewView preview={current.preview} />}
          </div>
        )}

        {analyzeError && (
          <p className="text-sm text-destructive" role="alert">
            {analyzeError}
          </p>
        )}
        {error && (
          <p className="text-sm text-destructive" role="alert">
            {error}
          </p>
        )}
        <DialogFooter>
          {progress ? (
            <>
              {running && (
                <Button variant="outline" onClick={() => void api.cancelJob(progress.jobId)}>
                  Cancel the job
                </Button>
              )}
              <Button onClick={onClose}>{running ? "Hide" : "Close"}</Button>
            </>
          ) : (
            <>
              <Button variant="outline" onClick={onClose} disabled={busy}>
                Cancel
              </Button>
              <WhyDisabled reason={reason}>
                <Button onClick={() => void importIt()} disabled={reason !== null}>
                  {busy ? "Submitting…" : "Import"}
                </Button>
              </WhyDisabled>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
