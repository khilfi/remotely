// VM-23, VM-12, VM-11, VM-16: the Settings tab's edit dialogs. Each builds one command for the bus and hands it
// to `onSubmit` (the page's submit, which shows the approval dialog when the tier asks for one); the shared folder's
// path is picked in a dialog the shell opens (api.vmPickSharedFolder), never typed here. The core checks every
// value again and the approval preview shows what changes on each VM.

import { useEffect, useState, type ReactNode } from "react";
import { FolderOpenIcon, TriangleAlertIcon } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
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
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { usePresentation } from "@/components/Presentation";
import {
  api,
  errorMessage,
  type Command,
  type VmFirmware,
  type GuestOsType,
  type MacAddress,
  type NicNetwork,
  type SubmitOutcome,
  type TargetRef,
  type VirtualDisk,
  type VirtualNic,
  type VmHardware,
  type VmRecord,
} from "@/lib/api";
import {
  cardModels,
  formatMb,
  gbToMb,
  macProblem,
  networkKinds,
  networkOf,
  normalMac,
  resourcesProblem,
  shareNameProblem,
  tpmReason,
  workstationWarning,
} from "@/lib/vm-settings";

/** Submits one command; resolves true when the bus took it (queued, or waiting for approval). */
export type Submit = (command: Command) => Promise<boolean>;

const target = (vm: VmRecord): TargetRef => ({ kind: "vm", vmxPath: vm.vmxPath });

function EditDialog({
  title,
  description,
  submitLabel,
  problem,
  onSubmit,
  onClose,
  children,
  wide,
  vms,
}: {
  title: string;
  description: ReactNode;
  submitLabel: string;
  /** Why it can't be sent yet; null when it can. */
  problem: string | null;
  /** Resolves true when the command went to the bus. */
  onSubmit: () => Promise<boolean>;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  /** The VMs it changes: a Workstation one gets the warning while Workstation's window runs. */
  vms: Pick<VmRecord, "hypervisor">[];
}) {
  const [busy, setBusy] = useState(false);
  const warning = useWorkstationWarning(vms);
  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className={wide ? "sm:max-w-lg" : "sm:max-w-md"}>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (problem) return;
            setBusy(true);
            void onSubmit()
              .then((sent) => sent && onClose())
              .finally(() => setBusy(false));
          }}
        >
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            <DialogDescription>{description}</DialogDescription>
          </DialogHeader>
          {children}
          {warning && (
            <Alert>
              <TriangleAlertIcon />
              <AlertDescription>{warning}</AlertDescription>
            </Alert>
          )}
          {problem && <p className="text-xs text-muted-foreground">{problem}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" disabled={problem !== null || busy}>
              {submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** VM-23: the warning while Workstation's window runs, asked once when a dialog for a Workstation VM opens. */
export function useWorkstationWarning(vms: Pick<VmRecord, "hypervisor">[]): string | null {
  const vmware = vms.some((vm) => vm.hypervisor === "vmware");
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!vmware) return;
    let stale = false;
    api.vmWorkstationOpen().then(
      (running) => {
        if (!stale) setOpen(running);
      },
      () => undefined,
    );
    return () => {
      stale = true;
    };
  }, [vmware]);
  return workstationWarning(vms, vmware && open);
}

function Field({ id, label, children, hint }: { id: string; label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function SwitchRow({
  id,
  label,
  checked,
  onChange,
  disabled,
  hint,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (on: boolean) => void;
  disabled?: boolean;
  hint?: string | null;
}) {
  return (
    <div className="flex items-start gap-3">
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
      <div className="grid gap-0.5">
        <Label htmlFor={id}>{label}</Label>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
    </div>
  );
}

const whole = (text: string) => (text.trim() === "" ? null : Number(text));

/**
 * VM-23, VM-12: vCPUs, cores per socket (Workstation), memory and nested virtualization, for one VM or every VM of
 * a bulk resize (one approval). Fields left empty keep what each VM has.
 */
export function ResourcesDialog({
  vms,
  hardware,
  left,
  onSubmit,
  onClose,
}: {
  vms: VmRecord[];
  /** One VM's hardware, to start from. */
  hardware?: VmHardware | null;
  /** VM-12: selected VMs a bulk resize leaves out, and why. */
  left?: { name: string; why: string }[];
  onSubmit: Submit;
  onClose: () => void;
}) {
  const one = vms.length === 1 ? vms[0] : null;
  const [vcpus, setVcpus] = useState(one ? String(hardware?.vcpus ?? one.numVcpus ?? "") : "");
  const [cores, setCores] = useState(hardware?.coresPerSocket ? String(hardware.coresPerSocket) : "");
  const [memoryGb, setMemoryGb] = useState(() => {
    const mb = hardware?.memoryMb ?? one?.memsizeMb ?? null;
    return one && mb ? String(mb / 1024) : "";
  });
  const [nested, setNested] = useState<boolean | null>(one ? (hardware?.nestedVirtualization ?? false) : null);
  const hypervisors = [...new Set(vms.map((v) => v.hypervisor))];
  const workstationOnly = hypervisors.every((h) => h === "vmware");
  const memoryMb = memoryGb.trim() === "" ? null : gbToMb(memoryGb);
  const values = {
    vcpus: whole(vcpus),
    coresPerSocket: workstationOnly ? whole(cores) : null,
    memoryMb,
    hypervisors,
  };
  const unchanged =
    one &&
    values.vcpus === (hardware?.vcpus ?? one.numVcpus) &&
    values.memoryMb === (hardware?.memoryMb ?? one.memsizeMb) &&
    (values.coresPerSocket ?? null) === (hardware?.coresPerSocket ?? null) &&
    nested === (hardware?.nestedVirtualization ?? false);
  const problem =
    memoryGb.trim() !== "" && memoryMb === null
      ? "Memory: a size in GB"
      : unchanged
        ? "Change something first"
        : resourcesProblem({ ...values, coresPerSocket: values.coresPerSocket });
  const nestedChanged = one ? nested !== (hardware?.nestedVirtualization ?? false) : nested !== null;
  return (
    <EditDialog
      vms={vms}
      title={one ? `CPU and memory of ${one.displayName}` : `Resize ${vms.length} VMs`}
      description={
        one
          ? "The VM must be off. Workstation's settings are written to its .vmx after a backup copy; VirtualBox's through VBoxManage."
          : "One approval for every VM listed; empty fields keep what each VM has. Each VM must be off."
      }
      submitLabel={one ? "Save" : `Resize ${vms.length} VMs`}
      problem={problem}
      onSubmit={() =>
        onSubmit({
          type: "vmConfig",
          targets: vms.map(target),
          edit: {
            kind: "resources",
            vcpus: values.vcpus,
            coresPerSocket: values.coresPerSocket,
            memoryMb: values.memoryMb,
            nestedVirtualization: nestedChanged ? nested : null,
          },
        })
      }
      onClose={onClose}
    >
      <div className="grid grid-cols-2 gap-3">
        <Field id="res-vcpus" label="vCPUs">
          <Input id="res-vcpus" inputMode="numeric" value={vcpus} onChange={(e) => setVcpus(e.currentTarget.value)} />
        </Field>
        {workstationOnly && (
          <Field id="res-cores" label="Cores per socket" hint="Must divide the vCPUs">
            <Input
              id="res-cores"
              inputMode="numeric"
              placeholder="1"
              value={cores}
              onChange={(e) => setCores(e.currentTarget.value)}
            />
          </Field>
        )}
        <Field id="res-memory" label="Memory (GB)" hint={memoryMb ? formatMb(memoryMb) : undefined}>
          <Input
            id="res-memory"
            inputMode="decimal"
            value={memoryGb}
            onChange={(e) => setMemoryGb(e.currentTarget.value)}
          />
        </Field>
      </div>
      <SwitchRow
        id="res-nested"
        label="Nested virtualization"
        hint="Lets the guest run VMs or containers that need hardware virtualization"
        checked={nested ?? false}
        onChange={setNested}
      />
      {left && left.length > 0 && (
        <Alert>
          <AlertDescription>
            <p>Left out:</p>
            <ul className="list-disc pl-5">
              {left.map((l) => (
                <li key={l.name}>
                  {l.name}: {l.why}
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
    </EditDialog>
  );
}

/** VM-23: BIOS or UEFI, Secure Boot, and on VirtualBox a TPM 2.0 (Windows 11). */
export function FirmwareDialog({
  vm,
  hardware,
  onSubmit,
  onClose,
}: {
  vm: VmRecord;
  hardware: VmHardware;
  onSubmit: Submit;
  onClose: () => void;
}) {
  const [firmware, setFirmware] = useState<VmFirmware>(hardware.firmware === "UEFI" ? "efi" : "bios");
  const [secureBoot, setSecureBoot] = useState(hardware.secureBoot ?? false);
  const hasTpm = hardware.tpm !== null;
  const [tpm, setTpm] = useState(hasTpm);
  const noTpm = tpmReason(vm.hypervisor);
  const problem = firmware === "bios" && (secureBoot || tpm) ? "Secure Boot and a TPM need UEFI" : null;
  return (
    <EditDialog
      vms={[vm]}
      title={`Firmware of ${vm.displayName}`}
      description="The VM must be off. A guest installed with BIOS usually doesn't boot with UEFI, and the other way round."
      submitLabel="Save"
      problem={problem}
      onSubmit={() =>
        onSubmit({
          type: "vmConfig",
          targets: [target(vm)],
          edit: {
            kind: "firmware",
            firmware,
            secureBoot: firmware === "efi" && secureBoot,
            tpm: noTpm || tpm === hasTpm ? null : tpm,
          },
        })
      }
      onClose={onClose}
    >
      <RadioGroup value={firmware} onValueChange={(v) => setFirmware(v as VmFirmware)} className="flex gap-6">
        <div className="flex items-center gap-2">
          <RadioGroupItem value="bios" id="fw-bios" />
          <Label htmlFor="fw-bios">BIOS</Label>
        </div>
        <div className="flex items-center gap-2">
          <RadioGroupItem value="efi" id="fw-efi" />
          <Label htmlFor="fw-efi">UEFI</Label>
        </div>
      </RadioGroup>
      <SwitchRow
        id="fw-secure"
        label="Secure Boot"
        checked={firmware === "efi" && secureBoot}
        onChange={setSecureBoot}
        disabled={firmware !== "efi"}
        hint={firmware !== "efi" ? "Needs UEFI" : null}
      />
      <SwitchRow
        id="fw-tpm"
        label="TPM 2.0"
        checked={tpm}
        onChange={setTpm}
        disabled={noTpm !== null || firmware !== "efi"}
        hint={noTpm ?? (firmware !== "efi" ? "Needs UEFI" : "For Windows 11")}
      />
    </EditDialog>
  );
}

/** VM-23: the guest OS the VM is set up for, from the hypervisor's own list. */
export function GuestOsDialog({
  vm,
  hardware,
  onSubmit,
  onClose,
}: {
  vm: VmRecord;
  hardware: VmHardware;
  onSubmit: Submit;
  onClose: () => void;
}) {
  const [types, setTypes] = useState<GuestOsType[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const current = hardware.guestOs ?? "";
  const [chosen, setChosen] = useState("");
  useEffect(() => {
    api.vmGuestOsTypes(vm.vmxPath).then(setTypes, (err) => setError(errorMessage(err)));
  }, [vm.vmxPath]);
  // VirtualBox prints a VM's type by its description; its id is what modifyvm takes.
  const currentId = types?.find((t) => t.id === current || t.description === current)?.id ?? current;
  const value = chosen || currentId;
  const options = types ?? [];
  const shown =
    options.some((t) => t.id === currentId) || !currentId
      ? options
      : [{ id: currentId, description: current }, ...options];
  return (
    <EditDialog
      vms={[vm]}
      title={`Guest OS type of ${vm.displayName}`}
      description="What the VM is set up for: it decides the defaults the hypervisor uses (devices, drivers). It changes nothing in the guest. The VM must be off."
      submitLabel="Save"
      problem={error ?? (!types ? "Reading the types…" : !value || value === currentId ? "Choose another type" : null)}
      onSubmit={() => onSubmit({ type: "vmConfig", targets: [target(vm)], edit: { kind: "guestOs", osType: value } })}
      onClose={onClose}
    >
      <Field id="guest-os" label="Guest OS type">
        <Select value={value} onValueChange={setChosen}>
          <SelectTrigger id="guest-os" className="w-full">
            <SelectValue placeholder="Choose a type" />
          </SelectTrigger>
          <SelectContent className="max-h-72">
            {shown.map((t) => (
              <SelectItem key={t.id} value={t.id}>
                {t.description}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
    </EditDialog>
  );
}

/** VM-11: a new network adapter, or one adapter's network, card, MAC and power-on connection. */
export function NicDialog({
  vm,
  nic,
  onSubmit,
  onClose,
}: {
  vm: VmRecord;
  /** The adapter to change; none to add one. */
  nic?: VirtualNic;
  onSubmit: Submit;
  onClose: () => void;
}) {
  const kinds = networkKinds(vm.hypervisor);
  const startKind = (): NicNetwork["kind"] => {
    const c = (nic?.connection ?? "nat").toLowerCase();
    if (c.startsWith("custom")) return "custom";
    if (c === "hostonly") return "hostOnly";
    if (c === "natnetwork") return "natNetwork";
    if (c === "intnet") return "internal";
    if (c === "bridged") return "bridged";
    return "nat";
  };
  const [kind, setKind] = useState<NicNetwork["kind"]>(startKind);
  const [name, setName] = useState(nic?.networkName ?? "");
  const models = cardModels(vm.hypervisor);
  const [model, setModel] = useState(nic?.model ?? "");
  const [macMode, setMacMode] = useState<"keep" | "generated" | "static">("keep");
  const [mac, setMac] = useState(nic?.mac ?? "");
  const [connect, setConnect] = useState(nic?.connected ?? true);
  const named = kinds.find((k) => k.kind === kind)?.named;
  const network = networkOf(kind, name);
  const problem = !network
    ? kind === "custom"
      ? "Name the VMnet: VMnet0 to VMnet19"
      : "Name the network"
    : macMode === "static"
      ? macProblem(mac, vm.hypervisor)
      : null;
  const macValue: MacAddress | null =
    macMode === "generated"
      ? { kind: "generated" }
      : macMode === "static"
        ? { kind: "static", mac: normalMac(mac) ?? mac }
        : null;
  return (
    <EditDialog
      vms={[vm]}
      title={nic ? `Network adapter ${nic.slot} of ${vm.displayName}` : `Add a network adapter to ${vm.displayName}`}
      description="The VM must be off. To plug the cable in or out of a running VM, use Connect or Disconnect."
      submitLabel={nic ? "Save" : "Add adapter"}
      problem={problem}
      onSubmit={() =>
        network
          ? onSubmit(
              nic
                ? {
                    type: "vmConfig",
                    targets: [target(vm)],
                    edit: {
                      kind: "editNic",
                      slot: nic.slot,
                      network,
                      model: model && model !== nic.model ? model : null,
                      mac: macValue,
                      connectAtPowerOn: connect !== (nic.connected ?? true) ? connect : null,
                    },
                  }
                : { type: "vmConfig", targets: [target(vm)], edit: { kind: "addNic", network, model: model || null } },
            )
          : Promise.resolve(false)
      }
      onClose={onClose}
    >
      <Field id="nic-network" label="Network">
        <Select value={kind} onValueChange={(v) => setKind(v as NicNetwork["kind"])}>
          <SelectTrigger id="nic-network" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {kinds.map((k) => (
              <SelectItem key={k.kind} value={k.kind}>
                {k.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      {named && (
        <Field id="nic-name" label={named}>
          <Input id="nic-name" autoComplete="off" value={name} onChange={(e) => setName(e.currentTarget.value)} />
        </Field>
      )}
      <Field id="nic-model" label="Card">
        <Select value={model || "default"} onValueChange={(v) => setModel(v === "default" ? "" : v)}>
          <SelectTrigger id="nic-model" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="default">{nic?.model ? `Keep ${nic.model}` : "The hypervisor's default"}</SelectItem>
            {models
              .filter((m) => m !== nic?.model)
              .map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
          </SelectContent>
        </Select>
      </Field>
      {nic && (
        <>
          <Field id="nic-mac" label="MAC address">
            <Select value={macMode} onValueChange={(v) => setMacMode(v as typeof macMode)}>
              <SelectTrigger id="nic-mac" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="keep">Keep the one it has</SelectItem>
                <SelectItem value="generated">A new one, made by the hypervisor</SelectItem>
                <SelectItem value="static">One I choose</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          {macMode === "static" && (
            <Input
              aria-label="MAC address"
              data-mask="mac"
              autoComplete="off"
              placeholder={vm.hypervisor === "vmware" ? "00:50:56:00:00:01" : "08:00:27:00:00:01"}
              value={mac}
              onChange={(e) => setMac(e.currentTarget.value)}
            />
          )}
          <SwitchRow id="nic-connect" label="Connected when the VM starts" checked={connect} onChange={setConnect} />
        </>
      )}
    </EditDialog>
  );
}

/** VM-16: a new disk file in the VM's folder, on the boot disk's controller unless another is chosen. */
export function DiskAddDialog({
  vm,
  hardware,
  onSubmit,
  onClose,
}: {
  vm: VmRecord;
  hardware: VmHardware;
  onSubmit: Submit;
  onClose: () => void;
}) {
  const [sizeGb, setSizeGb] = useState("20");
  const [thin, setThin] = useState(true);
  const [bus, setBus] = useState("boot");
  const sizeMb = gbToMb(sizeGb);
  const problem = !sizeMb ? "The size in GB" : sizeMb > 8 * 1024 * 1024 ? "At most 8 TB" : null;
  return (
    <EditDialog
      vms={[vm]}
      title={`Add a disk to ${vm.displayName}`}
      description="A new disk file in the VM's folder. The VM must be off; the guest still has to partition and format it."
      submitLabel="Add disk"
      problem={problem}
      onSubmit={() =>
        sizeMb
          ? onSubmit({
              type: "vmDisk",
              targets: [target(vm)],
              op: { kind: "add", sizeMb, thin, bus: bus === "boot" ? null : bus },
            })
          : Promise.resolve(false)
      }
      onClose={onClose}
    >
      <Field id="disk-size" label="Size (GB)">
        <Input id="disk-size" inputMode="decimal" value={sizeGb} onChange={(e) => setSizeGb(e.currentTarget.value)} />
      </Field>
      <SwitchRow
        id="disk-thin"
        label="Thin"
        checked={thin}
        onChange={setThin}
        hint={thin ? "Takes only what the guest writes" : "Allocates the whole size on this PC now"}
      />
      {hardware.controllers.length > 1 && (
        <Field id="disk-bus" label="Controller">
          <Select value={bus} onValueChange={setBus}>
            <SelectTrigger id="disk-bus" className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="boot">The boot disk&apos;s</SelectItem>
              {hardware.controllers.map((c) => (
                <SelectItem key={c.name} value={c.name}>
                  {c.name}
                  {c.kind ? ` (${c.kind})` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Field>
      )}
    </EditDialog>
  );
}

/** VM-16: a disk grown to a new size. It can't be shrunk back. */
export function DiskExpandDialog({
  vm,
  disk,
  onSubmit,
  onClose,
}: {
  vm: VmRecord;
  disk: VirtualDisk;
  onSubmit: Submit;
  onClose: () => void;
}) {
  const nowMb = disk.provisionedBytes ? Math.round(disk.provisionedBytes / (1024 * 1024)) : null;
  const [sizeGb, setSizeGb] = useState(nowMb ? String(Math.ceil((nowMb * 1.5) / 1024)) : "");
  const sizeMb = gbToMb(sizeGb);
  const problem = !sizeMb
    ? "The new size in GB"
    : nowMb && sizeMb <= nowMb
      ? `Larger than ${formatMb(nowMb)}: a disk only grows`
      : null;
  return (
    <EditDialog
      vms={[vm]}
      title={`Expand disk ${disk.slot} of ${vm.displayName}`}
      description="The disk grows; it can't be shrunk back. The guest's partition and filesystem have to be grown in the guest afterwards. The VM must be off and have no snapshots."
      submitLabel="Expand"
      problem={problem}
      onSubmit={() =>
        sizeMb
          ? onSubmit({ type: "vmDisk", targets: [target(vm)], op: { kind: "expand", slot: disk.slot, sizeMb } })
          : Promise.resolve(false)
      }
      onClose={onClose}
    >
      <p className="text-sm">Now {formatMb(nowMb)}</p>
      <Field id="expand-size" label="New size (GB)">
        <Input id="expand-size" inputMode="decimal" value={sizeGb} onChange={(e) => setSizeGb(e.currentTarget.value)} />
      </Field>
    </EditDialog>
  );
}

/**
 * VM-23: a folder of this PC shared with the guest. The folder is chosen in a dialog the shell opens, so its path
 * never comes from the UI (the guest can read what is in it).
 */
export function SharedFolderDialog({
  vm,
  onSubmitted,
  onClose,
}: {
  vm: VmRecord;
  onSubmitted: (outcome: SubmitOutcome) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [writable, setWritable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <EditDialog
      vms={[vm]}
      title={`Share a folder with ${vm.displayName}`}
      description="The guest can read (and with write access, change) everything in the folder you choose next. The VM must be off."
      submitLabel="Choose the folder…"
      problem={shareNameProblem(name) ?? error}
      onSubmit={async () => {
        setError(null);
        try {
          const outcome = await api.vmPickSharedFolder(vm.vmxPath, name.trim(), writable);
          if (!outcome) return false;
          onSubmitted(outcome);
          return true;
        } catch (err) {
          setError(errorMessage(err));
          return false;
        }
      }}
      onClose={onClose}
    >
      <Field id="share-name" label="Name in the guest">
        <Input
          id="share-name"
          autoFocus
          autoComplete="off"
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
        />
      </Field>
      <SwitchRow id="share-write" label="The guest may write to it" checked={writable} onChange={setWritable} />
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
        <FolderOpenIcon className="size-3.5" aria-hidden /> Remotely shares folders on this PC only, not network shares.
      </p>
    </EditDialog>
  );
}

/** VM-23: a running VirtualBox VM's screen, read on demand (nothing is kept). */
export function ScreenshotDialog({ vm, onClose }: { vm: VmRecord; onClose: () => void }) {
  // FD-03: a picture of the guest's screen can't be masked, so it stays hidden while presenting.
  const { presenting } = usePresentation();
  const [image, setImage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [n, setN] = useState(0);
  useEffect(() => {
    let stale = false;
    api.vmScreenshot(vm.vmxPath).then(
      (url) => !stale && setImage(url),
      (err) => !stale && setError(errorMessage(err)),
    );
    return () => {
      stale = true;
    };
  }, [vm.vmxPath, n]);
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{vm.displayName}&apos;s screen</DialogTitle>
          <DialogDescription>Taken now through VirtualBox; it isn&apos;t saved.</DialogDescription>
        </DialogHeader>
        {error && <p className="text-sm text-destructive">{error}</p>}
        {presenting ? (
          <p className="text-sm text-muted-foreground">
            Hidden while presenting: Remotely can&apos;t mask what is on the guest&apos;s screen.
          </p>
        ) : image ? (
          <img
            src={image}
            alt={`${vm.displayName}'s screen`}
            className="max-h-[70vh] w-full rounded border object-contain"
          />
        ) : (
          !error && <p className="text-sm text-muted-foreground">Taking the screenshot…</p>
        )}
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              setImage(null);
              setError(null);
              setN((k) => k + 1);
            }}
          >
            Take again
          </Button>
          <Button onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
