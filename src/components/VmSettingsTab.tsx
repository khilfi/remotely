// VM-23: a VM's Settings tab in its details panel: everything the hypervisor's files say about it (CPU and its
// layout, nested virtualization, memory, firmware, Secure Boot and TPM, hardware version, guest OS type, the guest
// tools, each disk with its controller, type, sizes and snapshot chain, CD/DVD drives, network adapters, shared
// folders, USB, sound, display, serial ports and the guest's addresses), read when the tab opens, after a VM job and
// on Refresh. Each section has its Edit button; every change is a command on the bus (VmSettingsDialogs), and a
// button that is off says why (QL-08). ISO and shared-folder paths are picked in dialogs the shell opens. MACs carry
// data-mask="mac" and addresses data-mask="ip" (FD-03).

import { useEffect, useState, type ReactNode } from "react";
import {
  CameraIcon,
  CircleAlertIcon,
  DiscIcon,
  EllipsisIcon,
  HardDriveIcon,
  NetworkIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ToolsLabel } from "@/components/Badges";
import { FactList } from "@/components/HostDetailsSheet";
import { NameDialog } from "@/components/NameDialog";
import {
  DiskAddDialog,
  DiskExpandDialog,
  FirmwareDialog,
  GuestOsDialog,
  NicDialog,
  ResourcesDialog,
  ScreenshotDialog,
  SharedFolderDialog,
  type Submit,
} from "@/components/VmSettingsDialogs";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type SubmitOutcome,
  type TargetRef,
  type VirtualDisk,
  type VirtualNic,
  type VmRecord,
  type VmSpecs,
} from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { toolsName } from "@/lib/hypervisors";
import { formatBytes } from "@/lib/metrics";
import {
  cableReason,
  diskActionReason,
  diskFileLabel,
  isoReason,
  nicText,
  toolsReason,
  vmActionReason,
  vmFolder,
  vmNameProblem,
} from "@/lib/vm-settings";

interface Props {
  vm: VmRecord;
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  busy: boolean;
  /** The VM's snapshot count once its tree is read; null before, "failed" when it couldn't be read. */
  snapshots: number | "failed" | null;
  /** Changes when a job finished or a setting changed: the files are read again. */
  refreshKey: string;
  onSubmit: Submit;
  /** For the commands the shell builds from its own dialogs (ISO, shared folder). */
  onSubmitted: (outcome: SubmitOutcome) => void;
  /** Counts the palette's asks to rename the VM; the rename dialog opens while one is not yet seen. */
  askRename?: number;
  renameSeen?: number;
  onRenameSeen?: (n: number) => void;
}

type Dialog =
  | { kind: "resources" }
  | { kind: "firmware" }
  | { kind: "guestOs" }
  | { kind: "rename" }
  | { kind: "nic"; nic?: VirtualNic }
  | { kind: "diskAdd" }
  | { kind: "diskExpand"; disk: VirtualDisk }
  | { kind: "share" }
  | { kind: "screenshot" }
  | null;

const dash = <span className="text-muted-foreground">—</span>;

function onOff(value: boolean | null | undefined) {
  return value === null || value === undefined ? null : value ? "On" : "Off";
}

function Section({
  title,
  icon,
  action,
  children,
}: {
  title: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <h3 className="flex items-center gap-1.5 text-sm font-medium">
          {icon}
          {title}
        </h3>
        {action && <div className="ml-auto flex items-center gap-1.5">{action}</div>}
      </div>
      {children}
    </section>
  );
}

/** A small button that says why when it is off. */
function ActionButton({
  label,
  reason,
  onClick,
  icon,
}: {
  label: string;
  reason: string | null;
  onClick: () => void;
  icon?: ReactNode;
}) {
  return (
    <WhyDisabled reason={reason}>
      <Button size="sm" variant="outline" disabled={reason !== null} onClick={onClick}>
        {icon}
        {label}
      </Button>
    </WhyDisabled>
  );
}

function vcpuText(specs: VmSpecs): string | null {
  const h = specs.hardware;
  if (!h.vcpus) return null;
  const layout =
    h.coresPerSocket && h.vcpus % h.coresPerSocket === 0
      ? ` (${h.vcpus / h.coresPerSocket} socket${h.vcpus / h.coresPerSocket === 1 ? "" : "s"} × ${h.coresPerSocket} cores)`
      : "";
  return `${h.vcpus}${layout}`;
}

export function VmSettingsTab({
  vm,
  readOnly,
  busy,
  snapshots,
  refreshKey,
  onSubmit,
  onSubmitted,
  askRename = 0,
  renameSeen = 0,
  onRenameSeen,
}: Props) {
  const [read, setRead] = useState<{ for: string; specs: VmSpecs } | null>(null);
  const [error, setError] = useState<{ for: string; message: string } | null>(null);
  const [reading, setReading] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(askRename > renameSeen ? { kind: "rename" } : null);
  // The palette's Rename while the tab shows: handled while rendering, once per ask.
  const [lastAsk, setLastAsk] = useState(askRename);
  if (askRename !== lastAsk) {
    setLastAsk(askRename);
    if (askRename > renameSeen) setDialog({ kind: "rename" });
  }
  const key = `${vm.vmxPath}|${refreshKey}`;
  const vmxPath = vm.vmxPath;

  useEffect(() => {
    let stale = false;
    api.vmSpecs(vmxPath).then(
      (specs) => !stale && setRead({ for: key, specs }),
      (err) => !stale && setError({ for: key, message: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [key, vmxPath]);

  const specs = read?.for === key ? read.specs : read?.specs.vmxPath === vm.vmxPath ? read.specs : null;
  const failed = error?.for === key ? error.message : null;
  const h = specs?.hardware ?? null;
  const ref: TargetRef = { kind: "vm", vmxPath: vm.vmxPath };
  const off = vmActionReason({ vm, needs: "off", readOnly, busy });
  const anyState = vmActionReason({ vm, needs: "any", readOnly, busy });
  const vbox = vm.hypervisor === "virtualbox";
  const running = vm.powerState === "running" || vm.powerState === "paused";
  const folder = vmFolder(vm);

  async function pickIso(slot: string | null) {
    try {
      const outcome = await api.vmPickIso(vm.vmxPath, slot);
      if (outcome) onSubmitted(outcome);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  const diskReason = (disk: VirtualDisk, action: "expand" | "compact" | "defragment" | "remove") =>
    off ?? diskActionReason({ action, hypervisor: vm.hypervisor, snapshots, diskPath: disk.path, vmFolder: folder });

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {specs && <span>Read from the VM&apos;s files {formatWhen(specs.collectedAt)}</span>}
        {vbox && running && (
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => setDialog({ kind: "screenshot" })}>
            <CameraIcon data-icon="inline-start" />
            Screenshot
          </Button>
        )}
        <Button
          className={vbox && running ? undefined : "ml-auto"}
          variant="outline"
          size="sm"
          disabled={reading}
          onClick={() => {
            setReading(true);
            api
              .vmSpecs(vm.vmxPath)
              .then(
                (s) => setRead({ for: key, specs: s }),
                (err) => setError({ for: key, message: errorMessage(err) }),
              )
              .finally(() => setReading(false));
          }}
        >
          <RefreshCwIcon data-icon="inline-start" className={reading ? "animate-spin" : undefined} />
          Refresh
        </Button>
      </div>

      {failed && (
        <Alert variant="destructive">
          <CircleAlertIcon />
          <AlertTitle>Could not read the VM&apos;s files</AlertTitle>
          <AlertDescription>{failed}</AlertDescription>
        </Alert>
      )}
      {specs?.stored && (
        <Alert>
          <CircleAlertIcon />
          <AlertTitle>Showing what was read {formatWhen(specs.collectedAt)}</AlertTitle>
          <AlertDescription>{specs.problem ?? "The VM's files can't be read now."}</AlertDescription>
        </Alert>
      )}
      {!specs && !failed && (
        <div className="flex flex-col gap-2" aria-label="Reading the VM's files">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-20 w-full" />
        </div>
      )}
      {off && running && specs && (
        <p className="text-xs text-muted-foreground">
          Settings and disks change only while the VM is off. An ISO, a network cable and the guest tools change while
          it runs.
        </p>
      )}

      {specs && h && (
        <>
          <Section
            title="General"
            action={<ActionButton label="Rename…" reason={off} onClick={() => setDialog({ kind: "rename" })} />}
          >
            <FactList
              rows={[
                { label: "Name", value: vm.displayName },
                {
                  label: "Guest OS type",
                  value: (
                    <span className="flex flex-wrap items-center gap-2">
                      {h.guestOs ?? dash}
                      <WhyDisabled reason={off}>
                        <Button
                          size="xs"
                          variant="ghost"
                          disabled={off !== null}
                          onClick={() => setDialog({ kind: "guestOs" })}
                        >
                          Change…
                        </Button>
                      </WhyDisabled>
                    </span>
                  ),
                  hint: "What the VM is set up for; the guest reports its own OS",
                },
                ...(h.hardwareVersion
                  ? [
                      {
                        label: "Hardware version",
                        value: (
                          <span className="flex flex-wrap items-center gap-2">
                            {h.hardwareVersion}
                            <WhyDisabled reason={off}>
                              <Button
                                size="xs"
                                variant="ghost"
                                disabled={off !== null}
                                onClick={() =>
                                  void onSubmit({ type: "vmConfig", targets: [ref], edit: { kind: "upgradeHardware" } })
                                }
                              >
                                Upgrade…
                              </Button>
                            </WhyDisabled>
                          </span>
                        ),
                        hint: "Can't be undone: older Workstation versions won't open the VM after it",
                      },
                    ]
                  : []),
                {
                  label: toolsName(vm.hypervisor),
                  value: (
                    <span className="flex flex-wrap items-center gap-2">
                      <ToolsLabel state={vm.toolsState} />
                      {h.toolsVersion && <span className="text-xs text-muted-foreground">{h.toolsVersion}</span>}
                      <WhyDisabled reason={toolsReason(vm, readOnly, h)}>
                        <Button
                          size="xs"
                          variant="ghost"
                          disabled={toolsReason(vm, readOnly, h) !== null || busy}
                          onClick={() =>
                            void onSubmit({ type: "vmDevice", targets: [ref], op: { kind: "installTools" } })
                          }
                        >
                          Install or upgrade
                        </Button>
                      </WhyDisabled>
                    </span>
                  ),
                },
              ]}
            />
          </Section>

          <Section
            title="Processor and memory"
            action={
              <ActionButton
                label="Edit…"
                icon={<PencilIcon />}
                reason={off}
                onClick={() => setDialog({ kind: "resources" })}
              />
            }
          >
            <FactList
              rows={[
                { label: "vCPUs", value: vcpuText(specs) },
                { label: "Memory", value: h.memoryMb ? formatBytes(h.memoryMb * 1024 * 1024) : null },
                {
                  label: "Nested virtualization",
                  value: onOff(h.nestedVirtualization),
                  hint: "Hardware virtualization passed on to the guest",
                },
              ]}
            />
          </Section>

          <Section
            title="Firmware"
            action={
              <ActionButton
                label="Edit…"
                icon={<PencilIcon />}
                reason={off}
                onClick={() => setDialog({ kind: "firmware" })}
              />
            }
          >
            <FactList
              rows={[
                { label: "Firmware", value: h.firmware },
                { label: "Secure Boot", value: h.secureBoot === null ? "Needs UEFI" : onOff(h.secureBoot) },
                { label: "TPM", value: h.tpm ?? "None" },
              ]}
            />
          </Section>

          <Section
            title={`Disks (${h.disks.length})`}
            icon={<HardDriveIcon className="size-4 text-muted-foreground" />}
            action={
              <ActionButton
                label="Add…"
                icon={<PlusIcon />}
                reason={off}
                onClick={() => setDialog({ kind: "diskAdd" })}
              />
            }
          >
            {h.disks.length === 0 ? (
              <p className="text-xs text-muted-foreground">No virtual disk is attached.</p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Slot</TableHead>
                      <TableHead>File</TableHead>
                      <TableHead className="text-right" title="The size the guest sees">
                        Size
                      </TableHead>
                      <TableHead className="text-right" title="What its files take on this PC">
                        On disk
                      </TableHead>
                      <TableHead className="w-8" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {h.disks.map((d) => (
                      <TableRow key={`${d.slot}|${d.path}`}>
                        <TableCell className="text-xs">
                          <div className="font-mono">{d.slot}</div>
                          {d.controller && <div className="text-muted-foreground">{d.controller}</div>}
                        </TableCell>
                        <TableCell className="text-xs whitespace-normal">
                          <div className="font-mono break-all" title={d.path}>
                            {diskFileLabel(d.path, folder)}
                          </div>
                          <div className="text-muted-foreground">
                            {[
                              d.thin === null ? null : d.thin ? "thin" : "thick",
                              d.format,
                              d.delta ? "snapshot delta" : null,
                              d.files > 1 ? `${d.files} files` : null,
                            ]
                              .filter(Boolean)
                              .join(" · ")}
                          </div>
                          {d.chain.length > 0 && <div className="text-muted-foreground">On {d.chain.join(" → ")}</div>}
                          {d.problem && <div className="text-tier-medium">{d.problem}</div>}
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">
                          {formatBytes(d.provisionedBytes)}
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">{formatBytes(d.onDiskBytes)}</TableCell>
                        <TableCell>
                          <DiskMenu
                            disk={d}
                            vbox={vbox}
                            reason={diskReason}
                            onExpand={() => setDialog({ kind: "diskExpand", disk: d })}
                            onRun={(op) => void onSubmit({ type: "vmDisk", targets: [ref], op })}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </Section>

          <Section
            title={`CD/DVD (${h.cdroms.length})`}
            icon={<DiscIcon className="size-4 text-muted-foreground" />}
            action={
              h.cdroms.length === 0 && (
                <ActionButton
                  label="Attach an ISO…"
                  reason={isoReason(vm, readOnly, h)}
                  onClick={() => void pickIso(null)}
                />
              )
            }
          >
            {h.cdroms.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No CD/DVD drive. Attaching an ISO while the VM is off adds one.
              </p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableBody>
                    {h.cdroms.map((c) => (
                      <TableRow key={c.slot}>
                        <TableCell className="font-mono text-xs">{c.slot}</TableCell>
                        <TableCell className="text-xs whitespace-normal">
                          {c.image ? (
                            <span className="font-mono break-all">{c.image}</span>
                          ) : c.hostDrive ? (
                            `This PC's drive (${c.hostDrive})`
                          ) : (
                            <span className="text-muted-foreground">Empty</span>
                          )}
                          {c.connected === false && (
                            <div className="text-muted-foreground">not connected at power-on</div>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <span className="inline-flex gap-1.5">
                            <ActionButton
                              label="Attach…"
                              reason={isoReason(vm, readOnly, h)}
                              onClick={() => void pickIso(c.slot)}
                            />
                            <ActionButton
                              label="Eject"
                              reason={anyState ?? (!c.image && !c.hostDrive ? "Nothing to eject" : null)}
                              onClick={() =>
                                void onSubmit({
                                  type: "vmDevice",
                                  targets: [ref],
                                  op: { kind: "ejectIso", slot: c.slot },
                                })
                              }
                            />
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
            <p className="text-xs text-muted-foreground">Or drop an ISO on the VM in the list.</p>
          </Section>

          <Section
            title={`Network adapters (${h.nics.length})`}
            icon={<NetworkIcon className="size-4 text-muted-foreground" />}
            action={
              <ActionButton label="Add…" icon={<PlusIcon />} reason={off} onClick={() => setDialog({ kind: "nic" })} />
            }
          >
            {h.nics.length === 0 ? (
              <p className="text-xs text-muted-foreground">No network adapter.</p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableBody>
                    {h.nics.map((n) => (
                      <TableRow key={n.slot}>
                        <TableCell className="text-xs">
                          <div className="font-mono">{n.slot}</div>
                          {n.model && <div className="text-muted-foreground">{n.model}</div>}
                        </TableCell>
                        <TableCell className="text-xs whitespace-normal">
                          {nicText(n)}
                          <div className="text-muted-foreground">
                            {n.connectedNow !== null
                              ? n.connectedNow
                                ? "connected"
                                : "disconnected"
                              : n.connected === false
                                ? "not connected at power-on"
                                : "connected at power-on"}
                          </div>
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs">
                          {n.mac ? <span data-mask="mac">{n.mac}</span> : "—"}
                          {n.staticMac && <div className="font-sans text-muted-foreground">chosen by hand</div>}
                        </TableCell>
                        <TableCell className="w-8">
                          <NicMenu
                            nic={n}
                            off={off}
                            anyState={anyState}
                            running={running}
                            onEdit={() => setDialog({ kind: "nic", nic: n })}
                            onRun={(command) => void onSubmit(command)}
                            target={ref}
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </Section>

          <Section
            title={`Shared folders (${h.sharedFolders.length})`}
            action={
              <ActionButton
                label="Share…"
                icon={<PlusIcon />}
                reason={off}
                onClick={() => setDialog({ kind: "share" })}
              />
            }
          >
            {h.sharedFolders.length === 0 ? (
              <p className="text-xs text-muted-foreground">No folder of this PC is shared with the guest.</p>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableBody>
                    {h.sharedFolders.map((f) => (
                      <TableRow key={f.name}>
                        <TableCell className="text-xs">{f.name}</TableCell>
                        <TableCell className="text-xs whitespace-normal">
                          <span className="font-mono break-all">{f.hostPath}</span>
                          <div className="text-muted-foreground">
                            {[
                              f.writable === null ? null : f.writable ? "read and write" : "read only",
                              f.enabled === false ? "off" : null,
                            ]
                              .filter(Boolean)
                              .join(" · ")}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <ActionButton
                            label="Remove"
                            reason={off}
                            onClick={() =>
                              void onSubmit({
                                type: "vmConfig",
                                targets: [ref],
                                edit: { kind: "removeSharedFolder", name: f.name },
                              })
                            }
                          />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </Section>

          <Section title="Other devices">
            <FactList
              rows={[
                {
                  label: "Controllers",
                  value: h.controllers.map((c) => `${c.name}${c.kind ? ` (${c.kind})` : ""}`).join(", ") || null,
                },
                { label: "USB", value: h.usb.length > 0 ? h.usb.join(", ") : "None" },
                { label: "Sound", value: h.sound ?? "None" },
                {
                  label: "Display",
                  value: h.display
                    ? [
                        h.display.videoMemoryMb ? `${h.display.videoMemoryMb} MB video memory` : null,
                        h.display.accelerate3d ? "3D on" : h.display.accelerate3d === false ? "3D off" : null,
                        h.display.monitors && h.display.monitors > 1 ? `${h.display.monitors} monitors` : null,
                        h.display.controller,
                      ]
                        .filter(Boolean)
                        .join(" · ") || null
                    : null,
                },
                {
                  label: "Serial ports",
                  value:
                    h.serialPorts.length > 0
                      ? h.serialPorts.map((s) => `${s.slot}: ${s.kind}${s.target ? ` ${s.target}` : ""}`).join("; ")
                      : "None",
                },
              ]}
            />
          </Section>

          <Section title="Guest addresses">
            {(h.guestIps.length > 0 ? h.guestIps : vm.ipAddress ? [vm.ipAddress] : []).length === 0 ? (
              <p className="text-xs text-muted-foreground">
                {running ? `The ${toolsName(vm.hypervisor)} report no address yet.` : "Shown while the VM runs."}
              </p>
            ) : (
              <ul className="flex flex-wrap gap-2 font-mono text-xs">
                {(h.guestIps.length > 0 ? h.guestIps : [vm.ipAddress as string]).map((ip) => (
                  <li key={ip} data-mask="ip">
                    {ip}
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </>
      )}

      {dialog?.kind === "resources" && h && (
        <ResourcesDialog vms={[vm]} hardware={h} onSubmit={onSubmit} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "firmware" && h && (
        <FirmwareDialog vm={vm} hardware={h} onSubmit={onSubmit} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "guestOs" && h && (
        <GuestOsDialog vm={vm} hardware={h} onSubmit={onSubmit} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "rename" && (
        <NameDialog
          title={`Rename ${vm.displayName}`}
          description={
            vbox
              ? "VirtualBox renames the VM's folder and files with it. The VM must be off."
              : "The name Workstation shows (displayName in its .vmx); its files keep their names. The VM must be off."
          }
          label="Name"
          submitLabel="Rename"
          initial={vm.displayName}
          maxLength={80}
          onSubmit={async (name) => {
            const problem = vmNameProblem(name);
            if (problem) throw new Error(problem);
            if (name === vm.displayName) throw new Error("That is its name already");
            if (!(await onSubmit({ type: "vmConfig", targets: [ref], edit: { kind: "rename", name } }))) {
              throw new Error("Not renamed");
            }
          }}
          onClose={() => {
            onRenameSeen?.(askRename);
            setDialog(null);
          }}
        />
      )}
      {dialog?.kind === "nic" && (
        <NicDialog vm={vm} nic={dialog.nic} onSubmit={onSubmit} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "diskAdd" && h && (
        <DiskAddDialog vm={vm} hardware={h} onSubmit={onSubmit} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "diskExpand" && (
        <DiskExpandDialog vm={vm} disk={dialog.disk} onSubmit={onSubmit} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "share" && (
        <SharedFolderDialog vm={vm} onSubmitted={onSubmitted} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "screenshot" && <ScreenshotDialog vm={vm} onClose={() => setDialog(null)} />}
    </div>
  );
}

function DiskMenu({
  disk,
  vbox,
  reason,
  onExpand,
  onRun,
}: {
  disk: VirtualDisk;
  vbox: boolean;
  reason: (disk: VirtualDisk, action: "expand" | "compact" | "defragment" | "remove") => string | null;
  onExpand: () => void;
  onRun: (op: { kind: "compact" | "defragment" | "remove"; slot: string }) => void;
}) {
  const expand = reason(disk, "expand");
  const compact = reason(disk, "compact");
  const defragment = reason(disk, "defragment");
  const remove = reason(disk, "remove");
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="icon-sm" variant="ghost" aria-label={`Actions for disk ${disk.slot}`}>
          <EllipsisIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuItem disabled={expand !== null} onSelect={onExpand}>
          <div>
            Expand…
            <ReasonLine reason={expand} />
          </div>
        </DropdownMenuItem>
        <DropdownMenuItem disabled={compact !== null} onSelect={() => onRun({ kind: "compact", slot: disk.slot })}>
          <div>
            Compact
            <ReasonLine reason={compact} />
          </div>
        </DropdownMenuItem>
        {!vbox && (
          <DropdownMenuItem
            disabled={defragment !== null}
            onSelect={() => onRun({ kind: "defragment", slot: disk.slot })}
          >
            <div>
              Defragment
              <ReasonLine reason={defragment} />
            </div>
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          variant="destructive"
          disabled={remove !== null}
          onSelect={() => onRun({ kind: "remove", slot: disk.slot })}
        >
          <div>
            Remove and delete its files…
            <ReasonLine reason={remove} />
          </div>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function NicMenu({
  nic,
  off,
  anyState,
  running,
  onEdit,
  onRun,
  target,
}: {
  nic: VirtualNic;
  off: string | null;
  anyState: string | null;
  running: boolean;
  onEdit: () => void;
  onRun: (command: Parameters<Submit>[0]) => void;
  target: TargetRef;
}) {
  const connect = cableReason(nic, true, running, anyState);
  const disconnect = cableReason(nic, false, running, anyState);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="icon-sm" variant="ghost" aria-label={`Actions for network adapter ${nic.slot}`}>
          <EllipsisIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuItem disabled={off !== null} onSelect={onEdit}>
          <div>
            Edit…
            <ReasonLine reason={off} />
          </div>
        </DropdownMenuItem>
        <DropdownMenuItem
          disabled={connect !== null}
          onSelect={() => onRun({ type: "vmDevice", targets: [target], op: { kind: "connectNic", slot: nic.slot } })}
        >
          <div>
            Connect
            <ReasonLine reason={connect} />
          </div>
        </DropdownMenuItem>
        <DropdownMenuItem
          disabled={disconnect !== null}
          onSelect={() => onRun({ type: "vmDevice", targets: [target], op: { kind: "disconnectNic", slot: nic.slot } })}
        >
          <div>
            Disconnect
            <ReasonLine reason={disconnect} />
          </div>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          variant="destructive"
          disabled={off !== null}
          onSelect={() => onRun({ type: "vmConfig", targets: [target], edit: { kind: "removeNic", slot: nic.slot } })}
        >
          <div>
            Remove…
            <ReasonLine reason={off} />
          </div>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
