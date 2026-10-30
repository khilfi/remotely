// VM-11: the hypervisors' host networks in a side sheet on the Virtual machines page. Workstation's vmnets (vmrun
// listHostNetworks) with a NAT vmnet's port forwards; VirtualBox's host-only interfaces, NAT networks with their
// rules, each VM's NAT adapter rules, and the bridged and internal networks VMs are on. The VMs on each network come
// from each VM's adapters (R3's settings model, through the topology map's read). Read when the sheet opens, on
// Refresh, and after a job ends; what it read is kept for the palette's search (host-networks-cache.ts).
//
// Adding or removing a forward is a `hostNetwork` command on the bus: High (a forward reaches every VM on the network;
// Critical when a VM on it is labelled Prod), with the approval dialog's warnings (who can reach it, whose address it
// is). Workstation keeps its forwards where only administrators can write, and Remotely never asks to run as one, so
// its Add and Remove say why they're off (QL-08) unless the app itself was started as administrator. IPs carry the
// masker's patterns (FD-03).

import { useEffect, useRef, useState, type ReactNode } from "react";
import { NetworkIcon, PlusIcon, ShieldIcon, Trash2Icon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EnvBadge, StateBadge } from "@/components/Badges";
import { WhyDisabled } from "@/components/WhyDisabled";
import { RefreshButton } from "@/components/RefreshButton";
import { api, errorMessage, type SubmitOutcome } from "@/lib/api";
import { formatWhen } from "@/lib/format";
import { rememberHostNetworks } from "@/lib/host-networks-cache";
import { networkEnvironment } from "@/lib/vm-page";
import {
  insightApi,
  type ForwardProtocol,
  type HostNetworksReport,
  type NatForward,
  type NetworkVm,
} from "@/lib/vm-insight-api";
import {
  EMPTY_FORWARD,
  describeForward,
  forwardCommand,
  forwardFromForm,
  forwardProblems,
  forwardReason,
  topologyHostNetworks,
  vboxForward,
  vmnetForward,
  vmnetKindLabel,
  type ForwardForm,
  type ForwardPlace,
} from "@/lib/vm-insight";

interface Props {
  open: boolean;
  onClose: () => void;
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  /** The approval dialog for what the bus asks. */
  onSubmitted: (outcome: SubmitOutcome) => void;
}

/** One forward row: what it is, and the place its Remove goes to. */
interface Row {
  key: string;
  forward: NatForward;
}

export function HostNetworksSheet({ open, onClose, readOnly, onSubmitted }: Props) {
  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      {/* Mounted while open, so each opening reads the networks afresh. */}
      {open && <NetworksBody readOnly={readOnly} onSubmitted={onSubmitted} />}
    </Sheet>
  );
}

function NetworksBody({ readOnly, onSubmitted }: Pick<Props, "readOnly" | "onSubmitted">) {
  // What the last read found, for the read it answered (`reads`): a newer read shows as loading.
  const [result, setResult] = useState<{ for: number; report?: HostNetworksReport; error?: string } | null>(null);
  const [reads, setReads] = useState(0);
  const [adding, setAdding] = useState<{ place: ForwardPlace; vms: NetworkVm[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const reloadTimer = useRef<number | undefined>(undefined);
  const loading = result?.for !== reads;
  const report = result?.report ?? null;
  const error = result?.error ?? null;

  useEffect(() => {
    let stale = false;
    insightApi.hostNetworks().then(
      (found) => {
        rememberHostNetworks(topologyHostNetworks(found));
        if (!stale) setResult({ for: reads, report: found });
      },
      (err: unknown) => !stale && setResult({ for: reads, error: errorMessage(err) }),
    );
    return () => {
      stale = true;
    };
  }, [reads]);

  // A forward added or removed: read again once its job ends.
  useEffect(() => {
    const unlisten = api.onJobEvent((event) => {
      if (event.event !== "finished") return;
      window.clearTimeout(reloadTimer.current);
      reloadTimer.current = window.setTimeout(() => setReads((n) => n + 1), 500);
    });
    return () => {
      window.clearTimeout(reloadTimer.current);
      void unlisten.then((stop) => stop());
    };
  }, []);

  async function submit(place: ForwardPlace, add: boolean, forward: NatForward) {
    setBusy(true);
    try {
      onSubmitted(await api.submit(forwardCommand(place, add, forward)));
      return true;
    } catch (err) {
      toast.error(errorMessage(err));
      return false;
    } finally {
      setBusy(false);
    }
  }

  const refused = report?.vmware.forwardsRefused ?? null;

  return (
    <SheetContent className="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-4xl">
      <SheetHeader>
        <SheetTitle className="flex items-center gap-2">
          <NetworkIcon className="size-4" /> Host networks
        </SheetTitle>
        <SheetDescription>
          Workstation&apos;s and VirtualBox&apos;s networks, the VMs on each, and their NAT port forwards. Adding or
          removing a forward asks for approval (High): it reaches every VM on the network.
        </SheetDescription>
      </SheetHeader>
      <div className="flex items-center gap-2 border-b px-4 pb-2 text-xs text-muted-foreground">
        {report && <>Read {formatWhen(report.readAt)}</>}
        {report && report.staleVms.length > 0 && (
          <span>· adapters of {report.staleVms.join(", ")} as read before (their files can&apos;t be read now)</span>
        )}
        <RefreshButton className="ml-auto" busy={loading} onClick={() => setReads((n) => n + 1)} />
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-4">
        {error && (
          <Alert variant="destructive">
            <TriangleAlertIcon />
            <AlertTitle>Could not read the networks</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {!report && !error && (
          <div className="flex flex-col gap-2" aria-label="Reading the networks">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-20 w-full" />
          </div>
        )}
        {report && (
          <Tabs defaultValue={report.vmware.available || !report.virtualbox.available ? "vmware" : "virtualbox"}>
            <TabsList>
              <TabsTrigger value="vmware">Workstation</TabsTrigger>
              <TabsTrigger value="virtualbox">VirtualBox</TabsTrigger>
            </TabsList>
            <TabsContent value="vmware" className="flex flex-col gap-3 pt-3">
              <WorkstationSide
                report={report}
                readOnly={readOnly}
                busy={busy}
                onAdd={(place, vms) => setAdding({ place, vms })}
                onRemove={(place, f) => void submit(place, false, f)}
              />
            </TabsContent>
            <TabsContent value="virtualbox" className="flex flex-col gap-3 pt-3">
              <VirtualBoxSide
                report={report}
                readOnly={readOnly}
                busy={busy}
                onAdd={(place, vms) => setAdding({ place, vms })}
                onRemove={(place, f) => void submit(place, false, f)}
              />
            </TabsContent>
          </Tabs>
        )}
      </div>
      {adding && (
        <AddForwardDialog
          place={adding.place}
          vms={adding.vms}
          refused={adding.place.kind === "vmnet" ? refused : null}
          onCancel={() => setAdding(null)}
          onAdd={async (forward) => {
            if (await submit(adding.place, true, forward)) setAdding(null);
          }}
        />
      )}
    </SheetContent>
  );
}

function Card({ title, badges, children }: { title: ReactNode; badges?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-md border p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <h3 className="font-medium">{title}</h3>
        {badges}
      </div>
      {children}
    </section>
  );
}

/** UX-12: a network is Prod when a VM on it is, so its forwards ask one tier higher; this says so, and why. */
function InheritedEnv({ vms }: { vms: NetworkVm[] }) {
  const text = networkEnvironment(vms);
  if (!text) return null;
  return (
    <Badge variant="outline" className="border-env-prod/50 bg-env-prod/10 font-normal text-env-prod">
      {text}
    </Badge>
  );
}

function VmList({ vms }: { vms: NetworkVm[] }) {
  if (vms.length === 0) return <p className="text-xs text-muted-foreground">No VM in the list is on it.</p>;
  return (
    <ul className="flex flex-col gap-1 text-sm">
      {vms.map((vm) => (
        <li key={`${vm.vmxPath}|${vm.adapter}`} className="flex flex-wrap items-center gap-1.5">
          <span className="font-medium">{vm.name}</span>
          {vm.protected && <ShieldIcon className="size-3.5 text-tier-high" aria-label="Protected" />}
          <StateBadge state={vm.powerState} />
          {vm.environment !== "none" && <EnvBadge env={vm.environment} />}
          <span className="text-xs text-muted-foreground">{vm.adapter}</span>
          {vm.ips.map((ip) => (
            <span key={ip} className="font-mono text-xs" data-mask="ip">
              {ip}
            </span>
          ))}
        </li>
      ))}
    </ul>
  );
}

interface SideProps {
  report: HostNetworksReport;
  readOnly: string | null;
  busy: boolean;
  onAdd: (place: ForwardPlace, vms: NetworkVm[]) => void;
  onRemove: (place: ForwardPlace, forward: NatForward) => void;
}

function Forwards({
  rows,
  reason,
  onRemove,
  empty,
}: {
  rows: Row[];
  reason: string | null;
  onRemove: (forward: NatForward) => void;
  empty: string;
}) {
  if (rows.length === 0) return <p className="text-xs text-muted-foreground">{empty}</p>;
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Protocol</TableHead>
          <TableHead>This PC</TableHead>
          <TableHead>Guest</TableHead>
          <TableHead className="w-10" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map(({ key, forward }) => (
          <TableRow key={key}>
            <TableCell>{forward.name || <span className="text-muted-foreground">—</span>}</TableCell>
            <TableCell className="uppercase">{forward.protocol}</TableCell>
            <TableCell className="font-mono text-xs">
              {forward.hostIp ?? "every address"}:{forward.hostPort}
            </TableCell>
            <TableCell className="font-mono text-xs">
              {forward.guestIp ?? "the guest"}:{forward.guestPort}
            </TableCell>
            <TableCell>
              <WhyDisabled reason={reason}>
                <Button
                  size="icon-sm"
                  variant="ghost"
                  aria-label={`Remove ${describeForward(forward)}`}
                  title="Remove this forward (asks for approval)"
                  disabled={reason !== null}
                  onClick={() => onRemove(forward)}
                >
                  <Trash2Icon />
                </Button>
              </WhyDisabled>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function AddButton({ reason, onClick }: { reason: string | null; onClick: () => void }) {
  return (
    <WhyDisabled reason={reason}>
      <Button variant="outline" size="sm" disabled={reason !== null} onClick={onClick}>
        <PlusIcon data-icon="inline-start" />
        Add forward…
      </Button>
    </WhyDisabled>
  );
}

function WorkstationSide({ report, readOnly, busy, onAdd, onRemove }: SideProps) {
  const side = report.vmware;
  if (!side.available) {
    return <NotThere text="Workstation was not found on this PC (vmrun.exe). Settings, General can name it." />;
  }
  const reason = forwardReason({ readOnly, refused: side.forwardsRefused, busy });
  return (
    <>
      {side.problem && <Problem title="Could not list Workstation's networks" text={side.problem} />}
      {side.forwardsRefused && (
        <Alert>
          <ShieldIcon />
          <AlertTitle>Port forwards need administrator rights</AlertTitle>
          <AlertDescription>{side.forwardsRefused}</AlertDescription>
        </Alert>
      )}
      {side.networks.map((view) => {
        const nat = view.network.kind === "nat";
        const place: ForwardPlace = { kind: "vmnet", name: view.network.name };
        return (
          <Card
            key={view.network.name}
            title={view.network.name}
            badges={
              <>
                <Badge variant="secondary">{vmnetKindLabel(view.network.kind)}</Badge>
                <InheritedEnv vms={view.vms} />
                {view.network.subnet && (
                  <span className="font-mono text-xs text-muted-foreground">
                    {view.network.subnet}
                    {view.network.mask ? ` / ${view.network.mask}` : ""}
                  </span>
                )}
                {view.network.dhcp !== null && (
                  <span className="text-xs text-muted-foreground">DHCP {view.network.dhcp ? "on" : "off"}</span>
                )}
                {nat && (
                  <span className="ml-auto">
                    <AddButton reason={reason} onClick={() => onAdd(place, view.vms)} />
                  </span>
                )}
              </>
            }
          >
            <VmList vms={view.vms} />
            {nat && (
              <div className="mt-3">
                <h4 className="mb-1 text-xs font-medium text-muted-foreground">Port forwards</h4>
                {view.forwardsProblem && (
                  <Problem title="Some forwards could not be read" text={view.forwardsProblem} />
                )}
                <Forwards
                  rows={view.forwards.map((f) => ({ key: `${f.protocol}:${f.hostPort}`, forward: vmnetForward(f) }))}
                  reason={reason}
                  onRemove={(f) => onRemove(place, f)}
                  empty="No port forwards."
                />
              </div>
            )}
          </Card>
        );
      })}
    </>
  );
}

function VirtualBoxSide({ report, readOnly, busy, onAdd, onRemove }: SideProps) {
  const side = report.virtualbox;
  if (!side.available) {
    return <NotThere text="VirtualBox was not found on this PC (VBoxManage.exe). Settings, General can name it." />;
  }
  const reason = forwardReason({ readOnly, busy });
  const nothing =
    side.hostOnly.length + side.natNetworks.length + side.other.length + side.vmNat.length === 0 && !side.problem;
  return (
    <>
      {side.problem && <Problem title="Could not list some of VirtualBox's networks" text={side.problem} />}
      {nothing && <NotThere text="No host-only or NAT networks, and no VM with a NAT adapter." />}
      {side.hostOnly.map(({ iface, vms }) => (
        <Card
          key={iface.name}
          title={iface.name}
          badges={
            <>
              <Badge variant="secondary">Host-only</Badge>
              {iface.ip && (
                <span className="font-mono text-xs text-muted-foreground">
                  {iface.ip}
                  {iface.mask ? ` / ${iface.mask}` : ""}
                </span>
              )}
              {iface.status && <span className="text-xs text-muted-foreground">{iface.status}</span>}
            </>
          }
        >
          <VmList vms={vms} />
        </Card>
      ))}
      {side.natNetworks.map(({ network, vms }) => {
        const place: ForwardPlace = { kind: "natNetwork", name: network.name };
        return (
          <Card
            key={network.name}
            title={network.name}
            badges={
              <>
                <Badge variant="secondary">NAT network</Badge>
                <InheritedEnv vms={vms} />
                {network.network && <span className="font-mono text-xs text-muted-foreground">{network.network}</span>}
                {network.enabled === false && <Badge variant="outline">Off</Badge>}
                <span className="ml-auto">
                  <AddButton reason={reason} onClick={() => onAdd(place, vms)} />
                </span>
              </>
            }
          >
            <VmList vms={vms} />
            <div className="mt-3">
              <h4 className="mb-1 text-xs font-medium text-muted-foreground">Port forwarding rules</h4>
              <Forwards
                rows={network.forwards.map((r) => ({ key: r.name, forward: vboxForward(r, null) }))}
                reason={reason}
                onRemove={(f) => onRemove(place, f)}
                empty="No rules."
              />
            </div>
          </Card>
        );
      })}
      {side.vmNat.map(({ vm, slot, rules, problem }) => {
        const place: ForwardPlace = { kind: "vboxVm", vmxPath: vm.vmxPath, slot, vmName: vm.name };
        const vmReason = forwardReason({ readOnly, vm, busy });
        return (
          <Card
            key={`${vm.vmxPath}|${slot}`}
            title={`${vm.name}: NAT adapter ${slot}`}
            badges={
              <>
                <StateBadge state={vm.powerState} />
                {vm.environment !== "none" && <EnvBadge env={vm.environment} />}
                <span className="ml-auto">
                  <AddButton reason={vmReason} onClick={() => onAdd(place, [vm])} />
                </span>
              </>
            }
          >
            {problem && <Problem title="Could not read its rules" text={problem} />}
            <Forwards
              rows={rules.map((r) => ({ key: r.name, forward: vboxForward(r, slot) }))}
              reason={vmReason}
              onRemove={(f) => onRemove(place, f)}
              empty="No port forwarding rules: the guest reaches out, nothing reaches in."
            />
          </Card>
        );
      })}
      {side.other.map((o) => (
        <Card
          key={`${o.kind}|${o.name}`}
          title={o.name}
          badges={
            <Badge variant="secondary">
              {o.kind === "bridged" ? "Bridged" : o.kind === "intnet" ? "Internal network" : o.kind}
            </Badge>
          }
        >
          <VmList vms={o.vms} />
        </Card>
      ))}
    </>
  );
}

function NotThere({ text }: { text: string }) {
  return (
    <Empty className="border py-8">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <NetworkIcon />
        </EmptyMedia>
        <EmptyTitle>Nothing to show</EmptyTitle>
        <EmptyDescription>{text}</EmptyDescription>
      </EmptyHeader>
    </Empty>
  );
}

function Problem({ title, text }: { title: string; text: string }) {
  return (
    <Alert variant="destructive" className="mb-2">
      <TriangleAlertIcon />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{text}</AlertDescription>
    </Alert>
  );
}

const PROTOCOLS: ForwardProtocol[] = ["tcp", "udp"];

function AddForwardDialog({
  place,
  vms,
  refused,
  onCancel,
  onAdd,
}: {
  place: ForwardPlace;
  vms: NetworkVm[];
  refused: string | null;
  onCancel: () => void;
  onAdd: (forward: NatForward) => Promise<void>;
}) {
  const [form, setForm] = useState<ForwardForm>(EMPTY_FORWARD);
  const [tried, setTried] = useState(false);
  const [sending, setSending] = useState(false);
  const problems = forwardProblems(form, place);
  const set = (change: Partial<ForwardForm>) => setForm((f) => ({ ...f, ...change }));
  const vbox = place.kind !== "vmnet";
  const guests = vms.flatMap((vm) => vm.ips.map((ip) => ({ ip, name: vm.name })));
  const where =
    place.kind === "vmnet"
      ? place.name
      : place.kind === "natNetwork"
        ? `the NAT network ${place.name}`
        : `${place.vmName}'s NAT adapter ${place.slot}`;

  return (
    <Dialog open onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add a port forward on {where}</DialogTitle>
          <DialogDescription>
            Connections to a port of this PC go to a port of the guest. It asks for approval next (High).
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid grid-cols-2 gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            setTried(true);
            if (problems.length > 0 || refused) return;
            setSending(true);
            void onAdd(forwardFromForm(form, place)).finally(() => setSending(false));
          }}
        >
          <div className="col-span-2 grid gap-1.5">
            <Label htmlFor="fwd-name">{vbox ? "Rule name" : "Description (optional)"}</Label>
            <Input id="fwd-name" value={form.name} onChange={(e) => set({ name: e.currentTarget.value })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="fwd-protocol">Protocol</Label>
            <Select value={form.protocol} onValueChange={(v) => set({ protocol: v as ForwardProtocol })}>
              <SelectTrigger id="fwd-protocol" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PROTOCOLS.map((p) => (
                  <SelectItem key={p} value={p}>
                    {p.toUpperCase()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="fwd-host-port">Port on this PC</Label>
            <Input
              id="fwd-host-port"
              inputMode="numeric"
              value={form.hostPort}
              onChange={(e) => set({ hostPort: e.currentTarget.value })}
            />
          </div>
          {vbox && (
            <div className="col-span-2 grid gap-1.5">
              <Label htmlFor="fwd-host-ip">Address of this PC it listens on</Label>
              <Input
                id="fwd-host-ip"
                placeholder="Empty: every address. 127.0.0.1: only this PC"
                value={form.hostIp}
                onChange={(e) => set({ hostIp: e.currentTarget.value })}
              />
            </div>
          )}
          <div className="grid gap-1.5">
            <Label htmlFor="fwd-guest-ip">Guest&apos;s address</Label>
            <Input
              id="fwd-guest-ip"
              list="fwd-guests"
              placeholder={place.kind === "vboxVm" ? "Empty: the guest's own" : ""}
              value={form.guestIp}
              onChange={(e) => set({ guestIp: e.currentTarget.value })}
              data-mask="ip"
            />
            <datalist id="fwd-guests">
              {guests.map((g) => (
                <option key={g.ip} value={g.ip}>
                  {g.name}
                </option>
              ))}
            </datalist>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="fwd-guest-port">Guest&apos;s port</Label>
            <Input
              id="fwd-guest-port"
              inputMode="numeric"
              value={form.guestPort}
              onChange={(e) => set({ guestPort: e.currentTarget.value })}
            />
          </div>
          {place.kind === "vmnet" && (
            <p className="col-span-2 text-xs text-muted-foreground">
              Workstation listens on every address of this PC, so other computers that can reach this PC can use the
              forward too.
            </p>
          )}
          {tried && problems.length > 0 && (
            <ul className="col-span-2 list-disc pl-5 text-xs text-destructive">
              {problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          )}
          <DialogFooter className="col-span-2">
            <Button type="button" variant="outline" onClick={onCancel}>
              Cancel
            </Button>
            <WhyDisabled reason={refused}>
              <Button type="submit" disabled={sending || refused !== null}>
                Add…
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
