// VM-32: the Templates page's Address pools tab: ranges of static addresses per network of one hypervisor, each with how
// many of its addresses VMs hold, the addresses and their VMs, and freeing one whose VM is gone. Edits are audited in
// the core with no approval tier and refused by the read-only lock; a pool isn't kept in the trash. Every element that
// holds one address carries `data-mask="ip"`, so presentation mode hides it.

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ListIcon, NetworkIcon, PencilIcon, PlusIcon, Trash2Icon, UnlinkIcon } from "lucide-react";
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
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { RowMenu } from "@/components/RowMenu";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type Hypervisor, type TemplateNetwork } from "@/lib/api";
import { addressPoolsApi, type AddressLease, type AddressPool } from "@/lib/address-pools-api";
import {
  deletePoolReason,
  EMPTY_POOL_FORM,
  freeReason,
  leaseStateLabel,
  MAX_NAME_CHARS,
  MAX_NETWORK_NAME,
  MAX_NOTES,
  NETWORK_KIND_LABEL,
  parsePoolForm,
  poolForm,
  sizeText,
  usedText,
  type PoolForm,
} from "@/lib/address-pools";
import { HYPERVISOR_LABEL, networkKinds, networkLabel, networkOfKind } from "@/lib/catalog";

interface Props {
  /** True while the tab shows: it reads the pools again when it comes back. */
  active: boolean;
  readOnly: string | null;
  /** Changes when the header's New address pool is pressed. */
  createRequest: number;
  /** How many pools there are, once read: the header shows New address pool only when the tab isn't empty. */
  onCount: (count: number) => void;
}

type Open =
  | { kind: "edit"; existing?: AddressPool }
  | { kind: "leases"; pool: AddressPool }
  | { kind: "delete"; pool: AddressPool };

export function AddressPoolsTab({ active, readOnly, createRequest, onCount }: Props) {
  const [pools, setPools] = useState<AddressPool[] | null>(null);
  const [dialog, setDialog] = useState<Open | null>(null);
  const [handled, setHandled] = useState(createRequest);

  const load = useCallback(() => {
    addressPoolsApi.list().then(setPools, (err) => toast.error(errorMessage(err)));
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  useEffect(() => {
    if (pools) onCount(pools.length);
  }, [pools, onCount]);

  if (createRequest !== handled) {
    setHandled(createRequest);
    if (!readOnly) setDialog({ kind: "edit" });
  }

  const names = (pools ?? []).map((p) => p.name);

  const newButton = (
    <WhyDisabled reason={readOnly}>
      <Button disabled={readOnly !== null} onClick={() => setDialog({ kind: "edit" })}>
        <PlusIcon data-icon="inline-start" />
        New address pool
      </Button>
    </WhyDisabled>
  );

  return (
    <>
      {pools?.length === 0 ? (
        <EmptyState
          icon={NetworkIcon}
          title="No address pools yet"
          description="A pool gives deployed VMs static addresses on one network, instead of DHCP."
          help="addressPool.free"
          action={newButton}
        />
      ) : (
        <>
          <p className="flex items-center gap-1 text-sm text-muted-foreground">
            A deployed VM gets a pool&apos;s next address that no VM holds and nothing answers on.
            <HelpTip topic="addressPool.free" />
          </p>
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address pool</TableHead>
                  <TableHead>Network</TableHead>
                  <TableHead>Range</TableHead>
                  <TableHead>Gateway</TableHead>
                  <TableHead>DNS servers</TableHead>
                  <TableHead>Used</TableHead>
                  <TableHead className="w-12">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {!pools && (
                  <TableRow>
                    <TableCell colSpan={7}>
                      <Skeleton className="h-6 w-full" />
                    </TableCell>
                  </TableRow>
                )}
                {pools?.map((p) => {
                  const deleteOff = deletePoolReason(readOnly, p);
                  return (
                    <TableRow key={p.id} className="align-top">
                      <TableCell className="font-medium whitespace-normal">
                        {p.name}
                        {p.notes && (
                          <div className="line-clamp-2 text-xs font-normal text-muted-foreground">{p.notes}</div>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        {networkLabel(p.network)}
                        <div className="text-xs text-muted-foreground">{HYPERVISOR_LABEL[p.hypervisor]}</div>
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        <span data-mask="ip">{p.firstIp}</span> to <span data-mask="ip">{p.lastIp}</span>
                        <span className="text-muted-foreground"> /{p.prefix}</span>
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        {p.gateway ? (
                          <span data-mask="ip">{p.gateway}</span>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        {p.dnsServers.length === 0 ? (
                          <span className="text-muted-foreground">None</span>
                        ) : (
                          <span className="flex flex-wrap gap-x-2">
                            {p.dnsServers.map((d) => (
                              <span key={d} data-mask="ip">
                                {d}
                              </span>
                            ))}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">{usedText(p)}</TableCell>
                      <TableCell>
                        <RowMenu label={p.name}>
                          <DropdownMenuItem
                            disabled={readOnly !== null}
                            onSelect={() => setDialog({ kind: "edit", existing: p })}
                          >
                            <PencilIcon />
                            Edit…
                          </DropdownMenuItem>
                          <DropdownMenuItem onSelect={() => setDialog({ kind: "leases", pool: p })}>
                            <ListIcon />
                            Show addresses…
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <WhyDisabled reason={deleteOff} className="flex w-full">
                            <DropdownMenuItem
                              className="w-full"
                              variant="destructive"
                              disabled={deleteOff !== null}
                              onSelect={() => setDialog({ kind: "delete", pool: p })}
                            >
                              <Trash2Icon />
                              Delete…
                            </DropdownMenuItem>
                          </WhyDisabled>
                        </RowMenu>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </>
      )}

      {dialog?.kind === "edit" && (
        <PoolDialog
          existing={dialog.existing}
          taken={names.filter((n) => n !== dialog.existing?.name)}
          readOnly={readOnly}
          onSaved={(p) => {
            toast.success(dialog.existing ? `Saved ${p.name}` : `Added the address pool ${p.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "leases" && (
        <LeasesSheet pool={dialog.pool} readOnly={readOnly} onChanged={load} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "delete" && (
        <ConfirmDialog
          title={`Delete the address pool ${dialog.pool.name}?`}
          description="No VM holds one of its addresses. Deleted pools aren't kept in the trash."
          confirmLabel="Delete"
          onConfirm={async () => {
            await addressPoolsApi.remove(dialog.pool.id);
            toast.success(`Deleted the address pool ${dialog.pool.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}

const HYPERVISORS: Hypervisor[] = ["vmware", "virtualbox"];

function PoolDialog({
  existing,
  taken,
  readOnly,
  onSaved,
  onClose,
}: {
  existing?: AddressPool;
  taken: string[];
  readOnly: string | null;
  onSaved: (pool: AddressPool) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<PoolForm>(() => (existing ? poolForm(existing) : EMPTY_POOL_FORM));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const parsed = useMemo(() => parsePoolForm(form, taken), [form, taken]);
  const set = (change: Partial<PoolForm>) => setForm((f) => ({ ...f, ...change }));
  const setDns = (index: number, value: string) =>
    setForm((f) => {
      const dns: PoolForm["dns"] = [...f.dns];
      dns[index] = value;
      return { ...f, dns };
    });
  const network = form.network;

  async function save() {
    if (!("input" in parsed)) return;
    setBusy(true);
    setError(null);
    try {
      const saved = existing
        ? await addressPoolsApi.update(existing.id, parsed.input)
        : await addressPoolsApi.add(parsed.input);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const reason = readOnly ?? (busy ? "Saving…" : "error" in parsed ? parsed.error : null);

  return (
    <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{existing ? `Edit ${existing.name}` : "New address pool"}</DialogTitle>
          <DialogDescription className="flex items-center gap-1">
            Static addresses for VMs deployed on one network.
            <HelpTip topic="addressPool.free" />
          </DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!reason) void save();
          }}
        >
          <div className="grid gap-2">
            <Label htmlFor="pool-name">Name</Label>
            <Input
              id="pool-name"
              value={form.name}
              maxLength={MAX_NAME_CHARS}
              placeholder="lab"
              onChange={(e) => set({ name: e.currentTarget.value })}
              autoFocus
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-2">
              <Label htmlFor="pool-hypervisor">Hypervisor</Label>
              <Select
                value={form.hypervisor}
                onValueChange={(v) => {
                  const h = v as Hypervisor;
                  set({ hypervisor: h, network: networkKinds(h).includes(network.kind) ? network : { kind: "nat" } });
                }}
              >
                <SelectTrigger id="pool-hypervisor" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {HYPERVISORS.map((h) => (
                    <SelectItem key={h} value={h}>
                      {HYPERVISOR_LABEL[h]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pool-network">Network</Label>
              <div className="flex gap-2">
                <Select
                  value={network.kind}
                  onValueChange={(v) => set({ network: networkOfKind(v as TemplateNetwork["kind"], network) })}
                >
                  <SelectTrigger id="pool-network" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {networkKinds(form.hypervisor).map((k) => (
                      <SelectItem key={k} value={k}>
                        {NETWORK_KIND_LABEL[k]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {network.kind === "vmnet" && (
                  <Input
                    aria-label="vmnet number"
                    className="w-20"
                    inputMode="numeric"
                    value={String(network.number)}
                    onChange={(e) => {
                      const n = Number(e.currentTarget.value.replace(/\D/g, "") || "0");
                      set({ network: { kind: "vmnet", number: Math.min(n, 99) } });
                    }}
                  />
                )}
                {(network.kind === "natNetwork" || network.kind === "internal") && (
                  <Input
                    aria-label="Network name"
                    placeholder="Name"
                    value={network.name}
                    maxLength={MAX_NETWORK_NAME}
                    onChange={(e) => {
                      const kind = network.kind as "natNetwork" | "internal";
                      set({ network: { kind, name: e.currentTarget.value } });
                    }}
                  />
                )}
              </div>
            </div>
          </div>
          <div className="grid grid-cols-[1fr_1fr_5rem] gap-3">
            <div className="grid gap-2">
              <Label htmlFor="pool-first">First address</Label>
              <Input
                id="pool-first"
                data-mask="ip"
                placeholder="192.0.2.10"
                value={form.firstIp}
                onChange={(e) => set({ firstIp: e.currentTarget.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pool-last">Last address</Label>
              <Input
                id="pool-last"
                data-mask="ip"
                placeholder="192.0.2.50"
                value={form.lastIp}
                onChange={(e) => set({ lastIp: e.currentTarget.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pool-prefix">Prefix</Label>
              <Input
                id="pool-prefix"
                inputMode="numeric"
                value={form.prefix}
                onChange={(e) => set({ prefix: e.currentTarget.value })}
              />
            </div>
          </div>
          {"input" in parsed && (
            <p className="-mt-2 text-xs text-muted-foreground">{sizeText(parsed.size, parsed.usable)}</p>
          )}
          <div className="grid gap-2">
            <Label htmlFor="pool-gateway">Gateway (optional)</Label>
            <Input
              id="pool-gateway"
              data-mask="ip"
              placeholder="192.0.2.1"
              value={form.gateway}
              onChange={(e) => set({ gateway: e.currentTarget.value })}
            />
          </div>
          <fieldset className="grid gap-2">
            <legend className="mb-2 text-sm font-medium">DNS servers (optional)</legend>
            <div className="grid grid-cols-3 gap-2">
              {form.dns.map((d, i) => (
                <Input
                  key={i}
                  aria-label={`DNS server ${i + 1}`}
                  data-mask="ip"
                  value={d}
                  onChange={(e) => setDns(i, e.currentTarget.value)}
                />
              ))}
            </div>
          </fieldset>
          <div className="grid gap-2">
            <Label htmlFor="pool-notes">Notes (optional)</Label>
            <Textarea
              id="pool-notes"
              rows={2}
              maxLength={MAX_NOTES}
              value={form.notes}
              onChange={(e) => set({ notes: e.currentTarget.value })}
            />
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
            <WhyDisabled reason={reason}>
              <Button type="submit" disabled={reason !== null}>
                {busy ? "Saving…" : existing ? "Save" : "Add address pool"}
              </Button>
            </WhyDisabled>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function LeasesSheet({
  pool,
  readOnly,
  onChanged,
  onClose,
}: {
  pool: AddressPool;
  readOnly: string | null;
  onChanged: () => void;
  onClose: () => void;
}) {
  const [leases, setLeases] = useState<AddressLease[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [freeing, setFreeing] = useState<AddressLease | null>(null);

  const load = useCallback(() => {
    addressPoolsApi.leases(pool.id).then(setLeases, (err: unknown) => setError(errorMessage(err)));
  }, [pool.id]);

  useEffect(() => load(), [load]);

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Addresses of &lsquo;{pool.name}&rsquo;</SheetTitle>
          <SheetDescription>Each taken address and its VM. Deleting the VM gives the address back.</SheetDescription>
        </SheetHeader>
        <div className="grid gap-2 px-4 pb-4">
          {error && <p className="text-sm text-destructive">{error}</p>}
          {!leases && !error && <Skeleton className="h-24 w-full" />}
          {leases?.length === 0 && (
            <p className="text-sm text-muted-foreground">No VM holds an address of this pool.</p>
          )}
          {leases && leases.length > 0 && (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Address</TableHead>
                    <TableHead>VM</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {leases.map((lease) => {
                    const off = freeReason(readOnly, lease);
                    return (
                      <TableRow key={lease.ip}>
                        <TableCell className="font-mono text-xs">
                          <span data-mask="ip">{lease.ip}</span>
                        </TableCell>
                        <TableCell className="whitespace-normal">{lease.vmName}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-normal">
                            {leaseStateLabel(lease)}
                          </Badge>
                          {lease.canFree && lease.state === "assigned" && (
                            <div className="text-xs text-muted-foreground">Not on the VMs page</div>
                          )}
                        </TableCell>
                        <TableCell>
                          <RowMenu label={lease.ip}>
                            <WhyDisabled reason={off} className="flex w-full">
                              <DropdownMenuItem
                                className="w-full"
                                disabled={off !== null}
                                onSelect={() => setFreeing(lease)}
                              >
                                <UnlinkIcon />
                                Free the address…
                              </DropdownMenuItem>
                            </WhyDisabled>
                          </RowMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
        {freeing && (
          <ConfirmDialog
            title={`Free the address of ${freeing.vmName}?`}
            description="Only when that VM is gone: a VM still using the address would share it with the next VM deployed."
            confirmLabel="Free"
            onConfirm={async () => {
              await addressPoolsApi.free(pool.id, freeing.ip);
              load();
              onChanged();
            }}
            onClose={() => setFreeing(null)}
          />
        )}
      </SheetContent>
    </Sheet>
  );
}
