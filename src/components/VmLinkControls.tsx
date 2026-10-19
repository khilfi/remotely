// QL-01: a session's link to the VM it reaches, shown on both sides: the session's VM on the Sessions
// page, and a VM's sessions on the VM list. Links are made automatically when a session's host (or
// what it resolves to) is a VM's guest IP; the user can keep (confirm), change or remove them, and a
// link they chose is never changed automatically. The app's own data: the core audits each change,
// with no approval step.

import { useState } from "react";
import { CheckIcon, LinkIcon, Unlink2Icon } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { api, errorMessage, type SessionRecord, type VmRecord } from "@/lib/api";

/** Marks a link auto-linking made and the user has not confirmed. */
export function AutoBadge() {
  return (
    <Badge variant="outline" className="px-1.5 font-normal text-muted-foreground" title="Linked automatically by IP">
      auto
    </Badge>
  );
}

async function run(action: () => Promise<unknown>, done: string, onChanged: () => void) {
  try {
    await action();
    toast.success(done);
    onChanged();
  } catch (err) {
    toast.error(errorMessage(err));
  }
}

function describe(session: SessionRecord) {
  if (session.vmLink === "auto") return "Linked automatically: its host is this VM's IP address.";
  if (session.vmId) return "Linked by hand. Auto-linking leaves it alone.";
  if (session.vmLink === "manual") return "Not linked, by choice. Auto-linking tries again if its host changes.";
  return "Not linked. It links on its own when its host is a running VM's IP address.";
}

/** The Sessions page's VM cell: which VM the session reaches, and how to change that. */
export function SessionVmLink({
  session,
  vms,
  candidates,
  onChanged,
}: {
  session: SessionRecord;
  vms: VmRecord[];
  /** VMs that all have the session's address (QL-01 leaves the choice to the user). */
  candidates: string[];
  onChanged: () => void;
}) {
  const vm = session.vmId ? vms.find((v) => v.id === session.vmId) : undefined;
  const matching = vms.filter((v) => candidates.includes(v.id));
  const others = vms.filter((v) => !candidates.includes(v.id) && v.id !== session.vmId);
  const link = (target: VmRecord) =>
    void run(
      () => api.linkSessionVm(session.id, target.id),
      `Linked ${session.name} to ${target.displayName}`,
      onChanged,
    );
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 max-w-48 justify-start font-normal"
          aria-label={`VM link of ${session.name}`}
        >
          {session.vmId ? (
            <>
              <span className="truncate">{vm?.displayName ?? "VM not listed now"}</span>
              {session.vmLink === "auto" && <AutoBadge />}
            </>
          ) : matching.length > 1 ? (
            <span className="text-status-warning">{matching.length} VMs match</span>
          ) : (
            <span className="text-muted-foreground">—</span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-72">
        <DropdownMenuLabel className="text-xs font-normal whitespace-normal text-muted-foreground">
          {matching.length > 1 && !session.vmId
            ? `${matching.length} VMs have this session's address. Pick the one it reaches.`
            : describe(session)}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {session.vmLink === "auto" && vm && (
          <DropdownMenuItem
            onSelect={() =>
              void run(
                () => api.confirmSessionVmLink(session.id),
                `Kept the link of ${session.name} to ${vm.displayName}`,
                onChanged,
              )
            }
          >
            <CheckIcon /> Keep this link
          </DropdownMenuItem>
        )}
        {matching.map((v) => (
          <DropdownMenuItem key={v.id} onSelect={() => link(v)}>
            <LinkIcon /> Link to {v.displayName}
            <span className="ml-auto font-mono text-xs text-muted-foreground" data-mask="ip">
              {v.ipAddress}
            </span>
          </DropdownMenuItem>
        ))}
        <DropdownMenuSub>
          <DropdownMenuSubTrigger disabled={others.length === 0}>
            <LinkIcon /> {session.vmId ? "Link to another VM" : "Link to a VM"}
          </DropdownMenuSubTrigger>
          <DropdownMenuSubContent className="max-h-80 overflow-y-auto">
            {others.map((v) => (
              <DropdownMenuItem key={v.id} onSelect={() => link(v)}>
                {v.displayName}
                {v.ipAddress && (
                  <span className="ml-auto font-mono text-xs text-muted-foreground" data-mask="ip">
                    {v.ipAddress}
                  </span>
                )}
              </DropdownMenuItem>
            ))}
          </DropdownMenuSubContent>
        </DropdownMenuSub>
        {session.vmId && (
          <DropdownMenuItem
            variant="destructive"
            onSelect={() => void run(() => api.linkSessionVm(session.id, null), `Unlinked ${session.name}`, onChanged)}
          >
            <Unlink2Icon /> Unlink
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** The VM list's Sessions cell: the sessions that reach the VM, and linking one more. */
export function VmSessionLinks({
  vm,
  sessions,
  onChanged,
}: {
  vm: VmRecord;
  /** Every saved session; the ones linked to this VM are shown. */
  sessions: SessionRecord[];
  onChanged: () => void;
}) {
  const [open, setOpen] = useState(false);
  const linked = sessions.filter((s) => s.vmId === vm.id);
  const others = sessions.filter((s) => s.vmId !== vm.id);
  const done = () => {
    setOpen(false);
    onChanged();
  };
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="-ml-2 max-w-44 justify-start font-normal"
          aria-label={`Sessions linked to ${vm.displayName}`}
        >
          {linked.length === 0 ? (
            <span className="text-muted-foreground">—</span>
          ) : (
            <>
              <span className="truncate">{linked[0].name}</span>
              {linked.length > 1 && <span className="text-muted-foreground">+{linked.length - 1}</span>}
              {linked.some((s) => s.vmLink === "auto") && <AutoBadge />}
            </>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-0">
        {linked.length > 0 && (
          <ul className="divide-y border-b">
            {linked.map((s) => (
              <li key={s.id} className="flex items-center gap-2 px-3 py-2 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span className="truncate font-medium">{s.name}</span>
                    {s.vmLink === "auto" && <AutoBadge />}
                  </div>
                  <div className="truncate font-mono text-xs text-muted-foreground" data-mask="host">
                    {s.host}
                  </div>
                </div>
                {s.vmLink === "auto" && (
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Keep the link of ${s.name}`}
                    title="Keep this link"
                    onClick={() =>
                      void run(
                        () => api.confirmSessionVmLink(s.id),
                        `Kept the link of ${s.name} to ${vm.displayName}`,
                        done,
                      )
                    }
                  >
                    <CheckIcon />
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label={`Unlink ${s.name}`}
                  title="Unlink"
                  onClick={() => void run(() => api.linkSessionVm(s.id, null), `Unlinked ${s.name}`, done)}
                >
                  <Unlink2Icon />
                </Button>
              </li>
            ))}
          </ul>
        )}
        <Command>
          <CommandInput placeholder="Link a session…" />
          <CommandList>
            <CommandEmpty>No session matches.</CommandEmpty>
            <CommandGroup heading={vm.ipAddress ? `Sessions (this VM is ${vm.ipAddress})` : "Sessions"}>
              {others.map((s) => (
                <CommandItem
                  key={s.id}
                  value={`${s.name} ${s.host} ${s.id}`}
                  onSelect={() =>
                    void run(() => api.linkSessionVm(s.id, vm.id), `Linked ${s.name} to ${vm.displayName}`, done)
                  }
                >
                  <span className="truncate">{s.name}</span>
                  <span className="ml-auto truncate font-mono text-xs text-muted-foreground" data-mask="host">
                    {s.host}
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
        <p className="border-t px-3 py-2 text-xs text-muted-foreground">
          Sessions whose host is this VM&apos;s IP address link on their own. A linked session lets bulk runs and guest
          metrics reach the VM; links you choose are never changed automatically.
        </p>
      </PopoverContent>
    </Popover>
  );
}
