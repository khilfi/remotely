// VM-08: the header row of a stack instance's VMs on the VMs page: its name, stack and state, with Start (boot order),
// Shut down and Suspend (the last step first) and Tear down (Critical, the approval lists every file). Each goes
// through the bus and the approval dialog; VMs added by hand are kept by a teardown from here (pick them on the
// Templates page's Stacks tab).

import { toast } from "sonner";
import { BoxesIcon, MoreHorizontalIcon, PauseIcon, PlayIcon, PowerIcon, Trash2Icon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { TableCell, TableRow } from "@/components/ui/table";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type PowerOp, type SubmitOutcome } from "@/lib/api";
import { instancePowerReason, instanceStateText, teardownReason } from "@/lib/stacks";
import { stacksApi, type StackInstance } from "@/lib/stacks-api";

interface Props {
  instance: StackInstance;
  colSpan: number;
  readOnly: string | null;
  onSubmitted: (outcome: SubmitOutcome) => void;
}

export function StackGroupRow({ instance, colSpan, readOnly, onSubmitted }: Props) {
  async function run(submit: () => Promise<SubmitOutcome>) {
    try {
      onSubmitted(await submit());
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }
  const power = (op: PowerOp) => run(() => stacksApi.power(instance.id, op));
  const start = instancePowerReason(instance, "start", readOnly);
  const stop = instancePowerReason(instance, "stop", readOnly);
  const suspend = instancePowerReason(instance, "suspend", readOnly);
  const tear = teardownReason(instance, readOnly);
  const steps = instance.steps.length;
  return (
    <TableRow className="bg-muted/40 hover:bg-muted/40" data-stack-instance={instance.id}>
      <TableCell colSpan={colSpan} className="py-1.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2 text-sm">
            <BoxesIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="font-medium">{instance.name}</span>
            <span className="truncate text-xs text-muted-foreground">
              stack {instance.stackName}
              {steps > 1 && ` · ${steps} steps`} · {instanceStateText(instance)}
            </span>
          </div>
          <div className="flex items-center gap-1">
            <WhyDisabled reason={start}>
              <Button
                size="sm"
                variant="ghost"
                disabled={start !== null}
                onClick={() => void power({ kind: "start" })}
                aria-label={`Start ${instance.name} in boot order`}
              >
                <PlayIcon data-icon="inline-start" />
                Start
              </Button>
            </WhyDisabled>
            <WhyDisabled reason={stop}>
              <Button
                size="sm"
                variant="ghost"
                disabled={stop !== null}
                onClick={() => void power({ kind: "stop", mode: "soft" })}
                aria-label={`Shut down ${instance.name}, the last step first`}
              >
                <PowerIcon data-icon="inline-start" />
                Shut down
              </Button>
            </WhyDisabled>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="icon" variant="ghost" aria-label={`More for ${instance.name}`}>
                  <MoreHorizontalIcon />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem disabled={suspend !== null} onSelect={() => void power({ kind: "suspend" })}>
                  <PauseIcon />
                  <span>
                    Suspend
                    <ReasonLine reason={suspend} />
                  </span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  disabled={tear !== null}
                  onSelect={() => void run(() => stacksApi.teardown(instance.id, []))}
                >
                  <Trash2Icon />
                  <span>
                    Tear down…
                    <ReasonLine reason={tear} />
                  </span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </TableCell>
    </TableRow>
  );
}
