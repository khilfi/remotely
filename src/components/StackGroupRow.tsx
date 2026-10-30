// VM-08: the header row of a stack instance's VMs on the VMs page: its name, stack and state, and one row menu with
// Start (boot order), Shut down and Suspend (the last step first). UX-03: this is the one home of an instance's power;
// Add a VM, Forget and Tear down are on the Templates page's Stacks tab. Each goes through the bus and the approval
// dialog.

import { toast } from "sonner";
import { BoxesIcon, PauseIcon, PlayIcon, SquareIcon } from "lucide-react";
import { DropdownMenuItem } from "@/components/ui/dropdown-menu";
import { TableCell, TableRow } from "@/components/ui/table";
import { RowMenu } from "@/components/RowMenu";
import { Term } from "@/components/Term";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type PowerOp, type SubmitOutcome } from "@/lib/api";
import { instancePowerReason, instanceStateText } from "@/lib/stacks";
import { stacksApi, type StackInstance } from "@/lib/stacks-api";

interface Props {
  instance: StackInstance;
  colSpan: number;
  readOnly: string | null;
  onSubmitted: (outcome: SubmitOutcome) => void;
}

export function StackGroupRow({ instance, colSpan, readOnly, onSubmitted }: Props) {
  async function power(op: PowerOp) {
    try {
      onSubmitted(await stacksApi.power(instance.id, op));
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }
  const start = instancePowerReason(instance, "start", readOnly);
  const stop = instancePowerReason(instance, "stop", readOnly);
  const suspend = instancePowerReason(instance, "suspend", readOnly);
  const steps = instance.steps.length;
  const items = [
    { key: "start", label: "Start in boot order", icon: PlayIcon, off: start, op: { kind: "start" } as PowerOp },
    {
      key: "stop",
      label: "Shut down, last step first",
      icon: SquareIcon,
      off: stop,
      op: { kind: "stop", mode: "soft" } as PowerOp,
    },
    {
      key: "suspend",
      label: "Suspend, last step first",
      icon: PauseIcon,
      off: suspend,
      op: { kind: "suspend" } as PowerOp,
    },
  ];
  return (
    <TableRow className="bg-muted/40 hover:bg-muted/40" data-stack-instance={instance.id}>
      <TableCell colSpan={colSpan} className="py-1">
        <div className="flex items-center gap-2">
          <div className="flex min-w-0 flex-1 items-center gap-2 text-sm">
            <BoxesIcon className="size-4 shrink-0 text-muted-foreground" aria-hidden />
            <span className="font-medium">{instance.name}</span>
            <span className="truncate text-xs text-muted-foreground">
              <Term id="stack">stack</Term> {instance.stackName}
              {steps > 1 && ` · ${steps} steps`} · {instanceStateText(instance)}
            </span>
          </div>
          <RowMenu label={instance.name} disabled={readOnly !== null}>
            {items.map(({ key, label, icon: Icon, off, op }) => (
              <WhyDisabled key={key} reason={off} className="flex w-full">
                <DropdownMenuItem className="w-full" disabled={off !== null} onSelect={() => void power(op)}>
                  <Icon />
                  {label}
                </DropdownMenuItem>
              </WhyDisabled>
            ))}
          </RowMenu>
        </div>
      </TableCell>
    </TableRow>
  );
}
