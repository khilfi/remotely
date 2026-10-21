// VM-04 one VM's snapshot tree, in its details panel on the Virtual machines page (QL-14): read from the VM's .vmsd
// (tree order, creation times, "you are here"), snapshots older than the limit flagged and Remotely's safety snapshots
// (VM-05) marked. Revert and delete on a snapshot are commands for the bus; the approval dialog follows.

import type { ReactElement } from "react";
import { CameraIcon, MapPinIcon, Trash2Icon, Undo2Icon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { WhyDisabled } from "@/components/WhyDisabled";
import type { SnapshotNode, VmSnapshots } from "@/lib/api";
import { formatAge } from "@/lib/format";
import { cn } from "@/lib/utils";
import { snapshotActionReason, unreachableByName } from "@/lib/vm-snapshots";

interface Props {
  tree: VmSnapshots;
  oldAfterDays: number;
  /** FD-03: the read-only lock's reason, or null. */
  readOnly: string | null;
  busy: boolean;
  /** What reverting and deleting would mean for this VM (its tier, approval, safety snapshot). */
  hints: { revert: string | null; delete: string | null };
  onRevert: (node: SnapshotNode) => void;
  onDelete: (node: SnapshotNode) => void;
}

export function SnapshotTree({ tree, oldAfterDays, readOnly, busy, hints, onRevert, onDelete }: Props) {
  return (
    <ol aria-label={`Snapshots of ${tree.displayName}`} className="flex flex-col gap-0.5">
      {tree.snapshots.map((node) => {
        const reason = snapshotActionReason({
          node,
          hypervisor: tree.hypervisor,
          readOnly,
          protected: tree.protected,
          busy,
        });
        const label = node.name || "(no name)";
        return (
          <li
            key={node.uid}
            aria-current={node.current ? "step" : undefined}
            className={cn(
              "flex items-start gap-2 rounded-md py-1.5 pr-1 hover:bg-muted/50",
              node.current && "bg-muted/60",
            )}
            style={{ paddingLeft: `${0.5 + node.depth * 1.25}rem` }}
          >
            <span className="mt-px w-3 shrink-0 text-muted-foreground" aria-hidden>
              {node.depth > 0 ? "└" : "•"}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-medium break-words">{label}</span>
                {node.current && (
                  <Badge variant="secondary" className="font-normal">
                    <MapPinIcon />
                    You are here
                  </Badge>
                )}
                {node.safety && (
                  <Badge variant="outline" className="font-normal">
                    <CameraIcon />
                    Safety
                  </Badge>
                )}
                {node.old && (
                  <Badge variant="outline" className="border-tier-medium/40 text-tier-medium">
                    Older than {oldAfterDays} days
                  </Badge>
                )}
              </div>
              <div className="text-xs text-muted-foreground">
                {node.createdAt ? (
                  <span title={new Date(node.createdAt).toLocaleString()}>
                    Taken {new Date(node.createdAt).toLocaleDateString()} ({formatAge(node.ageDays)})
                  </span>
                ) : (
                  "Taken: unknown"
                )}
              </div>
              {node.description && (
                <div className="text-xs break-words whitespace-pre-line text-muted-foreground">{node.description}</div>
              )}
              {unreachableByName(node, tree.hypervisor) && (
                <div className="text-xs text-muted-foreground">
                  vmrun reads &apos;/&apos; as a path, so manage this one in Workstation
                </div>
              )}
            </div>
            <div className="flex shrink-0 gap-0.5">
              <IconAction
                label={`Revert ${tree.displayName} to ${label}`}
                tip={hints.revert ? `Revert to this snapshot. ${hints.revert}` : "Revert to this snapshot"}
                reason={reason}
                onClick={() => onRevert(node)}
              >
                <Undo2Icon />
              </IconAction>
              <IconAction
                label={`Delete the snapshot ${label} of ${tree.displayName}`}
                tip={hints.delete ? `Delete this snapshot. ${hints.delete}` : "Delete this snapshot"}
                reason={reason}
                destructive
                onClick={() => onDelete(node)}
              >
                <Trash2Icon />
              </IconAction>
            </div>
          </li>
        );
      })}
    </ol>
  );
}

/** An icon button with its purpose in a tooltip, or (QL-08) why it is off. */
function IconAction({
  label,
  tip,
  reason,
  destructive,
  onClick,
  children,
}: {
  label: string;
  tip: string;
  reason: string | null;
  destructive?: boolean;
  onClick: () => void;
  children: ReactElement;
}) {
  const button = (
    <Button
      size="icon-sm"
      variant="ghost"
      aria-label={label}
      className={destructive ? "text-destructive hover:text-destructive" : undefined}
      disabled={reason !== null}
      onClick={onClick}
    >
      {children}
    </Button>
  );
  if (reason) return <WhyDisabled reason={reason}>{button}</WhyDisabled>;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent className="max-w-72">{tip}</TooltipContent>
    </Tooltip>
  );
}
