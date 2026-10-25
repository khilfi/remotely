// SS-08: the transfers panel: each file going up or down through a terminal, with its progress, speed and time left.
// Cancel while it runs, retry once it failed or was cancelled (an upload goes through the approval flow again), and
// "Open folder" for a finished download. The core keeps the list; "Clear finished" only hides rows here. P6: the list
// comes from the transfers store (src/lib/transfers-store.ts), so a transfer's progress re-renders this panel and its
// changed row only, not the Terminal page around it.

import {
  ArrowDownToLineIcon,
  ArrowUpFromLineIcon,
  CircleCheckIcon,
  CircleXIcon,
  FolderOpenIcon,
  RotateCcwIcon,
  XIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api, errorMessage, type TransferInfo } from "@/lib/api";
import { formatDuration } from "@/lib/format";
import { formatSize, formatSpeed, isActive, percent, secondsLeft } from "@/lib/transfers";
import { cn } from "@/lib/utils";
import { toast } from "sonner";
import { memo } from "react";
import { useTransfers } from "@/hooks/use-transfers";
import { transferStore } from "@/lib/transfers-store";

interface Props {
  onRetry: (transfer: TransferInfo) => void;
}

export function TransfersList({ onRetry }: Props) {
  // Newest last, as the core keeps them; the panel shows the newest first.
  const transfers = useTransfers().shown;
  const shown = [...transfers].reverse();
  const finished = transfers.some((t) => !isActive(t));
  return (
    <section className="flex min-h-0 flex-col gap-1" aria-label="Transfers">
      <div className="flex items-center gap-2">
        <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Transfers</h3>
        {finished && (
          <Button size="xs" variant="ghost" className="ml-auto" onClick={() => transferStore.clearFinished()}>
            Clear finished
          </Button>
        )}
      </div>
      {shown.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          Nothing yet. Uploads and downloads show here with their progress.
        </p>
      ) : (
        <ul className="min-h-0 divide-y overflow-auto rounded-md border">
          {shown.map((t) => (
            <TransferRow key={t.id} transfer={t} onRetry={onRetry} />
          ))}
        </ul>
      )}
    </section>
  );
}

function RowButton({ label, onClick, children }: { label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button variant="ghost" size="icon-xs" aria-label={label} onClick={onClick}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}

/** Memoised: a change to one transfer re-renders its own row only. */
const TransferRow = memo(function TransferRow({
  transfer: t,
  onRetry,
}: {
  transfer: TransferInfo;
  onRetry: (transfer: TransferInfo) => void;
}) {
  const active = isActive(t);
  const left = secondsLeft(t);
  const speed = formatSpeed(t.bytesPerSec);
  const where = t.direction === "upload" ? `to ${t.remotePath}` : `from ${t.remotePath}`;
  let line: string;
  if (t.state === "queued") line = `Waiting · ${formatSize(t.size)}`;
  else if (t.state === "running")
    line = [`${formatSize(t.done)} of ${formatSize(t.size)}`, speed, left !== null && `${formatDuration(left)} left`]
      .filter(Boolean)
      .join(" · ");
  else if (t.state === "done")
    line = t.direction === "download" && t.localPath ? `Saved to ${t.localPath}` : `${formatSize(t.size)} uploaded`;
  else line = t.message ?? (t.state === "cancelled" ? "Cancelled" : "Failed");

  async function cancel() {
    try {
      await api.filesCancel(t.id);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function openFolder() {
    try {
      await api.filesOpenFolder(t.id);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  return (
    <li className="grid gap-1 px-2 py-1.5 text-xs">
      <div className="flex min-w-0 items-center gap-1.5">
        {t.direction === "upload" ? (
          <ArrowUpFromLineIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="Upload" />
        ) : (
          <ArrowDownToLineIcon className="size-3.5 shrink-0 text-muted-foreground" aria-label="Download" />
        )}
        <span className="truncate font-medium" title={`${t.name} ${where} (${t.terminal})`}>
          {t.name}
        </span>
        {t.replace && <span className="shrink-0 text-tier-medium">replaces</span>}
        {t.state === "done" && <CircleCheckIcon className="size-3.5 shrink-0 text-success" aria-label="Done" />}
        {t.state === "failed" && <CircleXIcon className="size-3.5 shrink-0 text-destructive" aria-label="Failed" />}
        <span className="ml-auto flex shrink-0 items-center">
          {active && (
            <RowButton label="Cancel" onClick={() => void cancel()}>
              <XIcon />
            </RowButton>
          )}
          {(t.state === "failed" || t.state === "cancelled") && (
            <RowButton label="Retry" onClick={() => onRetry(t)}>
              <RotateCcwIcon />
            </RowButton>
          )}
          {t.state === "done" && t.direction === "download" && (
            <RowButton label="Open folder" onClick={() => void openFolder()}>
              <FolderOpenIcon />
            </RowButton>
          )}
        </span>
      </div>
      {active && <Progress value={percent(t)} className="h-1" aria-label={`${t.name}: ${percent(t)}%`} />}
      <p
        className={cn(
          "truncate text-muted-foreground",
          t.state === "failed" && "text-destructive",
          t.state === "failed" && "whitespace-normal",
        )}
        title={t.sha256 ? `SHA-256 ${t.sha256}` : (t.message ?? undefined)}
      >
        {line}
      </p>
      {/* A8: a finished download that could not be marked as from the internet says so. */}
      {t.state === "done" && t.message && <p className="whitespace-normal text-tier-medium">{t.message}</p>}
      <p className="truncate text-[11px] text-muted-foreground/80">
        {where} · {t.terminal}
      </p>
    </li>
  );
});
