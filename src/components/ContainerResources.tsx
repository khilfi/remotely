// CT-01, CT-02: a container host's images, volumes and networks on the Containers page. Images and volumes can be
// selected and removed (High; removing volumes deletes their data, so Critical), and the page's host menu pulls and
// prunes. Networks are listed only. Every change is a command for the bus; nothing here runs a CLI.

import { useState, type MouseEvent } from "react";
import { Trash2Icon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { WhyDisabled } from "@/components/WhyDisabled";
import type { ContainerSummary, ImageSummary, NetworkSummary, VolumeSummary } from "@/lib/api";
import { formatBytes } from "@/lib/containers";
import { formatWhen, plural } from "@/lib/format";
import { cn } from "@/lib/utils";

/** Click toggles a row; Shift+click selects the range from the last click. */
function useRangeSelection(keys: string[]) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [anchor, setAnchor] = useState<number | null>(null);
  const shown = new Set(keys);
  const kept = new Set([...selected].filter((k) => shown.has(k)));
  function toggle(index: number, e: MouseEvent) {
    const key = keys[index];
    setSelected((prev) => {
      const next = new Set([...prev].filter((k) => shown.has(k)));
      if (e.shiftKey && anchor !== null) {
        const [from, to] = anchor < index ? [anchor, index] : [index, anchor];
        for (let i = from; i <= to; i++) next.add(keys[i]);
      } else if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
    setAnchor(index);
  }
  return {
    selected: kept,
    toggle,
    all: kept.size > 0 && kept.size === keys.length,
    setAll: (on: boolean) => setSelected(on ? new Set(keys) : new Set()),
    clear: () => setSelected(new Set()),
  };
}

const dash = <span className="text-muted-foreground">—</span>;

export function ImagesTab({
  images,
  containers,
  removeReason,
  onRemove,
}: {
  images: ImageSummary[];
  containers: ContainerSummary[];
  /** QL-08: why removing is off for the whole tab (read-only lock, protected host), or null. */
  removeReason: string | null;
  onRemove: (images: ImageSummary[]) => void;
}) {
  const keys = images.map((i) => i.id);
  const pick = useRangeSelection(keys);
  const picked = images.filter((i) => pick.selected.has(i.id));
  const usedBy = (image: ImageSummary) =>
    containers.filter(
      (c) => image.tags.includes(c.image) || c.image.includes(image.id.replace("sha256:", "").slice(0, 12)),
    );
  const reason = removeReason ?? (picked.length === 0 ? "Select images first" : null);
  return (
    <div className="grid min-h-0 gap-2">
      <div className="flex items-center gap-2">
        <WhyDisabled reason={reason}>
          <Button
            variant="outline"
            size="sm"
            disabled={reason !== null}
            onClick={() => {
              onRemove(picked);
              pick.clear();
            }}
          >
            <Trash2Icon data-icon="inline-start" />
            Remove{picked.length > 0 ? ` ${plural(picked.length, "image")}` : ""}…
          </Button>
        </WhyDisabled>
        <span className="text-xs text-muted-foreground">
          {plural(images.length, "image")}, {formatBytes(images.reduce((sum, i) => sum + (i.sizeBytes ?? 0), 0))}
        </span>
      </div>
      <div className="overflow-auto rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">
                <Checkbox
                  aria-label="Select all images"
                  checked={pick.all ? true : pick.selected.size > 0 ? "indeterminate" : false}
                  onCheckedChange={() => pick.setAll(!pick.all)}
                />
              </TableHead>
              <TableHead>Image</TableHead>
              <TableHead>Id</TableHead>
              <TableHead className="text-right">Size</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Used by</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {images.map((image, i) => {
              const users = usedBy(image);
              return (
                <TableRow
                  key={image.id}
                  data-state={pick.selected.has(image.id) ? "selected" : undefined}
                  onClick={(e) => pick.toggle(i, e)}
                  className="select-none"
                >
                  <TableCell>
                    <Checkbox
                      aria-label={`Select ${image.tags[0] ?? image.id}`}
                      checked={pick.selected.has(image.id)}
                    />
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    {image.tags.length === 0 ? (
                      <Badge variant="outline" className="text-muted-foreground">
                        No tag (dangling)
                      </Badge>
                    ) : (
                      image.tags.map((t) => (
                        <div key={t} className="break-all">
                          {t}
                        </div>
                      ))
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{image.id.replace("sha256:", "").slice(0, 12)}</TableCell>
                  <TableCell className="text-right tabular-nums">{formatBytes(image.sizeBytes)}</TableCell>
                  <TableCell>{image.createdAt ? formatWhen(image.createdAt) : dash}</TableCell>
                  <TableCell className="whitespace-normal">
                    {users.length > 0 ? users.map((c) => c.name).join(", ") : dash}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export function VolumesTab({
  volumes,
  containers,
  removeReason,
  onRemove,
}: {
  volumes: VolumeSummary[];
  containers: ContainerSummary[];
  removeReason: string | null;
  onRemove: (volumes: VolumeSummary[]) => void;
}) {
  const keys = volumes.map((v) => v.name);
  const pick = useRangeSelection(keys);
  const picked = volumes.filter((v) => pick.selected.has(v.name));
  const usedBy = (volume: VolumeSummary) => containers.filter((c) => c.mounts.includes(volume.name));
  const reason = removeReason ?? (picked.length === 0 ? "Select volumes first" : null);
  return (
    <div className="grid min-h-0 gap-2">
      <div className="flex items-center gap-2">
        <WhyDisabled reason={reason}>
          <Button
            variant="outline"
            size="sm"
            disabled={reason !== null}
            onClick={() => {
              onRemove(picked);
              pick.clear();
            }}
          >
            <Trash2Icon data-icon="inline-start" />
            Remove{picked.length > 0 ? ` ${plural(picked.length, "volume")}` : ""}…
          </Button>
        </WhyDisabled>
        <span className="text-xs text-muted-foreground">
          Removing a volume deletes every file in it: Critical, so it asks for the vault password.
        </span>
      </div>
      <div className="overflow-auto rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">
                <Checkbox
                  aria-label="Select all volumes"
                  checked={pick.all ? true : pick.selected.size > 0 ? "indeterminate" : false}
                  onCheckedChange={() => pick.setAll(!pick.all)}
                />
              </TableHead>
              <TableHead>Volume</TableHead>
              <TableHead>Driver</TableHead>
              <TableHead>Project</TableHead>
              <TableHead title="From each container's mounts as the engine lists them; Podman may leave it empty">
                Used by
              </TableHead>
              <TableHead>Where</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {volumes.map((volume, i) => {
              const users = usedBy(volume);
              return (
                <TableRow
                  key={volume.name}
                  data-state={pick.selected.has(volume.name) ? "selected" : undefined}
                  onClick={(e) => pick.toggle(i, e)}
                  className="select-none"
                >
                  <TableCell>
                    <Checkbox aria-label={`Select ${volume.name}`} checked={pick.selected.has(volume.name)} />
                  </TableCell>
                  <TableCell className={cn("break-all whitespace-normal", volume.anonymous && "font-mono text-xs")}>
                    {volume.anonymous ? volume.name.slice(0, 12) : volume.name}
                    {volume.anonymous && (
                      <Badge variant="outline" className="ml-1.5 font-sans text-muted-foreground">
                        anonymous
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>{volume.driver ?? dash}</TableCell>
                  <TableCell>{volume.project ?? dash}</TableCell>
                  <TableCell className="whitespace-normal">
                    {users.length > 0 ? users.map((c) => c.name).join(", ") : dash}
                  </TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal text-muted-foreground">
                    {volume.mountpoint ?? "—"}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

export function NetworksTab({ networks }: { networks: NetworkSummary[] }) {
  return (
    <div className="overflow-auto rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Network</TableHead>
            <TableHead>Driver</TableHead>
            <TableHead>Scope</TableHead>
            <TableHead>Subnets</TableHead>
            <TableHead>Id</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {networks.map((n) => (
            <TableRow key={n.id}>
              <TableCell>
                {n.name}
                {n.internal && (
                  <Badge variant="outline" className="ml-1.5">
                    internal
                  </Badge>
                )}
              </TableCell>
              <TableCell>{n.driver ?? dash}</TableCell>
              <TableCell>{n.scope ?? dash}</TableCell>
              <TableCell className="font-mono text-xs">{n.subnets.join(", ") || "—"}</TableCell>
              <TableCell className="font-mono text-xs">{n.id.slice(0, 12)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
