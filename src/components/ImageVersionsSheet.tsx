// VM-30: an image Remotely builds, version by version, newest first: each version's state (the newest, which its
// launch templates deploy; kept; deleted by retention or by hand), its VM and snapshot, when it was built and from
// which install config, the linked clones made from it (read now: a version with any is never deleted), and what
// making it generic found missing. "Show the VM" opens the version's VM on the VMs page.

import { useEffect, useState } from "react";
import { MonitorIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Term } from "@/components/Term";
import { WhyDisabled } from "@/components/WhyDisabled";
import { errorMessage, type Image } from "@/lib/api";
import { HYPERVISOR_LABEL } from "@/lib/catalog";
import { formatWhen } from "@/lib/format";
import { goldenApi, type ImageVersion, type VersionState } from "@/lib/golden-api";
import { factsText, keepText, versionStateText, versionText } from "@/lib/golden";
import { linkLabel, requestLink } from "@/lib/links";
import { cn } from "@/lib/utils";

const TONE: Record<VersionState, string> = {
  newest: "border-success/40 text-success",
  kept: "text-muted-foreground",
  deleted: "border-destructive/40 text-destructive",
};

interface Props {
  image: Image;
  /** Changes when a VM job finished (a build, or retention): the list is read again. */
  refreshKey?: number;
  onClose: () => void;
}

export function ImageVersionsSheet({ image, refreshKey, onClose }: Props) {
  const [versions, setVersions] = useState<ImageVersion[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    goldenApi.versions(image.id).then(
      (list) => {
        if (!live) return;
        setVersions(list);
        setError(null);
      },
      (err: unknown) => live && setError(errorMessage(err)),
    );
    return () => {
      live = false;
    };
  }, [image.id, refreshKey]);

  function showVm(version: ImageVersion) {
    requestLink({ kind: "vm", vmxPath: version.vmKey });
    onClose();
  }

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>Versions of &lsquo;{image.name}&rsquo;</SheetTitle>
          <SheetDescription>
            {keepText(image.build?.keep ?? null)}. Its launch templates deploy the newest; each{" "}
            <Term id="linkedClone">linked clone</Term> keeps the version it was made from.
          </SheetDescription>
        </SheetHeader>
        <div className="grid gap-2 px-4 pb-4">
          {error && <p className="text-sm text-destructive">{error}</p>}
          {!versions && !error && <Skeleton className="h-24 w-full" />}
          {versions?.length === 0 && <p className="text-sm text-muted-foreground">No version yet.</p>}
          {versions?.map((v) => {
            const missing = factsText(v.facts);
            const gone = v.state === "deleted";
            return (
              <div key={v.id} className="grid gap-1 rounded-md border p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{versionText(v.number)}</span>
                  <Badge variant="outline" className={cn("shrink-0", TONE[v.state])}>
                    {versionStateText(v)}
                  </Badge>
                  <span className="ml-auto text-xs text-muted-foreground">built {formatWhen(v.builtAt)}</span>
                </div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
                  <dt className="text-muted-foreground">VM</dt>
                  <dd className="break-all">
                    <span className="font-mono">{v.vmName}</span>
                    <span className="text-muted-foreground"> on {HYPERVISOR_LABEL[v.hypervisor]}</span>
                  </dd>
                  <dt className="text-muted-foreground">Snapshot</dt>
                  <dd className="break-words">&lsquo;{v.snapshotName}&rsquo;</dd>
                  <dt className="text-muted-foreground">Install config</dt>
                  <dd className="break-words">&lsquo;{v.configName}&rsquo;</dd>
                  {v.linkedClones.length > 0 && (
                    <>
                      <dt className="text-muted-foreground">Linked clones</dt>
                      <dd className="break-words">{v.linkedClones.join(", ")}</dd>
                    </>
                  )}
                  {v.clonesUnread && (
                    <>
                      <dt className="text-muted-foreground">Linked clones</dt>
                      <dd className="break-words text-tier-medium">not read: {v.clonesUnread}</dd>
                    </>
                  )}
                  {missing.length > 0 && (
                    <>
                      <dt className="text-muted-foreground">Found</dt>
                      <dd className="text-tier-medium">{missing.join(", ")}</dd>
                    </>
                  )}
                  {v.deletedAt && (
                    <>
                      <dt className="text-muted-foreground">Deleted</dt>
                      <dd>{formatWhen(v.deletedAt)}</dd>
                    </>
                  )}
                </dl>
                <div>
                  <WhyDisabled reason={gone ? "Its VM was deleted" : null}>
                    <Button variant="ghost" size="sm" disabled={gone} onClick={() => showVm(v)}>
                      <MonitorIcon data-icon="inline-start" />
                      {linkLabel({ kind: "vm", vmxPath: v.vmKey })}
                    </Button>
                  </WhyDisabled>
                </div>
              </div>
            );
          })}
        </div>
      </SheetContent>
    </Sheet>
  );
}
