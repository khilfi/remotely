// VM-30: what a golden image build makes and does, for the build dialog's preview and the approval dialog: the image
// and its version (a new image or not), the version's VM, the install config and the ISO it installs from, the
// snapshot its clones are made from, what making it generic does, how Remotely signs in to do it, and the retention.
// The build VM's deploy preview (DeployPreviewView) and this PC after it (CapacityPlanView) show beside it.

import { Term } from "@/components/Term";
import type { BuildDetails } from "@/lib/golden-api";
import { BUILD_OS_LABEL, keepText, versionText } from "@/lib/golden";

export function BuildDetailsView({ details }: { details: BuildDetails }) {
  return (
    <section aria-label="What the build makes" className="grid gap-2 rounded-md border p-3 text-sm">
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-muted-foreground">
          <Term id="goldenImage">Image</Term>
        </dt>
        <dd className="break-words">
          {details.imageName}, {versionText(details.version).toLowerCase()}
          <span className="text-muted-foreground">
            {details.newImage ? ": a new image, made by this build" : ": the image's next version"}
          </span>
        </dd>
        <dt className="text-muted-foreground">VM</dt>
        <dd className="font-mono text-xs break-all">{details.vmName}</dd>
        <dt className="text-muted-foreground">Installs</dt>
        <dd className="break-words">
          {BUILD_OS_LABEL[details.os]} from &apos;{details.configName}&apos;
        </dd>
        <dt className="text-muted-foreground">ISO</dt>
        <dd className="font-mono text-xs break-all">{details.isoPath}</dd>
        <dt className="text-muted-foreground">Snapshot</dt>
        <dd>&lsquo;{details.snapshotName}&rsquo;, which its clones are made from</dd>
        <dt className="text-muted-foreground">Signs in</dt>
        <dd className="break-words">{details.signIn}</dd>
        {details.keep !== null && (
          <>
            <dt className="text-muted-foreground">Retention</dt>
            <dd className="text-tier-high">
              {keepText(details.keep)}: older versions&apos; VMs are deleted after the build, unless a linked clone uses
              them
            </dd>
            {/* B3 of PR 100's review: each old version it deletes is named, as a target of the approval. */}
            <dt className="text-muted-foreground">Deletes</dt>
            <dd className="break-words">{details.deletes.length > 0 ? details.deletes.join(", ") : "nothing now"}</dd>
            {details.retained.length > 0 && (
              <>
                <dt className="text-muted-foreground">Keeps</dt>
                <dd className="grid gap-0.5 break-words">
                  {details.retained.map((r) => (
                    <span key={r}>{r}</span>
                  ))}
                </dd>
              </>
            )}
          </>
        )}
      </dl>
      <div className="grid gap-1">
        <span className="text-muted-foreground">Then it makes the system generic, so each clone is its own:</span>
        <ul className="list-disc pl-5">
          {details.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}
