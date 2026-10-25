// VM-19 to VM-21: the spec catalogue, like a cloud provider's. Sizes (twelve built-ins, read only, with Duplicate; the
// owner's own beside them), images (golden VMs' snapshots, cloud images, ISOs, OVA/OVF appliances, each file checked
// and hashed when added, with links to the official cloud image pages) and launch templates (an image and a size with
// everything a deploy needs, each saying why it can't deploy when it can't). VM-21: Deploy on a template's row opens
// the Deploy dialog on it.
//
// Edits are the app's own data: audited in the core with no approval tier, and refused by the read-only lock (FD-03).
// P6: the page reads nothing while it is hidden.

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import {
  CopyIcon,
  RocketIcon,
  DiscIcon,
  ExternalLinkIcon,
  FileBoxIcon,
  HardDriveIcon,
  LayersIcon,
  LockIcon,
  MoreHorizontalIcon,
  PencilIcon,
  PlusIcon,
  ServerIcon,
  Trash2Icon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge } from "@/components/Badges";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ImageDialog } from "@/components/ImageDialog";
import { useReadOnlyReason } from "@/components/Presentation";
import { SizeDialog } from "@/components/SizeDialog";
import { TemplateDialog } from "@/components/TemplateDialog";
import { ReasonLine, WhyDisabled } from "@/components/WhyDisabled";
import {
  api,
  errorMessage,
  type Image,
  type ImageSite,
  type LaunchTemplate,
  type OsProfile,
  type Size,
  type SizeInput,
  type TemplateInput,
} from "@/lib/api";
import {
  copyName,
  fileSize,
  HYPERVISOR_LABEL,
  hypervisorsText,
  IMAGE_KIND_LABEL,
  imageFormatText,
  imageWhere,
  networkLabel,
  sizeSummary,
  templateCopyName,
  templateReason,
} from "@/lib/catalog";
import { plural } from "@/lib/format";
import { reveal } from "@/lib/reveal";
import { cn } from "@/lib/utils";

export type TemplatesTab = "sizes" | "images" | "templates";

interface Props {
  /** True while the page is shown: it reads the catalogue again when the user comes back. */
  active: boolean;
  /** The palette asked for a tab, or for a new launch template. */
  /** R10 `id`: a size, image or template to show (a search result): scrolled to and lit. */
  request: { tab: TemplatesTab; create?: boolean; id?: string; n: number } | null;
  /** VM-21: opens the Deploy dialog on a template. */
  onDeploy: (templateId: string) => void;
}

type Dialog =
  | { kind: "size"; existing?: Size; initial?: SizeInput }
  | { kind: "image"; existing?: Image }
  | { kind: "template"; existing?: LaunchTemplate; initial?: TemplateInput }
  | { kind: "deleteSize"; size: Size }
  | { kind: "deleteImage"; image: Image }
  | { kind: "deleteTemplate"; template: LaunchTemplate };

export function TemplatesPage({ active, request, onDeploy }: Props) {
  const readOnly = useReadOnlyReason();
  const [tab, setTab] = useState<TemplatesTab>("templates");
  const [sizes, setSizes] = useState<Size[]>([]);
  const [images, setImages] = useState<Image[]>([]);
  const [templates, setTemplates] = useState<LaunchTemplate[]>([]);
  const [profiles, setProfiles] = useState<OsProfile[]>([]);
  const [sites, setSites] = useState<ImageSite[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [dialog, setDialog] = useState<Dialog | null>(null);

  const load = useCallback(() => {
    Promise.all([
      api.catalogSizes(),
      api.catalogImages(),
      api.catalogTemplates(),
      api.catalogProfiles(),
      api.catalogSites(),
    ]).then(
      ([s, i, t, p, w]) => {
        setSizes(s);
        setImages(i);
        setTemplates(t);
        setProfiles(p);
        setSites(w);
        setLoaded(true);
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  // A new request from the palette: its tab, and the new item's dialog when it asked for one.
  const [handled, setHandled] = useState(0);
  // R10: the item a search result asked for, lit until it has been seen.
  const [lit, setLit] = useState<string | null>(null);
  const litShown = lit !== null && [...sizes, ...images, ...templates].some((item) => item.id === lit);
  useEffect(() => {
    if (!litShown || !lit) return;
    reveal(document.querySelector(`[data-catalog-id="${CSS.escape(lit)}"]`));
    const timer = window.setTimeout(() => setLit(null), 2500);
    return () => window.clearTimeout(timer);
  }, [litShown, lit]);
  if (request && request.n !== handled) {
    setHandled(request.n);
    setTab(request.tab);
    setLit(request.id ?? null);
    if (request.create && !readOnly) {
      if (request.tab === "sizes") setDialog({ kind: "size" });
      else if (request.tab === "images") setDialog({ kind: "image" });
      else if (images.length > 0) setDialog({ kind: "template" });
    }
  }

  const profileName = useCallback((id: string) => profiles.find((p) => p.id === id)?.name ?? id, [profiles]);
  const sizeName = useCallback(
    (id: string) => sizes.find((s) => s.id.toLowerCase() === id.toLowerCase())?.name ?? "(deleted size)",
    [sizes],
  );
  const imageName = useCallback((id: string) => images.find((i) => i.id === id)?.name ?? "(deleted image)", [images]);
  const usedBy = useCallback(
    (pick: (t: LaunchTemplate) => boolean) => templates.filter(pick).map((t) => t.name),
    [templates],
  );

  const newImageReason = readOnly;
  const newTemplateReason = readOnly ?? (images.length === 0 ? "Add an image first: a template starts from one" : null);

  return (
    <div className="flex flex-col gap-4">
      <p className="max-w-3xl text-sm text-muted-foreground">
        Describe VMs like a cloud provider does: a <span className="font-medium text-foreground">size</span> (CPU, RAM
        and disks), an <span className="font-medium text-foreground">image</span> (where the OS comes from) and a{" "}
        <span className="font-medium text-foreground">launch template</span> that puts them together with the network,
        SSH key, names and what happens after deploy. Deploying arrives with the deploy package.
      </p>
      <Tabs value={tab} onValueChange={(v) => setTab(v as TemplatesTab)}>
        <TabsList>
          <TabsTrigger value="sizes">
            <HardDriveIcon />
            Sizes
          </TabsTrigger>
          <TabsTrigger value="images">
            <DiscIcon />
            Images
          </TabsTrigger>
          <TabsTrigger value="templates">
            <LayersIcon />
            Launch templates
          </TabsTrigger>
        </TabsList>

        <TabsContent value="sizes" className="flex min-w-0 flex-col gap-3">
          <div className="flex items-center gap-2">
            <WhyDisabled reason={readOnly}>
              <Button size="sm" disabled={readOnly !== null} onClick={() => setDialog({ kind: "size" })}>
                <PlusIcon data-icon="inline-start" />
                New size
              </Button>
            </WhyDisabled>
            <span className="text-sm text-muted-foreground">
              Built-in sizes are read only; Duplicate one to make an editable copy.
            </span>
          </div>
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Size</TableHead>
                  <TableHead>vCPU</TableHead>
                  <TableHead>RAM, disks</TableHead>
                  <TableHead>Good for</TableHead>
                  <TableHead className="w-12">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sizes.map((s) => (
                  <TableRow key={s.id} data-catalog-id={s.id} className={cn(lit === s.id && "bg-accent")}>
                    <TableCell className="font-mono font-medium">
                      <span className="flex items-center gap-2">
                        {s.name}
                        {s.builtIn && (
                          <Badge variant="outline" className="font-sans font-normal text-muted-foreground">
                            <LockIcon />
                            Built-in
                          </Badge>
                        )}
                      </span>
                    </TableCell>
                    <TableCell className="whitespace-nowrap">
                      {s.sockets * s.coresPerSocket}
                      {s.sockets > 1 && (
                        <span className="text-muted-foreground">
                          {" "}
                          ({s.sockets} × {s.coresPerSocket})
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {sizeSummary(s).split(" · ").slice(1).join(" · ")}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{s.description}</TableCell>
                    <TableCell>
                      <RowMenu label={s.name}>
                        <DropdownMenuItem
                          disabled={readOnly !== null}
                          onSelect={() =>
                            setDialog({
                              kind: "size",
                              initial: {
                                ...s,
                                name: copyName(
                                  s.name,
                                  sizes.map((x) => x.name),
                                ),
                              },
                            })
                          }
                        >
                          <CopyIcon />
                          <span>
                            Duplicate
                            <ReasonLine reason={readOnly} />
                          </span>
                        </DropdownMenuItem>
                        {!s.builtIn && (
                          <>
                            <DropdownMenuItem
                              disabled={readOnly !== null}
                              onSelect={() => setDialog({ kind: "size", existing: s })}
                            >
                              <PencilIcon />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              disabled={readOnly !== null}
                              onSelect={() => setDialog({ kind: "deleteSize", size: s })}
                            >
                              <Trash2Icon />
                              Delete
                            </DropdownMenuItem>
                          </>
                        )}
                      </RowMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        <TabsContent value="images" className="flex min-w-0 flex-col gap-3">
          <div className="flex items-center gap-2">
            <WhyDisabled reason={newImageReason}>
              <Button size="sm" disabled={newImageReason !== null} onClick={() => setDialog({ kind: "image" })}>
                <PlusIcon data-icon="inline-start" />
                Add an image
              </Button>
            </WhyDisabled>
          </div>
          {loaded && images.length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <DiscIcon />
                </EmptyMedia>
                <EmptyTitle>No images yet</EmptyTitle>
                <EmptyDescription>
                  Add a cloud image or ISO you downloaded, an OVA, or a snapshot of one of your VMs.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Image</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>Where</TableHead>
                    <TableHead>OS profile</TableHead>
                    <TableHead>Deploys on</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {images.map((i) => (
                    <TableRow
                      key={i.id}
                      data-catalog-id={i.id}
                      className={cn("align-top", lit === i.id && "bg-accent")}
                    >
                      <TableCell className="font-medium whitespace-normal">
                        {i.name}
                        {i.problem && <div className="text-xs font-normal text-destructive">{i.problem}</div>}
                        {i.notes && (
                          <div className="line-clamp-2 text-xs font-normal text-muted-foreground">{i.notes}</div>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        {IMAGE_KIND_LABEL[i.source.kind]}
                        {imageFormatText(i) && (
                          <div className="text-xs text-muted-foreground">{imageFormatText(i)}</div>
                        )}
                      </TableCell>
                      <TableCell className="max-w-sm whitespace-normal">
                        <div className="text-xs break-all">{imageWhere(i)}</div>
                        {i.sha256 && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <code className="font-mono text-xs text-muted-foreground">
                                SHA-256 {i.sha256.slice(0, 16)}…
                              </code>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-md font-mono break-all">{i.sha256}</TooltipContent>
                          </Tooltip>
                        )}
                        {i.sizeBytes !== null && (
                          <span className="text-xs text-muted-foreground"> · {fileSize(i.sizeBytes)}</span>
                        )}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{profileName(i.osProfile)}</TableCell>
                      <TableCell className="whitespace-nowrap text-muted-foreground">
                        {hypervisorsText(i.hypervisors)}
                      </TableCell>
                      <TableCell>
                        <RowMenu label={i.name}>
                          <DropdownMenuItem
                            disabled={readOnly !== null}
                            onSelect={() => setDialog({ kind: "image", existing: i })}
                          >
                            <PencilIcon />
                            <span>
                              Edit
                              <ReasonLine reason={readOnly} />
                            </span>
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            variant="destructive"
                            disabled={readOnly !== null}
                            onSelect={() => setDialog({ kind: "deleteImage", image: i })}
                          >
                            <Trash2Icon />
                            Delete
                          </DropdownMenuItem>
                        </RowMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <section className="grid gap-2 rounded-lg border p-4">
            <h3 className="text-sm font-medium">Get cloud images</h3>
            <p className="text-sm text-muted-foreground">
              The official download pages open in your browser. Remotely downloads nothing itself: save the file, then
              add it here.
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              {sites.map((site) => (
                <Button
                  key={site.id}
                  variant="outline"
                  className="h-auto justify-start py-2 text-left whitespace-normal"
                  onClick={() => void api.catalogOpenSite(site.url).catch((err) => toast.error(errorMessage(err)))}
                >
                  <ExternalLinkIcon data-icon="inline-start" />
                  <span className="grid gap-0.5">
                    <span>{site.name}</span>
                    <span className="text-xs font-normal text-muted-foreground">{site.hint}</span>
                  </span>
                </Button>
              ))}
            </div>
          </section>
        </TabsContent>

        <TabsContent value="templates" className="flex min-w-0 flex-col gap-3">
          <div className="flex items-center gap-2">
            <WhyDisabled reason={newTemplateReason}>
              <Button size="sm" disabled={newTemplateReason !== null} onClick={() => setDialog({ kind: "template" })}>
                <PlusIcon data-icon="inline-start" />
                New launch template
              </Button>
            </WhyDisabled>
          </div>
          {loaded && templates.length === 0 ? (
            <Empty className="border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <FileBoxIcon />
                </EmptyMedia>
                <EmptyTitle>No launch templates yet</EmptyTitle>
                <EmptyDescription>
                  A template is an image and a size with a network, SSH key, naming pattern and after-deploy steps.
                  {images.length === 0 && " Add an image first."}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Template</TableHead>
                    <TableHead>Image and size</TableHead>
                    <TableHead>Hypervisor, network</TableHead>
                    <TableHead>Names</TableHead>
                    <TableHead>Can deploy</TableHead>
                    <TableHead className="w-12">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {templates.map((t) => {
                    const why = templateReason(t);
                    return (
                      <TableRow
                        key={t.id}
                        data-catalog-id={t.id}
                        className={cn("align-top", lit === t.id && "bg-accent")}
                      >
                        <TableCell className="font-medium whitespace-normal">
                          <span className="flex flex-wrap items-center gap-2">
                            {t.name}
                            {t.environment !== "none" && <EnvBadge env={t.environment} />}
                          </span>
                          {t.tags.length > 0 && (
                            <div className="text-xs font-normal text-muted-foreground">{t.tags.join(", ")}</div>
                          )}
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          {imageName(t.imageId)}
                          <div className="font-mono text-xs text-muted-foreground">{sizeName(t.sizeId)}</div>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <span className="flex items-center gap-1.5">
                            <ServerIcon className="size-3.5 text-muted-foreground" aria-hidden />
                            {HYPERVISOR_LABEL[t.hypervisor]}
                          </span>
                          <div className="text-xs text-muted-foreground">{networkLabel(t.network)}</div>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          <code className="font-mono text-xs">{t.namingPattern}</code>
                          <div className="text-xs text-muted-foreground">{plural(t.defaultCount, "VM")} by default</div>
                        </TableCell>
                        <TableCell className="max-w-xs whitespace-normal">
                          {why ? (
                            <>
                              <Badge variant="outline" className="border-destructive/40 text-destructive">
                                Can&apos;t deploy
                              </Badge>
                              <div className="text-xs text-muted-foreground">{why}</div>
                              {t.problems.length > 1 && (
                                <div className="text-xs text-muted-foreground">
                                  and {plural(t.problems.length - 1, "other problem")}
                                </div>
                              )}
                            </>
                          ) : (
                            <span className="flex flex-wrap items-center gap-2">
                              <Badge variant="outline" className="border-success/40 text-success">
                                Ready
                              </Badge>
                              <WhyDisabled reason={readOnly}>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={readOnly !== null}
                                  onClick={() => onDeploy(t.id)}
                                >
                                  <RocketIcon data-icon="inline-start" />
                                  Deploy
                                </Button>
                              </WhyDisabled>
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <RowMenu label={t.name}>
                            <DropdownMenuItem disabled={(readOnly ?? why) !== null} onSelect={() => onDeploy(t.id)}>
                              <RocketIcon />
                              <span>
                                Deploy…
                                <ReasonLine reason={readOnly ?? why} />
                              </span>
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              disabled={readOnly !== null}
                              onSelect={() => setDialog({ kind: "template", existing: t })}
                            >
                              <PencilIcon />
                              <span>
                                Edit
                                <ReasonLine reason={readOnly} />
                              </span>
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              disabled={readOnly !== null}
                              onSelect={() =>
                                setDialog({
                                  kind: "template",
                                  initial: {
                                    ...t,
                                    name: templateCopyName(
                                      t.name,
                                      templates.map((x) => x.name),
                                    ),
                                  },
                                })
                              }
                            >
                              <CopyIcon />
                              Duplicate
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              disabled={readOnly !== null}
                              onSelect={() => setDialog({ kind: "deleteTemplate", template: t })}
                            >
                              <Trash2Icon />
                              Delete
                            </DropdownMenuItem>
                          </RowMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>
      </Tabs>

      {dialog?.kind === "size" && (
        <SizeDialog
          existing={dialog.existing}
          initial={dialog.initial}
          onSaved={(s) => {
            toast.success(dialog.existing ? `Saved ${s.name}` : `Added the size ${s.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "image" && (
        <ImageDialog
          existing={dialog.existing}
          profiles={profiles}
          onSaved={(i) => {
            toast.success(dialog.existing ? `Saved ${i.name}` : `Added the image ${i.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "template" && (
        <TemplateDialog
          existing={dialog.existing}
          initial={dialog.initial}
          images={images}
          sizes={sizes}
          profiles={profiles}
          onSaved={(t) => {
            toast.success(dialog.existing ? `Saved ${t.name}` : `Added the launch template ${t.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "deleteSize" && (
        <DeleteDialog
          what={`the size ${dialog.size.name}`}
          used={usedBy((t) => t.sizeId === dialog.size.id)}
          onConfirm={async () => {
            await api.catalogSizeDelete(dialog.size.id);
            toast.success(`Deleted the size ${dialog.size.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "deleteImage" && (
        <DeleteDialog
          what={`the image ${dialog.image.name}`}
          extra="Only the catalogue's entry goes: the file or VM stays where it is."
          used={usedBy((t) => t.imageId === dialog.image.id)}
          onConfirm={async () => {
            await api.catalogImageDelete(dialog.image.id);
            toast.success(`Deleted the image ${dialog.image.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "deleteTemplate" && (
        <DeleteDialog
          what={`the launch template ${dialog.template.name}`}
          used={[]}
          onConfirm={async () => {
            await api.catalogTemplateDelete(dialog.template.id);
            toast.success(`Deleted the launch template ${dialog.template.name}`);
            load();
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </div>
  );
}

function RowMenu({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${label}`}>
          <MoreHorizontalIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">{children}</DropdownMenuContent>
    </DropdownMenu>
  );
}

function DeleteDialog({
  what,
  extra,
  used,
  onConfirm,
  onClose,
}: {
  what: string;
  extra?: string;
  used: string[];
  onConfirm: () => Promise<void>;
  onClose: () => void;
}) {
  const description = useMemo(
    () => (
      <>
        {extra && <span className="block">{extra}</span>}
        {used.length > 0 ? (
          <span className="block">
            {plural(used.length, "launch template")} use{used.length === 1 ? "s" : ""} it ({used.join(", ")}) and
            can&apos;t deploy until {used.length === 1 ? "it gets" : "they get"} another.
          </span>
        ) : (
          <span className="block">No launch template uses it.</span>
        )}
      </>
    ),
    [extra, used],
  );
  return (
    <ConfirmDialog
      title={`Delete ${what}?`}
      description={description}
      confirmLabel="Delete"
      onConfirm={onConfirm}
      onClose={onClose}
    />
  );
}
