// VM-19 to VM-21: the spec catalogue, like a cloud provider's. Images (golden VMs' snapshots, cloud images, ISOs,
// OVA/OVF appliances, each file checked and hashed when added, with links to the official cloud image pages), sizes
// (twelve built-ins, read only, with Duplicate; the owner's own beside them) and launch templates (an image and a size
// with everything a deploy needs, each saying why it can't deploy when it can't). VM-21: Deploy on a template's row
// opens the Deploy dialog on it.
//
// UX-07 (0.6.0): the tabs follow a first deploy's steps (Images, Sizes, Launch templates, Stacks, then Disk images),
// the page opens on the first step that isn't done, each tab's one primary action is in the header, and every empty
// tab offers the action that fills it.
//
// Edits are the app's own data: audited in the core with no approval tier, and refused by the read-only lock (FD-03).
// P6: the page reads nothing while it is hidden.

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { toast } from "sonner";
import {
  BoxesIcon,
  CopyIcon,
  RocketIcon,
  DiscIcon,
  ExternalLinkIcon,
  FileBoxIcon,
  FileCogIcon,
  HardDriveIcon,
  LayersIcon,
  LockIcon,
  PencilIcon,
  PlusIcon,
  ServerIcon,
  Trash2Icon,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EnvBadge } from "@/components/Badges";
import { EmptyState } from "@/components/EmptyState";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { HelpTip } from "@/components/HelpTip";
import { ImageDialog } from "@/components/ImageDialog";
import { PageHeader } from "@/components/PageHeader";
import { RowMenu } from "@/components/RowMenu";
import { Term } from "@/components/Term";
import { useReadOnlyReason } from "@/components/Presentation";
import { SizeDialog } from "@/components/SizeDialog";
import { StacksTab } from "@/components/StacksTab";
import { TemplateDialog } from "@/components/TemplateDialog";
import { WhyDisabled } from "@/components/WhyDisabled";
import { ImageToolsPage } from "@/pages/ImageToolsPage";
import {
  api,
  errorMessage,
  type Image,
  type ImageSite,
  type LaunchTemplate,
  type OsProfile,
  type Size,
  type SizeInput,
  type SubmitOutcome,
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
import { newStackReason, newTemplateReason, openingTab, TEMPLATE_TABS, type TemplatesTab } from "@/lib/templates-page";
import { cn } from "@/lib/utils";

export type { TemplatesTab } from "@/lib/templates-page";

const TAB_ICON: Record<TemplatesTab, typeof DiscIcon> = {
  images: DiscIcon,
  sizes: HardDriveIcon,
  templates: LayersIcon,
  stacks: BoxesIcon,
  disks: FileCogIcon,
};

interface Props {
  /** True while the page is shown: it reads the catalogue again when the user comes back. */
  active: boolean;
  /** The palette asked for a tab, or for a new launch template. */
  /** R10 `id`: a size, image or template to show (a search result): scrolled to and lit. */
  request: { tab: TemplatesTab; create?: boolean; id?: string; n: number } | null;
  /** VM-21: opens the Deploy dialog on a template. */
  onDeploy: (templateId: string) => void;
  /** VM-08: the approval dialog for a stack's deploy, an instance's power or a teardown. */
  onSubmitted?: (outcome: SubmitOutcome) => void;
  /** CV-01: the Import dialog (Disk images' Import as a VM), on a file when one is given. */
  onImport: (path?: string) => void;
  /** Disk images: Settings, for qemu-img's path. */
  onOpenSettings: () => void;
  /** VM-08: changes when a VM job finished, so the instances' states are read again. */
  refreshKey?: number;
}

type Dialog =
  | { kind: "size"; existing?: Size; initial?: SizeInput }
  | { kind: "image"; existing?: Image }
  | { kind: "template"; existing?: LaunchTemplate; initial?: TemplateInput }
  | { kind: "deleteSize"; size: Size }
  | { kind: "deleteImage"; image: Image }
  | { kind: "deleteTemplate"; template: LaunchTemplate };

export function TemplatesPage({ active, request, onDeploy, onSubmitted, onImport, onOpenSettings, refreshKey }: Props) {
  const readOnly = useReadOnlyReason();
  // The tab the user or a link picked; until then, the first step that isn't done (UX-07).
  const [picked, setPicked] = useState<TemplatesTab | null>(null);
  const submittedHere = useCallback((outcome: SubmitOutcome) => onSubmitted?.(outcome), [onSubmitted]);
  const [stackCreate, setStackCreate] = useState(0);
  const [sizes, setSizes] = useState<Size[]>([]);
  const [images, setImages] = useState<Image[]>([]);
  const [templates, setTemplates] = useState<LaunchTemplate[]>([]);
  const [profiles, setProfiles] = useState<OsProfile[]>([]);
  const [sites, setSites] = useState<ImageSite[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const tab: TemplatesTab =
    picked ?? (loaded ? openingTab({ images: images.length, templates: templates.length }) : "templates");

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
    setPicked(request.tab);
    setLit(request.id ?? null);
    if (request.create && !readOnly) {
      if (request.tab === "sizes") setDialog({ kind: "size" });
      else if (request.tab === "images") setDialog({ kind: "image" });
      else if (request.tab === "stacks") setStackCreate((n) => n + 1);
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

  const templateOff = newTemplateReason(readOnly, images.length);
  const stackOff = newStackReason(readOnly, templates.length);

  /** UX-07: a step's action from another tab's empty state: go there and start it. */
  function addImage() {
    setPicked("images");
    setDialog({ kind: "image" });
  }
  function newTemplate() {
    setPicked("templates");
    setDialog({ kind: "template" });
  }

  const addImageButton = (
    <WhyDisabled reason={readOnly}>
      <Button disabled={readOnly !== null} onClick={addImage}>
        <PlusIcon data-icon="inline-start" />
        Add an image
      </Button>
    </WhyDisabled>
  );
  const newTemplateButton = (
    <WhyDisabled reason={templateOff}>
      <Button disabled={templateOff !== null} onClick={newTemplate}>
        <PlusIcon data-icon="inline-start" />
        New launch template
      </Button>
    </WhyDisabled>
  );

  // UX-01: each tab's one primary action, in the header. An empty tab offers it in its empty state instead.
  const primary: Record<TemplatesTab, ReactNode> = {
    images: loaded && images.length > 0 ? addImageButton : null,
    sizes: (
      <WhyDisabled reason={readOnly}>
        <Button disabled={readOnly !== null} onClick={() => setDialog({ kind: "size" })}>
          <PlusIcon data-icon="inline-start" />
          New size
        </Button>
      </WhyDisabled>
    ),
    templates: loaded && templates.length > 0 ? newTemplateButton : null,
    stacks: (
      <WhyDisabled reason={stackOff}>
        <Button disabled={stackOff !== null} onClick={() => setStackCreate((n) => n + 1)}>
          <PlusIcon data-icon="inline-start" />
          New stack
        </Button>
      </WhyDisabled>
    ),
    disks: null,
  };

  return (
    <div className="flex flex-col gap-4">
      <Tabs value={tab} onValueChange={(v) => setPicked(v as TemplatesTab)} className="gap-4">
        <PageHeader
          page="templates"
          primary={primary[tab] ?? undefined}
          tabs={
            <TabsList>
              {TEMPLATE_TABS.map((t) => {
                const Icon = TAB_ICON[t.id];
                return (
                  <TabsTrigger key={t.id} value={t.id}>
                    <Icon />
                    {t.label}
                  </TabsTrigger>
                );
              })}
            </TabsList>
          }
        />

        <TabsContent value="images" className="flex min-w-0 flex-col gap-3">
          {loaded && images.length === 0 ? (
            <EmptyState
              icon={DiscIcon}
              title="No images yet"
              description="An image is where a new VM's OS comes from: a VM's snapshot, a cloud image, an ISO or an OVA."
              action={addImageButton}
            />
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
                        {i.source.kind === "goldenVm" ? (
                          <Term id="goldenVm">{IMAGE_KIND_LABEL[i.source.kind]}</Term>
                        ) : (
                          IMAGE_KIND_LABEL[i.source.kind]
                        )}
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
                        <RowMenu label={i.name} disabled={readOnly !== null}>
                          <DropdownMenuItem onSelect={() => setDialog({ kind: "image", existing: i })}>
                            <PencilIcon />
                            Edit…
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            variant="destructive"
                            onSelect={() => setDialog({ kind: "deleteImage", image: i })}
                          >
                            <Trash2Icon />
                            Delete…
                          </DropdownMenuItem>
                        </RowMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          <section className="grid gap-2 rounded-lg border p-4" aria-label="Get cloud images">
            <h3 className="flex items-center gap-1 text-sm font-medium">
              Get cloud images
              <HelpTip topic="cloudImages" />
            </h3>
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

        <TabsContent value="sizes" className="flex min-w-0 flex-col gap-3">
          <p className="text-sm text-muted-foreground">
            Built-in sizes are read only: Duplicate one to make a copy you can edit.
          </p>
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
                      <RowMenu label={s.name} disabled={readOnly !== null}>
                        <DropdownMenuItem
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
                          Duplicate…
                        </DropdownMenuItem>
                        {!s.builtIn && (
                          <>
                            <DropdownMenuItem onSelect={() => setDialog({ kind: "size", existing: s })}>
                              <PencilIcon />
                              Edit…
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              onSelect={() => setDialog({ kind: "deleteSize", size: s })}
                            >
                              <Trash2Icon />
                              Delete…
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

        <TabsContent value="templates" className="flex min-w-0 flex-col gap-3">
          {loaded && templates.length === 0 ? (
            <EmptyState
              icon={FileBoxIcon}
              title="No launch templates yet"
              description={
                images.length === 0 ? (
                  <>
                    A <Term id="launchTemplate">launch template</Term> starts from an image: add one first.
                  </>
                ) : (
                  <>
                    A <Term id="launchTemplate">launch template</Term> is an image and a size with a network, SSH key
                    and names.
                  </>
                )
              }
              action={images.length === 0 ? addImageButton : newTemplateButton}
            />
          ) : (
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Template</TableHead>
                    <TableHead>Image and size</TableHead>
                    <TableHead>Hypervisor, network</TableHead>
                    <TableHead>Names</TableHead>
                    <TableHead>Deploy</TableHead>
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
                        <TableCell className="whitespace-nowrap">
                          {why ? (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Badge
                                  variant="outline"
                                  tabIndex={0}
                                  className="cursor-help border-destructive/40 text-destructive"
                                >
                                  Can&apos;t deploy
                                  {t.problems.length > 1 && ` · ${t.problems.length}`}
                                </Badge>
                              </TooltipTrigger>
                              <TooltipContent className="max-w-sm">
                                {why}
                                {t.problems.length > 1 && ` And ${plural(t.problems.length - 1, "other problem")}.`}
                              </TooltipContent>
                            </Tooltip>
                          ) : (
                            // UX-03: the row's main action, here only (not in its menu too).
                            <WhyDisabled reason={readOnly}>
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={readOnly !== null}
                                onClick={() => onDeploy(t.id)}
                              >
                                <RocketIcon data-icon="inline-start" />
                                Deploy…
                              </Button>
                            </WhyDisabled>
                          )}
                        </TableCell>
                        <TableCell>
                          <RowMenu label={t.name} disabled={readOnly !== null}>
                            <DropdownMenuItem onSelect={() => setDialog({ kind: "template", existing: t })}>
                              <PencilIcon />
                              Edit…
                            </DropdownMenuItem>
                            <DropdownMenuItem
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
                              Duplicate…
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              variant="destructive"
                              onSelect={() => setDialog({ kind: "deleteTemplate", template: t })}
                            >
                              <Trash2Icon />
                              Delete…
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

        {/* VM-08: stacks of launch templates, and their instances on this PC. */}
        <TabsContent value="stacks" className="flex min-w-0 flex-col gap-3">
          <StacksTab
            active={active && tab === "stacks"}
            templates={templates}
            readOnly={readOnly}
            onSubmitted={(outcome) => onSubmitted?.(outcome)}
            refreshKey={refreshKey}
            createRequest={stackCreate}
            onNewTemplate={images.length === 0 ? addImage : newTemplate}
            newTemplateLabel={images.length === 0 ? "Add an image" : "New launch template"}
          />
        </TabsContent>

        <TabsContent value="disks" className="flex min-w-0 flex-col gap-3">
          <ImageToolsPage
            active={active && tab === "disks"}
            onSubmitted={submittedHere}
            onImport={onImport}
            onOpenSettings={onOpenSettings}
          />
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
