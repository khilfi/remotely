// VM-30 (0.8.0 G7) golden image builds: the types the core sends (crates/core/src/golden) and the IPC wrappers in
// src-tauri/src/golden.rs. A build or a rebuild is a command on the bus (the approval dialog, then one job); the build
// settings are the catalogue's own data (audited, refused by the read-only lock); the check and the versions only read.
// Like api.ts, every answer goes past the presentation masker (FD-03).

import {
  invoke,
  type DeployPreview,
  type Hypervisor,
  type Image,
  type SubmitOutcome,
  type TemplateNetwork,
} from "@/lib/api";
import type { DeployCapacity } from "@/lib/stacks-api";

/** What an image Remotely builds is built from (the image's `build`), and what a rebuild builds again. */
export interface BuildRecipe {
  /** The catalogue's ISO image the system installs from; its OS profile is the image's. */
  isoImageId: string;
  /** An own install config Remotely builds from: Ubuntu autoinstall or Debian preseed (no Windows unattend in 0.8.0). */
  installConfigId: string;
  /** A built-in size's name or an own size's id. */
  sizeId: string;
  hypervisor: Hypervisor;
  network: TemplateNetwork;
  /** VirtualBox's host-only or bridged adapter; null: the first VirtualBox lists. */
  hostAdapter?: string | null;
  /** Where each version's VM folder goes; null: the hypervisor's default folder. */
  vmFolder?: string | null;
  /** The install config's own variables; a missing one takes its default. */
  values: Record<string, string>;
  /** VM-32: the build VM's `{{ip}}` from this address pool. */
  addressPoolId?: string | null;
  /** How long the install is watched, in minutes (1 to 240; 60 by default). */
  installMinutes: number;
  /** Keep only the newest this many versions (1 to 20); null: every version. */
  keep: number | null;
}

/** A new image of this name (its first build makes it), or an image Remotely builds (its next version). */
export type BuildTarget = { kind: "new"; name: string } | { kind: "image"; id: string };

export interface BuildRequest {
  target: BuildTarget;
  recipe: BuildRecipe;
}

/** The system a build makes generic, by its install config's kind. */
export type BuildOs = "ubuntu" | "debian" | "windows";

/** A build as the build dialog's preview and the approval dialog show it, besides its VM's deploy preview. */
export interface BuildDetails {
  imageName: string;
  /** The first build makes the image. */
  newImage: boolean;
  version: number;
  os: BuildOs;
  vmName: string;
  configName: string;
  isoPath: string;
  snapshotName: string;
  /** What making it generic does, in words. */
  steps: string[];
  /** How Remotely signs in to do it, in words. */
  signIn: string;
  /** The newest versions it keeps; null: every version. */
  keep: number | null;
  /** The older versions it deletes once it is registered ("version 1 (ubuntu-golden-v1)"), each a target. */
  deletes: string[];
  /** Older versions it leaves past `keep`, and why. */
  retained: string[];
}

export interface BuildPreview {
  details: BuildDetails;
  deploy: DeployPreview;
  capacity: DeployCapacity;
  /** What to read before building (the deploy's warnings included). */
  warnings: string[];
}

/** The build dialog's check: why it can't build (`preview` null), or what it would build and why it can't run now. */
export interface BuildCheck {
  problems: string[];
  preview: BuildPreview | null;
}

export type VersionState = "newest" | "kept" | "deleted";

/** One version of an image Remotely builds. */
export interface ImageVersion {
  id: string;
  number: number;
  state: VersionState;
  hypervisor: Hypervisor;
  vmKey: string;
  vmName: string;
  snapshotName: string;
  configName: string;
  builtAt: string;
  deletedAt: string | null;
  /** The linked clones made from it, read now (a version with any is never deleted). */
  linkedClones: string[];
  /** Why its clones couldn't be looked up, if they couldn't. */
  clonesUnread: string | null;
  /** What making it generic found; null or missing: not said. */
  facts: { cloudInit?: boolean | null; vmTools?: boolean | null };
}

export const goldenApi = {
  /** A read, called while the build dialog is filled in. */
  check: (request: BuildRequest) => invoke<BuildCheck>("golden_build_check", { request }),
  /** Approval, then one job. */
  submit: (request: BuildRequest) => invoke<SubmitOutcome>("golden_build_submit", { request }),
  /** The image's next version from its saved build settings. */
  rebuild: (imageId: string) => invoke<SubmitOutcome>("golden_rebuild", { imageId }),
  /** The saved build settings, as a rebuild would send them. */
  rebuildRequest: (imageId: string) => invoke<BuildRequest>("golden_rebuild_request", { imageId }),
  /** Saves the build settings (checked as a build of its next version). Audited; refused by the read-only lock. */
  setRecipe: (imageId: string, recipe: BuildRecipe) => invoke<Image>("golden_set_recipe", { imageId, recipe }),
  /** Newest first. */
  versions: (imageId: string) => invoke<ImageVersion[]>("golden_versions", { imageId }),
};
