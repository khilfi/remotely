// QL-20: the palette's search providers, in the order their groups show on a tie. Each reads only what the app
// already reads or keeps, once per opening of the palette: no background polling and no logins (containers come from
// what the Containers page last read, host networks from what the map or the networks view last read; the command
// library is read once a run, as it never changes). A later package adds its provider to SEARCH_PROVIDERS (deploy,
// schedules, stacks); its items come from a pure builder in search-sources.ts, tested there. Pages and the palette's own actions are searched too, from the palette's props.

import {
  BookOpenIcon,
  BoxIcon,
  CalendarClockIcon,
  ContainerIcon,
  DiscIcon,
  LayersIcon,
  MonitorIcon,
  NetworkIcon,
  ServerIcon,
  SettingsIcon,
  SquareChevronRightIcon,
  type LucideIcon,
} from "lucide-react";
import { api, type LibraryEntry, type SessionRecord, type VmRecord } from "@/lib/api";
import { cachedContainers } from "@/lib/container-cache";
import { cachedHostNetworks } from "@/lib/host-networks-cache";
import type { SearchItem } from "@/lib/search";
import { glossaryTerms } from "@/lib/glossary";
import {
  containerItems,
  glossaryItems,
  hostNetworkItems,
  imageItems,
  scheduleItems,
  sessionItems,
  settingItems,
  sizeItems,
  snippetItems,
  templateItems,
  vmItems,
} from "@/lib/search-sources";
import { schedulesApi } from "@/lib/schedules-api";
import { SETTINGS_SECTIONS } from "@/lib/settings-index";

/** Reads the palette makes anyway, shared with the providers so nothing is read twice. */
export interface SearchContext {
  vms: Promise<VmRecord[]>;
  sessions: Promise<SessionRecord[]>;
}

export interface SearchProvider {
  id: string;
  heading: string;
  icon: LucideIcon;
  load: (ctx: SearchContext) => Promise<SearchItem[]>;
}

let library: Promise<LibraryEntry[]> | null = null;

/** BX-08's built-in commands, read once a run. */
function commandLibrary(): Promise<LibraryEntry[]> {
  library ??= api.commandLibrary().catch((err: unknown) => {
    library = null;
    throw err;
  });
  return library;
}

export const SEARCH_PROVIDERS: readonly SearchProvider[] = [
  { id: "vms", heading: "Virtual machines", icon: MonitorIcon, load: async (ctx) => vmItems(await ctx.vms) },
  { id: "sessions", heading: "Sessions", icon: ServerIcon, load: async (ctx) => sessionItems(await ctx.sessions) },
  {
    id: "containers",
    heading: "Containers",
    icon: ContainerIcon,
    load: async () => containerItems(cachedContainers()),
  },
  {
    id: "hostNetworks",
    heading: "Host networks",
    icon: NetworkIcon,
    load: async () => hostNetworkItems(cachedHostNetworks()),
  },
  {
    id: "templates",
    heading: "Launch templates",
    icon: LayersIcon,
    load: async () => templateItems(await api.catalogTemplates()),
  },
  { id: "sizes", heading: "VM sizes", icon: BoxIcon, load: async () => sizeItems(await api.catalogSizes()) },
  { id: "images", heading: "VM images", icon: DiscIcon, load: async () => imageItems(await api.catalogImages()) },
  {
    id: "schedules",
    heading: "Schedules",
    icon: CalendarClockIcon,
    load: async () => scheduleItems(await schedulesApi.list()),
  },
  {
    id: "snippets",
    heading: "Commands",
    icon: SquareChevronRightIcon,
    load: async () => {
      const [favourites, built] = await Promise.all([api.favourites(), commandLibrary()]);
      return snippetItems(favourites, built);
    },
  },
  { id: "settings", heading: "Settings", icon: SettingsIcon, load: async () => settingItems(SETTINGS_SECTIONS) },
  // UX-05: last, so a term shows after the things it names on a tie.
  { id: "glossary", heading: "Terms", icon: BookOpenIcon, load: async () => glossaryItems(glossaryTerms()) },
];

/** Every provider's items; one that fails gives none (the others still show). */
export async function loadSearchItems(ctx: SearchContext): Promise<SearchItem[]> {
  const loaded = await Promise.all(SEARCH_PROVIDERS.map((p) => p.load(ctx).catch(() => [] as SearchItem[])));
  return loaded.flat();
}
