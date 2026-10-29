// UX-01: the one page header. Each page renders it first:
//
//   [Title ?]  [search and filters, or the SelectionBar ...........]  [Primary] [⋯]
//   [tabs, when the page has them]
//
// - The title comes from the page registry (lib/navigation.ts), so it always matches the sidebar.
// - "?" opens the page's help entry (lib/help.ts `page.<id>`); pass `help` for another key, or null for none.
// - `children` is the search and filters; while rows are selected the page passes a SelectionBar instead.
// - `primary` is the page's one filled button (Button, default variant and size). Everything else goes in `tools`,
//   DropdownMenuItems shown in the "⋯" menu.
// - `tabs` is a TabsList: the page wraps the header and its content in <Tabs>, so the list sits under the title.
//
//   <Tabs value={tab} onValueChange={setTab}>
//     <PageHeader
//       page="templates"
//       primary={<Button onClick={add}><PlusIcon data-icon="inline-start" /> Add an image</Button>}
//       tools={<DropdownMenuItem onSelect={importVm}>Import a VM…</DropdownMenuItem>}
//       tabs={<TabsList>…</TabsList>}
//     />
//     <TabsContent value="images">…</TabsContent>
//   </Tabs>

import type { ReactNode } from "react";
import { MoreHorizontalIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { HelpTip } from "@/components/HelpTip";
import { isHelpKey, type HelpKey } from "@/lib/help";
import { pageLabel, type PageId } from "@/lib/navigation";
import { cn } from "@/lib/utils";

export interface PageHeaderProps {
  page: PageId;
  /** The "?" next to the title: the page's own entry by default, another key, or null for none. */
  help?: HelpKey | null;
  /** Search and filters, after the title; a SelectionBar while rows are selected. */
  children?: ReactNode;
  /** The page's one primary (filled) button. */
  primary?: ReactNode;
  /** DropdownMenuItems for the "⋯" menu: every other page-wide action. */
  tools?: ReactNode;
  /** A TabsList, shown under the title row. */
  tabs?: ReactNode;
  className?: string;
}

export function PageHeader({ page, help, children, primary, tools, tabs, className }: PageHeaderProps) {
  const title = pageLabel(page);
  const own = `page.${page}`;
  const helpKey = help === undefined ? (isHelpKey(own) ? own : null) : help;
  return (
    <header className={cn("flex shrink-0 flex-col gap-3", className)} data-page-header={page}>
      <div className="flex min-h-8 flex-wrap items-center gap-x-3 gap-y-2">
        <div className="flex items-center gap-1">
          <h1 className="text-lg leading-none font-semibold tracking-tight">{title}</h1>
          {helpKey && <HelpTip topic={helpKey} />}
        </div>
        {children && <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">{children}</div>}
        {(primary || tools) && (
          <div className="ml-auto flex shrink-0 items-center gap-2">
            {primary}
            {tools && (
              <DropdownMenu>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <DropdownMenuTrigger asChild>
                      <Button type="button" variant="outline" size="icon" aria-label={`More actions on ${title}`}>
                        <MoreHorizontalIcon />
                      </Button>
                    </DropdownMenuTrigger>
                  </TooltipTrigger>
                  <TooltipContent>More actions</TooltipContent>
                </Tooltip>
                <DropdownMenuContent align="end" className="min-w-52">
                  {tools}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        )}
      </div>
      {tabs}
    </header>
  );
}
