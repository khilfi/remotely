// FD-09: the Toolbox, in the sidebar's Remote group. A tab per tool: Ping, Trace route, DNS lookup, Check ports,
// Certificate, Subnet calculator, Wake up and File server. Session and VM row menus open a tool with their target
// filled in, through a `toolbox` link (lib/links.ts); the palette opens the page.
//
// Every tool but Wake up and File server only reads (no tier, not audited, allowed while presenting with the read-only
// lock). Each tab keeps its last 20 inputs in the window's local storage (lib/toolbox.ts); the file server keeps its
// last choices in the core, per workspace.

import { useEffect, useState } from "react";
import {
  ActivityIcon,
  CalculatorIcon,
  FolderUpIcon,
  GlobeIcon,
  NetworkIcon,
  PowerIcon,
  RouteIcon,
  ShieldCheckIcon,
  type LucideIcon,
} from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/PageHeader";
import { CertificateTool } from "@/components/toolbox/CertificateTool";
import { FileServerTool } from "@/components/toolbox/FileServerTool";
import { DnsTool, PingTool, PortsTool, TraceTool, type Incoming } from "@/components/toolbox/ProbeTools";
import { SubnetTool } from "@/components/toolbox/SubnetTool";
import { WakeTool } from "@/components/toolbox/WakeTool";
import type { SubmitOutcome } from "@/lib/api";
import { recentScope, setRecentScope, TOOLBOX_TOOLS, type ToolboxTool, type ToolTarget } from "@/lib/toolbox";
import { workspacesApi } from "@/lib/workspaces-api";

/** A tool asked for from a row, a link or the palette; `n` counts the asks. */
export interface ToolboxRequest {
  tool: ToolboxTool;
  target?: ToolTarget;
  n: number;
}

const ICONS: Record<ToolboxTool, LucideIcon> = {
  ping: ActivityIcon,
  trace: RouteIcon,
  dns: GlobeIcon,
  ports: NetworkIcon,
  certificate: ShieldCheckIcon,
  subnet: CalculatorIcon,
  wake: PowerIcon,
  fileServer: FolderUpIcon,
};

/** A target from a link only when it is one (links can come back from the notification centre as plain JSON). */
function cleanTarget(target: unknown): ToolTarget | null {
  if (typeof target !== "object" || target === null) return null;
  const t = target as Record<string, unknown>;
  const text = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 1000;
  if (t.kind === "address" && typeof t.host === "string") return { kind: "address", host: t.host };
  if (t.kind === "session" && text(t.sessionId))
    return {
      kind: "session",
      sessionId: t.sessionId as string,
      label: text(t.label) ? (t.label as string) : "Session",
    };
  if (t.kind === "vm" && text(t.vmKey))
    return { kind: "vm", vmKey: t.vmKey as string, label: text(t.label) ? (t.label as string) : "VM" };
  return null;
}

interface Props {
  /** True while the page is shown: Wake up reads this PC's adapters only then (P6). */
  active: boolean;
  request: ToolboxRequest | null;
  onSubmitted: (outcome: SubmitOutcome) => void;
}

export function ToolboxPage({ active, request, onSubmitted }: Props) {
  // FD-02: the recent inputs are the shown workspace's; it is read once the page first shows (the window loads again
  // after a switch).
  useEffect(() => {
    if (!active || recentScope()) return;
    workspacesApi.current().then(
      (w) => setRecentScope(w.id),
      () => undefined,
    );
  }, [active]);
  const [tab, setTab] = useState<ToolboxTool>(request?.tool ?? "ping");
  const [handled, setHandled] = useState(request?.n ?? 0);
  // What each tool was handed last, so each tab takes only its own.
  const [incoming, setIncoming] = useState<Partial<Record<ToolboxTool, Incoming>>>(() => {
    const target = cleanTarget(request?.target);
    return request && target ? { [request.tool]: { target, n: request.n } } : {};
  });
  if (request && request.n !== handled) {
    setHandled(request.n);
    setTab(request.tool);
    const target = cleanTarget(request.target);
    if (target) setIncoming((prev) => ({ ...prev, [request.tool]: { target, n: request.n } }));
  }

  return (
    <div className="flex flex-col gap-4">
      <Tabs value={tab} onValueChange={(v) => setTab(v as ToolboxTool)} className="gap-4">
        <PageHeader
          page="toolbox"
          tabs={
            <TabsList className="flex-wrap">
              {TOOLBOX_TOOLS.map((t) => {
                const Icon = ICONS[t.id];
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
        {/* Mounted while hidden, so a tab keeps its inputs and a run going on. */}
        <TabsContent value="ping" forceMount className="data-[state=inactive]:hidden">
          <PingTool incoming={incoming.ping ?? null} />
        </TabsContent>
        <TabsContent value="trace" forceMount className="data-[state=inactive]:hidden">
          <TraceTool incoming={incoming.trace ?? null} />
        </TabsContent>
        <TabsContent value="dns" forceMount className="data-[state=inactive]:hidden">
          <DnsTool />
        </TabsContent>
        <TabsContent value="ports" forceMount className="data-[state=inactive]:hidden">
          <PortsTool incoming={incoming.ports ?? null} />
        </TabsContent>
        <TabsContent value="certificate" forceMount className="data-[state=inactive]:hidden">
          <CertificateTool incoming={incoming.certificate ?? null} />
        </TabsContent>
        <TabsContent value="subnet" forceMount className="data-[state=inactive]:hidden">
          <SubnetTool />
        </TabsContent>
        <TabsContent value="wake" forceMount className="data-[state=inactive]:hidden">
          <WakeTool incoming={incoming.wake ?? null} shown={active && tab === "wake"} onSubmitted={onSubmitted} />
        </TabsContent>
        <TabsContent value="fileServer" forceMount className="data-[state=inactive]:hidden">
          <FileServerTool shown={active && tab === "fileServer"} onSubmitted={onSubmitted} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
