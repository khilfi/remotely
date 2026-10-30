// Status badges on top of the shadcn Badge. Colours come from the app tokens in src/styles.css.

import { Badge } from "@/components/ui/badge";
import { HYPERVISORS, hypervisorName } from "@/lib/hypervisors";
import { cn } from "@/lib/utils";
import type {
  CommandRisk,
  ContainerState,
  EngineKind,
  Environment,
  Hypervisor,
  JobStatus,
  PowerState,
  SecretKind,
  SessionColor,
  StartupRating,
  Tier,
  ToolsState,
} from "@/lib/api";

const TIER_CLASS: Record<Tier, string> = {
  low: "border-tier-low/40 text-tier-low",
  medium: "border-tier-medium/40 text-tier-medium",
  high: "border-tier-high/40 text-tier-high",
  critical: "border-tier-critical/50 bg-tier-critical/10 text-tier-critical",
};

export function TierBadge({ tier }: { tier: Tier }) {
  return (
    <Badge variant="outline" className={cn("capitalize", TIER_CLASS[tier])}>
      {tier}
    </Badge>
  );
}

const ENV_CLASS: Record<Exclude<Environment, "none">, string> = {
  lab: "border-env-lab/40 text-env-lab",
  staging: "border-env-staging/40 text-env-staging",
  prod: "border-env-prod/50 bg-env-prod/10 text-env-prod",
};

/** SS-06 environment label. Unlabelled targets show a dash. */
export function EnvBadge({ env }: { env: Environment }) {
  if (env === "none") return <span className="text-muted-foreground">—</span>;
  return (
    <Badge variant="outline" className={cn("capitalize", ENV_CLASS[env])}>
      {env}
    </Badge>
  );
}

const STATE: Record<PowerState, { label: string; className: string }> = {
  running: { label: "Running", className: "border-success/40 text-success" },
  suspended: { label: "Suspended", className: "border-tier-medium/40 text-tier-medium" },
  paused: { label: "Paused", className: "border-tier-medium/40 text-tier-medium" },
  not_running: { label: "Off", className: "text-muted-foreground" },
  unknown: { label: "Unknown", className: "text-muted-foreground" },
};

export function StateBadge({ state }: { state: PowerState }) {
  const { label, className } = STATE[state];
  return (
    <Badge variant="outline" className={className}>
      {state === "running" && <span className="size-1.5 rounded-full bg-current" aria-hidden />}
      {label}
    </Badge>
  );
}

const CONTAINER_STATE: Record<ContainerState, { label: string; className: string }> = {
  running: { label: "Running", className: "border-success/40 text-success" },
  paused: { label: "Paused", className: "border-tier-medium/40 text-tier-medium" },
  restarting: { label: "Restarting", className: "border-tier-medium/40 text-tier-medium" },
  removing: { label: "Removing", className: "border-tier-medium/40 text-tier-medium" },
  created: { label: "Created", className: "text-muted-foreground" },
  exited: { label: "Stopped", className: "text-muted-foreground" },
  dead: { label: "Dead", className: "border-destructive/40 text-destructive" },
  unknown: { label: "Unknown", className: "text-muted-foreground" },
};

/** CT-01, CT-02: a container's state. */
export function ContainerStateBadge({ state }: { state: ContainerState }) {
  const { label, className } = CONTAINER_STATE[state];
  return (
    <Badge variant="outline" className={className}>
      {state === "running" && <span className="size-1.5 rounded-full bg-current" aria-hidden />}
      {label}
    </Badge>
  );
}

/** CT-01, CT-02: which engine, and whether its CLI runs under sudo. */
export function EngineBadge({ engine, sudo = false }: { engine: EngineKind; sudo?: boolean }) {
  return (
    <Badge variant="secondary" className="gap-1 font-normal">
      {engine === "docker" ? "Docker" : "Podman"}
      {sudo && <span className="text-[0.65rem] text-muted-foreground uppercase">sudo</span>}
    </Badge>
  );
}

const TOOLS: Record<ToolsState, { label: string; className: string }> = {
  running: { label: "Running", className: "text-success" },
  installed: { label: "Not running", className: "text-tier-medium" },
  notInstalled: { label: "Not installed", className: "text-tier-medium" },
  notRunning: { label: "Not running", className: "text-tier-medium" },
  unknown: { label: "Unknown", className: "text-muted-foreground" },
};

/** VM-18: which hypervisor runs the VM, with its full name on hover. */
export function HypervisorLabel({ hypervisor }: { hypervisor: Hypervisor }) {
  const label = HYPERVISORS.find((h) => h.value === hypervisor)?.label ?? hypervisor;
  return (
    <span className="text-sm whitespace-nowrap" title={label}>
      {hypervisorName(hypervisor)}
    </span>
  );
}

/** VM-01 VMware Tools (VM-18: or Guest Additions) state. VMs that are off show a dash. */
export function ToolsLabel({ state }: { state: ToolsState | null }) {
  if (!state) return <span className="text-muted-foreground">—</span>;
  const { label, className } = TOOLS[state];
  return <span className={cn("text-sm", className)}>{label}</span>;
}

const STATUS_CLASS: Record<JobStatus, string> = {
  succeeded: "border-success/40 text-success",
  failed: "border-destructive/40 text-destructive",
  partially_failed: "border-destructive/40 text-destructive",
  interrupted: "border-destructive/40 text-destructive",
  queued: "text-foreground",
  countdown: "text-foreground",
  running: "text-foreground",
  cancelled: "text-muted-foreground",
};

export function StatusBadge({ status }: { status: JobStatus }) {
  return (
    <Badge variant="outline" className={cn("capitalize", STATUS_CLASS[status])}>
      {status.replace("_", " ")}
    </Badge>
  );
}

/** SS-01 session colours, in the order the editor offers them. */
export const SESSION_COLORS: SessionColor[] = [
  "red",
  "orange",
  "amber",
  "green",
  "teal",
  "blue",
  "violet",
  "pink",
  "slate",
];

const COLOR_CLASS: Record<SessionColor, string> = {
  red: "bg-red-500",
  orange: "bg-orange-500",
  amber: "bg-amber-500",
  green: "bg-green-500",
  teal: "bg-teal-500",
  blue: "bg-blue-500",
  violet: "bg-violet-500",
  pink: "bg-pink-500",
  slate: "bg-slate-500",
};

/** A session's colour as a dot; nothing when it has none. */
export function ColorDot({ color, className }: { color: SessionColor | null; className?: string }) {
  if (!color) return null;
  return (
    <span className={cn("inline-block size-2.5 shrink-0 rounded-full", COLOR_CLASS[color], className)} aria-hidden />
  );
}

export const SECRET_KIND_LABEL: Record<SecretKind, string> = {
  password: "Password",
  privateKey: "Private key",
  passphrase: "Passphrase",
};

const RISK: Record<CommandRisk["action"], { label: string; className: string; hint: string }> = {
  execReadOnly: {
    label: "Read-only",
    className: "text-muted-foreground",
    hint: "Every part only reads, by the read-only list in Settings. Type in all tabs and Compare hosts send it without asking.",
  },
  execOther: {
    label: "Changes",
    className: "border-tier-medium/40 text-tier-medium",
    hint: "Not on the read-only list, so it may change the host. Type in all tabs and Compare hosts ask for a confirm first, and for the full approval on many hosts at once (5 or more by default).",
  },
  execDangerous: {
    label: "Dangerous",
    className: "border-tier-high/50 bg-tier-high/10 text-tier-high",
    hint: "Matches a dangerous-command rule. Type in all tabs and Compare hosts need the full approval.",
  },
};

/** SS-01: a startup command's rating: the tier a command like it gets on its session, and its kind. */
export function StartupRatingBadges({ rating }: { rating: StartupRating }) {
  return (
    <span className="inline-flex items-center gap-1">
      <TierBadge tier={rating.tier} />
      <RiskBadge risk={rating} />
    </span>
  );
}

/** BX-08: what the policy engine makes of a command (BX-06), with the rules it matches in the tooltip. */
export function RiskBadge({ risk, className }: { risk: CommandRisk; className?: string }) {
  const { label, className: tone, hint } = RISK[risk.action];
  const rules = risk.dangerous.length > 0 ? ` Rule: ${risk.dangerous.join(", ")}.` : "";
  return (
    <Badge variant="outline" className={cn(tone, className)} title={`${hint}${rules}`}>
      {label}
    </Badge>
  );
}
