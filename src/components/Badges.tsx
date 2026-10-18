// Status badges on top of the shadcn Badge. Colours come from the app tokens in src/styles.css.

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Environment, JobStatus, PowerState, SecretKind, SessionColor, Tier, ToolsState } from "@/lib/api";

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

const TOOLS: Record<ToolsState, { label: string; className: string }> = {
  running: { label: "Running", className: "text-success" },
  installed: { label: "Not running", className: "text-tier-medium" },
  notInstalled: { label: "Not installed", className: "text-tier-medium" },
  unknown: { label: "Unknown", className: "text-muted-foreground" },
};

/** VM-01 VMware Tools state. VMs that are off show a dash. */
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
