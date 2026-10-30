// UX-11 (AP-03, AP-08): the approval dialog's pure parts, tested in approval.test.ts.
//
// - The summary line: the targets in a few words and the tier with one plain reason ("High: db-01 is Prod"); the
//   core's own reasons stay behind "Why?" (plainReason words them for the popover).
// - Type to confirm: a lone target's name rather than the number 1; several targets keep the count. While presenting,
//   names may be masked on screen, so the count is asked then too. The core checks the count either way: the dialog
//   sends it once the name matches.
// - One field for the reason and the change ID: the whole text is the reason, and its first word is the change ID
//   when it reads as a ticket or change number (CHG0012345, INC-42, #1234, 12345) and isn't a target's name. Only the
//   first word: "Patch RHEL9 kernel" or "Restart DB01" must not record RHEL9 or DB01 (AP-08). When the workspace
//   requires a change ID for Prod, Approve waits until the field starts with one; the core enforces that rule again.

import type { ApprovalRequest, ApprovalStep, Target, Tier } from "./api.ts";
import { MAX_CHANGE_ID } from "./disabled-reasons.ts";

const TIER_LABEL: Record<Tier, string> = { low: "Low", medium: "Medium", high: "High", critical: "Critical" };

function step<S extends ApprovalStep["step"]>(steps: readonly ApprovalStep[], kind: S) {
  return steps.find((s) => s.step === kind) as Extract<ApprovalStep, { step: S }> | undefined;
}

// ---- The summary ----

/** "db-01", "db-01 and web-01", "db-01, web-01 and 3 more". */
export function targetsLine(targets: readonly Pick<Target, "name">[], shown = 2): string {
  const names = targets.map((t) => t.name);
  if (names.length === 0) return "";
  if (names.length === 1) return names[0];
  if (names.length <= shown + 1) return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  return `${names.slice(0, shown).join(", ")} and ${names.length - shown} more`;
}

/** The tier and one plain reason for it, such as "High: db-01 is Prod". */
export function tierLine(request: Pick<ApprovalRequest, "tier" | "targets" | "reasons" | "exec">): string {
  return `${TIER_LABEL[request.tier]}: ${tierBecause(request)}`;
}

function tierBecause(request: Pick<ApprovalRequest, "targets" | "reasons" | "exec">): string {
  const has = (pattern: RegExp) => request.reasons.some((r) => pattern.test(r));
  if (has(/labelled Prod/i)) {
    const prod = request.targets.filter((t) => t.environment === "prod");
    if (prod.length === 1) return `${prod[0].name} is Prod`;
    if (prod.length > 1) return `${prod.length} targets are Prod`;
    return "a target is Prod";
  }
  const dangerous = request.exec?.dangerous ?? [];
  if (dangerous.length === 1) return `the command matches the dangerous-command rule “${dangerous[0].rule}”`;
  if (dangerous.length > 1) return `the command matches ${dangerous.length} dangerous-command rules`;
  if (has(/^flagged dangerous/i)) return "the command matches a dangerous-command rule";
  if (has(/bulk tier/i)) return `${request.targets.length} targets at once get the bulk tier`;
  if (has(/can't follow/i)) return "Remotely couldn't follow how the line was edited";
  if (has(/signed in to this PC/i)) return "other users are signed in to this PC";
  if (has(/rated like/i)) return "it's rated like the same action on the Containers page";
  return "set in the approval rules";
}

/** A reason of the core's, for the "Why?" popover: a capital first letter, tiers as names and arrows as arrows. */
export function plainReason(reason: string): string {
  const words = reason
    .replace(/\s*->\s*/g, " → ")
    .replace(/(^|[:→(]\s*)(low|medium|high|critical)\b/g, (_, before: string, tier: Tier) => before + TIER_LABEL[tier]);
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// ---- Type to confirm (AP-03) ----

export type ConfirmPhrase =
  /** Type the one target's name. */
  | { kind: "name"; expected: string; count: number }
  /** Type how many targets there are. */
  | { kind: "count"; expected: number; count: number };

/** The longest name asked for; a longer one asks for the count. */
export const MAX_CONFIRM_NAME = 60;

/** What the dialog asks to type, or null when the action doesn't ask (Low and Medium). */
export function confirmPhrase(
  request: Pick<ApprovalRequest, "steps" | "targets">,
  presenting: boolean,
): ConfirmPhrase | null {
  const typed = step(request.steps, "typeTargetCount");
  if (!typed) return null;
  if (!presenting && typed.expected === 1 && request.targets.length === 1) {
    const name = request.targets[0].name.trim();
    // eslint-disable-next-line no-control-regex
    if (name !== "" && [...name].length <= MAX_CONFIRM_NAME && !/[\u0000-\u001f\u007f]/.test(name)) {
      return { kind: "name", expected: name, count: typed.expected };
    }
  }
  return { kind: "count", expected: typed.expected, count: typed.expected };
}

/** The field's label. */
export function confirmLabel(phrase: ConfirmPhrase): string {
  return phrase.kind === "name"
    ? "Type the name to confirm"
    : `Type the number of targets (${phrase.expected}) to confirm`;
}

/** Whether the text typed is the phrase: a name without regard to case or the spaces around it, or the count. */
export function confirmMatches(phrase: ConfirmPhrase, typed: string): boolean {
  const text = typed.trim();
  if (phrase.kind === "name") return text.toLocaleLowerCase() === phrase.expected.toLocaleLowerCase();
  return text !== "" && Number(text) === phrase.expected;
}

/** The count the core checks, once the phrase matches. */
export function typedCount(phrase: ConfirmPhrase, typed: string): number | undefined {
  if (phrase.kind === "name") return confirmMatches(phrase, typed) ? phrase.count : undefined;
  const text = typed.trim();
  return text === "" ? undefined : Number(text);
}

// ---- One field for the reason and the change ID (AP-03, AP-08) ----

/** A word that reads as a ticket or change number: CHG0012345, INC-42, RITM_7, #1234 or a number of 5 digits or more. */
const CHANGE_ID_WORD = /^(?:#\d+|\d{5,}|[A-Z]{2,}[A-Z0-9]*[-_]?\d+)$/;

/**
 * The change ID the text starts with, or null: its first word, without the punctuation around it, when that reads as
 * a ticket or change number and isn't one of `targetNames` (any case). A ticket number later in the text is part of
 * the reason only.
 */
export function findChangeId(text: string, targetNames: readonly string[] = []): string | null {
  const first = text.trim().split(/\s+/)[0] ?? "";
  const word = first.replace(/^[("'[]+|[)"'\],.;:!?]+$/g, "");
  if ([...word].length > MAX_CHANGE_ID || !CHANGE_ID_WORD.test(word)) return null;
  const lower = word.toLocaleLowerCase();
  if (targetNames.some((name) => name.trim().toLocaleLowerCase() === lower)) return null;
  return word;
}

/** What the field holds for these steps. */
export interface ReasonField {
  /** Whether the dialog shows the field at all. */
  shown: boolean;
  label: string;
  placeholder: string;
  /** The workspace requires a change ID here (AP-08). */
  changeIdRequired: boolean;
}

export function reasonField(steps: readonly ApprovalStep[]): ReasonField {
  const reason = Boolean(step(steps, "reason"));
  const changeId = step(steps, "changeId");
  const required = changeId?.required ?? false;
  if (reason && changeId) {
    return required
      ? {
          shown: true,
          label: "Change ID and reason",
          placeholder: "CHG0012345, then why",
          changeIdRequired: true,
        }
      : {
          shown: true,
          label: "Reason or change ID",
          placeholder: "Why, or a ticket first: CHG0012345 restart",
          changeIdRequired: false,
        };
  }
  if (reason) return { shown: true, label: "Reason", placeholder: "Why", changeIdRequired: false };
  if (changeId) {
    return {
      shown: true,
      label: required ? "Change ID" : "Change ID (optional)",
      placeholder: "CHG0012345",
      changeIdRequired: required,
    };
  }
  return { shown: false, label: "", placeholder: "", changeIdRequired: false };
}

/** The answers the field gives: the reason is the whole text; the change ID is the ticket number it starts with. */
export function reasonAnswers(
  steps: readonly ApprovalStep[],
  text: string,
  targetNames: readonly string[] = [],
): { reason?: string; changeId?: string } {
  const trimmed = text.trim();
  const reason = Boolean(step(steps, "reason"));
  const changeId = Boolean(step(steps, "changeId"));
  const answers: { reason?: string; changeId?: string } = {};
  if (reason) answers.reason = trimmed;
  if (changeId) {
    // Without a reason step the field is the change ID alone.
    const id = reason ? findChangeId(trimmed, targetNames) : trimmed || null;
    if (id) answers.changeId = id;
  }
  return answers;
}

// ---- Why Approve is off ----

export function approvalProblem(input: {
  steps: readonly ApprovalStep[];
  phrase: ConfirmPhrase | null;
  typed: string;
  text: string;
  password: string;
  busy: boolean;
  /** The targets' names, which are never taken as the change ID. */
  targetNames?: readonly string[];
}): string | null {
  const { steps, phrase } = input;
  if (phrase && !confirmMatches(phrase, input.typed)) {
    return phrase.kind === "name"
      ? `Type ${phrase.expected} to confirm first`
      : `Type the number of targets (${phrase.expected}) first`;
  }
  const field = reasonField(steps);
  const answers = reasonAnswers(steps, input.text, input.targetNames);
  if (step(steps, "reason") && !answers.reason) {
    return step(steps, "changeId") ? "Give a reason or change ID first" : "Give a reason first";
  }
  if (field.changeIdRequired && !answers.changeId) {
    return "Start with a change ID such as CHG0012345: this workspace needs one for Prod";
  }
  if (answers.changeId && [...answers.changeId].length > MAX_CHANGE_ID) {
    return `A change ID is at most ${MAX_CHANGE_ID} characters`;
  }
  if (step(steps, "vaultReauth") && input.password === "") return "Type the vault password first";
  if (input.busy) return "Checking the answers…";
  return null;
}
