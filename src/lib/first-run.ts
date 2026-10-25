// QL-23 first-run wizard, the pure part (tested in first-run.test.ts): when it offers itself, its steps and what each
// already has. It shows at start when there is no vault and no session, until it is finished or skipped; Settings
// (General, Setup guide) and the palette open it again. Skipping is remembered per machine, like the theme. Every
// step uses the same commands as Settings, the Vault page and the Sessions page, so nothing it does skips their
// checks or their audit entries.

export type FirstRunStep = "hypervisors" | "vault" | "folders" | "sessions" | "done";

export const FIRST_RUN_STEPS: { id: FirstRunStep; title: string; hint: string }[] = [
  { id: "hypervisors", title: "Find Workstation and VirtualBox", hint: "Where vmrun.exe and VBoxManage.exe are" },
  { id: "vault", title: "Create the vault", hint: "Where passwords and keys are kept, encrypted" },
  { id: "folders", title: "Pick VM folders", hint: "Folders with VMs that Workstation's library doesn't list" },
  { id: "sessions", title: "Import sessions", hint: "From PuTTY, MobaXterm, OpenSSH or a CSV file" },
  { id: "done", title: "Done", hint: "Where to go next" },
];

export interface FirstRunFacts {
  vaultStatus: "notSetUp" | "locked" | "unlocked" | null;
  sessionCount: number | null;
  vmrunFound: boolean;
  vboxmanageFound: boolean;
  scanFolders: number;
}

/** What a step shows in the list: done, needs doing, or can be left. */
export type StepMark = "done" | "todo" | "optional";

export function stepMark(step: FirstRunStep, facts: FirstRunFacts): StepMark {
  switch (step) {
    case "hypervisors":
      return facts.vmrunFound || facts.vboxmanageFound ? "done" : "todo";
    case "vault":
      return facts.vaultStatus && facts.vaultStatus !== "notSetUp" ? "done" : "todo";
    case "folders":
      return facts.scanFolders > 0 ? "done" : "optional";
    case "sessions":
      return (facts.sessionCount ?? 0) > 0 ? "done" : "optional";
    case "done":
      return "optional";
  }
}

/** It offers itself at start: no vault, no session, and not finished or skipped before on this machine. */
export function shouldOfferFirstRun(facts: Pick<FirstRunFacts, "vaultStatus" | "sessionCount">, dismissed: boolean) {
  return !dismissed && facts.vaultStatus === "notSetUp" && facts.sessionCount === 0;
}

export function nextStep(step: FirstRunStep): FirstRunStep {
  const i = FIRST_RUN_STEPS.findIndex((s) => s.id === step);
  return FIRST_RUN_STEPS[Math.min(i + 1, FIRST_RUN_STEPS.length - 1)].id;
}

export function previousStep(step: FirstRunStep): FirstRunStep {
  const i = FIRST_RUN_STEPS.findIndex((s) => s.id === step);
  return FIRST_RUN_STEPS[Math.max(i - 1, 0)].id;
}

const STORAGE_KEY = "remotely.firstRun";

/** Finished or skipped before, on this machine. */
export function firstRunDismissed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) !== null;
  } catch {
    return false;
  }
}

export function dismissFirstRun(how: "done" | "skipped") {
  try {
    localStorage.setItem(STORAGE_KEY, how);
  } catch {
    // Not kept: it may offer itself again next start.
  }
}

// Settings and the palette open it again.
const openers = new Set<() => void>();

export function requestFirstRun() {
  for (const open of openers) open();
}

export function onFirstRunRequest(open: () => void): () => void {
  openers.add(open);
  return () => {
    openers.delete(open);
  };
}
