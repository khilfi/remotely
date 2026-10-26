// VM-08 stacks and VM-26 the deploy capacity planner: the types the core sends and the IPC wrappers. Edits are the
// app's own data (audited, refused by the read-only lock); a deploy, an instance's start, stop or suspend, and a
// teardown come back as a SubmitOutcome for the approval dialog, built in the core.

import {
  invoke,
  type DeployPreview,
  type Environment,
  type Hypervisor,
  type PowerOp,
  type PowerState,
  type SubmitOutcome,
} from "@/lib/api";

/** What a step's VMs must show before the next step starts. */
export type Readiness = { kind: "none" } | { kind: "tools" } | { kind: "sshPort"; port: number };

export interface StackStep {
  templateId: string;
  count: number;
  readiness: Readiness;
  /** How long the check may take before the stack stops there (30 s to an hour). */
  readyTimeoutSecs: number;
  /** How long to wait after this step before the next starts (up to an hour). */
  delaySecs: number;
}

export interface StackInput {
  name: string;
  description?: string | null;
  /** In boot order. */
  steps: StackStep[];
}

export interface StackStepView extends StackStep {
  /** Null when the template was deleted. */
  templateName: string | null;
  hypervisor: Hypervisor | null;
  problems: string[];
}

export interface Stack {
  id: string;
  name: string;
  description: string | null;
  steps: StackStepView[];
  vmCount: number;
  /** Its instances on this PC. */
  instances: number;
  /** Why it can't deploy now (empty when it can). */
  problems: string[];
  createdAt: string;
  updatedAt: string;
}

export interface StackCheck {
  /** Why it can't be saved. */
  invalid: string | null;
  /** Why it couldn't deploy now (it can be saved anyway). */
  problems: string[];
  vmCount: number;
}

export type MemberOrigin = "deploy" | "hand";

export interface InstanceVm {
  key: string;
  name: string;
  /** From 0: the first to boot. */
  step: number;
  origin: MemberOrigin;
  /** Null when the VM isn't on this PC any more. */
  powerState: PowerState | null;
  protected: boolean;
  environment: Environment;
}

export interface InstanceStep {
  label: string;
  readiness: Readiness;
  readyTimeoutSecs: number;
  delaySecs: number;
}

export interface StackInstance {
  id: string;
  stackId: string;
  stackName: string;
  name: string;
  steps: InstanceStep[];
  jobId: string | null;
  createdAt: string;
  /** In step order. */
  vms: InstanceVm[];
}

export interface StackDeployRequest {
  stackId: string;
  /** Null: `<stack name> <n>`. */
  instanceName?: string | null;
}

export type StackAction = "deploy" | "start" | "shutDown" | "suspend" | "teardown";

export interface StepDetails {
  label: string;
  vms: string[];
  readiness: Readiness;
  readyTimeoutSecs: number;
  delaySecs: number;
  deploy: DeployPreview | null;
}

export interface KeptVm {
  key: string;
  name: string;
  why: string;
}

/** AP-02 for a stack command. */
export interface StackDetails {
  action: StackAction;
  instanceName: string;
  stackName: string | null;
  steps: StepDetails[];
  kept: KeptVm[];
  diskBytes: number;
  thickBytes: number;
  warnings: string[];
  refusals: string[];
}

/** A VM's place in its stack instance (AP-02). */
export interface StackMembership {
  instanceId: string;
  instanceName: string;
  stackName: string;
  /** From 1. */
  step: number;
  steps: number;
  byHand: boolean;
}

export interface StackDeployCheck {
  problems: string[];
  instanceName: string;
  details: StackDetails | null;
  capacity: DeployCapacity | null;
}

// ---- VM-26 --------------------------------------------------------------------------------------------------------

export interface RamPlan {
  physicalMb: number | null;
  /** What Windows has in use now, VMs included. */
  inUseMb: number | null;
  /** Assigned to the running VMs now. */
  runningMb: number;
  /** What the new VMs that start add. */
  addsMb: number;
  afterMb: number;
  fits: boolean;
}

export interface CpuPlan {
  logicalCpus: number | null;
  runningVcpus: number;
  addsVcpus: number;
  afterVcpus: number;
  largestVmVcpus: number;
  fits: boolean;
}

export interface DrivePlan {
  drive: string;
  freeBytes: number | null;
  totalBytes: number | null;
  /** Thin disks at their full size. */
  addsBytes: number;
  thickBytes: number;
  freeAfterBytes: number | null;
  /** The thick disks fit. */
  fits: boolean;
  /** Every disk fits at its full size. */
  worstCaseFits: boolean;
  lowAfter: boolean;
}

export interface SuspendVm {
  key: string;
  name: string;
  ramMb: number;
  environment: Environment;
}

export interface SuspendPlan {
  vms: SuspendVm[];
  freesMb: number;
  needsMb: number;
  /** False: every VM that could be suspended, and still not enough. */
  enough: boolean;
}

/** VM-26: this PC after a deploy, next to now. */
export interface DeployCapacity {
  ram: RamPlan;
  cpu: CpuPlan;
  drives: DrivePlan[];
  runningVms: number;
  unsizedVms: number;
  newVms: number;
  startingVms: number;
  /** RAM, CPU and the thick disks fit. */
  fits: boolean;
  problems: string[];
  warnings: string[];
  suspend: SuspendPlan | null;
  unchecked: string[];
}

export const stacksApi = {
  list: () => invoke<Stack[]>("stacks_list"),
  check: (input: StackInput) => invoke<StackCheck>("stacks_check", { input }),
  add: (input: StackInput) => invoke<Stack>("stacks_add", { input }),
  update: (id: string, input: StackInput) => invoke<Stack>("stacks_update", { id, input }),
  /** Its instances stay. */
  remove: (id: string) => invoke<void>("stacks_delete", { id }),
  deployCheck: (request: StackDeployRequest) => invoke<StackDeployCheck>("stacks_deploy_check", { request }),
  deploy: (request: StackDeployRequest) => invoke<SubmitOutcome>("stacks_deploy", { request }),
  instances: () => invoke<StackInstance[]>("stacks_instances"),
  /** Start (boot order), shut down or suspend (the last step first). */
  power: (id: string, op: PowerOp) => invoke<SubmitOutcome>("stacks_instance_power", { id, op }),
  /** Critical. `also`: VMs added by hand to delete too, by key. */
  teardown: (id: string, also: string[]) => invoke<SubmitOutcome>("stacks_teardown", { id, also }),
  addVm: (id: string, vmKey: string, step: number) => invoke<StackInstance>("stacks_add_vm", { id, vmKey, step }),
  removeVm: (id: string, vmKey: string) => invoke<StackInstance>("stacks_remove_vm", { id, vmKey }),
  /** Its VMs stay as they are. */
  forgetInstance: (id: string) => invoke<void>("stacks_forget_instance", { id }),
};
