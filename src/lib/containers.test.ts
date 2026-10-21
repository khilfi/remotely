/// <reference types="node" />
// CT-01, CT-02 (QL-08): the Containers page's decisions. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ContainerState, ContainerSummary, LogLine } from "./api.ts";
import {
  actionReason,
  appendLogs,
  applicable,
  containerTarget,
  containerTargetKey,
  filterContainers,
  formatBytes,
  hostActionReason,
  imageReferenceProblem,
  lastLogTime,
  portTexts,
  PROTECTED_HOST_REASON,
  pruneReason,
  searchLogs,
  shellReason,
  statsFor,
} from "./containers.ts";
import { READ_ONLY_REASON } from "./disabled-reasons.ts";

const ID = "4f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

function container(name: string, state: ContainerState, extra: Partial<ContainerSummary> = {}): ContainerSummary {
  return {
    id: `${name.length.toString(16).padStart(2, "0")}${ID.slice(2)}`,
    name,
    image: "nginx:1.27",
    command: null,
    state,
    status: state === "running" ? "Up 2 hours" : "Exited (0) 1 hour ago",
    createdAt: null,
    startedAt: null,
    ports: [],
    networks: [],
    mounts: [],
    project: null,
    health: null,
    ...extra,
  };
}

const free = { readOnly: false, protectedHost: false, submitting: false };

test("container targets are keyed as the core keys them", () => {
  const target = containerTarget({ kind: "session", sessionId: "s1" }, "docker", { kind: "container", id: ID });
  assert.equal(target.kind, "container");
  if (target.kind !== "container") return;
  assert.equal(containerTargetKey(target), `s1/docker/container:${ID}`);
  const pc = containerTarget({ kind: "thisPc" }, "docker", { kind: "volume", name: "pgdata" });
  if (pc.kind !== "container") return;
  assert.equal(containerTargetKey(pc), "this-pc/docker/volume:pgdata");
  const engine = containerTarget({ kind: "session", sessionId: "s1" }, "podman", { kind: "engine" });
  if (engine.kind !== "container") return;
  assert.equal(containerTargetKey(engine), "s1/podman/engine");
});

test("actions fit the selection's states and say why when none does", () => {
  const web = container("web", "running");
  const db = container("db", "exited");
  const cache = container("cache", "paused");
  assert.deepEqual(
    applicable("start", [web, db, cache]).map((c) => c.name),
    ["db"],
  );
  assert.deepEqual(
    applicable("stop", [web, db, cache]).map((c) => c.name),
    ["web", "cache"],
  );
  assert.equal(actionReason("start", [web, db], free), null);
  assert.equal(actionReason("start", [web], free), "web is running");
  assert.equal(actionReason("pause", [db, cache], free), "None of the selected containers is running");
  assert.equal(actionReason("unpause", [web], free), "web is running");
  assert.equal(actionReason("remove", [web], free), "web is running");
  assert.equal(actionReason("forceRemove", [web], free), null);
  assert.equal(actionReason("stop", [], free), "Select containers first");
  assert.equal(actionReason("stop", [web], { ...free, readOnly: true }), READ_ONLY_REASON);
  assert.equal(actionReason("stop", [web], { ...free, protectedHost: true }), PROTECTED_HOST_REASON);
  assert.equal(actionReason("stop", [web], { ...free, submitting: true }), "Sending the last action…");
});

test("a shell opens only in a running container on an SSH host", () => {
  const ssh = { kind: "session" as const, sessionId: "s1" };
  assert.equal(shellReason(container("web", "running"), ssh), null);
  assert.equal(shellReason(container("db", "exited"), ssh), "db is stopped: start it first");
  assert.equal(shellReason(undefined, ssh), "Select one container first");
  assert.match(shellReason(container("web", "running"), { kind: "thisPc" }) ?? "", /terminal on this PC/);
});

test("host actions and prunes say why they are off", () => {
  assert.equal(hostActionReason(undefined, { readOnly: false, submitting: false }), "Choose a container host first");
  assert.equal(pruneReason("buildCache", "podman")?.startsWith("Podman keeps no build cache"), true);
  assert.equal(pruneReason("buildCache", "docker"), null);
  assert.equal(pruneReason("volumes", "podman"), null);
});

test("filters match name, image, project, port and state", () => {
  const list = [
    container("shop-web-1", "running", {
      project: "shop",
      ports: [{ hostIp: "0.0.0.0", hostPort: 8080, containerPort: 80, protocol: "tcp" }],
    }),
    container("shop-db-1", "running", { image: "postgres:16", project: "shop" }),
    container("cache", "paused", { image: "redis:7" }),
    container("old-job", "exited", { image: "busybox" }),
  ];
  const names = (text: string, state: Parameters<typeof filterContainers>[2] = "all") =>
    filterContainers(list, text, state).map((c) => c.name);
  assert.deepEqual(names("shop"), ["shop-web-1", "shop-db-1"]);
  assert.deepEqual(names("POSTGRES"), ["shop-db-1"]);
  assert.deepEqual(names("8080"), ["shop-web-1"]);
  assert.deepEqual(names("", "paused"), ["cache"]);
  assert.deepEqual(names("", "stopped"), ["old-job"]);
  assert.deepEqual(names("shop web"), ["shop-web-1"], "every word");
});

test("ports show once, with the address only when it is not every address", () => {
  assert.deepEqual(
    portTexts([
      { hostIp: "0.0.0.0", hostPort: 8080, containerPort: 80, protocol: "tcp" },
      { hostIp: "::", hostPort: 8080, containerPort: 80, protocol: "tcp" },
      { hostIp: "127.0.0.1", hostPort: 9000, containerPort: 9000, protocol: "tcp" },
      { hostIp: "::1", hostPort: 53, containerPort: 53, protocol: "udp" },
      { hostIp: null, hostPort: null, containerPort: 443, protocol: "tcp" },
    ]),
    ["8080→80/tcp", "127.0.0.1:9000→9000/tcp", "[::1]:53→53/udp", "443/tcp"],
  );
});

test("sizes read like the CLIs print them, and stats match short ids", () => {
  assert.equal(formatBytes(null), "—");
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(12_582_912), "13 MB");
  assert.equal(formatBytes(4_300_000), "4.3 MB");
  const stats = [{ id: ID.slice(0, 12) } as never];
  assert.ok(statsFor(stats, ID));
  assert.equal(statsFor(stats, "ff".repeat(32)), undefined);
});

test("a followed log adds only new lines and keeps the newest", () => {
  const line = (at: string, text: string): LogLine => ({ at, stream: "stdout", text });
  const first = [line("2026-10-21T10:00:00.000000001Z", "a"), line("2026-10-21T10:00:01.000000000Z", "b")];
  const next = appendLogs(first, [
    line("2026-10-21T10:00:01.000000000Z", "b"),
    line("2026-10-21T10:00:02.000000000Z", "c"),
  ]);
  assert.deepEqual(
    next.map((l) => l.text),
    ["a", "b", "c"],
  );
  assert.equal(lastLogTime(next), "2026-10-21T10:00:02.000000000Z");
  assert.deepEqual(
    appendLogs(next, [line("2026-10-21T10:00:03.000000000Z", "d")], 2).map((l) => l.text),
    ["c", "d"],
  );
  assert.deepEqual(
    searchLogs(next, "B").map((m) => m.index),
    [1],
  );
  assert.equal(searchLogs(next, "  ").length, 3);
});

test("image references follow the grammar the core checks", () => {
  for (const good of ["nginx", "nginx:1.27", "registry.example.com:5000/team/app:2.1", "ghcr.io/example-org/tool"]) {
    assert.equal(imageReferenceProblem(good), null, good);
  }
  for (const bad of ["", "Nginx", "nginx;reboot", "-q", "nginx latest", "$(id)", "nginx:"]) {
    assert.notEqual(imageReferenceProblem(bad), null, bad);
  }
});
