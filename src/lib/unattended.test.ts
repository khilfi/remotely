import assert from "node:assert/strict";
import { test } from "node:test";

import type { AddressPool } from "./address-pools-api.ts";
import type { InstallConfig } from "./install-configs-api.ts";
import {
  csvCells,
  deliveryProblem,
  parseMinutes,
  parseRows,
  poolsFor,
  requestRows,
  rowVariables,
  usesPlaceholder,
} from "./unattended.ts";

function config(kind: InstallConfig["kind"], body: string): InstallConfig {
  return {
    id: "c1",
    builtIn: false,
    name: "lab",
    kind,
    body,
    variables: [
      { name: "gateway", default: "192.0.2.1" },
      { name: "role", default: null },
    ],
    secrets: [],
    notes: null,
    createdAt: null,
    updatedAt: null,
    problems: [],
    diskNeedMb: null,
  } as InstallConfig;
}

test("placeholders are found, escaped ones aren't", () => {
  assert.equal(usesPlaceholder("d-i netcfg/get_ipaddress string {{ip}}", "ip"), true);
  assert.equal(usesPlaceholder("address: {{ ip }}/24", "ip"), true);
  assert.equal(usesPlaceholder("literal \\{{ip}}", "ip"), false);
  assert.equal(usesPlaceholder("{{ipv6}}", "ip"), false);
});

test("only the kinds seen working by hand deliver", () => {
  assert.equal(deliveryProblem(config("autoinstall", "")), null);
  assert.equal(deliveryProblem(config("unattend", "")), null);
  assert.match(deliveryProblem(config("kickstart", "")) ?? "", /Kickstart/);
  assert.deepEqual(
    rowVariables(config("preseed", "")).map((v) => v.name),
    ["gateway", "role"],
  );
});

test("CSV rows map to ip and the config's variables", () => {
  assert.deepEqual(csvCells('a,"b, c",""" q """'), ["a", "b, c", '" q "']);
  const parsed = parseRows("name,ip,role\nweb-1,192.0.2.21,front\r\nweb-2,192.0.2.22,\n\n", ["gateway", "role"]);
  assert.equal(parsed.error, null);
  assert.deepEqual(parsed.rows, [
    { ip: "192.0.2.21", values: { role: "front" } },
    { ip: "192.0.2.22", values: {} },
  ]);
  assert.match(parseRows("ip,owner\n192.0.2.1,bob", ["role"]).error ?? "", /"owner" isn't ip/);
  assert.match(parseRows("", []).error ?? "", /header/);
  const tabbed = parseRows("ip\trole\n192.0.2.9\tdb", ["role"]);
  assert.deepEqual(tabbed.rows, [{ ip: "192.0.2.9", values: { role: "db" } }]);
});

test("a name column puts each line on its VM, whatever the order", () => {
  const names = ["web-1", "web-2", "web-3"];
  const parsed = parseRows("name,ip\nWEB-3,192.0.2.23\nweb-1,192.0.2.21", [], names);
  assert.equal(parsed.error, null);
  assert.deepEqual(parsed.rows, [{ ip: "192.0.2.21", values: {} }, null, { ip: "192.0.2.23", values: {} }]);
  assert.match(parseRows("name,ip\ndb-1,192.0.2.1", [], names).error ?? "", /no VM named "db-1"/);
  assert.match(parseRows("name\nweb-1\nweb-1", [], names).error ?? "", /two lines/);
});

test("the request has a row per VM, and a pool's VMs type no address", () => {
  const rows = [{ ip: " 192.0.2.21 ", values: { role: " web ", gateway: "" } }];
  assert.deepEqual(requestRows(rows, 2, false), [
    { ip: "192.0.2.21", values: { role: "web" } },
    { ip: null, values: {} },
  ]);
  assert.deepEqual(requestRows(rows, 1, true), [{ ip: null, values: { role: "web" } }]);
});

test("pools fit the hypervisor and network", () => {
  const pool = (id: string, hypervisor: "vmware" | "virtualbox", network: AddressPool["network"]) =>
    ({ id, hypervisor, network }) as AddressPool;
  const pools = [
    pool("a", "vmware", { kind: "nat" }),
    pool("b", "virtualbox", { kind: "nat" }),
    pool("c", "vmware", { kind: "vmnet", number: 3 }),
  ];
  assert.deepEqual(
    poolsFor(pools, "vmware", { kind: "nat" }).map((p) => p.id),
    ["a"],
  );
  assert.deepEqual(
    poolsFor(pools, "vmware", { kind: "vmnet", number: 3 }).map((p) => p.id),
    ["c"],
  );
  assert.deepEqual(poolsFor(pools, undefined, { kind: "nat" }), []);
});

test("time limits are whole minutes in range", () => {
  assert.equal(parseMinutes("60"), 60);
  assert.equal(parseMinutes(" 240 "), 240);
  assert.equal(parseMinutes("0"), null);
  assert.equal(parseMinutes("241"), null);
  assert.equal(parseMinutes("1.5"), null);
});
