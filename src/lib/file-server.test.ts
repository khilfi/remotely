/// <reference types="node" />
// FD-09: the File server tab's helpers: the form's defaults from the last choices, why Start is off, the request the
// core gets (paths only as a pick's token or "the last choice"), and the words the status and the log read in. Run
// with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { LogRow, ServeAddress, ServerStatus } from "./file-server-api.ts";
import {
  countsText,
  DEFAULT_HTTP_PORT,
  DEFAULT_MINUTES,
  DEFAULT_TFTP_PORT,
  endText,
  initialForm,
  listeningText,
  minutesText,
  parseMb,
  parsePort,
  refusalText,
  requestOf,
  requestText,
  rowsNote,
  sizeText,
  startReason,
  TIME_LIMITS,
  timesText,
} from "./file-server.ts";

const addresses: ServeAddress[] = [
  { address: "192.0.2.10", name: "Ethernet", loopback: false },
  { address: "127.0.0.1", name: "This PC only", loopback: true },
];

function status(over: Partial<ServerStatus> = {}): ServerStatus {
  return {
    jobId: "j1",
    running: true,
    served: "C:\\Images",
    folder: true,
    address: "192.0.2.10",
    tftpPort: 69,
    httpPort: 8080,
    urls: [],
    uploads: null,
    startedAt: "2026-11-01T10:00:00Z",
    endsAt: "2026-11-01T10:30:00Z",
    stopped: null,
    counts: {
      requests: 0,
      sent: 0,
      received: 0,
      refused: 0,
      failed: 0,
      bytesSent: 0,
      bytesReceived: 0,
      refusalsUnlisted: 0,
    },
    transfers: [],
    transferRows: 0,
    refusals: [],
    refusalRows: 0,
    ...over,
  };
}

function row(over: Partial<LogRow> = {}): LogRow {
  return {
    firstAt: "2026-11-01T10:00:00Z",
    at: "2026-11-01T10:00:00Z",
    protocol: "tftp",
    ip: "192.0.2.7",
    port: 51234,
    method: "read",
    path: "fw.bin",
    bytes: 0,
    outcome: "sent",
    detail: "",
    times: 1,
    ...over,
  };
}

test("the form starts on the first adapter with the defaults, or on the last choices", () => {
  const fresh = initialForm(null, addresses);
  assert.equal(fresh.address, "192.0.2.10");
  assert.equal(fresh.root, null);
  assert.equal(fresh.tftpPort, String(DEFAULT_TFTP_PORT));
  assert.equal(fresh.httpPort, String(DEFAULT_HTTP_PORT));
  assert.equal(fresh.minutes, DEFAULT_MINUTES);
  assert.equal(fresh.uploads, false);
  assert.ok(TIME_LIMITS.includes(DEFAULT_MINUTES));
  const last = initialForm(
    {
      root: "C:\\Images\\fw.bin",
      address: "127.0.0.1",
      tftpPort: 6969,
      httpPort: null,
      minutes: 60,
      uploads: { folder: "C:\\Uploads", maxFileMb: 10, maxTotalMb: 100 },
    },
    addresses,
  );
  // The last paths are shown, and sent back only as "the last choice", which the core reads and checks itself.
  assert.deepEqual(last.root, { path: "C:\\Images\\fw.bin", choice: { kind: "last" } });
  assert.equal(last.folder, false, "a path with an extension reads as a file");
  assert.equal(last.address, "127.0.0.1");
  assert.equal(last.tftpPort, "6969");
  assert.equal(last.http, false);
  assert.equal(last.minutes, 60);
  assert.equal(last.uploads, false, "uploads start off every time");
  assert.deepEqual(last.uploadFolder, { path: "C:\\Uploads", choice: { kind: "last" } });
  // An address this PC no longer has falls back to the first adapter.
  const gone = initialForm(
    { root: "C:\\x", address: "198.51.100.4", tftpPort: 69, httpPort: 8080, minutes: 7, uploads: null },
    addresses,
  );
  assert.equal(gone.address, "192.0.2.10");
  assert.equal(gone.minutes, DEFAULT_MINUTES, "a limit not offered falls back to the default");
});

test("ports and sizes are whole numbers in range", () => {
  assert.equal(parsePort("69"), 69);
  assert.equal(parsePort(" 8080 "), 8080);
  for (const bad of ["", "0", "65536", "-1", "6 9", "69.5", "0x45", "999999"]) assert.equal(parsePort(bad), null, bad);
  assert.equal(parseMb("2048"), 2048);
  for (const bad of ["", "0", "65537", "1.5", "a"]) assert.equal(parseMb(bad), null, bad);
});

test("Start says why it is off, and the request carries no path, only choices", () => {
  const picked = { path: "C:\\Images", choice: { kind: "picked", token: "t-root" } } as const;
  const form = { ...initialForm(null, addresses), root: picked };
  assert.equal(startReason({ ...form, root: null }), "Choose a file or folder to serve");
  assert.equal(startReason({ ...form, address: "" }), "Choose the address to serve on");
  assert.equal(startReason({ ...form, tftp: false, http: false }), "Turn on TFTP, HTTP or both");
  assert.equal(startReason({ ...form, tftpPort: "0" }), "Type a TFTP port from 1 to 65535");
  assert.equal(startReason({ ...form, httpPort: "69" }), "Give TFTP and HTTP different ports");
  assert.equal(startReason({ ...form, http: false, httpPort: "69" }), null);
  assert.equal(startReason({ ...form, uploads: true }), "Choose an empty folder for uploads");
  const folder = { path: "C:\\Uploads", choice: { kind: "picked", token: "t-up" } } as const;
  const uploads = { ...form, uploads: true, uploadFolder: folder };
  assert.equal(
    startReason({ ...uploads, maxFileMb: "200", maxTotalMb: "100" }),
    "One file can't be allowed more than all uploads together",
  );
  assert.match(startReason({ ...uploads, maxFileMb: "x" }) ?? "", /largest file/);
  assert.equal(startReason(uploads), null);
  const request = requestOf({ ...form, http: false });
  assert.deepEqual(request, {
    root: { kind: "picked", token: "t-root" },
    address: "192.0.2.10",
    tftpPort: 69,
    httpPort: null,
    minutes: 30,
    uploads: null,
  });
  assert.ok(!JSON.stringify(request).includes("Images"), "no path in what the core gets");
  assert.deepEqual(requestOf({ ...uploads, maxFileMb: "10", maxTotalMb: "100" }).uploads, {
    folder: { kind: "picked", token: "t-up" },
    maxFileMb: 10,
    maxTotalMb: 100,
  });
});

test("the status reads in words", () => {
  assert.equal(minutesText(30), "30 minutes");
  assert.equal(minutesText(60), "1 hour");
  assert.equal(minutesText(90), "1 hour 30 minutes");
  assert.equal(minutesText(480), "8 hours");
  assert.equal(sizeText(100), "100 bytes");
  assert.equal(sizeText(2048), "2 KB");
  assert.equal(sizeText(12 * 1024 * 1024), "12 MB");
  assert.equal(sizeText(1.5 * 1024 * 1024 * 1024), "1.5 GB");
  assert.equal(listeningText(status()), "TFTP on port 69 · HTTP on port 8080");
  assert.equal(listeningText(status({ tftpPort: null })), "HTTP on port 8080");
  assert.match(endText(status(), new Date("2026-11-01T10:00:00Z")), /^Stops at .+ \(in 30 minutes\)$/);
  assert.match(endText(status(), new Date("2026-11-01T10:29:40Z")), /in a minute or less/);
  assert.equal(endText(status({ running: false, stopped: "stopped by you" })), "Stopped by you");
  assert.equal(countsText(status()), "No requests yet");
  assert.equal(
    countsText(status({ counts: { ...status().counts, requests: 3, sent: 2, refused: 1 } })),
    "3 requests: 2 sent, 1 refused",
  );
});

test("log rows read as what was asked, repeats and refusals folded", () => {
  assert.deepEqual(requestText(row()), { what: "TFTP", path: "fw.bin" });
  assert.deepEqual(requestText(row({ method: "write" })), { what: "TFTP upload", path: "fw.bin" });
  assert.deepEqual(requestText(row({ protocol: "http", method: "GET", path: "" })), { what: "HTTP GET", path: "/" });
  assert.equal(timesText(row()), "");
  assert.equal(timesText(row({ times: 3 })), "×3");
  assert.equal(
    refusalText(row({ outcome: "refused", times: 12, path: "../x", detail: "the path leaves the served folder" })),
    "12 requests, last: TFTP ../x (the path leaves the served folder)",
  );
  assert.equal(rowsNote(status()), null);
  assert.equal(
    rowsNote(
      status({
        transfers: [row()],
        transferRows: 250,
        counts: { ...status().counts, refusalsUnlisted: 7 },
      }),
    ),
    "1 of 250 transfers shown; 7 more refusals from other clients counted. The job in Activity keeps every transfer.",
  );
});
