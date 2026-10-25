/// <reference types="node" />
// SS-10: input (through MultiExec) told from xterm.js's replies to the host (to their own pane only). Run with
// `npm test`.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import type { Terminal } from "@xterm/xterm";
import { InputOrigin, isHostReply, isInput } from "./terminal-input.ts";

const ESC = "\x1b";

/** What xterm.js 6 answers by itself (InputHandler, CoreBrowserTerminal). */
const REPLIES = [
  `${ESC}[12;40R`, // CPR, to ESC[6n
  `${ESC}[?12;40R`, // DECXCPR, to ESC[?6n
  `${ESC}[0n`, // DSR status, to ESC[5n
  `${ESC}[?1;2c`, // DA, to ESC[c
  `${ESC}[?6c`,
  `${ESC}[>0;276;0c`, // DA2, to ESC[>c
  `${ESC}[?2004;1$y`, // DECRQM, to ESC[?2004$p
  `${ESC}[4;1$y`,
  `${ESC}[I`, // focus in and out, with ESC[?1004h
  `${ESC}[O`,
  `${ESC}[8;24;80t`, // window reports
  `${ESC}[4;480;640t`,
  `${ESC}[6;20;10t`,
  `${ESC}]11;rgb:0c0c/0c0c/0d0d${ESC}\\`, // OSC 11, to ESC]11;?
  `${ESC}]10;rgb:e4e4/e4e4/e7e7${ESC}\\`,
  `${ESC}]4;1;rgb:cdcd/3131/3131${ESC}\\`,
  `${ESC}]12;rgb:e4e4/e4e4/e7e7\x07`,
  `${ESC}P1$r0;24r${ESC}\\`, // DECRQSS
  `${ESC}P0$r${ESC}\\`,
];

test("every reply xterm.js makes to a host's query looks like one", () => {
  for (const reply of REPLIES) assert.ok(isHostReply(reply), JSON.stringify(reply));
  assert.ok(isHostReply(`${ESC}[?1;2c${ESC}[12;40R`), "two at once");
});

test("typing, pastes and mouse reports don't look like replies", () => {
  for (const data of [
    "",
    "ls -la\r",
    "\r",
    "\x03",
    `${ESC}[A`, // Up
    `${ESC}OA`, // Up, application cursor keys
    `${ESC}[3~`, // Delete
    `${ESC}[15;2~`, // Shift+F5
    `${ESC}[200~echo hi${ESC}[201~`, // a bracketed paste
    `${ESC}[<0;10;5M`, // SGR mouse press
    `${ESC}[<0;10;5m`,
    `${ESC}[M #!`, // X10 mouse
    `${ESC}x`, // Alt+X
    `${ESC}[12;40Rls`, // a reply with text after it is not a reply
    "12;40R",
  ]) {
    assert.ok(!isHostReply(data), JSON.stringify(data));
  }
});

test("with xterm.js's own signal, what it marks is input and everything else a reply", () => {
  // Ctrl+F3 is ESC[1;5R, the same bytes as a cursor position report: the signal tells them apart.
  assert.equal(isInput(`${ESC}[1;5R`, { exact: true, marked: true }), true);
  assert.equal(isInput(`${ESC}[1;5R`, { exact: true, marked: false }), false);
  assert.equal(isInput("ls", { exact: true, marked: false }), false);
});

test("without it, unmarked data is a reply only when it looks like one", () => {
  assert.equal(isInput(`${ESC}[1;5R`, { exact: false, marked: true }), true, "a key event came first");
  assert.equal(isInput(`${ESC}[12;40R`, { exact: false, marked: false }), false);
  assert.equal(isInput(`${ESC}[I`, { exact: false, marked: false }), false);
  // IME text and mouse reports come without a key event: still input.
  assert.equal(isInput("日本", { exact: false, marked: false }), true);
  assert.equal(isInput(`${ESC}[<0;10;5M`, { exact: false, marked: false }), true);
});

/** A terminal with xterm.js 6's internal signal (or without it), and a way to fire data as xterm.js does. */
function fakeTerminal(withSignal: boolean) {
  const userInput: (() => void)[] = [];
  const keys: (() => void)[] = [];
  const term = {
    _core: withSignal ? { coreService: { onUserInput: (l: () => void) => userInput.push(l) } } : {},
    onKey: (l: () => void) => keys.push(l),
  };
  return {
    term: term as unknown as Terminal,
    /** CoreService.triggerDataEvent: onUserInput first, for input only. */
    data(origin: InputOrigin, data: string, wasUserInput: boolean, key = wasUserInput) {
      if (key) keys.forEach((l) => l());
      if (wasUserInput) userInput.forEach((l) => l());
      return origin.isInput(data);
    },
  };
}

test("InputOrigin follows xterm.js's onUserInput when it is there", async () => {
  const fake = fakeTerminal(true);
  const origin = new InputOrigin(fake.term);
  assert.equal(origin.exact, true);
  assert.equal(fake.data(origin, `${ESC}[1;5R`, true), true, "Ctrl+F3");
  assert.equal(fake.data(origin, `${ESC}[1;5R`, false), false, "a cursor position report");
  assert.equal(fake.data(origin, "pasted\r", true, false), true, "a paste, no key event");
  assert.equal(fake.data(origin, `${ESC}[I`, false), false);
  // A mark that no data followed is gone once the task ends.
  origin.mark();
  await Promise.resolve();
  assert.equal(origin.isInput(`${ESC}[12;40R`), false);
});

test("InputOrigin falls back to key events and its own pastes without it", () => {
  const fake = fakeTerminal(false);
  const origin = new InputOrigin(fake.term);
  assert.equal(origin.exact, false);
  assert.equal(fake.data(origin, `${ESC}[1;5R`, true), true, "Ctrl+F3 has a key event");
  assert.equal(fake.data(origin, `${ESC}[1;5R`, false), false);
  origin.mark();
  assert.equal(origin.isInput(`${ESC}[12;40R`), true, "the pane's own paste");
  assert.equal(fake.data(origin, `${ESC}[<0;3;4M`, true, false), true, "a mouse report");
});

test("the installed xterm.js still fires onUserInput just before onData, for input only", () => {
  // InputOrigin relies on these internals (it falls back without them, less exactly): a newer xterm.js that changes
  // them fails here first.
  const lib = readFileSync(new URL("../../node_modules/@xterm/xterm/lib/xterm.mjs", import.meta.url), "utf8");
  assert.ok(lib.includes("this.coreService="), "CoreTerminal.coreService");
  assert.ok(lib.includes("this._core="), "Terminal._core");
  assert.ok(lib.includes("this.onUserInput=this._onUserInput.event"), "CoreService.onUserInput");
  const trigger = /triggerDataEvent\((\w+),(\w+)(?:=[^)]*)?\)\{/.exec(lib);
  assert.ok(trigger, "CoreService.triggerDataEvent(data, wasUserInput)");
  const body = lib.slice(trigger.index, trigger.index + 600);
  const [, data, wasUserInput] = trigger;
  const fired = body.indexOf(`${wasUserInput}&&this._onUserInput.fire()`);
  assert.ok(fired > 0, "onUserInput fires when wasUserInput");
  assert.ok(body.indexOf(`this._onData.fire(${data})`) > fired, "and then onData, in the same call");
});
