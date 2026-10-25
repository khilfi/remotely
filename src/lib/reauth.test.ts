/// <reference types="node" />
// SS-04, AP-06: asking for the vault password when the core needs it again. Run with `npm test`.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ACTIVITY_PING_MS,
  isReauthCancelled,
  reauthReason,
  shouldPingActivity,
  withReauth,
  type AskPassword,
} from "./reauth.ts";

const needed = {
  code: "reauth_required",
  message:
    "this would send the password 'root' to web01.example.com:22, where no saved session sends it yet. Enter the vault password to go ahead",
};
const wrong = { code: "wrong_vault_password", message: "wrong vault password" };

test("a call that needs nothing more runs once and never asks", async () => {
  let asked = 0;
  const ask: AskPassword = async () => {
    asked++;
    return "x";
  };
  const calls: (string | undefined)[] = [];
  const result = await withReauth(async (password) => {
    calls.push(password);
    return 42;
  }, ask);
  assert.equal(result, 42);
  assert.deepEqual(calls, [undefined]);
  assert.equal(asked, 0);
});

test("when the core asks, the call runs again with the password the user gave", async () => {
  const reasons: string[] = [];
  const ask: AskPassword = async (reason) => {
    reasons.push(reason);
    return "correct horse battery staple";
  };
  const calls: (string | undefined)[] = [];
  const result = await withReauth(async (password) => {
    calls.push(password);
    if (!password) throw needed;
    return "done";
  }, ask);
  assert.equal(result, "done");
  assert.deepEqual(calls, [undefined, "correct horse battery staple"]);
  assert.deepEqual(reasons, [
    "This would send the password 'root' to web01.example.com:22, where no saved session sends it yet.",
  ]);
});

test("a wrong password asks again, saying so", async () => {
  const problems: (string | null)[] = [];
  const answers = ["wrong one", "right one"];
  const ask: AskPassword = async (_reason, problem) => {
    problems.push(problem);
    return answers.shift() ?? null;
  };
  const result = await withReauth(async (password) => {
    if (!password) throw needed;
    if (password !== "right one") throw wrong;
    return "ok";
  }, ask);
  assert.equal(result, "ok");
  assert.deepEqual(problems, [null, "That is not the vault password."]);
});

test("cancelling throws a cancellation, and other errors come through as they are", async () => {
  await assert.rejects(
    withReauth(
      async () => {
        throw needed;
      },
      async () => null,
    ),
    (err) => isReauthCancelled(err),
  );
  const other = { code: "invalid_input", message: "The port must be 1 to 65535." };
  await assert.rejects(
    withReauth(
      async (password) => {
        if (!password) throw needed;
        throw other;
      },
      async () => "pw",
    ),
    (err) => err === other,
  );
  await assert.rejects(
    withReauth(
      async () => {
        throw other;
      },
      async () => "pw",
    ),
    (err) => err === other,
  );
});

test("the reason reads as a sentence without the core's closing instruction", () => {
  assert.equal(
    reauthReason("this loosens the approval rules (a shorter countdown). Enter the vault password to go ahead"),
    "This loosens the approval rules (a shorter countdown).",
  );
  assert.equal(reauthReason("Enter the vault password to go ahead"), "This needs the vault password.");
});

test("activity reaches the core at most every 20 seconds", () => {
  assert.equal(shouldPingActivity(null, 1_000), true);
  assert.equal(shouldPingActivity(1_000, 1_000 + ACTIVITY_PING_MS - 1), false);
  assert.equal(shouldPingActivity(1_000, 1_000 + ACTIVITY_PING_MS), true);
});
