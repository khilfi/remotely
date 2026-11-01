import assert from "node:assert/strict";
import { test } from "node:test";
import { noteExcerpt, noteLink, noteLinkAction, noteLinkTitle } from "./notes.ts";
import { isAppLink } from "./links.ts";

test("a note's web link asks first, and app links open what they name", () => {
  assert.deepEqual(noteLinkAction({ kind: "web", url: "https://example.com/" }), { web: "https://example.com/" });
  assert.deepEqual(noteLinkAction({ kind: "session", name: "web01", id: "s1" }), {
    open: { kind: "session", sessionId: "s1" },
  });
  assert.deepEqual(noteLinkAction({ kind: "vm", name: "it-web", key: "C:\\VMs\\it-web.vmx" }), {
    open: { kind: "vm", vmxPath: "C:\\VMs\\it-web.vmx" },
  });
  assert.deepEqual(noteLinkAction({ kind: "vault", name: "DB admin", found: true }), { open: { kind: "vault" } });
  assert.deepEqual(noteLinkAction({ kind: "runbook", name: "Disk full", found: true }), {
    open: { kind: "snippet", command: "Disk full" },
  });
  assert.ok("none" in noteLinkAction({ kind: "session", name: "gone", id: null }));
  assert.ok("none" in noteLinkAction({ kind: "refused", target: "javascript:alert(1)" }));
});

test("a vault link's tooltip names the item, never more", () => {
  assert.equal(noteLinkTitle({ kind: "vault", name: "DB admin", found: true }), "Vault item DB admin");
  assert.equal(noteLinkTitle({ kind: "web", url: "https://example.com/x" }), "https://example.com/x");
  assert.ok(!noteLinkTitle({ kind: "refused", target: "javascript:alert(1)" }).includes("javascript"));
});

test("a note's own link is a link the app opens", () => {
  assert.ok(isAppLink(noteLink("session", "s1")));
  assert.ok(isAppLink(noteLink("vm", "C:\\VMs\\it-web\\it-web.vmx")));
  assert.ok(!isAppLink({ kind: "note", noteKind: "session" }));
});

test("an excerpt is the first line of text without markdown marks", () => {
  assert.equal(noteExcerpt("# Deploys\n\nOn **Fridays** only."), "Deploys");
  assert.equal(noteExcerpt("\n\n- [x] Patch `nginx`\n"), "Patch nginx");
  assert.equal(noteExcerpt("```bash\nls\n```"), "ls");
  assert.equal(noteExcerpt("x".repeat(200), 10), `${"x".repeat(9)}…`);
});
