import assert from "node:assert/strict";
import { test } from "node:test";
import { sendNoteCode, setNoteSendHandler } from "./note-send.ts";
import { noteCodeToSend } from "./notes.ts";

test("a code block is sent without the line break at its end, so nothing is entered by itself", () => {
  assert.equal(noteCodeToSend("systemctl restart nginx\n"), "systemctl restart nginx");
  assert.equal(noteCodeToSend("systemctl restart nginx\r\n\n"), "systemctl restart nginx");
  assert.equal(noteCodeToSend("a\nb\n"), "a\nb", "the lines inside stay: the terminal asks about them first");
});

test("the terminal gets exactly the text without its last line break", () => {
  const sent: string[] = [];
  setNoteSendHandler((text) => {
    sent.push(text);
    return true;
  });
  try {
    assert.equal(sendNoteCode("systemctl restart nginx\n"), true);
    assert.equal(sendNoteCode("sudo -i\nwhoami\n"), true);
    assert.equal(sendNoteCode("\n\n"), false, "an empty block sends nothing");
    assert.deepEqual(sent, ["systemctl restart nginx", "sudo -i\nwhoami"]);
    assert.ok(sent.every((t) => !/[\r\n]$/.test(t)));
  } finally {
    setNoteSendHandler(null);
  }
  assert.equal(sendNoteCode("ls\n"), false, "no terminal: nothing is sent");
});
