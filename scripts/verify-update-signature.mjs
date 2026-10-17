// Verifies Tauri update signatures (*.sig) against the updater public key in src-tauri/tauri.conf.json
// (FD-14). The release workflow runs it after the build, so a release signed with a key that installed
// apps do not trust fails before anyone publishes it. It only ever needs the public key.
//
//   node scripts/verify-update-signature.mjs [--pubkey <base64>] [file.sig ...]
//
// With no .sig files given, it checks every *.sig under the release bundle folders and fails if
// there are none. Tauri stores keys and signatures as base64 of minisign text files.

import { createHash, createPublicKey, verify } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BUNDLE_DIRS = ["target/release/bundle", "src-tauri/target/release/bundle"];
const TRUSTED = "trusted comment: ";

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

/** Minisign shows key IDs as the hex of a little-endian u64, e.g. 235096698EA9CC20. */
function keyIdText(bytes) {
  return Buffer.from(bytes).reverse().toString("hex").toUpperCase();
}

function minisignLines(base64Text, what) {
  const lines = Buffer.from(base64Text.trim(), "base64").toString("utf8").split(/\r?\n/);
  if (!lines[0]?.startsWith("untrusted comment:")) fail(`${what} is not a minisign file`);
  return lines;
}

function parsePublicKey(base64Text) {
  const raw = Buffer.from(minisignLines(base64Text, "the public key")[1] ?? "", "base64");
  if (raw.length !== 42 || raw.subarray(0, 2).toString() !== "Ed") fail("the public key is not a minisign Ed25519 key");
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw.subarray(10)]),
    format: "der",
    type: "spki",
  });
  return { keyId: raw.subarray(2, 10), key };
}

function configPublicKey() {
  const config = JSON.parse(readFileSync("src-tauri/tauri.conf.json", "utf8"));
  const pubkey = config.plugins?.updater?.pubkey;
  if (!pubkey || pubkey.startsWith("REPLACE_WITH")) fail("plugins.updater.pubkey in tauri.conf.json is not set");
  return pubkey;
}

function verifySignature(sigPath, pub) {
  const file = sigPath.replace(/\.sig$/, "");
  if (!existsSync(file)) fail(`${file} (signed by ${sigPath}) does not exist`);

  const lines = minisignLines(readFileSync(sigPath, "utf8"), sigPath);
  const sig = Buffer.from(lines[1] ?? "", "base64");
  if (sig.length !== 74 || !lines[2]?.startsWith(TRUSTED)) fail(`${sigPath} is not a minisign signature`);
  const algorithm = sig.subarray(0, 2).toString();
  const keyId = sig.subarray(2, 10);
  const signature = sig.subarray(10);

  if (!keyId.equals(pub.keyId)) {
    fail(
      `${sigPath} was signed with key ${keyIdText(keyId)}, but tauri.conf.json trusts key ${keyIdText(pub.keyId)}: ` +
        "the TAURI_SIGNING_PRIVATE_KEY secret does not match plugins.updater.pubkey",
    );
  }

  let message;
  if (algorithm === "ED") message = createHash("blake2b512").update(readFileSync(file)).digest();
  else if (algorithm === "Ed") message = readFileSync(file);
  else fail(`${sigPath} uses an unknown signature algorithm`);

  if (!verify(null, message, pub.key, signature)) fail(`${sigPath} does not match ${file}`);

  const trustedComment = Buffer.from(lines[2].slice(TRUSTED.length), "utf8");
  const globalSignature = Buffer.from(lines[3] ?? "", "base64");
  if (!verify(null, Buffer.concat([signature, trustedComment]), pub.key, globalSignature)) {
    fail(`${sigPath} has an invalid trusted-comment signature`);
  }
  console.log(`ok: ${file} is signed by key ${keyIdText(keyId)}`);
}

function findSignatures() {
  return BUNDLE_DIRS.filter((dir) => existsSync(dir)).flatMap((dir) =>
    readdirSync(dir, { recursive: true })
      .map(String)
      .filter((name) => name.endsWith(".sig"))
      .map((name) => join(dir, name)),
  );
}

const args = process.argv.slice(2);
const pubkeyAt = args.indexOf("--pubkey");
const pubkey = pubkeyAt >= 0 ? args.splice(pubkeyAt, 2)[1] : configPublicKey();
const signatures = args.length > 0 ? args : findSignatures();
if (signatures.length === 0) fail(`no .sig files found under ${BUNDLE_DIRS.join(" or ")}`);

const pub = parsePublicKey(pubkey);
for (const sigPath of signatures) verifySignature(sigPath, pub);
