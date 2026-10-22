// Verifies Tauri update signatures (*.sig) against the updater public key in src-tauri/tauri.conf.json
// (FD-14). The release workflow runs it right after signing, before any release exists, so an update
// signed with a key that installed apps do not trust never reaches a draft. It only ever needs the
// public key. scripts/publish-release.mjs uses the same functions.
//
//   node scripts/verify-update-signature.mjs [--pubkey <base64>] [--version <x.y.z>] [file.sig ...]
//
// With no .sig files given, it checks every *.sig under the release bundle folders and fails if
// there are none. With --version, each signature's trusted comment must also name its own file and
// that version (C3: `tauri signer sign --app-version` writes `file:` and `version:` there), which is
// what installed apps check before they offer an update. Tauri stores keys and signatures as base64
// of minisign text files.

import { createHash, createPublicKey, verify } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const BUNDLE_DIRS = ["target/release/bundle", "src-tauri/target/release/bundle"];
const TRUSTED = "trusted comment: ";

export class VerifyError extends Error {}

function fail(message) {
  throw new VerifyError(message);
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

export function parsePublicKey(base64Text) {
  const raw = Buffer.from(minisignLines(base64Text, "the public key")[1] ?? "", "base64");
  if (raw.length !== 42 || raw.subarray(0, 2).toString() !== "Ed") fail("the public key is not a minisign Ed25519 key");
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw.subarray(10)]),
    format: "der",
    type: "spki",
  });
  return { keyId: raw.subarray(2, 10), key };
}

export function tauriConfig() {
  return JSON.parse(readFileSync("src-tauri/tauri.conf.json", "utf8"));
}

export function configPublicKey(config = tauriConfig()) {
  const pubkey = config.plugins?.updater?.pubkey;
  if (!pubkey || pubkey.startsWith("REPLACE_WITH")) fail("plugins.updater.pubkey in tauri.conf.json is not set");
  return pubkey;
}

/** The `key:value` fields of a trusted comment, e.g. `timestamp:1792651013\tfile:...\tversion:0.4.0`. */
export function trustedFields(comment) {
  return Object.fromEntries(
    comment
      .split("\t")
      .map((field) => field.split(/:(.*)/s, 2))
      .filter((pair) => pair.length === 2),
  );
}

/**
 * Checks `signatureText` (the .sig file's content: base64 of a minisign signature) over `data`
 * against `pub`, then its trusted comment. With `expect.file` and `expect.version`, the comment must
 * name them. Returns the comment's fields. `what` names the signature in messages.
 */
export function verifySignature(signatureText, data, pub, { what = "the signature", file, version } = {}) {
  const lines = minisignLines(signatureText, what);
  const sig = Buffer.from(lines[1] ?? "", "base64");
  if (sig.length !== 74 || !lines[2]?.startsWith(TRUSTED)) fail(`${what} is not a minisign signature`);
  const algorithm = sig.subarray(0, 2).toString();
  const keyId = sig.subarray(2, 10);
  const signature = sig.subarray(10);

  if (!keyId.equals(pub.keyId)) {
    fail(
      `${what} was signed with key ${keyIdText(keyId)}, but tauri.conf.json trusts key ${keyIdText(pub.keyId)}: ` +
        "the TAURI_SIGNING_PRIVATE_KEY secret does not match plugins.updater.pubkey",
    );
  }

  let message;
  if (algorithm === "ED") message = createHash("blake2b512").update(data).digest();
  else if (algorithm === "Ed") message = data;
  else fail(`${what} uses an unknown signature algorithm`);

  if (!verify(null, message, pub.key, signature)) fail(`${what} does not match the file it signs`);

  const comment = lines[2].slice(TRUSTED.length);
  const globalSignature = Buffer.from(lines[3] ?? "", "base64");
  if (!verify(null, Buffer.concat([signature, Buffer.from(comment, "utf8")]), pub.key, globalSignature)) {
    fail(`${what} has an invalid trusted-comment signature`);
  }

  const fields = trustedFields(comment);
  if (file !== undefined && fields.file !== file) {
    fail(`${what} names file "${fields.file ?? ""}" in its trusted comment, not "${file}"`);
  }
  if (version !== undefined && fields.version !== version) {
    fail(
      `${what} was signed for version "${fields.version ?? ""}", not "${version}" ` +
        "(sign with `tauri signer sign --app-version`)",
    );
  }
  return fields;
}

/** Verifies `sigPath` against the file next to it (the same name without `.sig`). */
export function verifySignatureFile(sigPath, pub, { version } = {}) {
  const file = sigPath.replace(/\.sig$/, "");
  if (!existsSync(file)) fail(`${file} (signed by ${sigPath}) does not exist`);
  const expect = version === undefined ? {} : { file: basename(file), version };
  verifySignature(readFileSync(sigPath, "utf8"), readFileSync(file), pub, { what: sigPath, ...expect });
  return `${file} is signed by key ${keyIdText(pub.keyId)}${version === undefined ? "" : ` for ${version}`}`;
}

function findSignatures() {
  return BUNDLE_DIRS.filter((dir) => existsSync(dir)).flatMap((dir) =>
    readdirSync(dir, { recursive: true })
      .map(String)
      .filter((name) => name.endsWith(".sig"))
      .map((name) => join(dir, name)),
  );
}

/** `--name value` from `args`, removing both. */
export function takeOption(args, name) {
  const at = args.indexOf(name);
  if (at < 0) return undefined;
  const value = args[at + 1];
  if (value === undefined || value.startsWith("--")) fail(`${name} needs a value`);
  args.splice(at, 2);
  return value;
}

function main(args) {
  const pubkey = takeOption(args, "--pubkey") ?? configPublicKey();
  const version = takeOption(args, "--version");
  const signatures = args.length > 0 ? args : findSignatures();
  if (signatures.length === 0) fail(`no .sig files found under ${BUNDLE_DIRS.join(" or ")}`);

  const pub = parsePublicKey(pubkey);
  for (const sigPath of signatures) console.log(`ok: ${verifySignatureFile(sigPath, pub, { version })}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`error: ${err instanceof VerifyError ? err.message : err}`);
    process.exit(1);
  }
}
