// FD-14 release scripts against a fake GitHub on 127.0.0.1, with a throwaway signing key made at run time
// (never the real one). Run by `npm test`.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { fileURLToPath } from "node:url";

import { checkManifest, installerName, MANIFEST, PLATFORMS, publish } from "./publish-release.mjs";
import { parsePublicKey } from "./verify-update-signature.mjs";

const REPO = "alice/remotely";
const TOKEN = "test-token-not-a-secret";
const VERIFY_SCRIPT = fileURLToPath(new URL("./verify-update-signature.mjs", import.meta.url));

/** A minisign key pair, as `tauri signer generate` makes one; `sign` writes what `tauri signer sign` does. */
function makeSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const keyId = randomBytes(8);
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const b64 = (bytes) => Buffer.from(bytes).toString("base64");
  const pubkey = b64(
    `untrusted comment: minisign public key: TEST\n${b64(Buffer.concat([Buffer.from("Ed"), keyId, raw]))}\n`,
  );
  const sign = (data, comment) => {
    const signature = cryptoSign(null, createHash("blake2b512").update(data).digest(), privateKey);
    const global = cryptoSign(null, Buffer.concat([signature, Buffer.from(comment)]), privateKey);
    const sigLine = b64(Buffer.concat([Buffer.from("ED"), keyId, signature]));
    return b64(
      `untrusted comment: signature from tauri secret key\n${sigLine}\ntrusted comment: ${comment}\n${b64(global)}\n`,
    );
  };
  return { pubkey, sign };
}

/** GitHub's release API and its file storage, as a private repository serves them to a token. */
async function fakeGithub() {
  const state = { releases: [], assets: new Map(), nextId: 100, requests: [], corrupt: false };
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const url = new URL(req.url, base);
    state.requests.push({ method: req.method, path: url.pathname, authorization: req.headers.authorization });
    const json = (status, value) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(value === undefined ? undefined : JSON.stringify(value));
    };
    if (url.pathname.startsWith("/storage/")) {
      // Storage refuses a second kind of authorization, as GitHub's does.
      if (req.headers.authorization) return json(400, { message: "Only one auth mechanism allowed" });
      const asset = state.assets.get(Number(url.pathname.split("/").pop()));
      res.writeHead(200, { "Content-Type": "application/octet-stream" });
      return res.end(state.corrupt ? Buffer.from("MZ something else") : asset.bytes);
    }
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json(401, { message: "Bad credentials" });
    const repo = `/repos/${REPO}`;
    const uploads = `/uploads${repo}/releases/`;
    let match;
    if (req.method === "GET" && url.pathname === `${repo}/releases`) {
      const page = Number(url.searchParams.get("page") ?? 1);
      return json(200, page === 1 ? state.releases : []);
    }
    if (req.method === "POST" && url.pathname === `${repo}/releases`) {
      const input = JSON.parse(body.toString());
      const id = state.nextId++;
      const release = {
        ...input,
        id,
        assets: [],
        upload_url: `${base}${uploads}${id}/assets{?name,label}`,
        html_url: `https://github.com/${REPO}/releases/tag/untagged-${id}`,
      };
      state.releases.push(release);
      return json(201, release);
    }
    if (req.method === "POST" && (match = new RegExp(`^${uploads}(\\d+)/assets$`).exec(url.pathname))) {
      const release = state.releases.find((r) => r.id === Number(match[1]));
      const id = state.nextId++;
      const asset = { id, name: url.searchParams.get("name"), url: `${base}${repo}/releases/assets/${id}` };
      state.assets.set(id, { ...asset, bytes: body });
      release.assets.push(asset);
      return json(201, { ...asset, size: body.length, state: "uploaded" });
    }
    if (req.method === "GET" && (match = new RegExp(`^${repo}/releases/assets/(\\d+)$`).exec(url.pathname))) {
      res.writeHead(302, { Location: `${base}/storage/${match[1]}?X-Amz-Signature=fake` });
      return res.end();
    }
    if (req.method === "GET" && (match = new RegExp(`^${repo}/releases/(\\d+)/assets$`).exec(url.pathname))) {
      return json(200, state.releases.find((r) => r.id === Number(match[1])).assets);
    }
    if (req.method === "DELETE" && (match = new RegExp(`^${repo}/releases/(\\d+)$`).exec(url.pathname))) {
      state.releases = state.releases.filter((r) => r.id !== Number(match[1]));
      return json(204);
    }
    return json(404, { message: "Not Found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, state, close: () => new Promise((resolve) => server.close(resolve)) };
}

let dir;
let github;
let signer;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "remotely-release-test-"));
  github = await fakeGithub();
  signer = makeSigner();
});

afterEach(async () => {
  await github.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A build of `version` signed for `signedFor`, and a config that trusts `pubkey`. */
function build({ version = "0.9.0", signedFor = version, pubkey = signer.pubkey, sign = signer.sign } = {}) {
  const installer = join(dir, installerName("Remotely", version));
  const bytes = Buffer.from(`MZ fake NSIS installer for ${signedFor}`);
  writeFileSync(installer, bytes);
  const comment = `timestamp:1792651013\tfile:${installerName("Remotely", signedFor)}\tversion:${signedFor}`;
  writeFileSync(`${installer}.sig`, sign(bytes, comment));
  const config = join(dir, "tauri.conf.json");
  writeFileSync(config, JSON.stringify({ productName: "Remotely", version, plugins: { updater: { pubkey } } }));
  const notes = join(dir, "notes.md");
  writeFileSync(notes, `Remotely ${version}: what changed.\n\n`);
  return { installerPath: installer, configPath: config, notesPath: notes, bytes };
}

const run = (files, tag = "v0.9.0") =>
  publish({
    tag,
    ...files,
    env: { GITHUB_REPOSITORY: REPO, GITHUB_TOKEN: TOKEN, GITHUB_API_URL: github.base },
    log: () => {},
  });

test("publishes a draft whose latest.json an installed app accepts", async () => {
  const files = build();
  const { manifest } = await run(files);

  const [release] = github.state.releases;
  assert.equal(release.draft, true);
  assert.equal(release.prerelease, false);
  assert.equal(release.tag_name, "v0.9.0");
  assert.equal(release.name, "Remotely v0.9.0");
  assert.equal(release.body, "Remotely 0.9.0: what changed.");
  const names = release.assets.map((a) => a.name);
  assert.deepEqual(names, ["Remotely_0.9.0_x64-setup.exe", "Remotely_0.9.0_x64-setup.exe.sig", MANIFEST]);

  // latest.json as uploaded: tauri-action's shape, API asset URLs, the .sig's text.
  const uploaded = JSON.parse(github.state.assets.get(release.assets[2].id).bytes.toString());
  assert.deepEqual(uploaded, manifest);
  assert.deepEqual(Object.keys(uploaded), ["version", "notes", "pub_date", "platforms"]);
  assert.deepEqual(Object.keys(uploaded.platforms), PLATFORMS);
  assert.equal(uploaded.version, "0.9.0");
  assert.equal(uploaded.notes, "Remotely 0.9.0: what changed.");
  const installerUrl = `${github.base}/repos/${REPO}/releases/assets/${release.assets[0].id}`;
  for (const name of PLATFORMS) {
    assert.equal(uploaded.platforms[name].url, installerUrl);
    assert.equal(uploaded.platforms[name].signature, github.state.assets.get(release.assets[1].id).bytes.toString());
  }

  // The installer was fetched back through the API, and the token never went to the storage.
  const storage = github.state.requests.filter((r) => r.path.startsWith("/storage/"));
  assert.equal(storage.length, 1);
  assert.equal(storage[0].authorization, undefined);
});

test("refuses an installer signed for another version before any release exists", async () => {
  // An old, genuinely signed installer renamed as 0.9.0: its signature still names 0.5.0.
  const files = build({ signedFor: "0.5.0" });
  await assert.rejects(
    run(files),
    /names file "Remotely_0\.5\.0_x64-setup\.exe".*not "Remotely_0\.9\.0_x64-setup\.exe"/,
  );
  assert.equal(github.state.requests.length, 0);
});

test("refuses a signature from another key before any release exists", async () => {
  const files = build({ sign: makeSigner().sign });
  await assert.rejects(run(files), /does not match plugins\.updater\.pubkey/);
  assert.equal(github.state.requests.length, 0);
});

test("refuses a tag that doesn't match tauri.conf.json, or that already has a release", async () => {
  const files = build();
  await assert.rejects(run(files, "v0.9.1"), /does not match tauri\.conf\.json's version 0\.9\.0/);
  github.state.releases.push({ id: 1, tag_name: "v0.9.0", draft: true, assets: [] });
  await assert.rejects(run(files), /a release for v0\.9\.0 already exists \(a draft\)/);
  assert.ok(github.state.requests.every((r) => r.method === "GET"));
});

test("--pubkey publishes a key rotation release signed with the key installed apps still trust", async () => {
  // tauri.conf.json already holds the new key; the installer is signed with the old one.
  const files = build({ pubkey: makeSigner().pubkey });
  await assert.rejects(run(files), /does not match plugins\.updater\.pubkey/);
  await publish({
    tag: "v0.9.0",
    ...files,
    pubkey: signer.pubkey,
    env: { GITHUB_REPOSITORY: REPO, GITHUB_TOKEN: TOKEN, GITHUB_API_URL: github.base },
    log: () => {},
  });
  assert.equal(github.state.releases.length, 1);
});

test("deletes the draft when the API serves other bytes than were signed", async () => {
  const files = build();
  github.state.corrupt = true;
  await assert.rejects(run(files), /not the signed installer/);
  assert.equal(github.state.releases.length, 0, "the draft was deleted");
  assert.ok(github.state.requests.some((r) => r.method === "DELETE"));
});

test("checkManifest refuses another URL, version or signature", () => {
  const files = build();
  const signature = signer.sign(files.bytes, "timestamp:1\tfile:Remotely_0.9.0_x64-setup.exe\tversion:0.9.0");
  const url = `https://api.github.com/repos/${REPO}/releases/assets/7`;
  const good = {
    version: "0.9.0",
    notes: "n",
    pub_date: new Date().toISOString(),
    platforms: Object.fromEntries(PLATFORMS.map((p) => [p, { signature, url }])),
  };
  const expect = {
    version: "0.9.0",
    file: "Remotely_0.9.0_x64-setup.exe",
    installer: files.bytes,
    signature,
    pub: parsePublicKey(signer.pubkey),
    url,
    api: "https://api.github.com",
    repo: REPO,
  };
  checkManifest(good, expect);
  assert.throws(() => checkManifest({ ...good, version: "0.9.1" }, expect), /says version 0\.9\.1/);
  const elsewhere = `https://github.com/${REPO}/releases/download/v0.9.0/Remotely_0.9.0_x64-setup.exe`;
  assert.throws(() => checkManifest(good, { ...expect, url: elsewhere }), /is not the installer's API asset URL/);
  const other = signer.sign(files.bytes, "timestamp:1\tfile:Remotely_0.9.0_x64-setup.exe\tversion:0.9.0 ");
  assert.throws(() => checkManifest(good, { ...expect, signature: other }), /the signature is not the \.sig file's/);
});

test("verify-update-signature --version checks the trusted comment", () => {
  const { installerPath } = build({ signedFor: "0.5.0" });
  const cli = (...args) =>
    execFileSync(process.execPath, [VERIFY_SCRIPT, "--pubkey", signer.pubkey, ...args], {
      stdio: "pipe",
    });
  // Without --version only the key and the bytes are checked: the 0.5.0 signature is genuine.
  assert.match(cli(`${installerPath}.sig`).toString(), /^ok: /);
  assert.throws(() => cli("--version", "0.9.0", `${installerPath}.sig`), /signed for version|names file/);
});
