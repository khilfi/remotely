// Publishes a signed installer as a DRAFT GitHub Release (FD-14). release.yml's publish job runs it after
// `tauri signer sign`; the owner publishes the draft after a smoke test.
//
//   node scripts/publish-release.mjs --tag vX.Y.Z --installer <dir>/Remotely_X.Y.Z_x64-setup.exe --notes <file>
//                                    [--config src-tauri/tauri.conf.json] [--pubkey <base64>]
//
// The installer's .sig must be next to it. Needs GITHUB_TOKEN (contents: write) and GITHUB_REPOSITORY
// (owner/name); GITHUB_API_URL defaults to https://api.github.com.
//
// 1. Before any release exists: the tag matches tauri.conf.json's version, the installer has the bundler's
//    name for it, its signature checks out against plugins.updater.pubkey and names this file and version
//    (C3), and no release has this tag yet (C6).
// 2. Creates the draft with the installer and its .sig, which gives them their API asset URLs. Its text is
//    the notes plus the installer's SHA-256 and how to check it (releaseBody: the installer isn't
//    Authenticode-signed, so SmartScreen warns on a manual install); latest.json keeps the notes alone.
// 3. Writes latest.json as tauri-action did: version, notes, pub_date, and windows-x86_64 and
//    windows-x86_64-nsis entries with the .sig's content and the installer's API asset URL (installed apps
//    send their token only to API URLs).
// 4. Checks latest.json the way an installed app reads it: the version, each entry's signature over the
//    installer, and each URL, which it fetches back through the API, following the redirect to GitHub's
//    storage without the token as the app does, and compares with the signed installer.
// 5. Uploads latest.json, the file that makes the release installable, and checks the draft holds exactly
//    the three files.
// If anything after step 2 fails, the draft is deleted, so a failed run leaves nothing to publish.
//
// --pubkey is the public key installed apps trust, when it isn't tauri.conf.json's: only for the one
// release that moves them to a new signing key (README "Signing key compromise or loss").

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";
import {
  parsePublicKey,
  configPublicKey,
  takeOption,
  verifySignature,
  VerifyError,
} from "./verify-update-signature.mjs";

export const MANIFEST = "latest.json";
export const PLATFORMS = ["windows-x86_64", "windows-x86_64-nsis"];

function fail(message) {
  throw new VerifyError(message);
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The NSIS installer's name, as the Tauri bundler makes it (and the app expects it, C3). */
export function installerName(product, version) {
  return `${product}_${version}_x64-setup.exe`;
}

/** latest.json, in tauri-action's shape and key order. */
export function latestJson({ version, notes, pubDate, signature, url }) {
  const platform = { signature, url };
  return {
    version,
    notes,
    pub_date: pubDate,
    platforms: Object.fromEntries(PLATFORMS.map((name) => [name, platform])),
  };
}

/**
 * The release page's text: the tag message's notes, then the installer's SHA-256 and how to check it,
 * since the installer is not Authenticode-signed and SmartScreen warns on a manual install. latest.json
 * keeps the notes alone, so the app's update banner doesn't show this (updates check the signature).
 */
export function releaseBody({ notes, file, installer }) {
  return [
    notes,
    "",
    "---",
    "",
    "### Checksum",
    "",
    `\`${file}\` SHA-256: \`${sha256(installer)}\``,
    "",
    'The installer isn\'t code-signed yet, so Windows SmartScreen may say "Windows protected your PC" ' +
      "when you install it by hand. Check the checksum first, in PowerShell in the folder you downloaded it to:",
    "",
    "```powershell",
    `Get-FileHash .\\${file} -Algorithm SHA256`,
    "```",
    "",
    "If the hash matches, choose **More info**, then **Run anyway**. Automatic updates don't need this: " +
      "the app checks each update's signature itself.",
  ].join("\n");
}

/**
 * Checks `manifest` against what the publish job signed: the version, the .sig's text in every entry,
 * each signature over `installer`, and each URL equal to `url`, an API asset URL of `repo`.
 */
export function checkManifest(manifest, { version, file, installer, signature, pub, url, api, repo }) {
  if (manifest?.version !== version) fail(`${MANIFEST} says version ${manifest?.version}, not ${version}`);
  if (typeof manifest.notes !== "string" || manifest.notes.length === 0) fail(`${MANIFEST} has no notes`);
  if (Number.isNaN(Date.parse(manifest.pub_date))) fail(`${MANIFEST} has no valid pub_date`);
  const platforms = Object.keys(manifest.platforms ?? {}).sort();
  if (platforms.join() !== [...PLATFORMS].sort().join()) fail(`${MANIFEST} lists platforms ${platforms.join(", ")}`);
  const assetUrl = new RegExp(`^${escapeRegExp(`${api}/repos/${repo}/releases/assets/`)}\\d+$`);
  for (const name of PLATFORMS) {
    const entry = manifest.platforms[name];
    if (entry.signature !== signature) fail(`${MANIFEST} ${name}: the signature is not the .sig file's`);
    verifySignature(entry.signature, installer, pub, { what: `${MANIFEST} ${name}`, file, version });
    if (entry.url !== url || !assetUrl.test(entry.url)) {
      fail(`${MANIFEST} ${name}: ${entry.url} is not the installer's API asset URL ${url}`);
    }
  }
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

class Github {
  constructor(api, repo, token) {
    this.api = api;
    this.repo = repo;
    this.token = token;
  }

  headers(extra = {}) {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "remotely-release",
      ...extra,
    };
  }

  async call(method, url, { body, headers, expect = [200] } = {}) {
    const response = await fetch(url, { method, body, headers: this.headers(headers), redirect: "manual" });
    if (!expect.includes(response.status)) {
      const text = await response.text().catch(() => "");
      const message = (() => {
        try {
          return JSON.parse(text).message;
        } catch {
          return text.slice(0, 200);
        }
      })();
      fail(`${method} ${url.split("?")[0]} answered ${response.status}: ${message}`);
    }
    return response;
  }

  async json(method, path, options) {
    const response = await this.call(method, `${this.api}/repos/${this.repo}/${path}`, options);
    return response.status === 204 ? null : response.json();
  }

  async releaseWithTag(tag) {
    for (let page = 1; ; page++) {
      const releases = await this.json("GET", `releases?per_page=100&page=${page}`);
      const found = releases.find((release) => release.tag_name === tag);
      if (found || releases.length < 100) return found;
    }
  }

  async upload(release, name, bytes) {
    const url = `${release.upload_url.replace(/\{.*\}$/, "")}?name=${encodeURIComponent(name)}`;
    const response = await this.call("POST", url, {
      body: bytes,
      headers: { "Content-Type": "application/octet-stream" },
      expect: [201],
    });
    return response.json();
  }

  /** A release file through its API URL, as installed apps fetch it: the token goes to the API only. */
  async download(assetUrl) {
    const response = await this.call("GET", assetUrl, {
      headers: { Accept: "application/octet-stream" },
      expect: [200, 302],
    });
    if (response.status === 200) return Buffer.from(await response.arrayBuffer());
    const location = response.headers.get("location");
    if (!location) fail(`${assetUrl} redirected nowhere`);
    const stored = await fetch(location, { headers: { "User-Agent": "remotely-release" } });
    if (!stored.ok) fail(`the installer's storage URL answered ${stored.status}`);
    return Buffer.from(await stored.arrayBuffer());
  }
}

export async function publish({
  tag,
  installerPath,
  notesPath,
  configPath,
  pubkey,
  env = process.env,
  log = console.log,
}) {
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  const version = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(tag ?? "")?.[1];
  if (!version) fail(`${tag} is not a vX.Y.Z tag`);
  if (config.version !== version) fail(`tag ${tag} does not match tauri.conf.json's version ${config.version}`);
  const file = installerName(config.productName, version);
  if (basename(installerPath) !== file) fail(`the installer is ${basename(installerPath)}, not ${file}`);
  const sigPath = `${installerPath}.sig`;
  if (!existsSync(sigPath)) fail(`${sigPath} does not exist: sign the installer first`);

  const repo = env.GITHUB_REPOSITORY;
  const token = env.GITHUB_TOKEN;
  if (!repo || !token) fail("GITHUB_REPOSITORY and GITHUB_TOKEN must be set");
  const api = (env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");

  // 1. Everything that can be checked before a release exists.
  if (pubkey) log("checking against the public key given with --pubkey, not tauri.conf.json's (key rotation)");
  const pub = parsePublicKey(pubkey ?? configPublicKey(config));
  const installer = readFileSync(installerPath);
  const signature = readFileSync(sigPath, "utf8");
  verifySignature(signature, installer, pub, { what: sigPath, file, version });
  log(`ok: ${file} (sha256 ${sha256(installer)}) is signed for ${version} with the app's key`);
  const notes = (existsSync(notesPath) ? readFileSync(notesPath, "utf8") : "").trimEnd() || `Remotely ${tag}`;

  const github = new Github(api, repo, token);
  const existing = await github.releaseWithTag(tag);
  if (existing) {
    fail(`a release for ${tag} already exists (${existing.draft ? "a draft" : "published"}): delete it first`);
  }

  // 2. The draft, with the installer and its signature.
  const release = await github.json("POST", "releases", {
    body: JSON.stringify({
      tag_name: tag,
      name: `Remotely ${tag}`,
      body: releaseBody({ notes, file, installer }),
      draft: true,
      prerelease: false,
    }),
    headers: { "Content-Type": "application/json" },
    expect: [201],
  });
  log(`created draft release ${release.id} for ${tag}`);
  try {
    const asset = await github.upload(release, file, installer);
    await github.upload(release, `${file}.sig`, Buffer.from(signature, "utf8"));

    // 3 and 4. latest.json, checked as an installed app reads it.
    const manifest = latestJson({ version, notes, pubDate: new Date().toISOString(), signature, url: asset.url });
    checkManifest(manifest, { version, file, installer, signature, pub, url: asset.url, api, repo });
    const fetched = await github.download(asset.url);
    if (!fetched.equals(installer)) {
      fail(`${asset.url} serves ${fetched.length} bytes (sha256 ${sha256(fetched)}), not the signed installer`);
    }
    verifySignature(signature, fetched, pub, { what: `the installer fetched from ${asset.url}`, file, version });
    log(`ok: ${MANIFEST} checks out, and ${asset.url} serves the signed installer`);

    // 5. latest.json last: until it is there, the app can't install the release.
    await github.upload(release, MANIFEST, Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8"));
    const assets = await github.json("GET", `releases/${release.id}/assets?per_page=100`);
    const names = assets.map((a) => a.name).sort();
    const want = [file, `${file}.sig`, MANIFEST].sort();
    if (names.join() !== want.join()) fail(`the draft holds ${names.join(", ")}, not ${want.join(", ")}`);
    log(`draft ready: ${release.html_url ?? release.id} (${names.join(", ")}). Smoke-test it, then publish it.`);
    return { release, manifest };
  } catch (err) {
    log(`deleting draft release ${release.id}, because: ${err.message}`);
    await github.json("DELETE", `releases/${release.id}`, { expect: [204, 404] }).catch((deleteErr) => {
      log(`could not delete draft release ${release.id} (${deleteErr.message}): delete it by hand`);
    });
    throw err;
  }
}

async function main(args) {
  const tag = takeOption(args, "--tag");
  const installerPath = takeOption(args, "--installer");
  const notesPath = takeOption(args, "--notes") ?? "";
  const configPath = takeOption(args, "--config") ?? "src-tauri/tauri.conf.json";
  const pubkey = takeOption(args, "--pubkey");
  if (!tag || !installerPath || args.length > 0) {
    fail(
      "usage: publish-release.mjs --tag vX.Y.Z --installer <file> --notes <file> [--config <tauri.conf.json>] " +
        "[--pubkey <base64>]",
    );
  }
  await publish({ tag, installerPath, notesPath, configPath, pubkey });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main(process.argv.slice(2)).catch((err) => {
    console.error(`error: ${err instanceof VerifyError ? err.message : err}`);
    process.exit(1);
  });
}
